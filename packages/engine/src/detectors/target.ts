/**
 * targetRisk — what is the buyer about to touch on-chain?
 *
 * Given the action's target (and the payTo/asset from the intent) this detector classifies the
 * address (EOA vs contract), screens it against a bundled + pluggable scam/drainer denylist, and
 * runs best-effort ERC-20 red-flag reads (owner / pausable / fee-on-transfer) plus freshness and
 * verification heuristics. Every on-chain call is best-effort: a missing method or an RPC error
 * degrades to a note, never an exception.
 *
 * A viem PublicClient can be injected (`createTargetDetector({ client })`) so the whole thing is
 * unit-testable offline; otherwise one is built lazily from `ctx.rpcUrl` / `ctx.chainId`.
 */

import {
  knownToken,
  type Detector,
  type DetectorContext,
  type Finding,
  type FriskRequest,
} from "@frisk/shared";
import { createPublicClient, http } from "viem";
import { buildResult, eqAddr, finding, isHexAddress, skipped } from "../util";
import { DenylistChecker, type DenylistProvider } from "./denylist";
import { mapSecurityScan, type SecurityProvider } from "../providers/security";

const D = "target" as const;

/** Minimal read surface the detector needs; a viem PublicClient is adapted to it. */
export interface TargetClient {
  getBytecode(args: { address: `0x${string}` }): Promise<`0x${string}` | undefined>;
  getTransactionCount(args: { address: `0x${string}` }): Promise<number>;
  readContract(args: {
    address: `0x${string}`;
    abi: readonly unknown[];
    functionName: string;
    args?: readonly unknown[];
  }): Promise<unknown>;
}

/** Optional explorer/indexer metadata (verification + deployment age). Pluggable. */
export interface TargetMetadata {
  verified?: boolean;
  deployedAtSeconds?: number;
  sourceName?: string;
}
export interface TargetMetadataProvider {
  lookup(address: string, chainId: number): Promise<TargetMetadata | undefined> | TargetMetadata | undefined;
}

export interface TargetDetectorOptions {
  client?: TargetClient;
  denylistProvider?: DenylistProvider;
  metadataProvider?: TargetMetadataProvider;
  /** OKX OnchainOS token-security scanner; findings fold into the target result. */
  securityProvider?: SecurityProvider;
  /** contract younger than this (seconds) is "fresh"; default 7 days. */
  freshWindowSeconds?: number;
}

const FN = (name: string, outputs: { type: string }[]) =>
  [{ type: "function", name, inputs: [], outputs, stateMutability: "view" }] as const;

const OWNER_ABI = FN("owner", [{ type: "address" }]);
const PAUSED_ABI = FN("paused", [{ type: "bool" }]);
const ZERO = "0x0000000000000000000000000000000000000000";
const FEE_GETTERS = ["_taxFee", "sellTax", "_sellFee", "totalFees", "_totalTaxIfSelling"];

async function tryRead(
  client: TargetClient,
  address: `0x${string}`,
  abi: readonly unknown[],
  functionName: string,
): Promise<unknown> {
  try {
    return await client.readContract({ address, abi, functionName });
  } catch {
    return undefined;
  }
}

/** Adapt a viem PublicClient (or anything close) to the narrow TargetClient surface. */
export function adaptViemClient(client: Record<string, unknown>): TargetClient {
  const getCode = (client.getCode ?? client.getBytecode) as
    | ((a: { address: `0x${string}` }) => Promise<`0x${string}` | undefined>)
    | undefined;
  return {
    async getBytecode({ address }) {
      if (!getCode) return undefined;
      return getCode.call(client, { address });
    },
    async getTransactionCount({ address }) {
      const fn = client.getTransactionCount as (a: { address: `0x${string}` }) => Promise<number>;
      return fn.call(client, { address });
    },
    async readContract(args) {
      const fn = client.readContract as (a: unknown) => Promise<unknown>;
      return fn.call(client, args);
    },
  };
}

function lazyClient(ctx: DetectorContext): TargetClient | undefined {
  if (!ctx.rpcUrl) return undefined;
  try {
    // Constructing a client makes no network call; the transport only fires on a read.
    const client = createPublicClient({
      transport: http(ctx.rpcUrl),
      chain: {
        id: ctx.chainId,
        name: `chain-${ctx.chainId}`,
        nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 },
        rpcUrls: { default: { http: [ctx.rpcUrl] } },
      },
    });
    return adaptViemClient(client as unknown as Record<string, unknown>);
  } catch {
    return undefined;
  }
}

async function erc20RedFlags(
  client: TargetClient,
  address: `0x${string}`,
): Promise<Finding[]> {
  const out: Finding[] = [];

  const owner = (await tryRead(client, address, OWNER_ABI, "owner")) as string | undefined;
  if (typeof owner === "string" && isHexAddress(owner) && !eqAddr(owner, ZERO)) {
    out.push(
      finding(
        D,
        "MINT_AUTHORITY",
        "medium",
        "Contract has a privileged owner",
        `owner() is ${owner}. A live owner can typically mint, pause, blacklist or re-set fees — a rug/censorship lever.`,
        { owner },
      ),
    );
  }

  const paused = await tryRead(client, address, PAUSED_ABI, "paused");
  if (paused === true) {
    out.push(
      finding(
        D,
        "HONEYPOT_HEURISTIC",
        "high",
        "Token transfers are paused",
        "paused() returned true — funds sent may be untransferable (honeypot / freeze).",
        { paused: true },
      ),
    );
  }

  for (const getter of FEE_GETTERS) {
    const raw = await tryRead(client, address, FN(getter, [{ type: "uint256" }]), getter);
    const n = typeof raw === "bigint" ? Number(raw) : typeof raw === "number" ? raw : undefined;
    if (n === undefined) continue;
    // interpret as percent (0..100) or basis points (0..10000)
    const pct = n <= 100 ? n : n <= 10000 ? n / 100 : undefined;
    if (pct !== undefined && pct > 20) {
      out.push(
        finding(
          D,
          "HONEYPOT_HEURISTIC",
          "high",
          "Punitive transfer fee",
          `${getter}() implies a ~${pct}% transfer/sell fee — classic fee-on-transfer honeypot.`,
          { getter, value: n, pct },
        ),
      );
      break;
    }
  }

  return out;
}

export function createTargetDetector(opts: TargetDetectorOptions = {}): Detector {
  const denylist = new DenylistChecker({ provider: opts.denylistProvider });
  const freshWindow = opts.freshWindowSeconds ?? 7 * 24 * 60 * 60;

  return {
    name: D,
    async run(req: FriskRequest, ctx: DetectorContext) {
      const target = req.target?.address;
      const payTo = req.intent.expectedPayTo;
      const assetRaw = req.intent.expectedAsset;
      const asset = assetRaw && isHexAddress(assetRaw) ? (assetRaw as `0x${string}`) : undefined;
      const subject = (target ?? payTo) as `0x${string}` | undefined;

      if (!subject || !isHexAddress(subject)) {
        return skipped(D, "no target/payTo address to scan");
      }

      const findings: Finding[] = [];

      // 1) denylist — the cheapest, highest-signal check. Screen every distinct address.
      const candidates = [subject, payTo, asset].filter(
        (a): a is `0x${string}` => !!a && isHexAddress(a),
      );
      const seen = new Set<string>();
      for (const addr of candidates) {
        const key = addr.toLowerCase();
        if (seen.has(key)) continue;
        seen.add(key);
        const hit = await denylist.check(addr);
        if (hit) {
          findings.push(
            finding(
              D,
              "DENYLIST_HIT",
              "critical",
              "Address is on a scam/drainer denylist",
              `${addr} matches a known ${hit.category} address (${hit.label}, source ${hit.source}).`,
              { address: addr, category: hit.category, label: hit.label, source: hit.source },
            ),
          );
        }
      }

      // 1b) OKX OnchainOS security scan — orchestrate over OKX's own token scanner.
      // Trusted settlement tokens (USDT0/USDC/USDG) are legitimately mintable-by-bridge; don't
      // scan them — only unknown tokens carry rug surface.
      if (opts.securityProvider) {
        const tokenCandidates = [target, asset].filter(
          (a): a is `0x${string}` => !!a && isHexAddress(a) && !knownToken(a),
        );
        const scannedSet = new Set<string>();
        for (const addr of tokenCandidates) {
          const key = addr.toLowerCase();
          if (scannedSet.has(key)) continue;
          scannedSet.add(key);
          const scan = await opts.securityProvider.scan(addr, ctx.chainId);
          if (scan) findings.push(...mapSecurityScan(scan, addr));
        }
      }

      // 2) on-chain classification (best-effort)
      const client = opts.client ?? lazyClient(ctx);
      if (!client) {
        return buildResult(D, findings, {
          note: "on-chain checks skipped (no client / RPC unavailable)",
        });
      }

      let code: `0x${string}` | undefined;
      let onchainNote: string | undefined;
      try {
        code = await client.getBytecode({ address: subject });
      } catch {
        onchainNote = "bytecode read failed (RPC error)";
      }

      const isContract = !!code && code !== "0x" && code.length > 2;

      if (onchainNote) {
        return buildResult(D, findings, { note: onchainNote });
      }

      if (!isContract) {
        // EOA path
        let nonce: number | undefined;
        try {
          nonce = await client.getTransactionCount({ address: subject });
        } catch {
          nonce = undefined;
        }
        if (nonce === 0) {
          findings.push(
            finding(
              D,
              "FRESH_DEPLOY",
              "low",
              "Brand-new wallet with no history",
              `${subject} is an EOA with a zero nonce — no prior activity to build trust on.`,
              { address: subject, nonce },
            ),
          );
        }
        if (!findings.some((f) => f.severity === "critical")) {
          findings.push(
            finding(
              D,
              "EOA_TARGET_OK",
              "none",
              "Target is an externally-owned account",
              `${subject} is a plain wallet (no contract code); no contract-level rug surface.`,
              { address: subject, nonce },
            ),
          );
        }
        return buildResult(D, findings);
      }

      // contract path
      const isKnown = !!knownToken(subject);
      const meta = opts.metadataProvider
        ? await opts.metadataProvider.lookup(subject, ctx.chainId)
        : undefined;

      if (meta?.verified === false) {
        findings.push(
          finding(
            D,
            "UNVERIFIED_CONTRACT",
            "medium",
            "Contract source is not verified",
            `${subject} has no verified source on the explorer — its behaviour cannot be audited.`,
            { address: subject },
          ),
        );
      } else if (!isKnown && meta?.verified === undefined) {
        findings.push(
          finding(
            D,
            "UNVERIFIED_CONTRACT",
            "low",
            "Contract verification unknown",
            `${subject} is an unrecognized contract and no explorer provider is wired to confirm verified source.`,
            { address: subject },
          ),
        );
      }

      if (meta?.deployedAtSeconds !== undefined && ctx.now - meta.deployedAtSeconds < freshWindow) {
        const ageHrs = Math.max(0, Math.round((ctx.now - meta.deployedAtSeconds) / 3600));
        findings.push(
          finding(
            D,
            "FRESH_DEPLOY",
            "medium",
            "Freshly deployed contract",
            `${subject} was deployed ~${ageHrs}h ago — freshly-deployed targets are a common rug pattern.`,
            { address: subject, deployedAtSeconds: meta.deployedAtSeconds, ageHrs },
          ),
        );
      }

      if (!isKnown) {
        findings.push(...(await erc20RedFlags(client, subject)));
      }

      return buildResult(D, findings);
    },
  };
}
