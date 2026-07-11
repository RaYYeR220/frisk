/**
 * OKX OnchainOS security integration. Frisk orchestrates OKX's own token-security scanner
 * (honeypot / mint / tax / fund-linkage / counterfeit detection) under the hood and folds its
 * verdict into the target detector — then layers on the x402-payment-integrity and
 * prompt-injection checks that no commodity scanner performs.
 *
 * The provider shells out to the `onchainos security token-scan` CLI. Everything is best-effort:
 * if the CLI is absent (e.g. in a container) or errors, `scan()` returns undefined and the
 * detector falls back to its built-in heuristics. The mapper is pure and unit-tested.
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Finding } from "@frisk/shared";
import { finding } from "../util";

const pexec = promisify(execFile);

/** A single token's security scan (subset of the OKX token-scan response we act on). */
export interface SecurityScan {
  tokenAddress?: string;
  chainId?: string;
  riskLevel?: string; // "LOW" | "MEDIUM" | "HIGH"
  isHoneypot?: boolean;
  isMintable?: boolean;
  isNotRenounced?: boolean;
  isOverIssued?: boolean;
  isCounterfeit?: boolean;
  isAirdropScam?: boolean;
  isFundLinkage?: boolean;
  isNotOpenSource?: boolean;
  isFakeLiquidity?: boolean;
  isDumping?: boolean;
  isChainSupported?: boolean;
  buyTaxes?: string;
  sellTaxes?: string;
  [key: string]: unknown;
}

export interface SecurityProvider {
  scan(address: string, chainId: number): Promise<SecurityScan | undefined>;
}

const SRC = { source: "okx-onchainos-security" } as const;

function pctFromTax(tax: unknown): number | undefined {
  const n = typeof tax === "string" ? Number(tax) : typeof tax === "number" ? tax : NaN;
  if (!Number.isFinite(n)) return undefined;
  // values arrive either as a fraction (0.30) or as a percent (30). Treat <=1 as a fraction.
  return n <= 1 ? n * 100 : n;
}

/** Map an OKX token-security scan onto Frisk target-detector findings. Pure. */
export function mapSecurityScan(scan: SecurityScan, address: string): Finding[] {
  const out: Finding[] = [];
  const ev = (extra: Record<string, unknown>) => ({ address, ...SRC, ...extra });

  if (scan.isHoneypot === true) {
    out.push(finding("target", "HONEYPOT_HEURISTIC", "critical", "OKX flags this token as a honeypot",
      `${address} is flagged as a honeypot by OKX security — buyers may be unable to sell.`, ev({ isHoneypot: true })));
  }
  if (scan.isCounterfeit === true) {
    out.push(finding("target", "DENYLIST_HIT", "high", "Counterfeit token",
      `${address} is flagged as a counterfeit/impersonating token by OKX security.`, ev({ isCounterfeit: true })));
  }
  if (scan.isFundLinkage === true) {
    out.push(finding("target", "DENYLIST_HIT", "high", "Linked to flagged funds",
      `${address} is linked to addresses flagged for illicit fund movement (OKX security).`, ev({ isFundLinkage: true })));
  }
  if (scan.isAirdropScam === true) {
    out.push(finding("target", "DENYLIST_HIT", "medium", "Airdrop-scam token",
      `${address} is flagged as an airdrop scam by OKX security.`, ev({ isAirdropScam: true })));
  }
  if (scan.isMintable === true || scan.isNotRenounced === true || scan.isOverIssued === true) {
    out.push(finding("target", "MINT_AUTHORITY", "medium", "Mintable / owner not renounced",
      `${address} can still be minted or is controlled by a privileged owner (OKX security) — supply/rug lever.`,
      ev({ isMintable: scan.isMintable, isNotRenounced: scan.isNotRenounced, isOverIssued: scan.isOverIssued })));
  }
  if (scan.isNotOpenSource === true) {
    out.push(finding("target", "UNVERIFIED_CONTRACT", "medium", "Contract source not open",
      `${address} has no open/verified source (OKX security) — its behaviour can't be audited.`, ev({ isNotOpenSource: true })));
  }
  if (scan.isFakeLiquidity === true) {
    out.push(finding("target", "HONEYPOT_HEURISTIC", "medium", "Fake liquidity",
      `${address} shows fake-liquidity signals (OKX security).`, ev({ isFakeLiquidity: true })));
  }

  const buy = pctFromTax(scan.buyTaxes);
  const sell = pctFromTax(scan.sellTaxes);
  const maxTax = Math.max(buy ?? 0, sell ?? 0);
  if (maxTax >= 15) {
    out.push(finding("target", "HONEYPOT_HEURISTIC", "high", "Punitive transfer tax",
      `${address} carries a ~${Math.round(maxTax)}% buy/sell tax (OKX security) — fee-on-transfer honeypot pattern.`,
      ev({ buyTaxPct: buy, sellTaxPct: sell })));
  }

  const risk = (scan.riskLevel ?? "").toUpperCase();
  if (out.length === 0 && risk === "HIGH") {
    out.push(finding("target", "HONEYPOT_HEURISTIC", "high", "OKX security risk: HIGH",
      `${address} is rated HIGH risk by OKX security.`, ev({ riskLevel: risk })));
  } else if (out.length === 0 && (risk === "LOW" || risk === "")) {
    out.push(finding("target", "SECURITY_SCAN_CLEAN", "none", "OKX security scan: clean",
      `${address} passed OKX security scanning with no red flags (risk ${risk || "LOW"}).`, ev({ riskLevel: risk || "LOW" })));
  }

  return out;
}

/** Production provider: shells out to the OnchainOS `security token-scan` CLI. */
export class OnchainOsSecurityProvider implements SecurityProvider {
  constructor(private readonly opts: { bin?: string; timeoutMs?: number } = {}) {}

  async scan(address: string, chainId: number): Promise<SecurityScan | undefined> {
    try {
      const bin = this.opts.bin ?? "onchainos";
      const { stdout } = await pexec(
        bin,
        ["security", "token-scan", "--tokens", `${chainId}:${address}`],
        { timeout: this.opts.timeoutMs ?? 15_000, maxBuffer: 1 << 20 },
      );
      const parsed = JSON.parse(stdout) as { ok?: boolean; data?: SecurityScan[] };
      if (parsed?.ok && Array.isArray(parsed.data) && parsed.data.length > 0) return parsed.data[0];
      return undefined;
    } catch {
      return undefined; // CLI missing/unauthed/errored → detector falls back to heuristics
    }
  }
}
