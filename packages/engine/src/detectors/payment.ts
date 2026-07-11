/**
 * paymentIntegrity — the differentiator.
 *
 * A buyer-agent negotiates a deal (the intent), receives an x402 402 challenge, and is about
 * to sign an EIP-3009 `transferWithAuthorization`. Between "what the buyer meant" and "what the
 * buyer is about to sign" a hostile facilitator, MITM or malicious seller can rewrite the payee,
 * inflate the amount, swap the asset/network, slip in an unoffered requirement, or — worst —
 * decouple the signed authorization from the presented requirement so the signature drains funds
 * to an attacker while the UI shows the honest deal (CVE class GHSA-qr2g-p6q7-w82m).
 *
 * This detector is PURE (no network). It only needs the challenge, the (optional) payload the
 * buyer is about to send, the negotiated intent, and `ctx.now`, so it is fully unit-testable.
 */

import {
  caip2ToChainId,
  knownToken,
  type Detector,
  type DetectorContext,
  type Eip3009Authorization,
  type Finding,
  type FriskRequest,
  type PaymentRequired,
  type PaymentRequirements,
} from "@frisk/shared";
import { parseUnits, recoverTypedDataAddress, type TypedDataDomain } from "viem";
import { buildResult, eqAddr, finding, isBytes32, isHexAddress, skipped, toBigInt } from "../util";

const D = "payment" as const;

/** The ERC-20 EIP-712 struct a buyer signs to authorize a gasless transfer. */
const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: "from", type: "address" },
    { name: "to", type: "address" },
    { name: "value", type: "uint256" },
    { name: "validAfter", type: "uint256" },
    { name: "validBefore", type: "uint256" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

const ONE_YEAR = 365 * 24 * 60 * 60;
/** Amount over the negotiated figure that trips a critical (2x). */
const CRITICAL_INFLATION = 2;
const MAX_EXTRA_BYTES = 8 * 1024;
/** ~1e18 of a 6-decimal stablecoin — nobody legitimately authorizes this. */
const ABSURD_ATOMIC_VALUE = 10n ** 24n;

export interface PaymentDetectorOptions {
  /** Warn threshold for amount inflation vs the negotiated figure (fraction, default 0.5%). */
  amountTolerance?: number;
}

/** Normalize the many on-wire shapes of an EIP-3009 authorization into one struct. */
export function decodeEip3009(payload: Record<string, unknown>): Eip3009Authorization | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  // x402 exact-EVM wraps the fields under `authorization` with a sibling `signature`;
  // some producers flatten everything. Support both.
  const auth = (payload.authorization ?? payload) as Record<string, unknown>;
  const signature = (payload.signature ?? auth.signature) as unknown;

  const from = auth.from;
  const to = auth.to;
  const value = auth.value;
  const validAfter = auth.validAfter;
  const validBefore = auth.validBefore;
  const nonce = auth.nonce;

  if (!isHexAddress(from) || !isHexAddress(to)) return undefined;
  if (toBigInt(value) === undefined) return undefined;
  if (typeof signature !== "string" || !/^0x[0-9a-fA-F]+$/.test(signature)) return undefined;

  return {
    from: from as `0x${string}`,
    to: to as `0x${string}`,
    value: String(value),
    validAfter: validAfter === undefined ? "0" : String(validAfter),
    validBefore: validBefore === undefined ? "0" : String(validBefore),
    nonce: (isBytes32(nonce) ? nonce : "0x0") as `0x${string}`,
    signature: signature as `0x${string}`,
  };
}

/** EIP-712 domain of the settlement token, sourced from the x402 `extra` (name/version). */
function tokenDomain(req: PaymentRequirements): TypedDataDomain | undefined {
  const chainId = caip2ToChainId(req.network);
  if (chainId === undefined || !isHexAddress(req.asset)) return undefined;
  const extra = (req.extra ?? {}) as Record<string, unknown>;
  const name = typeof extra.name === "string" ? extra.name : undefined;
  const version = typeof extra.version === "string" ? extra.version : undefined;
  if (!name || !version) return undefined; // cannot recover a signer without the token domain
  return { name, version, chainId, verifyingContract: req.asset as `0x${string}` };
}

/** Structural equality of the offer-defining fields of a requirement. */
function sameRequirement(a: PaymentRequirements, b: PaymentRequirements): boolean {
  return (
    a.scheme === b.scheme &&
    a.network === b.network &&
    eqAddr(a.asset, b.asset) &&
    eqAddr(a.payTo, b.payTo) &&
    String(a.amount) === String(b.amount)
  );
}

function decimalsFor(asset: string, req?: PaymentRequirements): number {
  const known = knownToken(asset);
  if (known) return known.decimals;
  const extra = (req?.extra ?? {}) as Record<string, unknown>;
  if (typeof extra.decimals === "number") return extra.decimals;
  return 6; // X Layer stablecoins are all 6dp; safe default
}

function resolveExpectedAsset(expected: string): string {
  const t = expected.trim();
  if (isHexAddress(t)) return t.toLowerCase();
  const bySymbol = knownToken(t); // handles addresses; symbol handled below
  if (bySymbol) return bySymbol.address.toLowerCase();
  return t.toLowerCase();
}

function malformedChallenge(challenge: PaymentRequired): Finding[] {
  const out: Finding[] = [];

  // resource.url sanity
  const url = challenge.resource?.url;
  if (typeof url === "string" && url.length > 0) {
    const lowered = url.toLowerCase();
    const dangerous =
      lowered.startsWith("javascript:") ||
      lowered.startsWith("data:") ||
      lowered.startsWith("file:") ||
      lowered.includes("@") || // embedded credentials / host confusion
      lowered.includes("xn--"); // punycode homograph
    if (dangerous) {
      out.push(
        finding(
          D,
          "MALFORMED_CHALLENGE",
          "high",
          "Suspicious resource URL",
          `The challenge resource URL looks hostile or obfuscated: ${url}`,
          { url },
        ),
      );
    } else if (!/^https:\/\//.test(lowered) && !/^http:\/\/localhost/.test(lowered)) {
      out.push(
        finding(
          D,
          "MALFORMED_CHALLENGE",
          "low",
          "Non-HTTPS resource URL",
          `The challenge resource is not served over HTTPS: ${url}`,
          { url },
        ),
      );
    }
  }

  challenge.accepts?.forEach((r, i) => {
    const bad: string[] = [];
    if (!r.scheme) bad.push("scheme");
    if (!r.network || caip2ToChainId(r.network) === undefined) bad.push("network");
    if (!isHexAddress(r.asset)) bad.push("asset");
    if (!isHexAddress(r.payTo)) bad.push("payTo");
    if (toBigInt(r.amount) === undefined) bad.push("amount");
    if (bad.length) {
      out.push(
        finding(
          D,
          "MALFORMED_CHALLENGE",
          "medium",
          "Malformed payment requirement",
          `accepts[${i}] has invalid field(s): ${bad.join(", ")}.`,
          { index: i, invalid: bad },
        ),
      );
    }
    if (r.extra != null) {
      const size = JSON.stringify(r.extra).length;
      if (size > MAX_EXTRA_BYTES) {
        out.push(
          finding(
            D,
            "MALFORMED_CHALLENGE",
            "medium",
            "Oversized requirement extra",
            `accepts[${i}].extra is ${size} bytes (limit ${MAX_EXTRA_BYTES}).`,
            { index: i, size },
          ),
        );
      }
    }
  });

  return out;
}

/** Coherence of the intent against every offered requirement. */
function checkCoherence(req: FriskRequest, opts: PaymentDetectorOptions): Finding[] {
  const out: Finding[] = [];
  const intent = req.intent;
  const accepts = req.paymentChallenge?.accepts ?? [];
  const chosen = req.paymentPayload?.accepted;
  const tolerance = opts.amountTolerance ?? 0.005;

  // Candidate requirements to check the intent against: the one the buyer chose (if any),
  // else all offered.
  const targets: Array<{ where: string; r: PaymentRequirements }> = chosen
    ? [{ where: "paymentPayload.accepted", r: chosen }]
    : accepts.map((r, i) => ({ where: `accepts[${i}]`, r }));

  for (const { where, r } of targets) {
    // payTo
    if (intent.expectedPayTo && isHexAddress(r.payTo) && !eqAddr(intent.expectedPayTo, r.payTo)) {
      out.push(
        finding(
          D,
          "PAYTO_MISMATCH",
          "critical",
          "Payment recipient does not match the deal",
          `Buyer intends to pay ${intent.expectedPayTo} but ${where}.payTo is ${r.payTo}.`,
          { where, expected: intent.expectedPayTo, actual: r.payTo },
        ),
      );
    }
    // asset
    if (intent.expectedAsset && isHexAddress(r.asset)) {
      const want = resolveExpectedAsset(intent.expectedAsset);
      if (!eqAddr(want, r.asset)) {
        out.push(
          finding(
            D,
            "ASSET_SWAP",
            "high",
            "Settlement asset was swapped",
            `Buyer expected asset ${intent.expectedAsset} (${want}) but ${where}.asset is ${r.asset}.`,
            { where, expected: want, actual: r.asset.toLowerCase() },
          ),
        );
      }
    }
    // network
    if (intent.network && r.network && intent.network !== r.network) {
      out.push(
        finding(
          D,
          "NETWORK_MISMATCH",
          "high",
          "Settlement network was changed",
          `Buyer expected network ${intent.network} but ${where}.network is ${r.network}.`,
          { where, expected: intent.network, actual: r.network },
        ),
      );
    }
    // amount
    if (intent.expectedAmount) {
      const decimals = decimalsFor(r.asset, r);
      let expectedAtomic: bigint | undefined;
      try {
        expectedAtomic = parseUnits(intent.expectedAmount, decimals);
      } catch {
        expectedAtomic = undefined;
      }
      const actualAtomic = toBigInt(r.amount);
      if (expectedAtomic !== undefined && actualAtomic !== undefined && actualAtomic > expectedAtomic) {
        const ratio = expectedAtomic === 0n ? Infinity : Number(actualAtomic) / Number(expectedAtomic);
        const over = expectedAtomic === 0n ? 1 : Number(actualAtomic - expectedAtomic) / Number(expectedAtomic);
        if (over > tolerance) {
          out.push(
            finding(
              D,
              "AMOUNT_INFLATED",
              ratio >= CRITICAL_INFLATION ? "critical" : "high",
              "Charged amount exceeds the negotiated price",
              `Buyer agreed to ${intent.expectedAmount} but ${where} charges ${r.amount} atomic (~${(
                Number(actualAtomic) /
                10 ** decimals
              ).toString()}), ${(over * 100).toFixed(1)}% over.`,
              {
                where,
                expectedAtomic: expectedAtomic.toString(),
                actualAtomic: actualAtomic.toString(),
                overPct: over * 100,
              },
            ),
          );
        }
      }
    }
  }

  return out;
}

/** The accepted requirement must be one the server actually offered. */
function checkUnoffered(req: FriskRequest): Finding[] {
  const chosen = req.paymentPayload?.accepted;
  const accepts = req.paymentChallenge?.accepts;
  if (!chosen || !accepts?.length) return [];
  const offered = accepts.some((r) => sameRequirement(r, chosen));
  if (offered) return [];
  return [
    finding(
      D,
      "UNOFFERED_REQUIREMENT",
      "critical",
      "Signing a requirement the server never offered",
      "paymentPayload.accepted is not present in the challenge's accepts[] — the buyer was steered into signing terms the server did not advertise (facilitator swap / MITM).",
      { accepted: chosen, offeredCount: accepts.length },
    ),
  ];
}

/** Decode + cryptographically verify the EIP-3009 authorization against the accepted terms. */
async function checkAuthorization(req: FriskRequest, ctx: DetectorContext): Promise<Finding[]> {
  const payload = req.paymentPayload;
  if (!payload) return [];
  const out: Finding[] = [];

  const auth = decodeEip3009(payload.payload);
  if (!auth) {
    out.push(
      finding(
        D,
        "MALFORMED_CHALLENGE",
        "high",
        "Undecodable payment authorization",
        "paymentPayload.payload is not a decodable EIP-3009 transferWithAuthorization.",
        { payloadKeys: Object.keys(payload.payload ?? {}) },
      ),
    );
    return out;
  }

  const accepted = payload.accepted;
  const value = toBigInt(auth.value)!;
  const acceptedAmount = toBigInt(accepted?.amount);

  // The two structural links that must hold between signature and offer.
  const toMismatch = accepted?.payTo && !eqAddr(auth.to, accepted.payTo);
  const valueMismatch = acceptedAmount !== undefined && value !== acceptedAmount;

  // Cryptographic link: the signature must genuinely be the buyer's over THESE fields.
  let recovered: `0x${string}` | undefined;
  const domain = accepted ? tokenDomain(accepted) : undefined;
  if (domain) {
    try {
      recovered = await recoverTypedDataAddress({
        domain,
        types: TRANSFER_WITH_AUTHORIZATION_TYPES,
        primaryType: "TransferWithAuthorization",
        message: {
          from: auth.from,
          to: auth.to,
          value,
          validAfter: toBigInt(auth.validAfter) ?? 0n,
          validBefore: toBigInt(auth.validBefore) ?? 0n,
          nonce: auth.nonce,
        },
        signature: auth.signature,
      });
    } catch {
      recovered = undefined;
    }
  }
  // When we have the token domain we EXPECT the signature to recover to `from`. A recovery that
  // fails (throws → undefined) or lands on another address is just as decoupled as a wrong `to`.
  const signerMismatch = !!domain && !eqAddr(recovered, auth.from);

  if (toMismatch || valueMismatch || signerMismatch) {
    const reasons: string[] = [];
    if (toMismatch) reasons.push(`signed 'to' ${auth.to} != accepted.payTo ${accepted!.payTo}`);
    if (valueMismatch) reasons.push(`signed value ${auth.value} != accepted.amount ${accepted!.amount}`);
    if (signerMismatch)
      reasons.push(`recovered signer ${recovered ?? "<unrecoverable>"} != authorization.from ${auth.from}`);
    out.push(
      finding(
        D,
        "AUTH_DECOUPLED_FROM_INTENT",
        "critical",
        "Signed authorization is decoupled from the presented terms",
        `The EIP-3009 signature the buyer is about to send does not match the offer it is presented against: ${reasons.join(
          "; ",
        )}. This is the drain vector (GHSA-qr2g-p6q7-w82m).`,
        {
          signedTo: auth.to,
          signedValue: auth.value,
          acceptedPayTo: accepted?.payTo,
          acceptedAmount: accepted?.amount,
          recovered,
          from: auth.from,
        },
      ),
    );
  } else if (domain) {
    // positive confirmation: recovered signer == from, and to/value match the offer
    out.push(
      finding(
        D,
        "AUTH_VERIFIED",
        "none",
        "Authorization matches the deal",
        `Recovered signer ${recovered} authorizes exactly ${auth.value} to ${auth.to} as offered.`,
        { signer: recovered, to: auth.to, value: auth.value },
      ),
    );
  } else {
    out.push(
      finding(
        D,
        "AUTH_UNVERIFIED_DOMAIN",
        "low",
        "Could not recover signer (missing token EIP-712 domain)",
        "accepted.extra did not carry the token {name, version}; structural checks passed but the signature could not be cryptographically bound to the buyer.",
        { asset: accepted?.asset, network: accepted?.network },
      ),
    );
  }

  // ---- sanity on the authorization window / value / nonce ----
  const now = ctx.now;
  const validBefore = toBigInt(auth.validBefore) ?? 0n;
  const validAfter = toBigInt(auth.validAfter) ?? 0n;

  if (validBefore !== 0n && validBefore <= BigInt(now)) {
    out.push(
      finding(
        D,
        "AUTH_EXPIRED",
        "medium",
        "Authorization is already expired",
        `validBefore ${validBefore} is at/behind now ${now}; a facilitator replaying it is suspicious.`,
        { validBefore: validBefore.toString(), now },
      ),
    );
  } else if (validBefore !== 0n && validBefore - BigInt(now) > BigInt(ONE_YEAR)) {
    out.push(
      finding(
        D,
        "AUTH_WINDOW_EXCESSIVE",
        "medium",
        "Authorization valid for an excessive window",
        `validBefore is more than a year out (${validBefore}); over-long windows widen the replay surface.`,
        { validBefore: validBefore.toString(), now },
      ),
    );
  }
  if (validAfter > BigInt(now) + 3600n) {
    out.push(
      finding(
        D,
        "AUTH_NOT_YET_VALID",
        "low",
        "Authorization not valid until the future",
        `validAfter ${validAfter} is well ahead of now ${now}.`,
        { validAfter: validAfter.toString(), now },
      ),
    );
  }
  if (value > ABSURD_ATOMIC_VALUE) {
    out.push(
      finding(
        D,
        "AUTH_VALUE_EXCESSIVE",
        "high",
        "Authorized value is absurdly large",
        `Signed value ${auth.value} is beyond any plausible price — likely a max-drain authorization.`,
        { value: auth.value },
      ),
    );
  }
  if (/^0x0+$/.test(auth.nonce)) {
    out.push(
      finding(
        D,
        "NONCE_REPLAY_RISK",
        "low",
        "Non-random authorization nonce",
        "The EIP-3009 nonce is all-zero (non-random); it should be unpredictable to resist replay.",
        { nonce: auth.nonce },
      ),
    );
  }

  return out;
}

export function createPaymentDetector(opts: PaymentDetectorOptions = {}): Detector {
  return {
    name: D,
    async run(req, ctx) {
      if (!req.paymentChallenge) {
        return skipped(D, "no paymentChallenge to inspect");
      }
      if (!Array.isArray(req.paymentChallenge.accepts) || req.paymentChallenge.accepts.length === 0) {
        return buildResult(D, [
          finding(
            D,
            "MALFORMED_CHALLENGE",
            "high",
            "Challenge offers no payment requirements",
            "paymentChallenge.accepts is empty; nothing legitimate to pay.",
          ),
        ]);
      }

      const findings: Finding[] = [
        ...malformedChallenge(req.paymentChallenge),
        ...checkCoherence(req, opts),
        ...checkUnoffered(req),
        ...(await checkAuthorization(req, ctx)),
      ];

      return buildResult(D, findings);
    },
  };
}
