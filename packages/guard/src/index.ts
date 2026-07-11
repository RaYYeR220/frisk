import type { FriskRequest, FriskVerdict, PaymentRequired } from "@frisk/shared";

/** Thrown when Frisk returns a BLOCK verdict — the payment is never sent. */
export class FriskBlockedError extends Error {
  constructor(public readonly verdict: FriskVerdict) {
    super(`Frisk blocked this action: ${verdict.summary}`);
    this.name = "FriskBlockedError";
  }
}

/** What the buyer BELIEVES it negotiated — Frisk checks the challenge against this. */
export interface Deal {
  counterpartyAgentId?: string;
  expectedPayTo?: `0x${string}`;
  expectedAmount?: string;
  expectedAsset?: string;
  network?: string;
  description?: string;
  task?: { text: string; source?: string };
}

export interface GuardPolicy {
  onWarn?: (verdict: FriskVerdict) => void;
  /** treat WARN like BLOCK (default false). */
  blockOnWarn?: boolean;
}

export interface GuardOptions {
  /** Base URL of a Frisk ASP (its /v1/preflight is called). */
  friskUrl: string;
  /** Payment-capable fetch (e.g. wrapFetchWithPaymentFromConfig from @okxweb3/x402-fetch). Defaults to plain fetch. */
  pay?: typeof fetch;
  /** Override the preflight transport (testing / custom). */
  preflight?: (req: FriskRequest) => Promise<FriskVerdict>;
  policy?: GuardPolicy;
  /** fetch used for the unpaid probe + preflight POST. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export interface GuardedFetch {
  (input: string | URL | Request, init?: RequestInit, deal?: Deal): Promise<Response>;
  preflight(req: FriskRequest): Promise<FriskVerdict>;
}

/**
 * A drop-in fetch that frisks every x402 payment before it is signed. It probes the resource;
 * on a 402 it parses the payment challenge, calls Frisk, and only pays if the verdict is not a
 * BLOCK. Non-402 responses pass straight through.
 */
export function createGuardedFetch(opts: GuardOptions): GuardedFetch {
  const baseFetch = opts.fetchImpl ?? fetch;
  const payFetch = opts.pay ?? baseFetch;
  const friskBase = opts.friskUrl.replace(/\/$/, "");

  const preflight =
    opts.preflight ??
    (async (req: FriskRequest): Promise<FriskVerdict> => {
      const res = await baseFetch(`${friskBase}/v1/preflight`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(req),
      });
      if (!res.ok) throw new Error(`Frisk preflight failed: ${res.status}`);
      return (await res.json()) as FriskVerdict;
    });

  const guarded = (async (input, init, deal) => {
    const probe = await baseFetch(input, init);
    if (probe.status !== 402) return probe;

    let challenge: PaymentRequired | undefined;
    try {
      challenge = (await probe.clone().json()) as PaymentRequired;
    } catch {
      challenge = undefined;
    }

    const verdict = await preflight(buildRequest(deal, challenge));

    if (verdict.decision === "BLOCK") throw new FriskBlockedError(verdict);
    if (verdict.decision === "WARN") {
      opts.policy?.onWarn?.(verdict);
      if (opts.policy?.blockOnWarn) throw new FriskBlockedError(verdict);
    }

    return payFetch(input, init);
  }) as GuardedFetch;

  guarded.preflight = preflight;
  return guarded;
}

function buildRequest(deal: Deal | undefined, challenge?: PaymentRequired): FriskRequest {
  const accept = challenge?.accepts?.[0];
  return {
    intent: {
      action: "pay",
      counterpartyAgentId: deal?.counterpartyAgentId,
      expectedPayTo: deal?.expectedPayTo,
      expectedAmount: deal?.expectedAmount,
      expectedAsset: deal?.expectedAsset,
      network: deal?.network ?? accept?.network,
      description: deal?.description,
    },
    paymentChallenge: challenge,
    target: deal?.expectedPayTo ? { address: deal.expectedPayTo, kind: "unknown" } : undefined,
    task: deal?.task,
  };
}
