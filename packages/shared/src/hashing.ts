/**
 * Deterministic, canonical hashing so the same request/verdict always yields the same
 * intentHash / findingsHash — on the server, in the client, and (for the struct hash) on-chain.
 */

import { keccak256, stringToBytes } from "viem";
import type { Finding, FriskRequest } from "./types.js";

/** Stable JSON: object keys sorted recursively, arrays preserved, undefined dropped. */
export function canonicalize(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortValue(v);
    }
    return out;
  }
  return value;
}

function lc(s: string | undefined): string | undefined {
  return s === undefined ? undefined : s.toLowerCase();
}

/**
 * Hash the essential, buyer-meaningful fields of a request. This is what the attestation
 * binds to: if any of these change, the intentHash changes, so a verdict can't be replayed
 * against a different deal.
 */
export function intentHash(req: FriskRequest): `0x${string}` {
  const essence = {
    action: req.intent.action,
    counterpartyAgentId: req.intent.counterpartyAgentId,
    expectedPayTo: lc(req.intent.expectedPayTo),
    expectedAmount: req.intent.expectedAmount,
    expectedAsset: lc(req.intent.expectedAsset),
    network: req.intent.network,
    target: req.target
      ? { address: lc(req.target.address), chainId: req.target.chainId }
      : undefined,
    task: req.task ? { text: req.task.text } : undefined,
  };
  return keccak256(stringToBytes(canonicalize(essence)));
}

/** Deterministic id for a request (used as the verdict id). */
export function requestId(req: FriskRequest): `0x${string}` {
  return keccak256(stringToBytes(canonicalize(req)));
}

/** Hash the sorted set of findings so the attestation commits to exactly what was reported. */
export function findingsHash(findings: Finding[]): `0x${string}` {
  const canon = [...findings]
    .map((f) => ({ detector: f.detector, code: f.code, severity: f.severity }))
    .sort((a, b) =>
      a.detector === b.detector
        ? a.code.localeCompare(b.code)
        : a.detector.localeCompare(b.detector),
    );
  return keccak256(stringToBytes(canonicalize(canon)));
}
