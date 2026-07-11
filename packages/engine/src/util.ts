/**
 * Small shared helpers for the detectors. Kept dependency-light and pure so every
 * detector scores identically and the composite engine stays deterministic.
 */

import {
  SEVERITY_SCORE,
  scoreToDecision,
  type Decision,
  type DetectorName,
  type DetectorResult,
  type Finding,
  type Severity,
} from "@frisk/shared";

/** Case-insensitive equality for two optional addresses/strings. */
export function eqAddr(a?: string | null, b?: string | null): boolean {
  if (!a || !b) return false;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/** Strict 20-byte hex address shape check (does not verify checksum). */
export function isHexAddress(s: unknown): s is `0x${string}` {
  return typeof s === "string" && /^0x[0-9a-fA-F]{40}$/.test(s.trim());
}

/** 32-byte hex (nonce / bytes32). */
export function isBytes32(s: unknown): s is `0x${string}` {
  return typeof s === "string" && /^0x[0-9a-fA-F]{64}$/.test(s.trim());
}

/** Non-throwing BigInt parse for atomic-amount strings. */
export function toBigInt(v: unknown): bigint | undefined {
  try {
    if (typeof v === "bigint") return v;
    if (typeof v === "number" && Number.isInteger(v)) return BigInt(v);
    if (typeof v === "string" && /^\d+$/.test(v.trim())) return BigInt(v.trim());
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * A single detector's numeric risk: the worst finding dominates, with a small nudge when a
 * second independent finding also fires (defence in depth within one detector).
 */
export function scoreFromFindings(findings: Finding[]): number {
  if (findings.length === 0) return 0;
  const scores = findings.map((f) => SEVERITY_SCORE[f.severity]).sort((a, b) => b - a);
  const top = scores[0] ?? 0;
  const second = scores[1] ?? 0;
  return Math.min(100, top + Math.round(second * 0.15));
}

/** Build a DetectorResult with a consistent score/decision derivation. */
export function buildResult(
  detector: DetectorName,
  findings: Finding[],
  opts?: { ran?: boolean; note?: string },
): DetectorResult {
  const ran = opts?.ran ?? true;
  const active = ran ? findings : [];
  const hasCritical = active.some((f) => f.severity === "critical");
  const score = scoreFromFindings(active);
  const decision: Decision = ran ? scoreToDecision(score, hasCritical) : "ALLOW";
  return { detector, ran, score, decision, findings: active, note: opts?.note };
}

/** A detector that could not run for lack of required input (never an error). */
export function skipped(detector: DetectorName, note: string): DetectorResult {
  return { detector, ran: false, score: 0, decision: "ALLOW", findings: [], note };
}

/** Terse constructor for a Finding. */
export function finding(
  detector: DetectorName,
  code: string,
  severity: Severity,
  title: string,
  description: string,
  evidence?: Record<string, unknown>,
): Finding {
  return { detector, code, severity, title, description, evidence };
}
