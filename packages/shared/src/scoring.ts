/**
 * Composite scoring: how the four detector results combine into one verdict.
 * Kept in @frisk/shared so the engine, the service and the tests all agree.
 */

import {
  SEVERITY_ORDER,
  type Decision,
  type DetectorResult,
  type Finding,
  type Severity,
} from "./types.js";

export const THRESHOLDS = {
  /** score < WARN_AT => ALLOW */
  warnAt: 25,
  /** score >= BLOCK_AT => BLOCK */
  blockAt: 61,
} as const;

/** Baseline risk score a single finding of a given severity contributes. */
export const SEVERITY_SCORE: Record<Severity, number> = {
  none: 0,
  low: 15,
  medium: 40,
  high: 70,
  critical: 100,
};

export function severityFromScore(score: number): Severity {
  if (score >= 90) return "critical";
  if (score >= THRESHOLDS.blockAt) return "high";
  if (score >= THRESHOLDS.warnAt) return "medium";
  if (score > 0) return "low";
  return "none";
}

export function scoreToDecision(score: number, hasCritical: boolean): Decision {
  if (hasCritical) return "BLOCK";
  if (score >= THRESHOLDS.blockAt) return "BLOCK";
  if (score >= THRESHOLDS.warnAt) return "WARN";
  return "ALLOW";
}

export function maxSeverity(findings: Finding[]): Severity {
  let worst: Severity = "none";
  for (const f of findings) {
    if (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]) worst = f.severity;
  }
  return worst;
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
}

export interface Combined {
  score: number;
  decision: Decision;
  severity: Severity;
  findings: Finding[];
}

/**
 * Combine detector results. The composite score is the worst single detector score, nudged
 * up when multiple detectors independently flag risk (defence in depth). A single `critical`
 * finding forces BLOCK regardless of the numeric score.
 */
export function combineResults(results: DetectorResult[]): Combined {
  const ran = results.filter((r) => r.ran);
  const findings = sortFindings(ran.flatMap((r) => r.findings));
  const hasCritical = findings.some((f) => f.severity === "critical");

  const scores = ran.map((r) => r.score).sort((a, b) => b - a);
  const top = scores[0] ?? 0;
  const second = scores[1] ?? 0;
  // escalate when a second independent signal also fires
  const escalation = second >= THRESHOLDS.warnAt ? Math.round(second * 0.25) : 0;
  const score = Math.min(100, top + escalation);

  return {
    score,
    decision: scoreToDecision(score, hasCritical),
    severity: hasCritical ? "critical" : severityFromScore(score),
    findings,
  };
}
