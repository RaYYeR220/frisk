/**
 * The composite Frisk engine: run the applicable detectors, time each, combine their results with
 * the shared scorer, and assemble an UNSIGNED FriskVerdict. The verdict's `attestation` is left
 * undefined on purpose — the ASP holds the signing key and attaches the EIP-712 attestation.
 */

import {
  CHAINS,
  combineResults,
  intentHash,
  knownToken,
  requestId,
  type Decision,
  type Detector,
  type DetectorContext,
  type DetectorName,
  type DetectorResult,
  type Finding,
  type FriskEngine,
  type FriskRequest,
  type FriskVerdict,
} from "@frisk/shared";
import { createTargetDetector, type TargetDetectorOptions } from "./detectors/target";
import { createPaymentDetector, type PaymentDetectorOptions } from "./detectors/payment";
import {
  createCounterpartyDetector,
  type CounterpartyDetectorOptions,
} from "./detectors/counterparty";
import { createTaskDetector } from "./detectors/task";
import { MockReputationProvider } from "./providers/reputation";
import type { TaskClassifier } from "@frisk/shared";

/** Verdict lifetime in seconds (buyer must act within this window). */
export const VERDICT_TTL_SECONDS = 600;

const ALL_DETECTORS: DetectorName[] = ["target", "payment", "counterparty", "task"];

export interface CreateEngineOptions {
  /** Context defaults; per-call `ctxOverride` wins over these. */
  defaults?: Partial<DetectorContext>;
  target?: TargetDetectorOptions;
  payment?: PaymentDetectorOptions;
  counterparty?: CounterpartyDetectorOptions;
  /** default reputation provider when the context doesn't carry one. */
  reputation?: DetectorContext["reputation"];
  /** default task-injection LLM classifier. */
  classifier?: TaskClassifier;
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function buildSummary(decision: Decision, findings: Finding[]): string {
  if (findings.length === 0) {
    return decision === "ALLOW"
      ? "No risks detected across the enabled checks — safe to proceed."
      : `${decision}: no findings recorded.`;
  }
  const top = findings.slice(0, 3).map((f) => f.title);
  const criticals = findings.filter((f) => f.severity === "critical").length;
  const lead =
    decision === "BLOCK"
      ? criticals > 0
        ? `BLOCK — ${criticals} critical issue${criticals > 1 ? "s" : ""}`
        : "BLOCK — high combined risk"
      : decision === "WARN"
        ? "WARN — proceed only with caution"
        : "ALLOW — minor notes";
  return `${lead}: ${top.join("; ")}${findings.length > 3 ? ` (+${findings.length - 3} more)` : ""}.`;
}

export function createEngine(options: CreateEngineOptions = {}): FriskEngine {
  const detectors: Record<DetectorName, Detector> = {
    target: createTargetDetector(options.target),
    payment: createPaymentDetector(options.payment),
    counterparty: createCounterpartyDetector(options.counterparty),
    task: createTaskDetector({ classifier: options.classifier }),
  };

  const baseDefaults: Partial<DetectorContext> = {
    rpcUrl: CHAINS.xlayerMainnet.rpcUrl,
    chainId: CHAINS.xlayerMainnet.chainId,
    reputation: options.reputation ?? new MockReputationProvider(),
    classifier: options.classifier,
    ...options.defaults,
  };

  async function runOne(
    name: DetectorName,
    req: FriskRequest,
    ctx: DetectorContext,
  ): Promise<DetectorResult> {
    const start = performance.now();
    try {
      const res = await detectors[name].run(req, ctx);
      return { ...res, latencyMs: Math.round((performance.now() - start) * 1000) / 1000 };
    } catch (err) {
      // Detectors must never throw; if one does (e.g. an unexpected RPC error), degrade to a
      // non-blocking skipped result rather than failing the whole assessment.
      return {
        detector: name,
        ran: false,
        score: 0,
        decision: "ALLOW",
        findings: [],
        note: `detector errored: ${(err as Error)?.message ?? "unknown"}`,
        latencyMs: Math.round((performance.now() - start) * 1000) / 1000,
      };
    }
  }

  return {
    async assess(req: FriskRequest, ctxOverride?: Partial<DetectorContext>): Promise<FriskVerdict> {
      // Defensive: an agent-caller may POST a partial or empty body. Never throw — normalise so
      // every `req.intent.*` read below (and in intentHash) is safe. Missing signals simply make
      // a detector report ran:false; a valid verdict is still produced (ALLOW when nothing flags).
      req = { ...(req ?? {}), intent: (req?.intent ?? {}) } as FriskRequest;
      const now = ctxOverride?.now ?? baseDefaults.now ?? nowSeconds();
      const ctx: DetectorContext = {
        rpcUrl: baseDefaults.rpcUrl!,
        chainId: baseDefaults.chainId!,
        now,
        reputation: baseDefaults.reputation,
        classifier: baseDefaults.classifier,
        logger: baseDefaults.logger,
        ...ctxOverride,
      };

      const requested = req.options?.detectors;
      const enabled = (requested && requested.length ? requested : ALL_DETECTORS).filter((d) =>
        ALL_DETECTORS.includes(d),
      );

      const results = await Promise.all(enabled.map((name) => runOne(name, req, ctx)));

      const combined = combineResults(results);

      const asset = req.intent.expectedAsset;
      const resolvedAsset =
        asset && knownToken(asset) ? knownToken(asset)!.address : asset;

      const verdict: FriskVerdict = {
        version: "1",
        id: requestId(req),
        decision: combined.decision,
        score: combined.score,
        severity: combined.severity,
        summary: buildSummary(combined.decision, combined.findings),
        detectors: results,
        findings: combined.findings,
        subject: {
          counterpartyAgentId: req.intent.counterpartyAgentId,
          target: req.target?.address,
          payTo: req.intent.expectedPayTo,
          amount: req.intent.expectedAmount,
          asset: resolvedAsset,
          network: req.intent.network ?? (req.target?.chainId ? `eip155:${req.target.chainId}` : undefined),
          intentHash: intentHash(req),
        },
        issuedAt: now,
        expiresAt: now + VERDICT_TTL_SECONDS,
        // attestation intentionally undefined — signed by the ASP.
      };

      return verdict;
    },
  };
}
