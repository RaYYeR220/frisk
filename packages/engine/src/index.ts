/**
 * @frisk/engine — the four Frisk detectors + composite scorer.
 *
 * Buyer-agents call Frisk BEFORE they pay/sign. The engine composes targetRisk,
 * paymentIntegrity, counterpartyReputation and taskInjection into an unsigned FriskVerdict; the
 * ASP signs and (optionally) anchors it on-chain.
 */

// composite engine
export { createEngine, VERDICT_TTL_SECONDS, type CreateEngineOptions } from "./engine";

// detectors
export {
  createTargetDetector,
  adaptViemClient,
  type TargetDetectorOptions,
  type TargetClient,
  type TargetMetadata,
  type TargetMetadataProvider,
} from "./detectors/target";
export {
  createPaymentDetector,
  decodeEip3009,
  type PaymentDetectorOptions,
} from "./detectors/payment";
export {
  createCounterpartyDetector,
  evaluateReputation,
  type CounterpartyDetectorOptions,
} from "./detectors/counterparty";
export {
  createTaskDetector,
  scanText,
  HeuristicTaskClassifier,
  type HeuristicMatch,
} from "./detectors/task";

// denylist
export {
  DenylistChecker,
  staticDenylist,
  type DenylistEntry,
  type DenylistProvider,
} from "./detectors/denylist";

// default + production providers
export {
  MockReputationProvider,
  OnchainOsReputationProvider,
  DEFAULT_REPUTATION_FIXTURES,
  type OnchainOsReputationConfig,
} from "./providers/reputation";
export { AnthropicClassifier, type AnthropicClassifierOptions } from "./providers/anthropic";
export {
  OnchainOsSecurityProvider,
  mapSecurityScan,
  type SecurityProvider,
  type SecurityScan,
} from "./providers/security";

// helpers
export {
  buildResult,
  skipped,
  finding,
  scoreFromFindings,
  eqAddr,
  isHexAddress,
} from "./util";

// re-export the shared contract so consumers can `import { FriskRequest, ... } from "@frisk/engine"`
export * from "@frisk/shared";
