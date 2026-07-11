/**
 * Frisk core type contract. Every package imports these; do not fork them.
 *
 * A buyer-agent calls Frisk BEFORE it pays/signs. It sends a FriskRequest (the "intent
 * envelope"); Frisk runs four detectors and returns a FriskVerdict carrying a signed,
 * optionally on-chain, bond-backed Attestation.
 */

// ---------- x402 shapes (mirrors @okxweb3/x402-core/schemas, kept dependency-light) ----------

export interface PaymentRequirements {
  scheme: string;
  /** CAIP-2, e.g. "eip155:196" */
  network: string;
  /** atomic units of `asset` */
  amount: string;
  /** token contract address */
  asset: string;
  /** recipient wallet */
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown> | null;
}

export interface PaymentRequired {
  x402Version: 2;
  error?: string;
  resource: { url: string; description?: string; mimeType?: string };
  accepts: PaymentRequirements[];
  extensions?: Record<string, unknown> | null;
}

export interface PaymentPayload {
  x402Version: 2;
  resource?: { url: string; description?: string; mimeType?: string };
  /** the specific requirement the client chose to satisfy */
  accepted: PaymentRequirements;
  /** scheme-specific signed data; for exact-EVM this is the EIP-3009 authorization + signature */
  payload: Record<string, unknown>;
  extensions?: Record<string, unknown> | null;
}

/** Decoded EIP-3009 `transferWithAuthorization` inner payload (exact-EVM scheme). */
export interface Eip3009Authorization {
  from: `0x${string}`;
  to: `0x${string}`;
  value: string;
  validAfter: string;
  validBefore: string;
  nonce: `0x${string}`;
  signature: `0x${string}`;
}

// ---------- request ----------

export type ActionKind = "pay" | "sign" | "accept_task";
export type TargetKind = "token" | "contract" | "eoa" | "unknown";

export interface FriskIntent {
  action: ActionKind;
  /** seller ASP agent id on OKX.AI (ERC-8004 identity) */
  counterpartyAgentId?: string;
  /** who the buyer BELIEVES it is paying */
  expectedPayTo?: `0x${string}`;
  /** human units, e.g. "0.5" */
  expectedAmount?: string;
  /** token address or symbol the buyer expects to spend */
  expectedAsset?: string;
  /** CAIP-2 network the buyer expects */
  network?: string;
  /** the buyer's own note describing the negotiated deal */
  description?: string;
}

export interface FriskTarget {
  address?: `0x${string}`;
  chainId?: number;
  kind?: TargetKind;
}

export interface FriskTask {
  /** the task text an agent is being asked to execute */
  text: string;
  source?: string;
}

export type DetectorName = "target" | "payment" | "counterparty" | "task";

export interface FriskRequest {
  intent: FriskIntent;
  /** the x402 402 challenge the buyer received (powers the payment detector) */
  paymentChallenge?: PaymentRequired;
  /** the payment the buyer is about to send (strongest payment check) */
  paymentPayload?: PaymentPayload;
  /** the on-chain target of the action to risk-scan */
  target?: FriskTarget;
  /** task text to screen for prompt injection */
  task?: FriskTask;
  options?: {
    /** restrict which detectors run; default = all with sufficient input */
    detectors?: DetectorName[];
    /** anchor the verdict on-chain if severity warrants */
    anchor?: boolean;
  };
}

// ---------- verdict ----------

export type Decision = "ALLOW" | "WARN" | "BLOCK";
export type Severity = "none" | "low" | "medium" | "high" | "critical";

/** Decision <-> uint8 mapping shared with the Solidity FriskRegistry. */
export const DECISION_CODE: Record<Decision, number> = { ALLOW: 0, WARN: 1, BLOCK: 2 };
export const DECISION_FROM_CODE: Record<number, Decision> = { 0: "ALLOW", 1: "WARN", 2: "BLOCK" };

export const SEVERITY_ORDER: Record<Severity, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface Finding {
  detector: DetectorName;
  /** stable machine code, e.g. "PAYTO_MISMATCH" */
  code: string;
  title: string;
  severity: Severity;
  description: string;
  evidence?: Record<string, unknown>;
}

export interface DetectorResult {
  detector: DetectorName;
  /** false when the detector lacked required input (never throw for missing input) */
  ran: boolean;
  /** 0 = safe .. 100 = lethal */
  score: number;
  decision: Decision;
  findings: Finding[];
  latencyMs?: number;
  /** optional note, e.g. why the detector was skipped */
  note?: string;
}

export interface VerdictSubject {
  counterpartyAgentId?: string;
  target?: string;
  payTo?: string;
  amount?: string;
  asset?: string;
  network?: string;
  /** keccak256 of the canonical intent — binds the attestation to what the buyer meant */
  intentHash: `0x${string}`;
}

export interface FriskVerdict {
  version: "1";
  /** deterministic id (hash of the request) */
  id: string;
  decision: Decision;
  /** composite 0..100 */
  score: number;
  severity: Severity;
  summary: string;
  detectors: DetectorResult[];
  /** flattened, sorted most-severe first */
  findings: Finding[];
  subject: VerdictSubject;
  issuedAt: number;
  expiresAt: number;
  attestation?: Attestation;
}

// ---------- attestation (EIP-712, ERC-8004 Validation-shaped) ----------

/**
 * The signed struct — field order/types MUST match the Solidity `Verdict` struct.
 * `issuedAt`/`expiresAt` are `bigint` (Solidity uint64); viem's EIP-712 encoder requires it.
 */
export interface AttestationMessage {
  subject: `0x${string}`;
  intentHash: `0x${string}`;
  /** uint8: 0 ALLOW, 1 WARN, 2 BLOCK */
  decision: number;
  /** uint16: 0..100 */
  score: number;
  findingsHash: `0x${string}`;
  issuedAt: bigint;
  expiresAt: bigint;
  validator: `0x${string}`;
  nonce: `0x${string}`;
}

export interface Attestation {
  schema: "frisk.verdict.v1";
  domain: {
    name: "Frisk";
    version: "1";
    chainId: number;
    verifyingContract: `0x${string}`;
  };
  message: AttestationMessage;
  signature: `0x${string}`;
  /** struct hash / registry key; set once known */
  uid?: `0x${string}`;
}

// ---------- detector plumbing ----------

export interface ReputationRecord {
  agentId: string;
  found: boolean;
  jobsCompleted?: number;
  rating?: number;
  disputes?: number;
  /** identity age in seconds */
  ageSeconds?: number;
}

export interface ReputationProvider {
  lookup(agentId: string): Promise<ReputationRecord>;
}

export interface TaskClassifierResult {
  injection: boolean;
  confidence: number;
  categories: string[];
  rationale?: string;
}

export interface TaskClassifier {
  classify(text: string): Promise<TaskClassifierResult>;
}

export interface DetectorContext {
  rpcUrl: string;
  chainId: number;
  /** unix seconds; injected for determinism in tests */
  now: number;
  reputation?: ReputationProvider;
  classifier?: TaskClassifier;
  logger?: (msg: string) => void;
}

export interface Detector {
  name: DetectorName;
  run(req: FriskRequest, ctx: DetectorContext): Promise<DetectorResult>;
}

/**
 * Public engine surface. The engine composes the detectors into an unsigned FriskVerdict
 * (verdict.attestation is left undefined — the ASP holds the signing key and attaches the
 * signed, on-chain-anchored attestation).
 */
export interface FriskEngine {
  assess(req: FriskRequest, ctxOverride?: Partial<DetectorContext>): Promise<FriskVerdict>;
}
