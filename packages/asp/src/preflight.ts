import { pad, toHex, type Hex } from "viem";
import type { PrivateKeyAccount } from "viem/accounts";
import {
  ATTESTATION_TYPES,
  attestationUID,
  DECISION_CODE,
  findingsHash,
  type Attestation,
  type AttestationMessage,
  type FriskEngine,
  type FriskRequest,
  type FriskVerdict,
} from "@frisk/shared";

export interface PreflightDeps {
  engine: FriskEngine;
  /** Frisk's signing account. When absent, the verdict is returned unsigned (dev/preview). */
  signer?: PrivateKeyAccount;
  /** chainId the attestation domain is bound to (X Layer 196 / 1952). */
  chainId: number;
  /** FriskRegistry address = EIP-712 verifyingContract. */
  registryAddr: `0x${string}`;
}

const ZERO_REGISTRY = "0x0000000000000000000000000000000000000000" as const;

/** bytes32 subject the attestation commits to: the assessed address, else the intent hash. */
function subjectBytes32(req: FriskRequest, verdict: FriskVerdict): Hex {
  const addr = req.target?.address ?? req.intent.expectedPayTo;
  return addr ? pad(addr, { size: 32 }) : verdict.subject.intentHash;
}

function randomNonce(): Hex {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/**
 * The heart of Frisk: assess a request and, if a signer is configured, wrap the verdict in a
 * signed, ERC-8004-Validation-shaped attestation. Pure and Express-free so it can back the HTTP
 * route, the MCP tool and the demo identically.
 */
export async function runPreflight(req: FriskRequest, deps: PreflightDeps): Promise<FriskVerdict> {
  // Defensive: an agent-caller may POST a partial/empty body. Normalise once here so both the
  // engine and the attestation path (subjectBytes32 reads req.intent.expectedPayTo) are safe.
  req = { ...(req ?? {}), intent: (req?.intent ?? {}) } as FriskRequest;
  const verdict = await deps.engine.assess(req);
  if (!deps.signer) return verdict;

  const registryAddr = deps.registryAddr ?? ZERO_REGISTRY;
  const message: AttestationMessage = {
    subject: subjectBytes32(req, verdict),
    intentHash: verdict.subject.intentHash,
    decision: DECISION_CODE[verdict.decision],
    score: verdict.score,
    findingsHash: findingsHash(verdict.findings),
    issuedAt: BigInt(verdict.issuedAt),
    expiresAt: BigInt(verdict.expiresAt),
    validator: deps.signer.address,
    nonce: randomNonce(),
  };

  const domain = {
    name: "Frisk",
    version: "1",
    chainId: deps.chainId,
    verifyingContract: registryAddr,
  } as const;

  const signature = await deps.signer.signTypedData({
    domain,
    types: ATTESTATION_TYPES,
    primaryType: "Verdict",
    message,
  });

  const attestation: Attestation = {
    schema: "frisk.verdict.v1",
    domain,
    message,
    signature,
    uid: attestationUID(deps.chainId, registryAddr, message),
  };

  return { ...verdict, attestation };
}
