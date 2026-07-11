/**
 * EIP-712 typed-data for a Frisk verdict attestation. The struct is ERC-8004
 * Validation-Registry-shaped and MUST match the Solidity `FriskRegistry.Verdict` struct
 * byte-for-byte (same field order, same types) so an off-chain signature verifies on-chain.
 */

import {
  hashTypedData,
  recoverTypedDataAddress,
  verifyTypedData,
  type TypedDataDomain,
} from "viem";
import type { Attestation, AttestationMessage } from "./types.js";

export const ATTESTATION_TYPES = {
  Verdict: [
    { name: "subject", type: "bytes32" },
    { name: "intentHash", type: "bytes32" },
    { name: "decision", type: "uint8" },
    { name: "score", type: "uint16" },
    { name: "findingsHash", type: "bytes32" },
    { name: "issuedAt", type: "uint64" },
    { name: "expiresAt", type: "uint64" },
    { name: "validator", type: "address" },
    { name: "nonce", type: "bytes32" },
  ],
} as const;

export function attestationDomain(
  chainId: number,
  verifyingContract: `0x${string}`,
): TypedDataDomain {
  return { name: "Frisk", version: "1", chainId, verifyingContract };
}

/**
 * Coerce a message's numeric fields back to the types viem's EIP-712 encoder needs. An
 * attestation that round-tripped through JSON carries `issuedAt`/`expiresAt` as strings; this
 * makes verification robust to that.
 */
function normalizeMessage(m: AttestationMessage): AttestationMessage {
  return { ...m, issuedAt: BigInt(m.issuedAt), expiresAt: BigInt(m.expiresAt) };
}

/** The struct hash (EIP-712 digest) — also the registry key (`uid`). */
export function attestationUID(
  chainId: number,
  verifyingContract: `0x${string}`,
  message: AttestationMessage,
): `0x${string}` {
  return hashTypedData({
    domain: attestationDomain(chainId, verifyingContract),
    types: ATTESTATION_TYPES,
    primaryType: "Verdict",
    message: normalizeMessage(message),
  });
}

/** Verify a presented attestation: signature recovers to the claimed validator. */
export async function verifyAttestation(att: Attestation): Promise<boolean> {
  return verifyTypedData({
    address: att.message.validator,
    domain: att.domain,
    types: ATTESTATION_TYPES,
    primaryType: "Verdict",
    message: normalizeMessage(att.message),
    signature: att.signature,
  });
}

/** Recover the signer address from an attestation (for diagnostics). */
export async function recoverAttestationSigner(att: Attestation): Promise<`0x${string}`> {
  return recoverTypedDataAddress({
    domain: att.domain,
    types: ATTESTATION_TYPES,
    primaryType: "Verdict",
    message: normalizeMessage(att.message),
    signature: att.signature,
  });
}
