import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  type Account,
  type Hex,
  type PublicClient,
} from "viem";
import type { AttestationMessage } from "@frisk/shared";

/// Minimal ABI for the parts of FriskRegistry the ASP touches.
export const FRISK_REGISTRY_ABI = [
  {
    type: "function",
    name: "recordAttestation",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "v",
        type: "tuple",
        components: [
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
      },
      { name: "sig", type: "bytes" },
    ],
    outputs: [{ name: "uid", type: "bytes32" }],
  },
  {
    type: "function",
    name: "isValid",
    stateMutability: "view",
    inputs: [{ name: "uid", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "getAttestation",
    stateMutability: "view",
    inputs: [{ name: "uid", type: "bytes32" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "subject", type: "bytes32" },
          { name: "intentHash", type: "bytes32" },
          { name: "findingsHash", type: "bytes32" },
          { name: "decision", type: "uint8" },
          { name: "score", type: "uint16" },
          { name: "issuedAt", type: "uint64" },
          { name: "expiresAt", type: "uint64" },
          { name: "validator", type: "address" },
          { name: "slashed", type: "bool" },
          { name: "recorded", type: "bool" },
        ],
      },
    ],
  },
] as const;

export function publicClient(rpcUrl: string): PublicClient {
  return createPublicClient({ transport: http(rpcUrl) });
}

/** Read the on-chain validity of an anchored attestation. Returns null if none configured. */
export async function readOnChainValid(
  client: PublicClient,
  registry: `0x${string}`,
  uid: Hex,
): Promise<boolean> {
  return (await client.readContract({
    address: registry,
    abi: FRISK_REGISTRY_ABI,
    functionName: "isValid",
    args: [uid],
  })) as boolean;
}

/**
 * Anchor a signed verdict on-chain (best-effort). Returns the tx hash.
 * The caller decides whether to await it; failures should never block a response.
 */
export async function anchorAttestation(params: {
  rpcUrl: string;
  chainId: number;
  chainName: string;
  account: Account;
  registry: `0x${string}`;
  message: AttestationMessage;
  signature: Hex;
}): Promise<Hex> {
  const chain = defineChain({
    id: params.chainId,
    name: params.chainName,
    nativeCurrency: { name: "OKB", symbol: "OKB", decimals: 18 },
    rpcUrls: { default: { http: [params.rpcUrl] } },
  });
  const wallet = createWalletClient({ account: params.account, chain, transport: http(params.rpcUrl) });
  return wallet.writeContract({
    address: params.registry,
    abi: FRISK_REGISTRY_ABI,
    functionName: "recordAttestation",
    args: [params.message, params.signature],
  });
}
