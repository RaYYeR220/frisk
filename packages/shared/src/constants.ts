/**
 * X Layer network + settlement-token constants used across Frisk.
 * Verified against OKX docs, ChainList and the official xlayer-tokenlist.
 */

export interface ChainInfo {
  chainId: number;
  caip2: string;
  name: string;
  rpcUrl: string;
  explorer: string;
  nativeCurrency: { name: string; symbol: string; decimals: number };
}

export const CHAINS = {
  xlayerMainnet: {
    chainId: 196,
    caip2: "eip155:196",
    name: "X Layer",
    rpcUrl: "https://rpc.xlayer.tech",
    explorer: "https://www.oklink.com/xlayer",
    nativeCurrency: { name: "OKB", symbol: "OKB", decimals: 18 },
  },
  xlayerTestnet: {
    chainId: 1952,
    caip2: "eip155:1952",
    name: "X Layer Testnet",
    rpcUrl: "https://testrpc.xlayer.tech/terigon",
    explorer: "https://www.oklink.com/xlayer-test",
    nativeCurrency: { name: "OKB", symbol: "OKB", decimals: 18 },
  },
} as const satisfies Record<string, ChainInfo>;

export interface TokenInfo {
  address: `0x${string}`;
  symbol: string;
  decimals: number;
}

/** Stablecoins on X Layer mainnet (chainId 196). USDT0 is the x402 default settlement asset. */
export const TOKENS = {
  USDT0: {
    address: "0x779Ded0c9e1022225f8E0630b35a9b54bE713736",
    symbol: "USDT0",
    decimals: 6,
  },
  USDC: {
    address: "0x74b7F16337b8972027F6196A17a631aC6dE26d22",
    symbol: "USDC",
    decimals: 6,
  },
  USDG: {
    address: "0x4ae46a509f6b1d9056937ba4500cb143933d2dc8",
    symbol: "USDG",
    decimals: 6,
  },
} as const satisfies Record<string, TokenInfo>;

/** CAIP-2 helpers. */
export const CAIP2 = {
  mainnet: CHAINS.xlayerMainnet.caip2,
  testnet: CHAINS.xlayerTestnet.caip2,
} as const;

export function caip2ToChainId(caip2: string): number | undefined {
  const m = /^eip155:(\d+)$/.exec(caip2.trim());
  return m ? Number(m[1]) : undefined;
}

/** Look up a known token by (lowercased) address on X Layer mainnet. */
export function knownToken(address: string): TokenInfo | undefined {
  const a = address.toLowerCase();
  return Object.values(TOKENS).find((t) => t.address.toLowerCase() === a);
}
