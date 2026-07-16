import { config as loadEnv } from "dotenv";
import { z } from "zod";
import { CHAINS } from "@frisk/shared";

loadEnv();

const Env = z.object({
  FRISK_NETWORK: z.enum(["mainnet", "testnet"]).default("testnet"),
  FRISK_SIGNER_PK: z
    .string()
    .regex(/^0x[0-9a-fA-F]{64}$/, "FRISK_SIGNER_PK must be a 32-byte hex key")
    .optional(),
  FRISK_PAYTO: z.string().regex(/^0x[0-9a-fA-F]{40}$/).optional(),
  FRISK_PUBLIC_URL: z.string().url().optional(),
  XLAYER_RPC: z.string().url().optional(),
  FRISK_REGISTRY_ADDR: z.string().regex(/^0x[0-9a-fA-F]{40}$/).optional(),
  ANTHROPIC_API_KEY: z.string().optional(),
  OKX_API_KEY: z.string().optional(),
  OKX_SECRET_KEY: z.string().optional(),
  OKX_PASSPHRASE: z.string().optional(),
  FRISK_DEV_BYPASS: z
    .string()
    .optional()
    .transform((v) => v === "1" || v === "true"),
  PORT: z.coerce.number().int().positive().default(8080),
  FRISK_PRICE: z.string().default("$0.05"),
});

export interface FriskConfig {
  network: "mainnet" | "testnet";
  chainId: number;
  caip2: `${string}:${string}`;
  rpcUrl: string;
  explorer: string;
  signerPk?: `0x${string}`;
  payTo?: `0x${string}`;
  publicUrl?: string;
  registryAddr?: `0x${string}`;
  anthropicKey?: string;
  okx?: { apiKey: string; secretKey: string; passphrase: string };
  devBypass: boolean;
  port: number;
  price: string;
}

export function loadConfig(overrides: Partial<FriskConfig> = {}): FriskConfig {
  const env = Env.parse(process.env);
  const chain = env.FRISK_NETWORK === "mainnet" ? CHAINS.xlayerMainnet : CHAINS.xlayerTestnet;
  const okx =
    env.OKX_API_KEY && env.OKX_SECRET_KEY && env.OKX_PASSPHRASE
      ? { apiKey: env.OKX_API_KEY, secretKey: env.OKX_SECRET_KEY, passphrase: env.OKX_PASSPHRASE }
      : undefined;
  return {
    network: env.FRISK_NETWORK,
    chainId: chain.chainId,
    caip2: chain.caip2 as `${string}:${string}`,
    rpcUrl: env.XLAYER_RPC ?? chain.rpcUrl,
    explorer: chain.explorer,
    signerPk: env.FRISK_SIGNER_PK as `0x${string}` | undefined,
    payTo: (env.FRISK_PAYTO as `0x${string}` | undefined),
    publicUrl: env.FRISK_PUBLIC_URL,
    registryAddr: env.FRISK_REGISTRY_ADDR as `0x${string}` | undefined,
    anthropicKey: env.ANTHROPIC_API_KEY,
    okx,
    devBypass: env.FRISK_DEV_BYPASS ?? false,
    port: env.PORT,
    price: env.FRISK_PRICE,
    ...overrides,
  };
}
