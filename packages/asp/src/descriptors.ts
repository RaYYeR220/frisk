/**
 * Machine-readable service-discovery descriptors so an agent-caller (e.g. the OKX.AI A2MCP
 * platform) can learn how to invoke Frisk without a human in the loop. Served free at the
 * well-known paths callers probe: OpenAPI (`/openapi.json`, `/m2m-openapi.json`,
 * `/.well-known/openapi.json`), an MCP server-card (`/.well-known/mcp.json`,
 * `/.well-known/mcp/server-card.json`), and a root index.
 */
import type { FriskConfig } from "./config.js";

export function baseUrl(cfg: FriskConfig): string {
  return cfg.publicUrl ?? "https://frisk-930639894082.europe-west1.run.app";
}

const FRISK_REQUEST_SCHEMA = {
  type: "object",
  description: "What you believe you agreed to, plus the payment challenge / task / target to screen.",
  properties: {
    intent: {
      type: "object",
      description: "The deal the buyer-agent thinks it agreed to.",
      properties: {
        action: { type: "string", enum: ["pay", "sign", "accept_task"], default: "pay" },
        counterpartyAgentId: { type: "string", description: "The seller agent's id (for reputation)." },
        expectedPayTo: { type: "string", description: "Address you believe you are paying (0x…)." },
        expectedAmount: { type: "string", description: "Human amount you agreed to, e.g. '0.5'." },
        expectedAsset: { type: "string", description: "Token address or symbol you agreed to pay in." },
        network: { type: "string", description: "CAIP-2 network, e.g. 'eip155:196'." },
        description: { type: "string" },
      },
    },
    paymentChallenge: { type: "object", description: "The x402 402 challenge (PaymentRequired) you received." },
    paymentPayload: { type: "object", description: "The signed x402 payment you are about to send (optional)." },
    task: {
      type: "object",
      description: "Task text to screen for prompt-injection / key-exfiltration.",
      properties: { text: { type: "string" }, source: { type: "string" } },
    },
    target: {
      type: "object",
      description: "A contract/token/payee to risk-scan.",
      properties: { address: { type: "string" }, chainId: { type: "number" } },
    },
    options: {
      type: "object",
      properties: { detectors: { type: "array", items: { type: "string", enum: ["payment", "target", "task", "counterparty"] } } },
    },
  },
} as const;

const FRISK_VERDICT_SCHEMA = {
  type: "object",
  properties: {
    decision: { type: "string", enum: ["ALLOW", "WARN", "BLOCK"], description: "The verdict." },
    score: { type: "number", description: "Composite risk 0–100." },
    severity: { type: "string" },
    summary: { type: "string" },
    findings: { type: "array", items: { type: "object" }, description: "Per-detector findings." },
    attestation: { type: "object", description: "Signed EIP-712 attestation (ERC-8004 Validation-shaped)." },
  },
} as const;

export function openapiSpec(cfg: FriskConfig): unknown {
  const url = baseUrl(cfg);
  return {
    openapi: "3.1.0",
    info: {
      title: "Frisk — pre-payment safety check",
      version: "0.1.0",
      description:
        "Screen a payment, task or counterparty BEFORE an agent pays or signs. Four detectors " +
        "(payment-integrity, target-risk, task-injection, counterparty-reputation) return a single " +
        "ALLOW / WARN / BLOCK verdict with a signed, on-chain, bond-backed attestation. Paid per call via x402.",
    },
    servers: [{ url }],
    paths: {
      "/v1/preflight": {
        post: {
          operationId: "friskPreflight",
          summary: "Run the pre-payment safety check.",
          description:
            `Paid per call via x402 (${cfg.price} on ${cfg.caip2}): the first call returns HTTP 402 with the ` +
            "payment challenge in the `payment-required` header; replay with the payment header to receive the " +
            "signed verdict. Body is a FriskRequest.",
          "x-payment": { protocol: "x402", network: cfg.caip2, price: cfg.price, payTo: cfg.payTo },
          requestBody: {
            required: true,
            content: { "application/json": { schema: { $ref: "#/components/schemas/FriskRequest" } } },
          },
          responses: {
            "200": {
              description: "Signed verdict.",
              content: { "application/json": { schema: { $ref: "#/components/schemas/FriskVerdict" } } },
            },
            "402": { description: "Payment required (x402). Challenge (accepts array) in the `payment-required` header." },
          },
        },
      },
      "/v1/verify": {
        post: {
          operationId: "friskVerify",
          summary: "Verify a presented attestation (free).",
          responses: { "200": { description: "Verification result." } },
        },
      },
    },
    components: { schemas: { FriskRequest: FRISK_REQUEST_SCHEMA, FriskVerdict: FRISK_VERDICT_SCHEMA } },
  };
}

export function mcpCard(cfg: FriskConfig): unknown {
  const url = baseUrl(cfg);
  return {
    schemaVersion: "2025-06-18",
    name: "frisk",
    version: "0.1.0",
    description: "Pre-payment safety check for the agent economy — frisk a deal before you pay or sign.",
    endpoint: `${url}/v1/preflight`,
    payment: { protocol: "x402", network: cfg.caip2, price: cfg.price, payTo: cfg.payTo },
    tools: [
      {
        name: "frisk_preflight",
        description:
          "Screen a payment, task or counterparty before paying or signing. Returns a signed " +
          "ALLOW / WARN / BLOCK verdict with per-detector findings and an EIP-712 attestation.",
        inputSchema: FRISK_REQUEST_SCHEMA,
        outputSchema: FRISK_VERDICT_SCHEMA,
      },
    ],
  };
}

export function rootIndex(cfg: FriskConfig): unknown {
  const url = baseUrl(cfg);
  return {
    name: "Frisk",
    description: "Pre-payment safety check for the agent economy. Frisk it before you trust it.",
    type: "A2MCP",
    endpoint: `${url}/v1/preflight`,
    discovery: {
      openapi: `${url}/openapi.json`,
      mcp: `${url}/.well-known/mcp.json`,
      agentCard: `${url}/.well-known/agent.json`,
    },
    payment: { protocol: "x402", network: cfg.caip2, price: cfg.price },
  };
}
