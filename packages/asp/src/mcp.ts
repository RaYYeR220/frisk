/**
 * Frisk as an MCP server — the agent-facing surface. Any MCP-compatible agent host can call
 * `frisk_preflight` before it pays/signs and `frisk_verify_attestation` to check a verdict it was
 * handed. Same engine + signing path as the HTTP ASP.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { verifyAttestation, type Attestation, type FriskRequest } from "@frisk/shared";
import { loadConfig } from "./config.js";
import { buildDeps } from "./server.js";
import { runPreflight } from "./preflight.js";

const ADDR = /^0x[0-9a-fA-F]{40}$/;

function jsonify(value: unknown): string {
  return JSON.stringify(value, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2);
}

export function createMcpServer(): McpServer {
  const cfg = loadConfig();
  const deps = buildDeps(cfg);
  const server = new McpServer({ name: "frisk", version: "0.1.0" });

  server.registerTool(
    "frisk_preflight",
    {
      title: "Frisk pre-payment safety check",
      description:
        "Screen a payment, task or counterparty BEFORE an agent pays or signs. Returns a signed " +
        "verdict (ALLOW / WARN / BLOCK) with per-detector findings and an EIP-712 attestation. " +
        "Pass the negotiated intent plus the x402 payment challenge you received.",
      inputSchema: {
        action: z.enum(["pay", "sign", "accept_task"]).default("pay"),
        counterpartyAgentId: z.string().optional(),
        expectedPayTo: z.string().regex(ADDR).optional().describe("who you believe you are paying"),
        expectedAmount: z.string().optional().describe("human amount, e.g. '0.5'"),
        expectedAsset: z.string().optional().describe("token address or symbol"),
        network: z.string().optional().describe("CAIP-2, e.g. eip155:196"),
        description: z.string().optional(),
        paymentChallenge: z.any().optional().describe("the x402 402 challenge object (PaymentRequired)"),
        paymentPayload: z.any().optional().describe("the signed x402 payment you are about to send"),
        targetAddress: z.string().regex(ADDR).optional().describe("contract/token/payee to risk-scan"),
        taskText: z.string().optional().describe("the task text to screen for prompt injection"),
      },
    },
    async (args) => {
      const req: FriskRequest = {
        intent: {
          action: args.action,
          counterpartyAgentId: args.counterpartyAgentId,
          expectedPayTo: args.expectedPayTo as `0x${string}` | undefined,
          expectedAmount: args.expectedAmount,
          expectedAsset: args.expectedAsset,
          network: args.network,
          description: args.description,
        },
        paymentChallenge: args.paymentChallenge as FriskRequest["paymentChallenge"],
        paymentPayload: args.paymentPayload as FriskRequest["paymentPayload"],
        target: args.targetAddress
          ? { address: args.targetAddress as `0x${string}`, chainId: cfg.chainId }
          : undefined,
        task: args.taskText ? { text: args.taskText } : undefined,
      };
      const verdict = await runPreflight(req, deps);
      return {
        content: [{ type: "text", text: jsonify(verdict) }],
        isError: false,
      };
    },
  );

  server.registerTool(
    "frisk_verify_attestation",
    {
      title: "Verify a Frisk attestation",
      description:
        "Verify the EIP-712 signature of a Frisk verdict attestation (and its on-chain validity " +
        "when a registry is configured). Use this to trust a verdict another agent presents to you.",
      inputSchema: { attestation: z.any().describe("a Frisk Attestation object") },
    },
    async (args) => {
      const att = args.attestation as Attestation;
      let valid = false;
      try {
        valid = await verifyAttestation(att);
      } catch {
        valid = false;
      }
      return {
        content: [
          { type: "text", text: jsonify({ valid, validator: att?.message?.validator, uid: att?.uid }) },
        ],
      };
    },
  );

  return server;
}
