import express, { type Express, type Request, type Response } from "express";
import { privateKeyToAccount } from "viem/accounts";
import { paymentMiddleware } from "@okxweb3/x402-express";
import { x402ResourceServer } from "@okxweb3/x402-core/server";
import { OKXFacilitatorClient } from "@okxweb3/x402-core";
import { ExactEvmScheme } from "@okxweb3/x402-evm/exact/server";
import { createEngine, OnchainOsSecurityProvider } from "@frisk/engine";
import { verifyAttestation, type Attestation, type FriskRequest } from "@frisk/shared";
import { loadConfig, type FriskConfig } from "./config.js";
import { runPreflight, type PreflightDeps } from "./preflight.js";
import { publicClient, readOnChainValid } from "./registry.js";
import { openapiSpec, mcpCard, rootIndex } from "./descriptors.js";

/** JSON.stringify that survives bigint fields (the attestation carries uint64 as bigint). */
const jsonStringify = (v: unknown): string =>
  JSON.stringify(v, (_k, val) => (typeof val === "bigint" ? val.toString() : val));

const AGENT_NAME = "Frisk";
const AGENT_DESC =
  "Pre-payment safety for the agent economy. Frisk screens a payment, task or counterparty " +
  "before your agent signs — and returns a signed, on-chain, bond-backed verdict.";

export function buildDeps(cfg: FriskConfig): PreflightDeps {
  const engine = createEngine({
    defaults: { rpcUrl: cfg.rpcUrl, chainId: cfg.chainId },
    target: { securityProvider: new OnchainOsSecurityProvider() },
  });
  const signer = cfg.signerPk ? privateKeyToAccount(cfg.signerPk) : undefined;
  return {
    engine,
    signer,
    chainId: cfg.chainId,
    registryAddr: cfg.registryAddr ?? "0x0000000000000000000000000000000000000000",
  };
}

export function createServer(cfg: FriskConfig = loadConfig(), deps: PreflightDeps = buildDeps(cfg)): Express {
  const app = express();
  app.use(express.json({ limit: "1mb" }));

  const preflightHandler = async (req: Request, res: Response): Promise<void> => {
    try {
      const verdict = await runPreflight(req.body as FriskRequest, deps);
      res.type("application/json").send(jsonStringify(verdict));
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  };

  // --- paid route (A2MCP, x402) ------------------------------------------- //
  // In dev-bypass mode the check is free so demos/tests run without a facilitator.
  if (cfg.devBypass) {
    app.post("/v1/preflight", preflightHandler);
  } else {
    if (!cfg.okx) {
      throw new Error(
        "OKX facilitator credentials required for the paid route " +
          "(set OKX_API_KEY / OKX_SECRET_KEY / OKX_PASSPHRASE, or run with FRISK_DEV_BYPASS=1).",
      );
    }
    const resourceServer = new x402ResourceServer(
      new OKXFacilitatorClient({ ...cfg.okx, syncSettle: true }),
    ).register(cfg.caip2, new ExactEvmScheme());
    const paid = {
      accepts: {
        scheme: "exact",
        price: cfg.price,
        network: cfg.caip2,
        payTo: cfg.payTo ?? deps.signer?.address ?? "0x0000000000000000000000000000000000000000",
      },
      description: "Frisk pre-payment safety check — 4-detector verdict + signed attestation.",
    };
    app.use(
      paymentMiddleware(
        {
          // The x402 challenge is served on BOTH verbs: GET is the discovery/health probe
          // (returns the 402 + accepts array without a body), POST carries the FriskRequest.
          "GET /v1/preflight": paid,
          "POST /v1/preflight": paid,
        },
        resourceServer,
        undefined,
        undefined,
        true, // sync supported kinds from the facilitator on start so 402 challenges build
      ),
    );
    // A paid GET (rare — the probe never pays) just describes how to call the service.
    app.get("/v1/preflight", (_req: Request, res: Response): void => {
      res.json({
        service: "Frisk pre-payment safety check",
        method: "POST",
        body: "FriskRequest",
        price: cfg.price,
        network: cfg.caip2,
      });
    });
    app.post("/v1/preflight", preflightHandler);
  }

  // --- free routes -------------------------------------------------------- //
  app.post("/v1/verify", async (req: Request, res: Response): Promise<void> => {
    try {
      const att = req.body as Attestation;
      const valid = await verifyAttestation(att);
      let onChain: boolean | null = null;
      if (cfg.registryAddr && att.uid) {
        try {
          onChain = await readOnChainValid(publicClient(cfg.rpcUrl), cfg.registryAddr, att.uid);
        } catch {
          onChain = null;
        }
      }
      res.json({ valid, signer: att.message.validator, onChain });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });

  app.get("/.well-known/agent.json", (_req: Request, res: Response): void => {
    res.json({
      name: AGENT_NAME,
      description: AGENT_DESC,
      version: "0.1.0",
      network: cfg.caip2,
      signer: deps.signer?.address ?? null,
      registry: cfg.registryAddr ?? null,
      services: [
        {
          name: "preflight",
          type: "A2MCP",
          endpoint: "/v1/preflight",
          price: cfg.price,
          currency: "USDT0",
          description: "Screen a payment/task/counterparty; returns a signed verdict.",
        },
      ],
      x402: { version: 2, scheme: "exact", network: cfg.caip2 },
    });
  });

  app.get("/health", (_req: Request, res: Response): void => {
    res.json({ ok: true, name: AGENT_NAME, network: cfg.network, devBypass: cfg.devBypass });
  });

  // --- service discovery (free) — so agent-callers can learn how to invoke Frisk ------ //
  const openapi = (_req: Request, res: Response): void => void res.json(openapiSpec(cfg));
  app.get("/openapi.json", openapi);
  app.get("/m2m-openapi.json", openapi);
  app.get("/.well-known/openapi.json", openapi);
  const mcp = (_req: Request, res: Response): void => void res.json(mcpCard(cfg));
  app.get("/.well-known/mcp.json", mcp);
  app.get("/.well-known/mcp/server-card.json", mcp);
  app.get("/", (_req: Request, res: Response): void => void res.json(rootIndex(cfg)));

  return app;
}
