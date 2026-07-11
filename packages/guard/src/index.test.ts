import { describe, expect, it, vi } from "vitest";
import type { Decision, FriskVerdict, PaymentRequired } from "@frisk/shared";
import { createGuardedFetch, FriskBlockedError } from "./index.js";

const CHALLENGE: PaymentRequired = {
  x402Version: 2,
  resource: { url: "https://seller.example/report" },
  accepts: [
    {
      scheme: "exact",
      network: "eip155:196",
      amount: "5000000",
      asset: "0x779Ded0c9e1022225f8E0630b35a9b54bE713736",
      payTo: "0x9999999999999999999999999999999999999999",
      maxTimeoutSeconds: 300,
    },
  ],
};

function verdict(decision: Decision): FriskVerdict {
  return {
    version: "1",
    id: "0x1",
    decision,
    score: decision === "BLOCK" ? 100 : 0,
    severity: decision === "BLOCK" ? "critical" : "none",
    summary: "test",
    detectors: [],
    findings: [],
    subject: { intentHash: `0x${"00".repeat(32)}` },
    issuedAt: 0,
    expiresAt: 0,
  };
}

const probe402: typeof fetch = async () =>
  new Response(JSON.stringify(CHALLENGE), {
    status: 402,
    headers: { "content-type": "application/json" },
  });

describe("createGuardedFetch", () => {
  it("throws FriskBlockedError and never pays on BLOCK", async () => {
    const pay = vi.fn(async () => new Response("paid", { status: 200 }));
    const guarded = createGuardedFetch({
      friskUrl: "https://frisk.example",
      fetchImpl: probe402,
      preflight: async () => verdict("BLOCK"),
      pay,
    });
    await expect(guarded("https://seller.example/report", {}, { expectedPayTo: "0x1111111111111111111111111111111111111111" }))
      .rejects.toBeInstanceOf(FriskBlockedError);
    expect(pay).not.toHaveBeenCalled();
  });

  it("pays when the verdict is ALLOW", async () => {
    const pay = vi.fn(async () => new Response("paid", { status: 200 }));
    const guarded = createGuardedFetch({
      friskUrl: "https://frisk.example",
      fetchImpl: probe402,
      preflight: async () => verdict("ALLOW"),
      pay,
    });
    const res = await guarded("https://seller.example/report");
    expect(pay).toHaveBeenCalledTimes(1);
    expect(await res.text()).toBe("paid");
  });

  it("passes through non-402 responses without frisking", async () => {
    const pay = vi.fn(async () => new Response("paid", { status: 200 }));
    const preflight = vi.fn(async () => verdict("ALLOW"));
    const guarded = createGuardedFetch({
      friskUrl: "https://frisk.example",
      fetchImpl: async () => new Response("ok", { status: 200 }),
      preflight,
      pay,
    });
    const res = await guarded("https://seller.example/free");
    expect(await res.text()).toBe("ok");
    expect(preflight).not.toHaveBeenCalled();
    expect(pay).not.toHaveBeenCalled();
  });

  it("blocks on WARN when policy.blockOnWarn is set", async () => {
    const onWarn = vi.fn();
    const guarded = createGuardedFetch({
      friskUrl: "https://frisk.example",
      fetchImpl: probe402,
      preflight: async () => verdict("WARN"),
      policy: { onWarn, blockOnWarn: true },
    });
    await expect(guarded("https://seller.example/report")).rejects.toBeInstanceOf(FriskBlockedError);
    expect(onWarn).toHaveBeenCalledTimes(1);
  });
});
