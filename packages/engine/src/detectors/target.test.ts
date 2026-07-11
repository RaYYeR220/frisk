import { describe, it, expect } from "vitest";
import type { DetectorContext, FriskRequest } from "@frisk/shared";
import { TOKENS } from "@frisk/shared";
import { createTargetDetector, type TargetClient } from "./target";
import { staticDenylist } from "./denylist";

const NOW = 1_700_000_000;
const ctx: DetectorContext = { rpcUrl: "", chainId: 196, now: NOW };

const EOA = "0xE0a0000000000000000000000000000000000001" as const;
const CONTRACT = "0xC0114ac70000000000000000000000000000abcd" as const;
const CODE = "0x60806040526004361061..." as `0x${string}`;

interface FakeOpts {
  code?: Record<string, `0x${string}` | undefined>;
  defaultCode?: `0x${string}`;
  nonce?: Record<string, number>;
  reads?: Record<string, Record<string, unknown>>;
}
function fakeClient(o: FakeOpts = {}): TargetClient {
  return {
    async getBytecode({ address }) {
      const key = address.toLowerCase();
      return o.code && key in o.code ? o.code[key] : o.defaultCode;
    },
    async getTransactionCount({ address }) {
      return o.nonce?.[address.toLowerCase()] ?? 1;
    },
    async readContract({ address, functionName }) {
      const map = o.reads?.[address.toLowerCase()] ?? {};
      if (functionName in map) return map[functionName];
      throw new Error("revert (unimplemented)");
    },
  };
}

function req(over: Partial<FriskRequest["intent"]> = {}, target?: FriskRequest["target"]): FriskRequest {
  return { intent: { action: "pay", ...over }, target };
}

describe("target detector", () => {
  it("skips when there is no address to scan", async () => {
    const det = createTargetDetector({ client: fakeClient() });
    const res = await det.run(req(), ctx);
    expect(res.ran).toBe(false);
  });

  it("EOA with history => EOA_TARGET_OK, ALLOW", async () => {
    const det = createTargetDetector({ client: fakeClient({ defaultCode: "0x", nonce: { [EOA.toLowerCase()]: 42 } }) });
    const res = await det.run(req({ expectedPayTo: EOA }), ctx);
    expect(res.ran).toBe(true);
    expect(res.decision).toBe("ALLOW");
    expect(res.findings.map((f) => f.code)).toContain("EOA_TARGET_OK");
  });

  it("brand-new EOA (nonce 0) => FRESH_DEPLOY", async () => {
    const det = createTargetDetector({ client: fakeClient({ defaultCode: "0x", nonce: { [EOA.toLowerCase()]: 0 } }) });
    const res = await det.run(req({ expectedPayTo: EOA }), ctx);
    expect(res.findings.map((f) => f.code)).toContain("FRESH_DEPLOY");
  });

  it("denylist hit => DENYLIST_HIT (critical, BLOCK)", async () => {
    const scam = staticDenylist()[0]!.address as `0x${string}`;
    const det = createTargetDetector({ client: fakeClient({ defaultCode: "0x" }) });
    const res = await det.run(req({}, { address: scam }), { ...ctx });
    expect(res.decision).toBe("BLOCK");
    expect(res.findings.find((f) => f.code === "DENYLIST_HIT")?.severity).toBe("critical");
  });

  it("external denylist provider hook is consulted", async () => {
    const det = createTargetDetector({
      client: fakeClient({ defaultCode: "0x" }),
      denylistProvider: {
        lookup: (addr) => ({ address: addr, category: "drainer", label: "live-feed hit", source: "test-feed" }),
      },
    });
    const res = await det.run(req({}, { address: EOA }), ctx);
    expect(res.findings.map((f) => f.code)).toContain("DENYLIST_HIT");
  });

  it("unknown unverified contract => UNVERIFIED_CONTRACT", async () => {
    const det = createTargetDetector({
      client: fakeClient({ code: { [CONTRACT.toLowerCase()]: CODE } }),
    });
    const res = await det.run(req({}, { address: CONTRACT }), ctx);
    expect(res.findings.map((f) => f.code)).toContain("UNVERIFIED_CONTRACT");
  });

  it("contract with a live owner => MINT_AUTHORITY", async () => {
    const det = createTargetDetector({
      client: fakeClient({
        code: { [CONTRACT.toLowerCase()]: CODE },
        reads: { [CONTRACT.toLowerCase()]: { owner: "0x000000000000000000000000000000000000BEEF" } },
      }),
    });
    const res = await det.run(req({}, { address: CONTRACT }), ctx);
    expect(res.findings.map((f) => f.code)).toContain("MINT_AUTHORITY");
  });

  it("paused token => HONEYPOT_HEURISTIC (high, BLOCK)", async () => {
    const det = createTargetDetector({
      client: fakeClient({
        code: { [CONTRACT.toLowerCase()]: CODE },
        reads: { [CONTRACT.toLowerCase()]: { paused: true } },
      }),
    });
    const res = await det.run(req({}, { address: CONTRACT }), ctx);
    expect(res.findings.find((f) => f.code === "HONEYPOT_HEURISTIC")?.severity).toBe("high");
    expect(res.decision).toBe("BLOCK");
  });

  it("punitive fee-on-transfer => HONEYPOT_HEURISTIC", async () => {
    const det = createTargetDetector({
      client: fakeClient({
        code: { [CONTRACT.toLowerCase()]: CODE },
        reads: { [CONTRACT.toLowerCase()]: { _taxFee: 45n } },
      }),
    });
    const res = await det.run(req({}, { address: CONTRACT }), ctx);
    expect(res.findings.map((f) => f.code)).toContain("HONEYPOT_HEURISTIC");
  });

  it("metadata provider: unverified + fresh deploy", async () => {
    const det = createTargetDetector({
      client: fakeClient({ code: { [CONTRACT.toLowerCase()]: CODE } }),
      metadataProvider: {
        lookup: () => ({ verified: false, deployedAtSeconds: NOW - 3600 }),
      },
    });
    const res = await det.run(req({}, { address: CONTRACT }), { ...ctx });
    const codes = res.findings.map((f) => f.code);
    expect(codes).toContain("UNVERIFIED_CONTRACT");
    expect(codes).toContain("FRESH_DEPLOY");
    expect(res.findings.find((f) => f.code === "UNVERIFIED_CONTRACT")?.severity).toBe("medium");
  });

  it("known settlement token (USDT0) is trusted — no red flags", async () => {
    const det = createTargetDetector({
      client: fakeClient({ code: { [TOKENS.USDT0.address.toLowerCase()]: CODE } }),
    });
    const res = await det.run(req({}, { address: TOKENS.USDT0.address }), ctx);
    expect(res.ran).toBe(true);
    expect(res.decision).toBe("ALLOW");
    expect(res.findings).toHaveLength(0);
  });

  it("degrades gracefully when the RPC read throws", async () => {
    const throwing: TargetClient = {
      async getBytecode() {
        throw new Error("rpc timeout");
      },
      async getTransactionCount() {
        return 1;
      },
      async readContract() {
        throw new Error("rpc");
      },
    };
    const det = createTargetDetector({ client: throwing });
    const res = await det.run(req({}, { address: CONTRACT }), ctx);
    expect(res.ran).toBe(true);
    expect(res.note).toMatch(/rpc|failed/i);
  });
});
