import { describe, it, expect } from "vitest";
import type { DetectorContext, ReputationProvider, ReputationRecord } from "@frisk/shared";
import { createCounterpartyDetector, evaluateReputation } from "./counterparty";
import { MockReputationProvider } from "../providers/reputation";

const NOW = 1_700_000_000;
function ctx(reputation?: ReputationProvider): DetectorContext {
  return { rpcUrl: "", chainId: 196, now: NOW, reputation: reputation ?? new MockReputationProvider() };
}

describe("counterparty detector", () => {
  it("skips when no counterpartyAgentId", async () => {
    const det = createCounterpartyDetector();
    const res = await det.run({ intent: { action: "pay" } }, ctx());
    expect(res.ran).toBe(false);
  });

  it("trusted seller => ALLOW, no findings", async () => {
    const det = createCounterpartyDetector();
    const res = await det.run(
      { intent: { action: "pay", counterpartyAgentId: "okx:agent:trusted-seller" } },
      ctx(),
    );
    expect(res.ran).toBe(true);
    expect(res.decision).toBe("ALLOW");
    expect(res.findings).toHaveLength(0);
  });

  it("new identity => NEW_IDENTITY (WARN)", async () => {
    const det = createCounterpartyDetector();
    const res = await det.run(
      { intent: { action: "pay", counterpartyAgentId: "okx:agent:new-seller" } },
      ctx(),
    );
    expect(res.findings.map((f) => f.code)).toContain("NEW_IDENTITY");
    expect(res.decision).toBe("WARN");
  });

  it("low reputation => LOW_REPUTATION (BLOCK on meaningful sample)", async () => {
    const det = createCounterpartyDetector();
    const res = await det.run(
      { intent: { action: "pay", counterpartyAgentId: "okx:agent:low-rep" } },
      ctx(),
    );
    expect(res.findings.map((f) => f.code)).toContain("LOW_REPUTATION");
    expect(res.decision).toBe("BLOCK");
  });

  it("high dispute rate => HIGH_DISPUTE_RATE (BLOCK)", async () => {
    const det = createCounterpartyDetector();
    const res = await det.run(
      { intent: { action: "pay", counterpartyAgentId: "okx:agent:disputed" } },
      ctx(),
    );
    expect(res.findings.map((f) => f.code)).toContain("HIGH_DISPUTE_RATE");
    expect(res.decision).toBe("BLOCK");
  });

  it("unknown agent => UNKNOWN_COUNTERPARTY (WARN)", async () => {
    const det = createCounterpartyDetector();
    const res = await det.run(
      { intent: { action: "pay", counterpartyAgentId: "okx:agent:does-not-exist" } },
      ctx(),
    );
    expect(res.findings.map((f) => f.code)).toContain("UNKNOWN_COUNTERPARTY");
    expect(res.decision).toBe("WARN");
  });

  it("uses an injected custom provider", async () => {
    const custom: ReputationProvider = {
      async lookup(agentId: string): Promise<ReputationRecord> {
        return { agentId, found: true, jobsCompleted: 3, rating: 5, disputes: 0, ageSeconds: 1000 };
      },
    };
    const det = createCounterpartyDetector();
    const res = await det.run(
      { intent: { action: "pay", counterpartyAgentId: "whatever" } },
      ctx(custom),
    );
    // 1000s old => NEW_IDENTITY
    expect(res.findings.map((f) => f.code)).toContain("NEW_IDENTITY");
  });

  it("degrades to skipped if the provider throws", async () => {
    const boom: ReputationProvider = {
      async lookup(): Promise<ReputationRecord> {
        throw new Error("backend down");
      },
    };
    const det = createCounterpartyDetector();
    const res = await det.run({ intent: { action: "pay", counterpartyAgentId: "x" } }, ctx(boom));
    expect(res.ran).toBe(false);
    expect(res.note).toMatch(/failed/i);
  });
});

describe("evaluateReputation (unit)", () => {
  it("does not flag a healthy record", () => {
    const rec: ReputationRecord = {
      agentId: "a",
      found: true,
      jobsCompleted: 500,
      rating: 4.8,
      disputes: 2,
      ageSeconds: 300 * 24 * 60 * 60,
    };
    expect(evaluateReputation(rec, NOW, {})).toHaveLength(0);
  });
});
