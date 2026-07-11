/**
 * Reputation providers for the counterparty detector.
 *
 * `MockReputationProvider` is a deterministic, fixture-backed source used by tests + the demo.
 * `OnchainOsReputationProvider` is the production seam: it reads a seller ASP's ERC-8004
 * identity + marketplace history from an OnchainOS / okx-ai endpoint. It is dependency-injected
 * with a `fetchImpl` so it stays testable and needs no live creds to construct.
 */

import type { ReputationProvider, ReputationRecord } from "@frisk/shared";

const DAY = 24 * 60 * 60;

/** A small, legible fixture set covering each risk archetype the detector must catch. */
export const DEFAULT_REPUTATION_FIXTURES: Record<string, ReputationRecord> = {
  "okx:agent:trusted-seller": {
    agentId: "okx:agent:trusted-seller",
    found: true,
    jobsCompleted: 1240,
    rating: 4.9,
    disputes: 3,
    ageSeconds: 420 * DAY,
  },
  "okx:agent:new-seller": {
    agentId: "okx:agent:new-seller",
    found: true,
    jobsCompleted: 2,
    rating: 5,
    disputes: 0,
    ageSeconds: 2 * DAY,
  },
  "okx:agent:low-rep": {
    agentId: "okx:agent:low-rep",
    found: true,
    jobsCompleted: 60,
    rating: 2.4,
    disputes: 5,
    ageSeconds: 90 * DAY,
  },
  "okx:agent:disputed": {
    agentId: "okx:agent:disputed",
    found: true,
    jobsCompleted: 40,
    rating: 3.8,
    disputes: 18,
    ageSeconds: 150 * DAY,
  },
};

export class MockReputationProvider implements ReputationProvider {
  private readonly fixtures: Record<string, ReputationRecord>;

  constructor(fixtures: Record<string, ReputationRecord> = DEFAULT_REPUTATION_FIXTURES) {
    this.fixtures = fixtures;
  }

  async lookup(agentId: string): Promise<ReputationRecord> {
    const rec = this.fixtures[agentId];
    if (rec) return rec;
    return { agentId, found: false };
  }
}

export interface OnchainOsReputationConfig {
  /** Base URL of the OnchainOS / okx-ai reputation endpoint. */
  baseUrl?: string;
  apiKey?: string;
  /** Injected fetch (defaults to global fetch) so this is unit-testable. */
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

/**
 * Production reputation seam. Best-effort: any failure returns `{ found:false }` rather than
 * throwing, so a flaky backend degrades to "unknown counterparty" instead of crashing preflight.
 */
export class OnchainOsReputationProvider implements ReputationProvider {
  constructor(private readonly cfg: OnchainOsReputationConfig = {}) {}

  async lookup(agentId: string): Promise<ReputationRecord> {
    const base = this.cfg.baseUrl;
    const doFetch = this.cfg.fetchImpl ?? globalThis.fetch;
    if (!base || !doFetch) return { agentId, found: false };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.cfg.timeoutMs ?? 4000);
    try {
      const res = await doFetch(`${base.replace(/\/$/, "")}/agents/${encodeURIComponent(agentId)}`, {
        headers: this.cfg.apiKey ? { authorization: `Bearer ${this.cfg.apiKey}` } : undefined,
        signal: controller.signal,
      });
      if (!res.ok) return { agentId, found: false };
      const j = (await res.json()) as Partial<ReputationRecord> & Record<string, unknown>;
      return {
        agentId,
        found: true,
        jobsCompleted: numeric(j.jobsCompleted),
        rating: numeric(j.rating),
        disputes: numeric(j.disputes),
        ageSeconds: numeric(j.ageSeconds),
      };
    } catch {
      return { agentId, found: false };
    } finally {
      clearTimeout(timer);
    }
  }
}

function numeric(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
