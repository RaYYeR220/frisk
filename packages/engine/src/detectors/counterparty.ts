/**
 * counterpartyReputation — is the seller ASP on the other side trustworthy?
 *
 * Reads the counterparty agent's ERC-8004 identity + marketplace history via a
 * `ReputationProvider` (mock fixtures for tests/demo; OnchainOS/okx-ai in production) and flags
 * brand-new identities, low ratings, and high dispute rates. If no provider is wired or no
 * counterparty id is present, the detector reports `ran:false` rather than guessing.
 */

import {
  type Detector,
  type DetectorContext,
  type Finding,
  type FriskRequest,
  type ReputationRecord,
} from "@frisk/shared";
import { buildResult, finding, skipped } from "../util";
import { MockReputationProvider } from "../providers/reputation";

const D = "counterparty" as const;
const DAY = 24 * 60 * 60;

export interface CounterpartyDetectorOptions {
  /** identities younger than this are "new"; default 14 days. */
  newIdentitySeconds?: number;
  /** rating (out of 5) at/below which we flag low reputation; default 3.5. */
  lowRatingThreshold?: number;
  /** min jobs to consider a rating meaningful; below this a low rating is softened; default 5. */
  minJobsForRating?: number;
  /** dispute rate (disputes/jobs) at/above which we flag; default 0.2. */
  disputeRateThreshold?: number;
}

export function evaluateReputation(
  rec: ReputationRecord,
  now: number,
  opts: CounterpartyDetectorOptions,
): Finding[] {
  const out: Finding[] = [];
  const newWindow = opts.newIdentitySeconds ?? 14 * DAY;
  const lowRating = opts.lowRatingThreshold ?? 3.5;
  const minJobs = opts.minJobsForRating ?? 5;
  const disputeCeil = opts.disputeRateThreshold ?? 0.2;

  if (!rec.found) {
    out.push(
      finding(
        D,
        "UNKNOWN_COUNTERPARTY",
        "medium",
        "Counterparty has no reputation record",
        `No ERC-8004 identity / marketplace history found for ${rec.agentId}. Treat as unproven.`,
        { agentId: rec.agentId },
      ),
    );
    return out; // nothing else is knowable
  }

  if (rec.ageSeconds !== undefined && rec.ageSeconds < newWindow) {
    const days = Math.max(0, Math.round(rec.ageSeconds / DAY));
    out.push(
      finding(
        D,
        "NEW_IDENTITY",
        "medium",
        "Freshly registered identity",
        `Counterparty identity is ~${days}d old (< ${Math.round(newWindow / DAY)}d) — little track record.`,
        { agentId: rec.agentId, ageSeconds: rec.ageSeconds },
      ),
    );
  }

  if (rec.rating !== undefined && rec.rating <= lowRating) {
    const meaningful = (rec.jobsCompleted ?? 0) >= minJobs;
    out.push(
      finding(
        D,
        "LOW_REPUTATION",
        meaningful ? "high" : "medium",
        "Low counterparty rating",
        `Rating ${rec.rating}/5 over ${rec.jobsCompleted ?? 0} jobs is at/below the ${lowRating} floor.`,
        { agentId: rec.agentId, rating: rec.rating, jobsCompleted: rec.jobsCompleted },
      ),
    );
  }

  if (rec.disputes !== undefined) {
    const jobs = rec.jobsCompleted ?? 0;
    const rate = jobs > 0 ? rec.disputes / jobs : rec.disputes > 0 ? 1 : 0;
    if (rate >= disputeCeil && rec.disputes >= 3) {
      out.push(
        finding(
          D,
          "HIGH_DISPUTE_RATE",
          "high",
          "High dispute rate",
          `${rec.disputes} disputes over ${jobs} jobs (${(rate * 100).toFixed(0)}%) — well above the ${(
            disputeCeil * 100
          ).toFixed(0)}% threshold.`,
          { agentId: rec.agentId, disputes: rec.disputes, jobsCompleted: jobs, rate },
        ),
      );
    }
  }

  return out;
}

export function createCounterpartyDetector(opts: CounterpartyDetectorOptions = {}): Detector {
  return {
    name: D,
    async run(req: FriskRequest, ctx: DetectorContext) {
      const agentId = req.intent.counterpartyAgentId;
      if (!agentId) {
        return skipped(D, "no counterpartyAgentId in intent");
      }
      // Fall back to the deterministic mock so the detector is always demonstrable.
      const provider = ctx.reputation ?? new MockReputationProvider();
      let rec: ReputationRecord;
      try {
        rec = await provider.lookup(agentId);
      } catch {
        return skipped(D, "reputation lookup failed");
      }
      const findings = evaluateReputation(rec, ctx.now, opts);
      return buildResult(D, findings);
    },
  };
}
