/**
 * Bundled static scam/drainer denylist + a pluggable hook.
 *
 * The static JSON is a fast, offline first pass and demo fixture; real deployments inject a
 * `DenylistProvider` backed by a live feed (ScamSniffer, GoPlus, Chainalysis, Blockaid). Both
 * paths funnel through `DenylistChecker.check()` so the target detector never cares which it is.
 */

import denylistData from "./denylist.json";

export interface DenylistEntry {
  address: string;
  category: string;
  label: string;
  source: string;
}

/** A pluggable external denylist (live threat-intel feed). Best-effort; may be async. */
export interface DenylistProvider {
  lookup(address: string): Promise<DenylistEntry | undefined> | DenylistEntry | undefined;
}

const STATIC_ENTRIES: DenylistEntry[] = (denylistData.entries as DenylistEntry[]).map((e) => ({
  ...e,
  address: e.address.toLowerCase(),
}));

const STATIC_INDEX: ReadonlyMap<string, DenylistEntry> = new Map(
  STATIC_ENTRIES.map((e) => [e.address, e]),
);

/** The immutable bundled seed list (lowercased addresses). */
export function staticDenylist(): readonly DenylistEntry[] {
  return STATIC_ENTRIES;
}

export class DenylistChecker {
  private readonly extra: DenylistProvider | undefined;
  private readonly index: Map<string, DenylistEntry>;

  constructor(opts?: { provider?: DenylistProvider; extraEntries?: DenylistEntry[] }) {
    this.extra = opts?.provider;
    this.index = new Map(STATIC_INDEX);
    for (const e of opts?.extraEntries ?? []) {
      this.index.set(e.address.toLowerCase(), { ...e, address: e.address.toLowerCase() });
    }
  }

  /** Returns the matching entry (static first, then external provider) or undefined. */
  async check(address: string): Promise<DenylistEntry | undefined> {
    const key = address.trim().toLowerCase();
    const local = this.index.get(key);
    if (local) return local;
    if (this.extra) {
      try {
        const hit = await this.extra.lookup(key);
        if (hit) return { ...hit, address: hit.address.toLowerCase() };
      } catch {
        /* external feed is best-effort; ignore failures */
      }
    }
    return undefined;
  }
}
