// PABX extension presence reported on the heartbeat.
//
// The Agent reads the local engine once per heartbeat (never per page view), keeps the last
// report the API accepted and sends only what changed. A complete report goes every
// `fullIntervalMs`, on start, after a rejected or failed heartbeat and when the API asks for it.
// Engines whose read failed are left out, so the API never turns their extensions offline.

export type PresenceEngine = "asterisk" | "freeswitch";

export type PresenceObservation = {
  engine: PresenceEngine;
  username: string;
  domain?: string | null;
  userAgent?: string | null;
  networkIP?: string | null;
};

export type PresenceEntry = {
  engine: PresenceEngine;
  username: string;
  domain: string | null;
  contactCount: number;
  userAgent: string | null;
  networkIP: string | null;
};

export type PresenceRemoval = Pick<PresenceEntry, "engine" | "username" | "domain">;

export type PresenceReport = {
  full: boolean;
  engines: PresenceEngine[];
  registrations: PresenceEntry[];
  removed: PresenceRemoval[];
};

export type PresencePending = {
  report: PresenceReport;
  snapshot: Map<string, PresenceEntry>;
  at: number;
};

export type PresenceAck = { applied?: unknown; needsFull?: unknown } | null | undefined;

function presenceKey(engine: string, username: string, domain: string | null) {
  return `${engine}\u0000${username}\u0000${domain ?? ""}`;
}

/** One entry per extension (engine, username, domain); several contacts are several devices. */
export function aggregatePresence(observations: PresenceObservation[]) {
  const entries = new Map<string, PresenceEntry>();
  for (const item of observations) {
    const username = item.username.trim();
    if (!username) continue;
    const domain = item.domain?.trim().toLowerCase() || null;
    const key = presenceKey(item.engine, username, domain);
    const current = entries.get(key);
    entries.set(key, {
      engine: item.engine,
      username,
      domain,
      contactCount: (current?.contactCount ?? 0) + 1,
      userAgent: item.userAgent?.trim() || current?.userAgent || null,
      networkIP: item.networkIP?.trim() || current?.networkIP || null,
    });
  }
  return entries;
}

function changed(before: PresenceEntry | undefined, after: PresenceEntry) {
  return before?.contactCount !== after.contactCount ||
    before?.userAgent !== after.userAgent || before?.networkIP !== after.networkIP;
}

export class PabxPresenceTracker {
  private baseline: Map<string, PresenceEntry> | null = null;
  private lastFullAt = 0;
  private forceFull = true;

  constructor(private readonly fullIntervalMs = 10 * 60_000) {}

  /** `observed` holds only the engines read successfully in this heartbeat. */
  build(
    observed: Partial<Record<PresenceEngine, PresenceObservation[]>>,
    now = Date.now(),
  ): PresencePending {
    const engines = (Object.keys(observed) as PresenceEngine[]).sort((a, b) => a.localeCompare(b));
    const snapshot = aggregatePresence(engines.flatMap((engine) => observed[engine] ?? []));
    const full = this.forceFull || this.baseline === null ||
      now - this.lastFullAt >= this.fullIntervalMs;
    if (full) {
      return {
        report: { full: true, engines, registrations: [...snapshot.values()], removed: [] },
        snapshot,
        at: now,
      };
    }
    const baseline = this.baseline ?? new Map<string, PresenceEntry>();
    const registrations = [...snapshot.entries()]
      .filter(([key, entry]) => changed(baseline.get(key), entry))
      .map(([, entry]) => entry);
    const removed = [...baseline.entries()]
      .filter(([key, entry]) => engines.includes(entry.engine) && !snapshot.has(key))
      .map(([, entry]) => ({
        engine: entry.engine,
        username: entry.username,
        domain: entry.domain,
      }));
    return { report: { full: false, engines, registrations, removed }, snapshot, at: now };
  }

  /** Commit the report only when the API applied it; otherwise resend everything next time. */
  acknowledge(pending: PresencePending, ack: PresenceAck) {
    if (ack?.applied !== true) {
      this.forceFull = true;
      return;
    }
    const next = new Map<string, PresenceEntry>();
    for (const [key, entry] of this.baseline ?? []) {
      if (!pending.report.engines.includes(entry.engine)) next.set(key, entry);
    }
    for (const [key, entry] of pending.snapshot) next.set(key, entry);
    this.baseline = next;
    if (pending.report.full) this.lastFullAt = pending.at;
    this.forceFull = ack.needsFull === true;
  }
}

function hostOf(value: string) {
  const host = value.replace(/^\[/, "").split(/[;>]/)[0];
  if (host.includes("]")) return host.split("]")[0];
  const colons = host.split(":").length - 1;
  return colons === 1 ? host.split(":")[0] : host;
}

/**
 * `asterisk -rx "pjsip show contacts"`. The AOR is `<extension>@<domain>` (the PJSIP realtime id),
 * which identifies the extension; the contact URI only carries the device address.
 */
export function parseAsteriskPjsipContacts(output: string) {
  const reports: Array<PresenceObservation & { engine: "asterisk"; contact: string }> = [];
  for (const rawLine of output.split(/\r?\n/)) {
    const line = rawLine.trim();
    const match = /^Contact:\s+([^\s/]+)\/(sips?:\S+)/i.exec(line);
    if (!match || match[1].startsWith("<")) continue;
    const aor = match[1];
    const uri = match[2];
    const uriTarget = uri.replace(/^sips?:/i, "");
    const uriUser = uriTarget.includes("@") ? uriTarget.slice(0, uriTarget.indexOf("@")) : "";
    const uriHost = hostOf(
      uriTarget.includes("@") ? uriTarget.slice(uriTarget.indexOf("@") + 1) : uriTarget,
    );
    const at = aor.lastIndexOf("@");
    const username = at > 0 ? aor.slice(0, at) : (uriUser || aor);
    const domain = at > 0 ? aor.slice(at + 1).toLowerCase() : uriHost.toLowerCase();
    reports.push({
      engine: "asterisk",
      username,
      domain,
      contact: `${aor}/${uri}`,
      networkIP: uriHost || null,
    });
  }
  return reports;
}
