// dns.monitor: one continuous-monitoring cycle (DNS module, phase D4c). The API hands a monitor Agent
// the list of targets every 5 minutes; each service runs the probe catalog without the public
// resolvers, and each resolver gets one query of a fixed type. Nothing in the payload can choose a
// command, a port or a private address, and the cycle is bounded in size and time.

import {
  isPublicAddress,
  parseTarget,
  type ProbeDeps,
  type ProbeResult,
  runDnsProbe,
  type StepStatus,
  timed,
} from "./dns-probe.ts";

export const DNS_MONITOR_JOB_TYPE = "dns.monitor";
export const DNS_MONITOR_CAPABILITY = "mnscloud.dns.monitor";

const MAX_TARGETS = 100;
const CONCURRENCY = 4;
const QUERY_TIMEOUT_MS = 3_000;
const QUERY_TYPES = ["A", "AAAA", "NS"] as const;

export type MonitorQueryType = typeof QUERY_TYPES[number];

export type MonitorResult = {
  targetUUID: string;
  kind: "service" | "resolver";
  service?: ProbeResult;
  resolver?: { status: StepStatus; ms: number; answers: number };
  error?: "invalid_target";
};

export type MonitorDeps = ProbeDeps & {
  /** One query of `type` for `name` sent to `server`; resolves with the number of answers. */
  query: (
    name: string,
    type: MonitorQueryType,
    server: string,
    signal: AbortSignal,
  ) => Promise<number>;
};

const text = (value: unknown) => typeof value === "string" ? value : "";

async function measure(item: Record<string, unknown>, deps: MonitorDeps): Promise<MonitorResult> {
  const targetUUID = text(item.targetUUID);
  if (item.kind === "resolver") {
    const server = text(item.target);
    const name = text(item.queryName);
    const type = QUERY_TYPES.find((value) => value === item.queryType);
    if (!isPublicAddress(server) || !name || name.length > 253 || !type) {
      return { targetUUID, kind: "resolver", error: "invalid_target" };
    }
    const step = await timed(
      deps.now,
      () => deps.query(name, type, server, AbortSignal.timeout(QUERY_TIMEOUT_MS)),
    );
    const answers = step.value ?? 0;
    const status: StepStatus = step.status === "ok" && !answers ? "nodata" : step.status;
    return { targetUUID, kind: "resolver", resolver: { status, ms: step.ms, answers } };
  }
  try {
    const service = await runDnsProbe(parseTarget(item.target), deps, { publicResolvers: false });
    return { targetUUID, kind: "service", service };
  } catch {
    return { targetUUID, kind: "service", error: "invalid_target" };
  }
}

/** Measures every target of one cycle (the egress is looked up once and shared). */
export async function runDnsMonitor(payloadTargets: unknown, deps: MonitorDeps) {
  const items = (Array.isArray(payloadTargets) ? payloadTargets : [])
    .filter((item): item is Record<string, unknown> =>
      Boolean(item) && typeof item === "object" &&
      /^[0-9A-Fa-f-]{32,36}$/.test(text(item.targetUUID))
    )
    .slice(0, MAX_TARGETS);
  const egress = await deps.egress().catch(() => ({ ipv4: null, ipv6: null }));
  const shared: MonitorDeps = { ...deps, egress: () => Promise.resolve(egress) };
  const results: MonitorResult[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await measure(items[index], shared);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, worker));
  return { egress, results };
}

/** Real query of the monitor (Deno). */
export function denoMonitorQuery(): MonitorDeps["query"] {
  return async (name, type, server, signal) =>
    (await Deno.resolveDns(name, type, { signal, nameServer: { ipAddr: server, port: 53 } }))
      .length;
}
