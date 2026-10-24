// dns.probe: on-demand network diagnosis requested by a platform master (DNS module, phase D4a).
// The job carries only a target (host name, URL or IP); the probe runs a fixed catalog of read-only
// tests with bounded time and size: egress address, DNS resolution through the system resolver and
// well-known public resolvers, TCP and TLS reachability over IPv4/IPv6, and one HTTP request. It
// never runs a command and never connects to private, loopback, link-local or multicast addresses.

export const DNS_PROBE_JOB_TYPE = "dns.probe";
export const DNS_PROBE_CAPABILITY = "mnscloud.dns.probe";

export const PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"] as const;
const RESOLVE_TIMEOUT_MS = 3_000;
const CONNECT_TIMEOUT_MS = 4_000;
const HTTP_TIMEOUT_MS = 8_000;
const MAX_ANSWERS = 8;

export type ProbeTarget = {
  kind: "name" | "url" | "ip";
  host: string;
  port: number;
  url: string | null;
};

export type StepStatus =
  | "ok"
  | "nxdomain"
  | "nodata"
  | "servfail"
  | "refused"
  | "timeout"
  | "blocked"
  | "error";

export type ResolutionStep = {
  resolver: string;
  type: "A" | "AAAA";
  status: StepStatus;
  answers: string[];
  ms: number;
};

export type ConnectStep = {
  family: 4 | 6;
  address: string;
  port: number;
  tcp: { status: StepStatus; ms: number };
  tls: { status: StepStatus; ms: number } | null;
};

export type ProbeResult = {
  version: 1;
  target: ProbeTarget;
  egress: { address: string | null; status: StepStatus };
  resolution: ResolutionStep[];
  connect: ConnectStep[];
  http: { status: StepStatus; code: number | null; ms: number } | null;
  durationMs: number;
};

export type ProbeDeps = {
  resolve: (
    name: string,
    type: "A" | "AAAA",
    nameServer: string | null,
    signal: AbortSignal,
  ) => Promise<string[]>;
  connect: (address: string, port: number, tlsName: string | null) => Promise<{
    tcpMs: number;
    tls: { status: StepStatus; ms: number } | null;
  }>;
  http: (url: string, signal: AbortSignal) => Promise<number>;
  egress: () => Promise<string | null>;
  now: () => number;
};

const HOSTNAME =
  /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*\.?$/;

function ipVersion(value: string): 0 | 4 | 6 {
  if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value)) return 4;
  if (value.includes(":") && /^[0-9a-fA-F:.]{2,45}$/.test(value)) {
    try {
      new URL(`http://[${value}]/`);
      return 6;
    } catch {
      return 0;
    }
  }
  return 0;
}

/** Validates the requested target; anything that is not a host name, an http(s) URL or an IP fails. */
export function parseTarget(raw: unknown): ProbeTarget {
  const value = typeof raw === "string" ? raw.trim() : "";
  if (!value || value.length > 2048) throw new Error("invalid probe target");
  if (/^https?:\/\//i.test(value)) {
    const url = new URL(value);
    if (url.username || url.password) throw new Error("invalid probe target");
    const host = url.hostname.replace(/^\[|\]$/g, "");
    if (!ipVersion(host) && !HOSTNAME.test(host)) throw new Error("invalid probe target");
    const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
    return { kind: "url", host: host.toLowerCase(), port, url: url.toString() };
  }
  if (ipVersion(value)) return { kind: "ip", host: value, port: 443, url: null };
  if (HOSTNAME.test(value)) {
    const host = value.replace(/\.$/, "").toLowerCase();
    return { kind: "name", host, port: 443, url: `https://${host}/` };
  }
  throw new Error("invalid probe target");
}

function v4Number(address: string): number {
  return address.split(".").reduce((acc, part) => acc * 256 + Number(part), 0);
}

function inV4(address: string, base: string, bits: number): boolean {
  const size = 2 ** (32 - bits);
  return Math.floor(v4Number(address) / size) === Math.floor(v4Number(base) / size);
}

const V4_PRIVATE: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 3],
];

/** True only for globally routable unicast addresses (the probe never connects elsewhere). */
export function isPublicAddress(address: string): boolean {
  const version = ipVersion(address);
  if (version === 4) return !V4_PRIVATE.some(([base, bits]) => inV4(address, base, bits));
  if (version !== 6) return false;
  const normalized = new URL(`http://[${address}]/`).hostname.slice(1, -1).toLowerCase();
  const mapped = /^::ffff:([0-9.]+)$/.exec(normalized);
  if (mapped) return isPublicAddress(mapped[1]);
  if (normalized === "::" || normalized === "::1") return false;
  const first = parseInt(normalized.split(":")[0] || "0", 16);
  // Global unicast is 2000::/3; documentation 2001:db8::/32 is excluded too.
  if (first < 0x2000 || first > 0x3fff) return false;
  return !normalized.startsWith("2001:db8:") && !normalized.startsWith("2001:db8::");
}

function statusOf(error: unknown): StepStatus {
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message.toLowerCase() : "";
  if (name === "TimeoutError" || name === "AbortError" || message.includes("timed out")) {
    return "timeout";
  }
  if (name === "NotFound" || message.includes("nxdomain") || message.includes("no such host")) {
    return "nxdomain";
  }
  if (message.includes("no records") || message.includes("nodata")) return "nodata";
  if (message.includes("servfail") || message.includes("server failure")) return "servfail";
  if (message.includes("refused")) return "refused";
  return "error";
}

async function timed<T>(now: () => number, task: () => Promise<T>) {
  const started = now();
  try {
    return { value: await task(), status: "ok" as StepStatus, ms: now() - started };
  } catch (error) {
    return { value: null, status: statusOf(error), ms: now() - started };
  }
}

/** Runs the fixed catalog for one target. Every step is bounded; a failing step never stops the others. */
export async function runDnsProbe(target: ProbeTarget, deps: ProbeDeps): Promise<ProbeResult> {
  const started = deps.now();
  const egress = await timed(deps.now, deps.egress);
  const resolution: ResolutionStep[] = [];
  const addresses = new Map<string, 4 | 6>();
  if (target.kind === "ip") {
    addresses.set(target.host, ipVersion(target.host) as 4 | 6);
  } else {
    const resolvers: Array<string | null> = [null, ...PUBLIC_RESOLVERS];
    const steps = await Promise.all(
      resolvers.flatMap((resolver) =>
        (["A", "AAAA"] as const).map(async (type) => {
          const step = await timed(
            deps.now,
            () =>
              deps.resolve(target.host, type, resolver, AbortSignal.timeout(RESOLVE_TIMEOUT_MS)),
          );
          const answers = (step.value ?? []).slice(0, MAX_ANSWERS);
          const status: StepStatus = step.status === "ok" && !answers.length
            ? "nodata"
            : step.status;
          return { resolver: resolver ?? "system", type, status, answers, ms: step.ms };
        })
      ),
    );
    resolution.push(...steps);
    // Connections use what this host itself would use: the system resolver answers.
    for (const step of steps.filter((item) => item.resolver === "system")) {
      for (const answer of step.answers.slice(0, 1)) {
        addresses.set(answer, step.type === "A" ? 4 : 6);
      }
    }
  }
  const connect: ConnectStep[] = [];
  for (const [address, family] of addresses) {
    if (!isPublicAddress(address)) {
      connect.push({
        family,
        address,
        port: target.port,
        tcp: { status: "blocked", ms: 0 },
        tls: null,
      });
      continue;
    }
    const tlsName = target.port === 443 && target.kind !== "ip" ? target.host : null;
    const step = await timed(deps.now, () => deps.connect(address, target.port, tlsName));
    connect.push({
      family,
      address,
      port: target.port,
      tcp: { status: step.status, ms: step.value?.tcpMs ?? step.ms },
      tls: step.value?.tls ?? null,
    });
  }
  let http: ProbeResult["http"] = null;
  const everyPublic = [...addresses.keys()].every(isPublicAddress);
  if (target.url && addresses.size) {
    if (!everyPublic) {
      http = { status: "blocked", code: null, ms: 0 };
    } else {
      const step = await timed(
        deps.now,
        () => deps.http(target.url as string, AbortSignal.timeout(HTTP_TIMEOUT_MS)),
      );
      http = { status: step.status, code: step.value, ms: step.ms };
    }
  }
  return {
    version: 1,
    target,
    egress: { address: egress.value ?? null, status: egress.status },
    resolution,
    connect,
    http,
    durationMs: deps.now() - started,
  };
}

/** Real network operations of a host (Deno). */
export function denoProbeDeps(egress: () => Promise<string | null>): ProbeDeps {
  return {
    resolve: async (name, type, nameServer, signal) =>
      await Deno.resolveDns(name, type, {
        signal,
        ...(nameServer ? { nameServer: { ipAddr: nameServer, port: 53 } } : {}),
      }),
    connect: async (address, port, tlsName) => {
      const started = performance.now();
      const conn = await deadline(Deno.connect({ hostname: address, port }), CONNECT_TIMEOUT_MS);
      const tcpMs = Math.round(performance.now() - started);
      if (!tlsName) {
        conn.close();
        return { tcpMs, tls: null };
      }
      const tlsStarted = performance.now();
      try {
        const tls = await Deno.startTls(conn, { hostname: tlsName });
        try {
          await deadline(tls.handshake(), CONNECT_TIMEOUT_MS);
          return { tcpMs, tls: { status: "ok", ms: Math.round(performance.now() - tlsStarted) } };
        } finally {
          tls.close();
        }
      } catch (error) {
        return {
          tcpMs,
          tls: { status: statusOf(error), ms: Math.round(performance.now() - tlsStarted) },
        };
      }
    },
    http: async (url, signal) => {
      const response = await fetch(url, { redirect: "manual", signal, method: "GET" });
      await response.body?.cancel().catch(() => undefined);
      return response.status;
    },
    egress,
    now: () => Math.round(performance.now()),
  };
}

async function deadline<T>(task: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      task,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          const error = new Error("timed out");
          error.name = "TimeoutError";
          reject(error);
        }, ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
