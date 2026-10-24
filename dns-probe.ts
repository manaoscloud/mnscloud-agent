// dns.probe: on-demand network diagnosis requested by a platform master (DNS module, phase D4a).
// The job carries only a target (host name, URL or IP); the probe runs a fixed catalog of read-only
// tests with bounded time and size: public egress address (IPv4/IPv6), DNS resolution through the system resolver and
// well-known public resolvers, TCP and TLS reachability over IPv4/IPv6, and one HTTP request. It
// never runs a command and never connects to private, loopback, link-local or multicast addresses.

export const DNS_PROBE_JOB_TYPE = "dns.probe";
export const DNS_PROBE_CAPABILITY = "mnscloud.dns.probe";

// Well-known public resolvers compared with the host resolver (the diagnosis itself, not configuration).
export const PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "208.67.222.222"] as const; // NOSONAR
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
  egress: { address: string | null; ipv4: string | null; ipv6: string | null; status: StepStatus };
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
  egress: () => Promise<{ ipv4: string | null; ipv6: string | null }>;
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
    const defaultPort = url.protocol === "https:" ? 443 : 80;
    const port = url.port ? Number(url.port) : defaultPort;
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

// IANA special-purpose IPv4 ranges the probe must never contact.
const V4_PRIVATE: Array<[string, number]> = [ // NOSONAR
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
  const first = Number.parseInt(normalized.split(":")[0] || "0", 16);
  // Global unicast is 2000::/3; documentation 2001:db8::/32 is excluded too.
  if (first < 0x2000 || first > 0x3fff) return false;
  return !normalized.startsWith("2001:db8:") && !normalized.startsWith("2001:db8::");
}

export function statusOf(error: unknown): StepStatus {
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

export async function timed<T>(now: () => number, task: () => Promise<T>) {
  const started = now();
  try {
    return { value: await task(), status: "ok" as StepStatus, ms: now() - started };
  } catch (error) {
    return { value: null, status: statusOf(error), ms: now() - started };
  }
}

async function resolveAll(
  target: ProbeTarget,
  deps: ProbeDeps,
  publicResolvers: boolean,
): Promise<ResolutionStep[]> {
  const resolvers: Array<string | null> = publicResolvers ? [null, ...PUBLIC_RESOLVERS] : [null];
  return await Promise.all(
    resolvers.flatMap((resolver) =>
      (["A", "AAAA"] as const).map(async (type) => {
        const step = await timed(
          deps.now,
          () => deps.resolve(target.host, type, resolver, AbortSignal.timeout(RESOLVE_TIMEOUT_MS)),
        );
        const answers = (step.value ?? []).slice(0, MAX_ANSWERS);
        const status: StepStatus = step.status === "ok" && !answers.length ? "nodata" : step.status;
        return { resolver: resolver ?? "system", type, status, answers, ms: step.ms };
      })
    ),
  );
}

/** Addresses this host itself would use: the target IP, or the first system answer per family. */
function connectAddresses(target: ProbeTarget, resolution: ResolutionStep[]): Map<string, 4 | 6> {
  const addresses = new Map<string, 4 | 6>();
  if (target.kind === "ip") {
    addresses.set(target.host, ipVersion(target.host) as 4 | 6);
    return addresses;
  }
  for (const step of resolution.filter((item) => item.resolver === "system")) {
    const first = step.answers[0];
    if (first) addresses.set(first, step.type === "A" ? 4 : 6);
  }
  return addresses;
}

async function connectStep(
  target: ProbeTarget,
  address: string,
  family: 4 | 6,
  deps: ProbeDeps,
): Promise<ConnectStep> {
  const base = { family, address, port: target.port };
  if (!isPublicAddress(address)) return { ...base, tcp: { status: "blocked", ms: 0 }, tls: null };
  const tlsName = target.port === 443 && target.kind !== "ip" ? target.host : null;
  const step = await timed(deps.now, () => deps.connect(address, target.port, tlsName));
  return {
    ...base,
    tcp: { status: step.status, ms: step.value?.tcpMs ?? step.ms },
    tls: step.value?.tls ?? null,
  };
}

async function httpStep(
  target: ProbeTarget,
  addresses: Map<string, 4 | 6>,
  deps: ProbeDeps,
): Promise<ProbeResult["http"]> {
  if (!target.url || !addresses.size) return null;
  // The HTTP client resolves by itself: it runs only when every known answer is public.
  if (![...addresses.keys()].every(isPublicAddress)) {
    return { status: "blocked", code: null, ms: 0 };
  }
  const url = target.url;
  const step = await timed(deps.now, () => deps.http(url, AbortSignal.timeout(HTTP_TIMEOUT_MS)));
  return { status: step.status, code: step.value, ms: step.ms };
}

/**
 * Runs the fixed catalog for one target. Every step is bounded; a failing step never stops the others.
 * The continuous monitor (D4c) skips the public resolvers: it measures them as targets of their own.
 */
export async function runDnsProbe(
  target: ProbeTarget,
  deps: ProbeDeps,
  options: { publicResolvers?: boolean } = {},
): Promise<ProbeResult> {
  const started = deps.now();
  const egress = await timed(deps.now, deps.egress);
  const resolution = target.kind === "ip"
    ? []
    : await resolveAll(target, deps, options.publicResolvers ?? true);
  const addresses = connectAddresses(target, resolution);
  const connect = await Promise.all(
    [...addresses].map(([address, family]) => connectStep(target, address, family, deps)),
  );
  return {
    version: 1,
    target,
    egress: {
      address: egress.value?.ipv4 ?? egress.value?.ipv6 ?? null,
      ipv4: egress.value?.ipv4 ?? null,
      ipv6: egress.value?.ipv6 ?? null,
      status: egress.value?.ipv4 || egress.value?.ipv6 ? "ok" : egress.status,
    },
    resolution,
    connect,
    http: await httpStep(target, addresses, deps),
    durationMs: deps.now() - started,
  };
}

// Google's authoritative servers answer o-o.myaddr.l.google.com TXT with the address that asked:
// the public egress of this host on the internet (the API only sees the private platform path).
const EGRESS_NAME = "o-o.myaddr.l.google.com";
const EGRESS_SERVERS = { ipv4: "216.239.32.10", ipv6: "2001:4860:4802:32::a" } as const; // NOSONAR

async function egressOver(server: string): Promise<string | null> {
  try {
    const records = await Deno.resolveDns(EGRESS_NAME, "TXT", {
      nameServer: { ipAddr: server, port: 53 },
      signal: AbortSignal.timeout(RESOLVE_TIMEOUT_MS),
    });
    const value = records.flat()[0];
    return value && ipVersion(value) ? value : null;
  } catch {
    return null;
  }
}

/** Public egress addresses of this host (IPv4 and IPv6), each null when that family has no route. */
export async function publicEgress() {
  const [ipv4, ipv6] = await Promise.all([
    egressOver(EGRESS_SERVERS.ipv4),
    egressOver(EGRESS_SERVERS.ipv6),
  ]);
  return { ipv4, ipv6 };
}

/** Real network operations of a host (Deno). */
export function denoProbeDeps(
  egress: () => Promise<{ ipv4: string | null; ipv6: string | null }> = publicEgress,
): ProbeDeps {
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
