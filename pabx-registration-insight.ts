// Registration insight for PABX trunks: the last SIP failure the engine logged, the runtime
// destination/contact read from the engine CLI, the local SIP binding, and an optional
// unauthenticated REGISTER probe that reveals whether the registrar answers and which realm it
// announces. Everything here is read-only towards the provider: the probe never sends
// credentials and uses `Expires: 0`, so it cannot create or change a binding.

import dgram from "node:dgram";

export type SipTransport = "udp" | "tcp";

export type RegistrationFailure = {
  code: number;
  phrase: string | null;
  at: string | null;
  failures: number | null;
  retrySeconds: number | null;
  source: "engine-log";
};

export type RegistrationRuntime = {
  proxy: string | null;
  realm: string | null;
  username: string | null;
  from: string | null;
  contact: string | null;
  serverUri: string | null;
  clientUri: string | null;
  transport: SipTransport | null;
};

export type LocalBinding = { host: string; port: number; transport: string };

export type RegistrarProbe = {
  outcome: "response" | "timeout" | "error" | "skipped";
  target: string | null;
  transport: SipTransport;
  code: number | null;
  phrase: string | null;
  realm: string | null;
  server: string | null;
  durationMs: number | null;
  error: string | null;
};

export type SipTarget = { host: string; port: number | null; transport: SipTransport };

const FREESWITCH_LOG = "/var/log/freeswitch/freeswitch.log";
const ASTERISK_LOG = "/var/log/asterisk/messages";
const LOG_TAIL_BYTES = 1_048_576;
const MAX_TEXT = 160;

function clean(value: string | null | undefined, max = MAX_TEXT) {
  // deno-lint-ignore no-control-regex
  const text = String(value ?? "").replace(/[\u0000-\u001f\u007f]+/g, " ").trim();
  return text ? text.slice(0, max) : null;
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Local engine timestamps carry no zone; the Agent runs on the same host, so read them as local. */
function localTimestamp(date: string, time: string) {
  const parsed = new Date(`${date}T${time}`);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

function fieldValue(output: string, label: string) {
  return clean(output.match(new RegExp(`^\\s*${label}\\s+(.+?)\\s*$`, "im"))?.[1]);
}

function uriTransport(value: string | null): SipTransport | null {
  const transport = value?.match(/;transport=(udp|tcp)\b/i)?.[1]?.toLowerCase();
  return transport === "udp" || transport === "tcp" ? transport : null;
}

export function parseFreeswitchGateway(output: string): RegistrationRuntime {
  const contact = fieldValue(output, "Contact");
  return {
    proxy: fieldValue(output, "Proxy"),
    realm: fieldValue(output, "Realm"),
    username: fieldValue(output, "Username"),
    from: fieldValue(output, "From"),
    contact,
    serverUri: null,
    clientUri: null,
    transport: uriTransport(contact) ?? uriTransport(fieldValue(output, "Proxy")),
  };
}

export function parseAsteriskRegistration(
  output: string,
  runtimeName: string,
): RegistrationRuntime {
  const row = output.match(
    new RegExp(`^\\s*${escapeRegExp(runtimeName)}/(\\S+)`, "im"),
  );
  const serverUri = clean(row?.[1]);
  const clientUri = clean(output.match(/^\s*client_uri\s*:\s*(\S+)/im)?.[1]);
  return {
    proxy: serverUri,
    realm: null,
    username: clean(clientUri?.match(/^sips?:([^@;]+)@/i)?.[1]),
    from: clientUri,
    contact: null,
    serverUri,
    clientUri,
    transport: uriTransport(serverUri),
  };
}

/** Last `Failed Registration` FreeSWITCH logged for the gateway, unless it registered afterwards. */
export function lastFreeswitchFailure(
  log: string,
  runtimeName: string,
): RegistrationFailure | null {
  const name = escapeRegExp(runtimeName);
  const failed = new RegExp(
    `^(\\d{4}-\\d{2}-\\d{2}) (\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?)\\b.*?\\b${name} Failed Registration with status (.*?) \\[(\\d{3})\\]\\. failure #(\\d+)`,
  );
  const retry = new RegExp(
    `\\b${name} Failed Registration \\[(\\d{3})\\], setting retry to (\\d+) seconds`,
  );
  const registered = new RegExp(`\\b${name}\\b.*\\b(?:Registered|REGED)\\b`);
  let last: RegistrationFailure | null = null;
  for (const line of log.split("\n")) {
    const match = line.match(failed);
    if (match) {
      last = {
        code: Number(match[4]),
        phrase: clean(match[3]),
        at: localTimestamp(match[1], match[2].slice(0, 12)),
        failures: Number(match[5]),
        retrySeconds: null,
        source: "engine-log",
      };
      continue;
    }
    const retryMatch = line.match(retry);
    if (retryMatch && last && Number(retryMatch[1]) === last.code) {
      last.retrySeconds = Number(retryMatch[2]);
      continue;
    }
    if (registered.test(line)) last = null;
  }
  return last;
}

/** Last outbound registration failure Asterisk logged for the server URI of the trunk. */
export function lastAsteriskFailure(log: string, serverUri: string): RegistrationFailure | null {
  const server = escapeRegExp(serverUri);
  const stamp = /^\[(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})\]/;
  const response = new RegExp(
    `(?:Fatal|Temporal) response '(\\d{3})' received from '${server}'|'(\\d{3})' fatal response received from '${server}'`,
  );
  const noResponse = new RegExp(`No response received from '${server}'`);
  const retry = /retrying in '(\d+)'/;
  let last: RegistrationFailure | null = null;
  let failures = 0;
  for (const line of log.split("\n")) {
    const match = line.match(response);
    const timeout = !match && noResponse.test(line);
    if (!match && !timeout) continue;
    const when = line.match(stamp);
    failures += 1;
    last = {
      code: match ? Number(match[1] ?? match[2]) : 408,
      phrase: match ? null : "No response",
      at: when ? localTimestamp(when[1], when[2]) : null,
      failures,
      retrySeconds: Number(line.match(retry)?.[1]) || null,
      source: "engine-log",
    };
  }
  return last;
}

export function parseFreeswitchContactBinding(contact: string | null): LocalBinding | null {
  const match = contact?.match(/@(\[[^\]]+\]|[^:;>]+):(\d+)/);
  if (!match) return null;
  return {
    host: match[1].replace(/^\[|\]$/g, ""),
    port: Number(match[2]),
    transport: uriTransport(contact) ?? "udp",
  };
}

/** First Asterisk transport whose protocol matches (from `pjsip show transports`). */
export function parseAsteriskTransports(output: string, transport: string): LocalBinding | null {
  for (const line of output.split("\n")) {
    const match = line.match(
      /^\s*Transport:\s+(\S+)\s+(udp|tcp|tls|ws|wss)\s+\d+\s+\d+\s+(\S+):(\d+)\s*$/i,
    );
    if (match && match[2].toLowerCase() === transport) {
      return { host: match[3].replace(/^\[|\]$/g, ""), port: Number(match[4]), transport };
    }
  }
  return null;
}

/** Destination host/port/transport from a `sip:` URI or a bare host[:port]. */
export function sipTarget(value: string | null, fallback: SipTransport = "udp"): SipTarget | null {
  const raw = String(value ?? "").trim().replace(/^<|>$/g, "");
  if (!raw) return null;
  const transport = uriTransport(raw) ?? fallback;
  const hostPart = raw.replace(/^sips?:/i, "").replace(/^[^@]*@/, "").split(/[;?>]/)[0];
  const bracketed = hostPart.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (bracketed) {
    return { host: bracketed[1], port: bracketed[2] ? Number(bracketed[2]) : null, transport };
  }
  const plain = hostPart.match(/^([^:\s]+)(?::(\d+))?$/);
  if (!plain) return null;
  return { host: plain[1], port: plain[2] ? Number(plain[2]) : null, transport };
}

export function parseSipResponse(text: string) {
  const status = text.match(/^SIP\/2\.0 (\d{3})\s*([^\r\n]*)/);
  if (!status) return null;
  const header = (name: string) =>
    text.match(new RegExp(`^${name}\\s*:\\s*([^\\r\\n]*)`, "im"))?.[1] ?? null;
  const authenticate = header("WWW-Authenticate") ?? header("Proxy-Authenticate");
  return {
    code: Number(status[1]),
    phrase: clean(status[2]),
    realm: clean(authenticate?.match(/realm="([^"]*)"/i)?.[1]),
    server: clean(header("Server") ?? header("User-Agent")),
  };
}

function isIpAddress(host: string) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.includes(":");
}

async function resolveTarget(target: SipTarget) {
  if (isIpAddress(target.host)) return { address: target.host, port: target.port ?? 5060 };
  if (!target.port) {
    try {
      const records = await Deno.resolveDns(`_sip._${target.transport}.${target.host}`, "SRV");
      const best = records.sort((a, b) => a.priority - b.priority || b.weight - a.weight)[0];
      if (best) {
        const [address] = await Deno.resolveDns(best.target.replace(/\.$/, ""), "A");
        if (address) return { address, port: best.port };
      }
    } catch {
      // No SRV record: fall back to the A record on the default port.
    }
  }
  const [address] = await Deno.resolveDns(target.host, "A");
  if (!address) throw new Error("No IPv4 address found for the registrar.");
  return { address, port: target.port ?? 5060 };
}

function registerRequest(target: SipTarget, username: string, localPort: number) {
  const tag = crypto.randomUUID().replace(/-/g, "").slice(0, 16);
  const user = /^[A-Za-z0-9_.!~*'()&=+$,;?/-]{1,64}$/.test(username) ? username : "probe";
  const domain = target.host.includes(":") ? `[${target.host}]` : target.host;
  const proto = target.transport.toUpperCase();
  return [
    `REGISTER sip:${domain} SIP/2.0`,
    `Via: SIP/2.0/${proto} 0.0.0.0:${localPort};branch=z9hG4bK${tag};rport`,
    "Max-Forwards: 70",
    `From: <sip:${user}@${domain}>;tag=${tag}`,
    `To: <sip:${user}@${domain}>`,
    `Call-ID: ${tag}@mnscloud-agent`,
    "CSeq: 1 REGISTER",
    `Contact: <sip:${user}@0.0.0.0:${localPort}>`,
    "Expires: 0",
    "User-Agent: MNSCloud Agent registration probe",
    "Content-Length: 0",
    "",
    "",
  ].join("\r\n");
}

async function probeUdp(
  address: string,
  port: number,
  target: SipTarget,
  username: string,
  timeoutMs: number,
) {
  const socket = dgram.createSocket("udp4");
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject);
      socket.bind(0, () => resolve());
    });
    const localPort = socket.address().port;
    const reply = new Promise<string | null>((resolve) => {
      const timer = setTimeout(() => resolve(null), timeoutMs);
      socket.on("message", (message: Uint8Array) => {
        const text = new TextDecoder().decode(message);
        // Ignore provisional responses; wait for the final answer.
        if (/^SIP\/2\.0 1\d\d/.test(text)) return;
        clearTimeout(timer);
        resolve(text);
      });
    });
    socket.send(
      new TextEncoder().encode(registerRequest(target, username, localPort)),
      port,
      address,
    );
    return await reply;
  } finally {
    socket.close();
  }
}

async function probeTcp(
  address: string,
  port: number,
  target: SipTarget,
  username: string,
  timeoutMs: number,
) {
  const deadline = AbortSignal.timeout(timeoutMs);
  const conn = await Deno.connect({ hostname: address, port, transport: "tcp" });
  try {
    const localPort = (conn.localAddr as Deno.NetAddr).port;
    await conn.write(new TextEncoder().encode(registerRequest(target, username, localPort)));
    const buffer = new Uint8Array(8192);
    let text = "";
    while (!deadline.aborted) {
      const read = await Promise.race([
        conn.read(buffer),
        new Promise<null>((resolve) => deadline.addEventListener("abort", () => resolve(null))),
      ]);
      if (read === null) break;
      text += new TextDecoder().decode(buffer.subarray(0, read));
      const responses = text.split(/\r\n\r\n/).filter((part) => part.startsWith("SIP/2.0"));
      const final = responses.find((part) => !/^SIP\/2\.0 1\d\d/.test(part));
      if (final) return final;
    }
    return null;
  } finally {
    conn.close();
  }
}

export async function probeRegistrar(
  target: SipTarget,
  username: string,
  timeoutMs = 4_000,
): Promise<RegistrarProbe> {
  const started = performance.now();
  const base = { transport: target.transport, code: null, phrase: null, realm: null, server: null };
  try {
    const { address, port } = await resolveTarget(target);
    const label = `${address.includes(":") ? `[${address}]` : address}:${port}`;
    const reply = target.transport === "tcp"
      ? await probeTcp(address, port, target, username, timeoutMs)
      : await probeUdp(address, port, target, username, timeoutMs);
    const durationMs = Math.round(performance.now() - started);
    const parsed = reply ? parseSipResponse(reply) : null;
    if (!parsed) {
      return { ...base, outcome: "timeout", target: label, durationMs, error: null };
    }
    return {
      ...parsed,
      outcome: "response",
      target: label,
      transport: target.transport,
      durationMs,
      error: null,
    };
  } catch (error) {
    return {
      ...base,
      outcome: "error",
      target: null,
      durationMs: Math.round(performance.now() - started),
      error: clean(error instanceof Error ? error.message : String(error)),
    };
  }
}

/** Last `maxBytes` of a text file, starting at a line boundary. */
export async function readFileTail(path: string, maxBytes: number) {
  const file = await Deno.open(path, { read: true });
  try {
    const size = (await file.stat()).size;
    const start = Math.max(0, size - maxBytes);
    await file.seek(start, Deno.SeekMode.Start);
    const buffer = new Uint8Array(size - start);
    let offset = 0;
    while (offset < buffer.length) {
      const read = await file.read(buffer.subarray(offset));
      if (read === null) break;
      offset += read;
    }
    const text = new TextDecoder().decode(buffer.subarray(0, offset));
    return start > 0 ? text.slice(text.indexOf("\n") + 1) : text;
  } finally {
    file.close();
  }
}

export async function readEngineLogTail(engine: string) {
  const path = engine === "freeswitch" ? FREESWITCH_LOG : ASTERISK_LOG;
  try {
    return await readFileTail(path, LOG_TAIL_BYTES);
  } catch {
    return "";
  }
}
