/**
 * V9 network devices: read-only SNMP inventory of a router, firewall or switch on the network of
 * this Agent (job cyber.security.network-device.collect). The platform registers the device and
 * gives the credential only for the leased job; the Agent reads a fixed list of identity and
 * version objects with SNMP GET (v2c community, or v3 with SHA/SHA-256 authentication and AES-128
 * privacy), never SET or WALK, and returns the vendor, model and firmware version that the
 * platform matches with published vulnerabilities. Contract: docs/network-devices.md.
 */
import { Buffer } from "node:buffer";
import { createHash, createHmac } from "node:crypto";
import dgram from "node:dgram";

export const NETWORK_DEVICE_COMMAND = "cyber.security.network-device.collect";
export const NETWORK_DEVICE_CAPABILITY = "cyber.security.network-device.v1";

export type Vendor =
  | "mikrotik_routeros"
  | "fortinet_fortios"
  | "cisco_iosxe"
  | "cisco_asa"
  | "juniper_junos"
  | "paloalto_panos"
  | "sonicwall_sonicos"
  | "other";

export type SnmpCredentials =
  | { version: "v2c"; community: string }
  | {
    version: "v3";
    user: string;
    authProtocol: "sha" | "sha256";
    authPassword: string;
    privProtocol: "aes" | "none";
    privPassword?: string;
  };

export type DeviceTarget = { address: string; port: number; credentials: SnmpCredentials };

export type DeviceResult = {
  networkDevice: 1;
  deviceUUID: string;
  sysName: string | null;
  sysDescr: string | null;
  sysObjectId: string | null;
  vendor: Vendor;
  model: string | null;
  version: string | null;
  uptimeSeconds: number | null;
  durationMs: number;
};

export class NetworkDeviceError extends Error {}

// ---------------------------------------------------------------------------------------------
// Objects read (SNMPv2-MIB system group and one version object per vendor).

export const OID = {
  sysDescr: "1.3.6.1.2.1.1.1.0",
  sysObjectId: "1.3.6.1.2.1.1.2.0",
  sysUpTime: "1.3.6.1.2.1.1.3.0",
  sysName: "1.3.6.1.2.1.1.5.0",
} as const;

/** Vendor objects: [version OID, model OID]. */
export const VENDOR_OIDS: Partial<Record<Vendor, { version?: string; model?: string }>> = {
  // MIKROTIK-MIB mtxrLicVersion (RouterOS version) and mtxrBoardName.
  mikrotik_routeros: {
    version: "1.3.6.1.4.1.14988.1.1.4.4.0",
    model: "1.3.6.1.4.1.14988.1.1.7.8.0",
  },
  // FORTINET-FORTIGATE-MIB fgSysVersion ("v7.2.5,build1517,...").
  fortinet_fortios: { version: "1.3.6.1.4.1.12356.101.4.1.1.0" },
  // PAN-COMMON-MIB panSysSwVersion and panChassisType.
  paloalto_panos: {
    version: "1.3.6.1.4.1.25461.2.1.2.1.1.0",
    model: "1.3.6.1.4.1.25461.2.1.2.2.1.0",
  },
  // SONICWALL-FIREWALL-IP-STATISTICS-MIB snwlSysFirmwareVersion and snwlSysModel.
  sonicwall_sonicos: { version: "1.3.6.1.4.1.8741.1.3.1.3.0", model: "1.3.6.1.4.1.8741.1.3.1.2.0" },
};

// ---------------------------------------------------------------------------------------------
// BER (the subset SNMP uses).

const TAG = {
  integer: 0x02,
  octets: 0x04,
  null: 0x05,
  oid: 0x06,
  sequence: 0x30,
  timeticks: 0x43,
  get: 0xa0,
  response: 0xa2,
  report: 0xa8,
} as const;

function length(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return [0x80 | bytes.length, ...bytes];
}

function tlv(tag: number, value: Uint8Array): Uint8Array {
  return Uint8Array.from([tag, ...length(value.length), ...value]);
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function encodeInteger(value: number): Uint8Array {
  const bytes: number[] = [];
  // SNMP integers here are request ids, sizes and engine counters: 0 to 2^31-1.
  let v = value >>> 0;
  do {
    bytes.unshift(v & 0xff);
    v = v >>> 8;
  } while (v > 0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return tlv(TAG.integer, Uint8Array.from(bytes));
}

function encodeOctets(value: Uint8Array | string): Uint8Array {
  return tlv(TAG.octets, typeof value === "string" ? new TextEncoder().encode(value) : value);
}

export function encodeOid(oid: string): Uint8Array {
  const parts = oid.split(".").map(Number);
  if (parts.length < 2 || parts.some((n) => !Number.isInteger(n) || n < 0)) {
    throw new NetworkDeviceError(`Invalid OID ${oid}`);
  }
  const out = [parts[0] * 40 + parts[1]];
  for (const n of parts.slice(2)) {
    const chunk = [n & 0x7f];
    for (let v = Math.floor(n / 128); v > 0; v = Math.floor(v / 128)) {
      chunk.unshift(0x80 | (v & 0x7f));
    }
    out.push(...chunk);
  }
  return tlv(TAG.oid, Uint8Array.from(out));
}

const sequence = (...items: Uint8Array[]) => tlv(TAG.sequence, concat(...items));

type Node = { tag: number; value: Uint8Array; children?: Node[]; end: number };

export function decode(data: Uint8Array, offset = 0): Node {
  if (offset + 2 > data.length) throw new NetworkDeviceError("Truncated SNMP message");
  const tag = data[offset];
  let len = data[offset + 1];
  let start = offset + 2;
  if (len & 0x80) {
    const count = len & 0x7f;
    if (count === 0 || count > 4 || start + count > data.length) {
      throw new NetworkDeviceError("Invalid SNMP length");
    }
    len = 0;
    for (let i = 0; i < count; i++) len = len * 256 + data[start + i];
    start += count;
  }
  const end = start + len;
  if (end > data.length) throw new NetworkDeviceError("Truncated SNMP message");
  const value = data.subarray(start, end);
  const node: Node = { tag, value, end };
  // Constructed: universal SEQUENCE and the context PDUs (0xa0-0xa8).
  if (tag === TAG.sequence || (tag >= 0xa0 && tag <= 0xa8)) {
    node.children = [];
    for (let p = start; p < end;) {
      const child = decode(data, p);
      node.children.push(child);
      p = child.end;
    }
  }
  return node;
}

function readInteger(node: Node): number {
  let v = 0;
  for (const b of node.value) v = v * 256 + b;
  if (node.value.length && node.value[0] & 0x80) v -= 2 ** (8 * node.value.length);
  return v;
}

function readOid(node: Node): string {
  const bytes = node.value;
  if (!bytes.length) return "";
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (const b of bytes.slice(1)) {
    v = v * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}

function child(node: Node, index: number): Node {
  const found = node.children?.[index];
  if (!found) throw new NetworkDeviceError("Unexpected SNMP message");
  return found;
}

/** Value of one variable binding as text (null for noSuchObject/noSuchInstance/endOfMibView). */
function bindingValue(node: Node): string | null {
  switch (node.tag) {
    case TAG.octets:
      return printable(node.value);
    case TAG.oid:
      return readOid(node);
    case TAG.integer:
    case TAG.timeticks:
    case 0x41: // Counter32
    case 0x42: // Gauge32
      return String(readUnsigned(node));
    default:
      return null;
  }
}

function readUnsigned(node: Node): number {
  let v = 0;
  for (const b of node.value) v = v * 256 + b;
  return v;
}

function printable(bytes: Uint8Array): string {
  // Control characters (except tab and newline) are dropped.
  return Array.from(new TextDecoder("utf-8", { fatal: false }).decode(bytes))
    .filter((ch) => {
      const code = ch.codePointAt(0) ?? 0;
      return code === 9 || code === 10 || (code >= 32 && code !== 127);
    })
    .join("")
    .trim()
    .slice(0, 500);
}

function pdu(tag: number, requestId: number, oids: string[]): Uint8Array {
  return tlv(
    tag,
    concat(
      encodeInteger(requestId),
      encodeInteger(0),
      encodeInteger(0),
      sequence(...oids.map((oid) => sequence(encodeOid(oid), tlv(TAG.null, new Uint8Array())))),
    ),
  );
}

/** Decodes a response PDU into OID → value; an SNMP error status fails the request. */
function readPdu(node: Node, requestId: number): Map<string, string | null> {
  if (node.tag === TAG.report) throw new SnmpReport(node);
  if (node.tag !== TAG.response) throw new NetworkDeviceError("Unexpected SNMP answer");
  if (readInteger(child(node, 0)) !== requestId) {
    throw new NetworkDeviceError("SNMP answer to another request");
  }
  const status = readInteger(child(node, 1));
  if (status !== 0) throw new NetworkDeviceError(`The device answered with SNMP error ${status}`);
  const values = new Map<string, string | null>();
  for (const binding of child(node, 3).children ?? []) {
    values.set(readOid(child(binding, 0)), bindingValue(child(binding, 1)));
  }
  return values;
}

class SnmpReport extends Error {
  constructor(readonly node: Node) {
    super("SNMP report");
  }
  oid(): string | null {
    const binding = this.node.children?.[3]?.children?.[0];
    return binding ? readOid(child(binding, 0)) : null;
  }
}

// ---------------------------------------------------------------------------------------------
// SNMPv2c

export function encodeV2c(community: string, requestId: number, oids: string[]): Uint8Array {
  return sequence(encodeInteger(1), encodeOctets(community), pdu(TAG.get, requestId, oids));
}

export function decodeV2c(data: Uint8Array, requestId: number): Map<string, string | null> {
  const message = decode(data);
  if (readInteger(child(message, 0)) !== 1) throw new NetworkDeviceError("Unexpected SNMP version");
  return readPdu(child(message, 2), requestId);
}

// ---------------------------------------------------------------------------------------------
// SNMPv3 USM (RFC 3414, RFC 7860 for SHA-256, RFC 3826 for AES-128).

type Engine = { id: Uint8Array; boots: number; time: number };

const AUTH = {
  sha: { hash: "sha1", macLength: 12 },
  sha256: { hash: "sha256", macLength: 24 },
} as const;

/** Password to localized key (RFC 3414 A.2): hash of 1 MB of the password, then Ku+engineID+Ku. */
export function localizeKey(
  hash: "sha1" | "sha256",
  password: string,
  engineId: Uint8Array,
): Uint8Array {
  const pw = new TextEncoder().encode(password);
  if (pw.length < 8) throw new NetworkDeviceError("SNMPv3 passwords need at least 8 characters");
  const digest = createHash(hash);
  const block = new Uint8Array(64);
  for (let count = 0; count < 1048576; count += 64) {
    for (let i = 0; i < 64; i++) block[i] = pw[(count + i) % pw.length];
    digest.update(block);
  }
  const ku = digest.digest();
  return new Uint8Array(createHash(hash).update(ku).update(engineId).update(ku).digest());
}

/**
 * AES-128 in CFB-128 mode (RFC 3826). Deno has no aes-128-cfb, so each keystream block E(feedback)
 * comes from WebCrypto AES-CTR over one zero block with the feedback as the counter block.
 */
export async function aesCfb(
  key: Uint8Array,
  iv: Uint8Array,
  input: Uint8Array,
  decrypt: boolean,
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(key.subarray(0, 16)),
    { name: "AES-CTR" },
    false,
    ["encrypt"],
  );
  const zero = new Uint8Array(16);
  const out = new Uint8Array(input.length);
  let feedback = Uint8Array.from(iv);
  for (let offset = 0; offset < input.length; offset += 16) {
    const stream = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-CTR", counter: feedback, length: 64 },
        cryptoKey,
        zero,
      ),
    );
    const chunk = input.subarray(offset, offset + 16);
    const next = new Uint8Array(16);
    for (let i = 0; i < chunk.length; i++) {
      out[offset + i] = chunk[i] ^ stream[i];
      next[i] = decrypt ? chunk[i] : out[offset + i];
    }
    feedback = next;
  }
  return out;
}

function aesIv(engine: Engine, salt: Uint8Array): Uint8Array {
  const iv = new Uint8Array(16);
  new DataView(iv.buffer).setUint32(0, engine.boots >>> 0);
  new DataView(iv.buffer).setUint32(4, engine.time >>> 0);
  iv.set(salt, 8);
  return iv;
}

type V3Keys = { auth: Uint8Array | null; priv: Uint8Array | null };

function usmParameters(
  engine: Engine,
  user: string,
  authParams: Uint8Array,
  privParams: Uint8Array,
): Uint8Array {
  return sequence(
    encodeOctets(engine.id),
    encodeInteger(engine.boots),
    encodeInteger(engine.time),
    encodeOctets(user),
    encodeOctets(authParams),
    encodeOctets(privParams),
  );
}

export async function encodeV3(
  credentials: Extract<SnmpCredentials, { version: "v3" }> | null,
  engine: Engine,
  keys: V3Keys,
  messageId: number,
  requestId: number,
  oids: string[],
  salt: Uint8Array = crypto.getRandomValues(new Uint8Array(8)),
): Promise<Uint8Array> {
  const auth = credentials ? AUTH[credentials.authProtocol] : null;
  const priv = credentials !== null && credentials.privProtocol === "aes";
  // Discovery (no credentials): noAuthNoPriv, reportable.
  const flags = (auth ? 1 : 0) | (priv ? 2 : 0) | 4;
  const scoped = sequence(encodeOctets(engine.id), encodeOctets(""), pdu(TAG.get, requestId, oids));
  let data: Uint8Array = scoped;
  let privParams: Uint8Array = new Uint8Array();
  if (priv) {
    if (!keys.priv) throw new NetworkDeviceError("SNMPv3 privacy key missing");
    privParams = Uint8Array.from(salt);
    data = encodeOctets(await aesCfb(keys.priv, aesIv(engine, privParams), scoped, false));
  }
  const header = sequence(
    encodeInteger(messageId),
    encodeInteger(65507),
    encodeOctets(Uint8Array.of(flags)),
    encodeInteger(3),
  );
  const build = (authParams: Uint8Array) =>
    sequence(
      encodeInteger(3),
      header,
      encodeOctets(usmParameters(engine, credentials?.user ?? "", authParams, privParams)),
      data,
    );
  if (!auth) return build(new Uint8Array());
  if (!keys.auth) throw new NetworkDeviceError("SNMPv3 authentication key missing");
  const placeholder = new Uint8Array(auth.macLength);
  const unsigned = build(placeholder);
  const mac = new Uint8Array(
    createHmac(auth.hash, Buffer.from(keys.auth)).update(unsigned).digest(),
  ).subarray(0, auth.macLength);
  return build(mac);
}

type V3Answer = {
  engine: Engine;
  values: Map<string, string | null> | null;
  reportOid: string | null;
};

export async function decodeV3(
  data: Uint8Array,
  credentials: Extract<SnmpCredentials, { version: "v3" }> | null,
  keys: V3Keys,
  requestId: number,
): Promise<V3Answer> {
  const message = decode(data);
  if (readInteger(child(message, 0)) !== 3) throw new NetworkDeviceError("Unexpected SNMP version");
  const flags = child(child(message, 1), 2).value[0] ?? 0;
  const securityRaw = child(message, 2);
  const usm = decode(securityRaw.value);
  const engine: Engine = {
    id: Uint8Array.from(child(usm, 0).value),
    boots: readUnsigned(child(usm, 1)),
    time: readUnsigned(child(usm, 2)),
  };
  const authParams = child(usm, 4).value;
  const privParams = child(usm, 5).value;
  if (credentials && flags & 1) {
    // Verify the answer: HMAC over the message with the authentication parameters zeroed.
    const auth = AUTH[credentials.authProtocol];
    if (!keys.auth || authParams.length !== auth.macLength) {
      throw new NetworkDeviceError("SNMPv3 answer not authenticated");
    }
    // The parameters are a view into the message: their offset is exact.
    const copy = Uint8Array.from(data);
    const at = authParams.byteOffset - data.byteOffset;
    copy.fill(0, at, at + authParams.length);
    const mac = new Uint8Array(createHmac(auth.hash, Buffer.from(keys.auth)).update(copy).digest())
      .subarray(0, auth.macLength);
    if (!mac.every((b, i) => b === authParams[i])) {
      throw new NetworkDeviceError("SNMPv3 answer failed authentication");
    }
  }
  let scopedNode = child(message, 3);
  if (scopedNode.tag === TAG.octets) {
    if (credentials?.privProtocol !== "aes" || !keys.priv || privParams.length !== 8) {
      throw new NetworkDeviceError("Encrypted SNMPv3 answer cannot be read");
    }
    scopedNode = decode(await aesCfb(keys.priv, aesIv(engine, privParams), scopedNode.value, true));
  }
  const reportNode = child(scopedNode, 2);
  if (reportNode.tag === TAG.report) {
    return { engine, values: null, reportOid: new SnmpReport(reportNode).oid() };
  }
  return { engine, values: readPdu(reportNode, requestId), reportOid: null };
}

const USM_REPORTS: Record<string, string> = {
  "1.3.6.1.6.3.15.1.1.1.0": "SNMPv3 security level not supported by the device",
  "1.3.6.1.6.3.15.1.1.2.0": "SNMPv3 time window error",
  "1.3.6.1.6.3.15.1.1.3.0": "Unknown SNMPv3 user",
  "1.3.6.1.6.3.15.1.1.5.0": "Wrong SNMPv3 authentication password or protocol",
  "1.3.6.1.6.3.15.1.1.6.0": "Wrong SNMPv3 privacy password or protocol",
};

// ---------------------------------------------------------------------------------------------
// Transport

export type Transport = (address: string, port: number, packet: Uint8Array) => Promise<Uint8Array>;

/** One UDP request with retries; the answer must come from the device address and port. */
export function udpTransport(timeoutMs = 3000, attempts = 2): Transport {
  return async (address, port, packet) => {
    for (let attempt = 1; attempt <= attempts; attempt++) {
      try {
        return await new Promise<Uint8Array>((resolve, reject) => {
          const socket = dgram.createSocket(address.includes(":") ? "udp6" : "udp4");
          const timer = setTimeout(() => {
            socket.close();
            reject(
              new NetworkDeviceError(
                `No SNMP answer from ${address}:${port} (timeout): check the address, the UDP port, the firewall and the credential`,
              ),
            );
          }, timeoutMs);
          socket.on("error", (error: Error) => {
            clearTimeout(timer);
            socket.close();
            reject(
              new NetworkDeviceError(`SNMP request to ${address}:${port} failed: ${error.message}`),
            );
          });
          socket.on("message", (message: Uint8Array, remote: { address: string; port: number }) => {
            if (
              remote.port !== port || normalizeAddress(remote.address) !== normalizeAddress(address)
            ) return;
            clearTimeout(timer);
            socket.close();
            resolve(new Uint8Array(message));
          });
          socket.send(packet, port, address);
        });
      } catch (error) {
        if (attempt >= attempts) throw error;
      }
    }
    throw new NetworkDeviceError("SNMP request failed");
  };
}

function normalizeAddress(address: string) {
  return address.replace(/^::ffff:/, "").toLowerCase();
}

/** Unicast only: unspecified, loopback, link-local, multicast and broadcast are refused. */
export function allowedAddress(address: string): boolean {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    if (v4.slice(1).some((n) => Number(n) > 255)) return false;
    return !(a === 0 || a === 127 || a >= 224 || (a === 169 && b === 254));
  }
  if (!address.includes(":") || !/^[0-9a-f:.]+$/i.test(address)) return false;
  const lower = address.toLowerCase();
  return !(lower === "::" || lower === "::1" || lower.startsWith("ff") || /^fe[89ab]/.test(lower));
}

// ---------------------------------------------------------------------------------------------
// Session: GET a list of OIDs with the device credential.

export type SnmpSession = { get(oids: string[]): Promise<Map<string, string | null>> };

export function openSession(target: DeviceTarget, transport: Transport): SnmpSession {
  // A request id is not a secret: an unpredictable start only avoids matching stale answers.
  let requestId = (crypto.getRandomValues(new Uint32Array(1))[0] >>> 2) | 1;
  const next = () => (requestId = requestId >= 0x3ffffffe ? 1 : requestId + 1);
  const credentials = target.credentials;
  if (credentials.version === "v2c") {
    return {
      async get(oids) {
        const id = next();
        return decodeV2c(
          await transport(target.address, target.port, encodeV2c(credentials.community, id, oids)),
          id,
        );
      },
    };
  }
  let engine: Engine | null = null;
  let keys: V3Keys = { auth: null, priv: null };
  const discover = async () => {
    const id = next();
    const probe = await encodeV3(
      null,
      { id: new Uint8Array(), boots: 0, time: 0 },
      keys,
      id,
      id,
      [],
    );
    const answer = await decodeV3(
      await transport(target.address, target.port, probe),
      null,
      keys,
      id,
    );
    if (!answer.engine.id.length) {
      throw new NetworkDeviceError("The device did not report its SNMPv3 engine");
    }
    engine = answer.engine;
    const hash = AUTH[credentials.authProtocol].hash;
    keys = {
      auth: localizeKey(hash, credentials.authPassword, engine.id),
      priv: credentials.privProtocol === "aes"
        ? localizeKey(hash, credentials.privPassword ?? "", engine.id)
        : null,
    };
  };
  return {
    async get(oids) {
      if (!engine) await discover();
      for (let attempt = 0; attempt < 2; attempt++) {
        const id = next();
        const packet = await encodeV3(credentials, engine!, keys, id, id, oids);
        const answer = await decodeV3(
          await transport(target.address, target.port, packet),
          credentials,
          keys,
          id,
        );
        if (answer.values) return answer.values;
        // A time window report carries the current boots/time: retry once with them.
        if (answer.reportOid === "1.3.6.1.6.3.15.1.1.2.0" && attempt === 0) {
          engine = { ...engine!, boots: answer.engine.boots, time: answer.engine.time };
          continue;
        }
        throw new NetworkDeviceError(
          USM_REPORTS[answer.reportOid ?? ""] ?? "The device refused the SNMPv3 request",
        );
      }
      throw new NetworkDeviceError("SNMPv3 time window error");
    },
  };
}

// ---------------------------------------------------------------------------------------------
// Vendor, model and version

export function detectVendor(sysObjectId: string | null, sysDescr: string | null): Vendor {
  const oid = sysObjectId ?? "";
  const descr = sysDescr ?? "";
  const under = (prefix: string) => oid === prefix || oid.startsWith(prefix + ".");
  if (under("1.3.6.1.4.1.14988") || /^RouterOS\b/i.test(descr)) return "mikrotik_routeros";
  if (under("1.3.6.1.4.1.12356") || /\bFortiGate\b/i.test(descr)) return "fortinet_fortios";
  if (under("1.3.6.1.4.1.25461") || /\bPalo Alto Networks\b/i.test(descr)) return "paloalto_panos";
  if (under("1.3.6.1.4.1.8741") || /\bSonicWALL\b/i.test(descr)) return "sonicwall_sonicos";
  if (under("1.3.6.1.4.1.2636") || /\bJUNOS\b/.test(descr)) return "juniper_junos";
  if (/Adaptive Security Appliance/i.test(descr)) return "cisco_asa";
  if (/IOS[- ]?XE/i.test(descr)) return "cisco_iosxe";
  return "other";
}

/** The run of characters accepted by `allowed` that starts at `from` (no regex backtracking). */
function runFrom(text: string, from: number, allowed: (ch: string) => boolean): string {
  let end = from;
  while (end < text.length && allowed(text[end])) end++;
  return text.slice(from, end);
}

const isDigit = (ch: string) => ch >= "0" && ch <= "9";
const isVersionChar = (ch: string) => /[0-9A-Za-z.\-]/.test(ch);

/** The version-like token at the first digit of the text, or right after a marker word. */
function tokenAt(text: string, marker = "", allowed = isVersionChar): string {
  let from = 0;
  if (marker) {
    const at = text.toLowerCase().indexOf(marker.toLowerCase());
    if (at < 0) return "";
    from = at + marker.length;
  }
  while (from < text.length && !isDigit(text[from])) {
    if (marker && from - text.toLowerCase().indexOf(marker.toLowerCase()) > marker.length + 24) {
      return "";
    }
    from++;
  }
  return runFrom(text, from, allowed).replace(/[.\-]+$/, "");
}

const VERSION_PARSERS: Partial<Record<Vendor, (descr: string, raw: string) => string>> = {
  // mtxrLicVersion "7.12.1" or "6.49.10 (long-term)"; RouterOS 7 also "7.16rc2".
  mikrotik_routeros: (descr, raw) => tokenAt(raw) || tokenAt(descr, "RouterOS"),
  // fgSysVersion "v7.2.5,build1517,230606 (GA.F)".
  fortinet_fortios: (_descr, raw) => tokenAt(raw, "", (ch) => isDigit(ch) || ch === "."),
  // panSysSwVersion "10.2.4-h4".
  paloalto_panos: (_descr, raw) => tokenAt(raw),
  // snwlSysFirmwareVersion "SonicOS 7.0.1-5145-R4321" → 7.0.1-5145.
  sonicwall_sonicos: (descr, raw) => {
    const token = tokenAt(raw) || tokenAt(descr, "SonicOS");
    return /^\d+(\.\d+){2,3}(-\d+)?n?/i.exec(token)?.[0] ?? "";
  },
  // "JUNOS 21.4R3-S1.5" → 21.4r3-s1 (the respin after the service release is not in the advisories).
  juniper_junos: (descr) => /^\d+\.\d+[RXFD]\d+(-S\d+)?/i.exec(tokenAt(descr, "JUNOS"))?.[0] ?? "",
  // "..., Version 17.9.4a, RELEASE SOFTWARE".
  cisco_iosxe: (descr) => tokenAt(descr, "Version", (ch) => /[0-9A-Za-z.]/.test(ch)),
  // "Version 9.16(3)19" → 9.16.3.19, as in the NVD.
  cisco_asa: (descr) =>
    tokenAt(descr, "Version", (ch) => isDigit(ch) || ch === "." || ch === "(" || ch === ")")
      .split("(").join(".").split(")").join("."),
};

/** Normalized version (lowercase, comparable with the NVD CPE version and update fields). */
export function parseVersion(
  vendor: Vendor,
  sysDescr: string | null,
  vendorVersion: string | null,
): string | null {
  const parser = VERSION_PARSERS[vendor];
  if (!parser) return null;
  const version = parser(sysDescr ?? "", (vendorVersion ?? "").trim()).toLowerCase()
    .replace(/\.{2,}/g, ".").replace(/^\.|\.$/g, "");
  return /^[0-9a-z][0-9a-z.()_+-]{0,79}$/.test(version) ? version : null;
}

function parseModel(
  vendor: Vendor,
  sysDescr: string | null,
  vendorModel: string | null,
): string | null {
  const descr = sysDescr ?? "";
  const model = (vendorModel ?? "").trim() ||
    (vendor === "mikrotik_routeros" ? /^RouterOS\s+(\S+)/i.exec(descr)?.[1] ?? "" : "") ||
    (vendor === "sonicwall_sonicos" ? /SonicWALL\s+([^(]+)/i.exec(descr)?.[1]?.trim() ?? "" : "") ||
    (vendor === "fortinet_fortios" ? /^(Forti\S+|FG\S+)/i.exec(descr)?.[1] ?? "" : "") ||
    (vendor === "juniper_junos" ? /Juniper Networks, Inc\.\s+(\S+)/i.exec(descr)?.[1] ?? "" : "");
  return model ? model.slice(0, 120) : null;
}

// ---------------------------------------------------------------------------------------------
// Job

const text = (v: unknown) => (typeof v === "string" ? v : "");
const AUTH_PROTOCOLS = ["sha", "sha256"] as const;
const PRIV_PROTOCOLS = ["aes", "none"] as const;

function pickOne<T extends string>(value: unknown, allowed: readonly T[]): T | null {
  return allowed.find((item) => item === value) ?? null;
}

function parseCredentials(version: unknown, raw: unknown): SnmpCredentials {
  const c = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  if (version === "v2c") {
    if (!text(c.community)) throw new NetworkDeviceError("The SNMP community is missing");
    return { version: "v2c", community: text(c.community) };
  }
  if (version !== "v3") throw new NetworkDeviceError("Invalid SNMP version");
  const authProtocol = pickOne(c.authProtocol, AUTH_PROTOCOLS);
  const privProtocol = pickOne(c.privProtocol, PRIV_PROTOCOLS);
  const complete = text(c.user) && authProtocol && privProtocol && text(c.authPassword) &&
    (privProtocol !== "aes" || text(c.privPassword));
  if (!complete) throw new NetworkDeviceError("The SNMPv3 credential is incomplete");
  return {
    version: "v3",
    user: text(c.user),
    authProtocol,
    authPassword: text(c.authPassword),
    privProtocol,
    privPassword: text(c.privPassword) || undefined,
  };
}

export function parseMaterial(
  data: Record<string, unknown>,
): DeviceTarget & { deviceUUID: string } {
  const address = text(data.address).trim();
  const port = Number(data.port ?? 161);
  if (!allowedAddress(address)) {
    throw new NetworkDeviceError("The device address is not a unicast IP address");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new NetworkDeviceError("Invalid SNMP port");
  }
  const credentials = parseCredentials(data.snmpVersion, data.credentials);
  return { deviceUUID: text(data.deviceUUID), address, port, credentials };
}

/** Reads the fixed identity and version objects of one device. */
export async function collectDevice(
  target: DeviceTarget & { deviceUUID: string },
  transport: Transport,
  now: () => number = Date.now,
): Promise<DeviceResult> {
  const started = now();
  const session = openSession(target, transport);
  const system = await session.get([OID.sysDescr, OID.sysObjectId, OID.sysUpTime, OID.sysName]);
  const sysDescr = system.get(OID.sysDescr) ?? null;
  const sysObjectId = system.get(OID.sysObjectId) ?? null;
  const vendor = detectVendor(sysObjectId, sysDescr);
  const extra = VENDOR_OIDS[vendor];
  let vendorVersion: string | null = null;
  let vendorModel: string | null = null;
  const oids = [extra?.version, extra?.model].filter((o): o is string => !!o);
  if (oids.length) {
    try {
      const values = await session.get(oids);
      vendorVersion = extra?.version ? values.get(extra.version) ?? null : null;
      vendorModel = extra?.model ? values.get(extra.model) ?? null : null;
    } catch (error) {
      // A device without the vendor MIB still reports its identity; the version may come from sysDescr.
      if (!(error instanceof NetworkDeviceError)) throw error;
    }
  }
  const ticks = Number(system.get(OID.sysUpTime) ?? Number.NaN);
  return {
    networkDevice: 1,
    deviceUUID: target.deviceUUID,
    sysName: system.get(OID.sysName) ?? null,
    sysDescr,
    sysObjectId,
    vendor,
    model: parseModel(vendor, sysDescr, vendorModel),
    version: parseVersion(vendor, sysDescr, vendorVersion),
    uptimeSeconds: Number.isFinite(ticks) ? Math.floor(ticks / 100) : null,
    durationMs: now() - started,
  };
}

/** Test helper: the GetResponse a v2c device would send for these bindings. */
export function encodeV2cResponse(
  community: string,
  requestId: number,
  bindings: Array<[string, string | null]>,
): Uint8Array {
  const value = (v: string | null) => v === null ? tlv(0x81, new Uint8Array()) : encodeOctets(v);
  return sequence(
    encodeInteger(1),
    encodeOctets(community),
    tlv(
      TAG.response,
      concat(
        encodeInteger(requestId),
        encodeInteger(0),
        encodeInteger(0),
        sequence(
          ...bindings.map(([oid, v]) =>
            sequence(encodeOid(oid), oid === OID.sysObjectId && v ? encodeOid(v) : value(v))
          ),
        ),
      ),
    ),
  );
}
