/**
 * Cyber Security hardening baseline and native antivirus (V8). Two typed jobs that only the
 * platform creates for a server with the Advanced plan:
 *
 * - `cyber.security.posture.collect`: a fixed list of CIS-based hardening checks (read-only: files,
 *   kernel parameters, service states, `sshd -T`; Windows: one fixed PowerShell script) and the
 *   state of the native antivirus (Microsoft Defender, ClamAV) with its threats.
 * - `cyber.security.antivirus.run`: one action of a fixed list (`update`, `quick_scan`,
 *   `full_scan`, `install`), then the antivirus state again.
 *
 * Nothing in the payload reaches a command line except the action name, checked against the list.
 * Contract: docs/security-posture.md.
 */
import type { CommandResult, CommandRunner } from "./security-inventory.ts";

export const POSTURE_COMMAND = "cyber.security.posture.collect";
export const ANTIVIRUS_COMMAND = "cyber.security.antivirus.run";
export const POSTURE_CAPABILITY = "cyber.security.posture.v1";
export const ANTIVIRUS_ACTIONS = ["update", "quick_scan", "full_scan", "install"] as const;
export type AntivirusAction = typeof ANTIVIRUS_ACTIONS[number];

/** ClamAV loads its whole signature database in memory (about 1 GB). */
export const CLAMAV_MIN_TOTAL_MEMORY_KB = 1_900_000;
export const CLAMAV_MIN_AVAILABLE_MEMORY_KB = 1_200_000;
export const MAX_THREATS = 200;
const EVIDENCE_LIMIT = 200;
const MESSAGE_LIMIT = 500;
const MINUTE = 60_000;
export const TIMEOUTS = {
  check: 2 * MINUTE,
  windowsPosture: 5 * MINUTE,
  update: 20 * MINUTE,
  install: 30 * MINUTE,
  quickScan: 60 * MINUTE,
  fullScan: 160 * MINUTE,
};
export const QUICK_SCAN_PATHS = [
  "/tmp",
  "/var/tmp",
  "/dev/shm",
  "/home",
  "/root",
  "/var/www",
  "/srv",
  "/usr/local/bin",
];
const FULL_SCAN_EXCLUDES = [
  "^/proc/",
  "^/sys/",
  "^/dev/",
  "^/run/",
  "^/var/lib/clamav/",
  "^/var/lib/docker/overlay2/",
  "^/snap/",
];

export type Severity = "high" | "medium" | "low";
export type CheckStatus = "pass" | "fail" | "not_applicable" | "error";
export type HardeningCheck = {
  code: string;
  benchmark: string;
  severity: Severity;
  status: CheckStatus;
  evidence: string | null;
};
export type AntivirusState = {
  engine: "defender" | "clamav" | "none";
  installed: 0 | 1;
  serviceRunning: 0 | 1;
  realtime: 0 | 1 | null;
  mode: string | null;
  engineVersion: string | null;
  signatureVersion: string | null;
  signatureUpdatedAt: string | null;
  quickScanAt: string | null;
  fullScanAt: string | null;
  installable: 0 | 1;
  note: string | null;
};
export type Threat = {
  key: string;
  engine: "defender" | "clamav";
  name: string;
  severity: string;
  path: string | null;
  status: "active" | "resolved";
  action: string | null;
  detectedAt: string | null;
};
export type ActionResult = {
  action: AntivirusAction;
  outcome: "success" | "partial" | "failed";
  message: string;
  infected?: number;
};
export type PostureResult = {
  posture: 1;
  platform: "linux" | "windows";
  checks?: HardeningCheck[];
  antivirus: AntivirusState;
  threats: Threat[];
  actionResult?: ActionResult;
  durationMs: number;
};

/** Host access, injected so the checks are testable without a real host. */
export type PostureDeps = {
  run: CommandRunner;
  windows: boolean;
  powershell: () => string;
  encode: (script: string) => string;
  readText: (path: string) => Promise<string | null>;
  statMode: (path: string) => Promise<{ mode: number; uid: number } | null>;
  hasCommand: (name: string) => Promise<boolean>;
  writeText: (path: string, text: string) => Promise<void>;
  statePath: string;
  packageManager: () => Promise<"dpkg" | "rpm" | "apk" | "windows" | null>;
  now: () => Date;
};

export class AntivirusRequestError extends Error {}

export function parseAntivirusAction(raw: unknown): AntivirusAction {
  const value = raw && typeof raw === "object" && !Array.isArray(raw)
    ? (raw as Record<string, unknown>).action
    : undefined;
  const action = ANTIVIRUS_ACTIONS.find((item) => item === value);
  if (!action) throw new AntivirusRequestError("Invalid antivirus action");
  return action;
}

function clip(value: unknown, limit = EVIDENCE_LIMIT): string | null {
  if (value === undefined || value === null) return null;
  // deno-lint-ignore no-control-regex
  const text = String(value).split(/[\u0000-\u001f\u007f]+/).join(" ").trim();
  return text ? text.slice(0, limit) : null;
}

function check(
  code: string,
  benchmark: string,
  severity: Severity,
  status: CheckStatus,
  evidence: unknown,
): HardeningCheck {
  return { code, benchmark, severity, status, evidence: clip(evidence) };
}

function passIf(ok: boolean): CheckStatus {
  return ok ? "pass" : "fail";
}

// ---------------------------------------------------------------------------------------------
// Linux facts and checks

export type LinuxFacts = {
  sshd: Map<string, string> | null;
  passwd: string | null;
  shadow: string | null;
  loginDefs: string | null;
  shadowStat: { mode: number; uid: number } | null;
  passwdStat: { mode: number; uid: number } | null;
  sysctl: Record<string, string | null>;
  activeUnits: Set<string>;
  firewall: string | null;
};

export const SYSCTL_KEYS = [
  "kernel.randomize_va_space",
  "fs.suid_dumpable",
  "kernel.dmesg_restrict",
  "net.ipv4.ip_forward",
  "net.ipv4.conf.all.accept_redirects",
  "net.ipv4.conf.all.send_redirects",
  "net.ipv4.conf.all.accept_source_route",
  "net.ipv4.conf.all.rp_filter",
  "net.ipv4.tcp_syncookies",
  "net.ipv6.conf.all.accept_redirects",
];
export const WATCHED_UNITS = [
  "chrony",
  "chronyd",
  "systemd-timesyncd",
  "ntp",
  "ntpd",
  "ntpsec",
  "auditd",
  "ufw",
  "firewalld",
  "clamav-freshclam",
  "clamav-daemon",
  "clamd@scan",
  "clamd",
  "clamav-clamonacc",
  "clamonacc",
];

/** `sshd -T` output: lowercase keyword, a space, the effective value. */
export function parseSshdConfig(text: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of text.split("\n")) {
    const match = /^([a-z0-9]+)\s+(.*)$/.exec(line.trim());
    if (match && !map.has(match[1])) map.set(match[1], match[2].trim().toLowerCase());
  }
  return map;
}

function sshChecks(sshd: Map<string, string> | null): HardeningCheck[] {
  const rules: [string, Severity, string, (value: string) => boolean][] = [
    [
      "ssh.root_login",
      "high",
      "permitrootlogin",
      (v) => ["no", "prohibit-password", "without-password", "forced-commands-only"].includes(v),
    ],
    ["ssh.password_auth", "medium", "passwordauthentication", (v) => v === "no"],
    ["ssh.empty_passwords", "high", "permitemptypasswords", (v) => v === "no"],
    ["ssh.max_auth_tries", "low", "maxauthtries", (v) => Number(v) > 0 && Number(v) <= 4],
    ["ssh.x11_forwarding", "low", "x11forwarding", (v) => v === "no"],
  ];
  return rules.map(([code, severity, key, ok]) => {
    if (!sshd) {
      return check(code, "CIS 5.2", severity, "not_applicable", "OpenSSH server not found");
    }
    const value = sshd.get(key);
    if (value === undefined) {
      return check(code, "CIS 5.2", severity, "error", `${key} not reported`);
    }
    return check(code, "CIS 5.2", severity, passIf(ok(value)), `${key} ${value}`);
  });
}

function accountChecks(facts: LinuxFacts): HardeningCheck[] {
  const out: HardeningCheck[] = [];
  if (facts.passwd === null) {
    out.push(check("accounts.uid0", "CIS 6.2", "high", "error", "/etc/passwd unreadable"));
  } else {
    const uid0 = facts.passwd.split("\n").map((line) => line.split(":"))
      .filter((parts) => parts.length > 3 && parts[2] === "0").map((parts) => parts[0]);
    out.push(
      check(
        "accounts.uid0",
        "CIS 6.2",
        "high",
        passIf(uid0.length === 1 && uid0[0] === "root"),
        uid0.join(", ") || "none",
      ),
    );
  }
  if (facts.shadow === null) {
    out.push(
      check("accounts.empty_password", "CIS 6.2", "high", "error", "/etc/shadow unreadable"),
    );
  } else {
    // Only the account names leave the host, never a hash.
    const empty = facts.shadow.split("\n").map((line) => line.split(":"))
      .filter((parts) => parts.length > 1 && parts[0] && parts[1] === "").map((parts) => parts[0]);
    out.push(
      check(
        "accounts.empty_password",
        "CIS 6.2",
        "high",
        passIf(empty.length === 0),
        empty.length ? empty.join(", ") : "none",
      ),
    );
  }
  const maxDays = /^\s*PASS_MAX_DAYS\s+(\d+)/m.exec(facts.loginDefs ?? "")?.[1];
  out.push(
    maxDays === undefined
      ? check("accounts.pass_max_days", "CIS 5.5", "low", "not_applicable", "PASS_MAX_DAYS not set")
      : check(
        "accounts.pass_max_days",
        "CIS 5.5",
        "low",
        passIf(Number(maxDays) <= 365),
        `PASS_MAX_DAYS ${maxDays}`,
      ),
  );
  return out;
}

function modeText(stat: { mode: number; uid: number }) {
  return `${(stat.mode & 0o7777).toString(8).padStart(4, "0")} uid ${stat.uid}`;
}

function fileChecks(facts: LinuxFacts): HardeningCheck[] {
  const shadow = facts.shadowStat;
  const passwd = facts.passwdStat;
  return [
    shadow
      ? check(
        "files.shadow_permissions",
        "CIS 6.1",
        "high",
        passIf((shadow.mode & 0o037) === 0 && shadow.uid === 0),
        modeText(shadow),
      )
      : check("files.shadow_permissions", "CIS 6.1", "high", "error", "/etc/shadow not found"),
    passwd
      ? check(
        "files.passwd_permissions",
        "CIS 6.1",
        "medium",
        passIf((passwd.mode & 0o133) === 0 && passwd.uid === 0),
        modeText(passwd),
      )
      : check("files.passwd_permissions", "CIS 6.1", "medium", "error", "/etc/passwd not found"),
  ];
}

function sysctlCheck(
  facts: LinuxFacts,
  code: string,
  benchmark: string,
  severity: Severity,
  key: string,
  ok: (value: string) => boolean,
): HardeningCheck {
  const value = facts.sysctl[key];
  if (value === null || value === undefined) {
    return check(code, benchmark, severity, "not_applicable", `${key} not available`);
  }
  return check(code, benchmark, severity, passIf(ok(value)), `${key} = ${value}`);
}

function kernelChecks(facts: LinuxFacts): HardeningCheck[] {
  const routing = facts.sysctl["net.ipv4.ip_forward"] === "1";
  const routed = (code: string, key: string, ok: (value: string) => boolean) =>
    routing
      ? check(
        code,
        "CIS 3.3",
        "low",
        "not_applicable",
        "IP forwarding is on (router or container host)",
      )
      : sysctlCheck(facts, code, "CIS 3.3", "low", key, ok);
  const ipv6Redirects = facts.sysctl["net.ipv6.conf.all.accept_redirects"];
  const redirects = sysctlCheck(
    facts,
    "sysctl.accept_redirects",
    "CIS 3.3",
    "low",
    "net.ipv4.conf.all.accept_redirects",
    (v) =>
      v === "0" &&
      (ipv6Redirects === null || ipv6Redirects === undefined || ipv6Redirects === "0"),
  );
  if (
    redirects.status !== "not_applicable" && ipv6Redirects !== null && ipv6Redirects !== undefined
  ) {
    redirects.evidence =
      `${redirects.evidence}, net.ipv6.conf.all.accept_redirects = ${ipv6Redirects}`;
  }
  return [
    sysctlCheck(
      facts,
      "sysctl.aslr",
      "CIS 1.5",
      "medium",
      "kernel.randomize_va_space",
      (v) => v === "2",
    ),
    sysctlCheck(
      facts,
      "sysctl.suid_dumpable",
      "CIS 1.5",
      "low",
      "fs.suid_dumpable",
      (v) => v === "0",
    ),
    sysctlCheck(
      facts,
      "sysctl.dmesg_restrict",
      "CIS 1.5",
      "low",
      "kernel.dmesg_restrict",
      (v) => v === "1",
    ),
    redirects,
    sysctlCheck(
      facts,
      "sysctl.source_route",
      "CIS 3.3",
      "low",
      "net.ipv4.conf.all.accept_source_route",
      (v) => v === "0",
    ),
    routed("sysctl.send_redirects", "net.ipv4.conf.all.send_redirects", (v) => v === "0"),
    routed("sysctl.rp_filter", "net.ipv4.conf.all.rp_filter", (v) => v === "1" || v === "2"),
    sysctlCheck(
      facts,
      "sysctl.syncookies",
      "CIS 3.3",
      "low",
      "net.ipv4.tcp_syncookies",
      (v) => v === "1",
    ),
  ];
}

function serviceChecks(facts: LinuxFacts): HardeningCheck[] {
  const active = (names: string[]) => names.filter((name) => facts.activeUnits.has(name));
  const time = active(["chrony", "chronyd", "systemd-timesyncd", "ntp", "ntpd", "ntpsec"]);
  return [
    check(
      "firewall.active",
      "CIS 3.5",
      "medium",
      passIf(facts.firewall !== null),
      facts.firewall ?? "no active host firewall",
    ),
    check(
      "time.sync",
      "CIS 2.1",
      "low",
      passIf(time.length > 0),
      time.join(", ") || "no time sync service",
    ),
    check(
      "audit.auditd",
      "CIS 4.1",
      "low",
      passIf(facts.activeUnits.has("auditd")),
      facts.activeUnits.has("auditd") ? "auditd active" : "auditd inactive",
    ),
  ];
}

/** Fixed Linux check list, evaluated from facts already read from the host. */
export function evaluateLinux(facts: LinuxFacts): HardeningCheck[] {
  return [
    ...sshChecks(facts.sshd),
    ...accountChecks(facts),
    ...fileChecks(facts),
    ...kernelChecks(facts),
    ...serviceChecks(facts),
  ];
}

function sysctlPath(key: string) {
  return `/proc/sys/${key.split(".").join("/")}`;
}

/** Active systemd units of the watched list (one `systemctl is-active` call). */
async function activeUnits(deps: PostureDeps): Promise<Set<string>> {
  if (!await deps.hasCommand("systemctl")) return new Set();
  const result = await deps.run("systemctl", ["is-active", ...WATCHED_UNITS], TIMEOUTS.check);
  const states = result.stdout.split("\n").map((line) => line.trim());
  return new Set(WATCHED_UNITS.filter((_, index) => states[index] === "active"));
}

/** nftables or iptables with an input filter, ufw or firewalld: the host has a firewall. */
async function hostFirewall(deps: PostureDeps, units: Set<string>): Promise<string | null> {
  if (units.has("ufw")) return "ufw active";
  if (units.has("firewalld")) return "firewalld active";
  if (await deps.hasCommand("nft")) {
    const result = await deps.run("nft", ["list", "ruleset"], TIMEOUTS.check);
    if (result.code === 0 && /hook\s+input/.test(result.stdout)) return "nftables input hook";
  }
  if (await deps.hasCommand("iptables")) {
    const result = await deps.run("iptables", ["-S", "INPUT"], TIMEOUTS.check);
    const lines = result.stdout.split("\n").filter((line) => line.startsWith("-"));
    if (result.code === 0 && (lines.length > 1 || /-P INPUT DROP/.test(result.stdout))) {
      return "iptables INPUT rules";
    }
  }
  return null;
}

export async function collectLinuxFacts(deps: PostureDeps): Promise<LinuxFacts> {
  let sshd: Map<string, string> | null = null;
  if (await deps.hasCommand("sshd")) {
    const result = await deps.run("sshd", ["-T"], TIMEOUTS.check);
    if (result.code === 0) sshd = parseSshdConfig(result.stdout);
  }
  const sysctl: Record<string, string | null> = {};
  for (const key of SYSCTL_KEYS) {
    sysctl[key] = (await readProc(deps, sysctlPath(key)))?.trim() || null;
  }
  const units = await activeUnits(deps);
  return {
    sshd,
    passwd: await deps.readText("/etc/passwd"),
    shadow: await deps.readText("/etc/shadow"),
    loginDefs: await deps.readText("/etc/login.defs"),
    shadowStat: await deps.statMode("/etc/shadow"),
    passwdStat: await deps.statMode("/etc/passwd"),
    sysctl,
    activeUnits: units,
    firewall: await hostFirewall(deps, units),
  };
}

// ---------------------------------------------------------------------------------------------
// ClamAV (Linux)

type ClamState = {
  quickScanAt: string | null;
  fullScanAt: string | null;
  threats: { name: string; path: string; detectedAt: string }[];
};

export function emptyClamState(): ClamState {
  return { quickScanAt: null, fullScanAt: null, threats: [] };
}

export function parseClamState(text: string | null): ClamState {
  try {
    const value = JSON.parse(text ?? "") as Partial<ClamState>;
    const threats = Array.isArray(value.threats) ? value.threats : [];
    return {
      quickScanAt: typeof value.quickScanAt === "string" ? value.quickScanAt : null,
      fullScanAt: typeof value.fullScanAt === "string" ? value.fullScanAt : null,
      threats: threats.filter((item) =>
        item && typeof item.name === "string" && typeof item.path === "string"
      ).slice(0, MAX_THREATS),
    };
  } catch {
    return emptyClamState();
  }
}

/** `clamscan --version`: "ClamAV 1.0.7/27450/Sat Nov  9 08:21:26 2026" (database part optional). */
export function parseClamVersion(text: string) {
  const match = /ClamAV\s+([^/\s]+)(?:\/(\d+)\/(.+))?/.exec(text.trim());
  if (!match) return { engineVersion: null, signatureVersion: null, signatureUpdatedAt: null };
  const date = match[3] ? new Date(match[3].trim().split(/\s+/).join(" ")) : null;
  return {
    engineVersion: match[1],
    signatureVersion: match[2] ?? null,
    signatureUpdatedAt: date && !Number.isNaN(date.getTime()) ? date.toISOString() : null,
  };
}

/**
 * Reads a /proc file through `cat`: Deno 2 refuses to read /proc without --allow-all, so a direct
 * read returns null on the installed Agent (same path as the status sampler in main.ts).
 */
export async function readProc(deps: PostureDeps, path: string): Promise<string | null> {
  const result = await deps.run("cat", [path], TIMEOUTS.check);
  return result.code === 0 ? result.stdout : null;
}

export function memInfoKb(text: string | null, key: string): number | null {
  const match = new RegExp(`^${key}:\\s+(\\d+)\\s*kB`, "m").exec(text ?? "");
  return match ? Number(match[1]) : null;
}

async function processRunning(deps: PostureDeps, name: string) {
  if (!await deps.hasCommand("pgrep")) return false;
  return (await deps.run("pgrep", ["-x", name], TIMEOUTS.check)).code === 0;
}

export async function clamavState(deps: PostureDeps, state: ClamState, units: Set<string>) {
  const installed = await deps.hasCommand("clamscan");
  const total = memInfoKb(await readProc(deps, "/proc/meminfo"), "MemTotal");
  const enoughMemory = total !== null && total >= CLAMAV_MIN_TOTAL_MEMORY_KB;
  const managers = await deps.packageManager();
  if (!installed) {
    const antivirus: AntivirusState = {
      engine: "none",
      installed: 0,
      serviceRunning: 0,
      realtime: null,
      mode: null,
      engineVersion: null,
      signatureVersion: null,
      signatureUpdatedAt: null,
      quickScanAt: null,
      fullScanAt: null,
      installable: enoughMemory && managers !== null && managers !== "windows" ? 1 : 0,
      note: enoughMemory ? null : "ClamAV needs at least 2 GB of memory",
    };
    return antivirus;
  }
  const version = parseClamVersion(
    (await deps.run("clamscan", ["--version"], TIMEOUTS.check)).stdout,
  );
  const updater = units.has("clamav-freshclam") || await processRunning(deps, "freshclam");
  const onAccess = units.has("clamav-clamonacc") || units.has("clamonacc") ||
    await processRunning(deps, "clamonacc");
  const antivirus: AntivirusState = {
    engine: "clamav",
    installed: 1,
    serviceRunning: updater ? 1 : 0,
    realtime: onAccess ? 1 : 0,
    mode: units.has("clamav-daemon") || units.has("clamd@scan") || units.has("clamd")
      ? "clamd"
      : "on-demand",
    ...version,
    quickScanAt: state.quickScanAt,
    fullScanAt: state.fullScanAt,
    installable: 0,
    note: version.signatureVersion ? null : "The signature database was not downloaded yet",
  };
  return antivirus;
}

export async function threatKey(...parts: string[]) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(parts.join("|")));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function clamThreats(state: ClamState): Promise<Threat[]> {
  const out: Threat[] = [];
  for (const item of state.threats.slice(0, MAX_THREATS)) {
    out.push({
      key: await threatKey("clamav", item.name, item.path),
      engine: "clamav",
      name: item.name.slice(0, 200),
      severity: "unknown",
      path: item.path.slice(0, 500),
      status: "active",
      action: "none",
      detectedAt: item.detectedAt ?? null,
    });
  }
  return out;
}

/** clamscan/clamdscan `--infected` output: "<path>: <signature> FOUND". */
export function parseClamFindings(text: string) {
  const out: { path: string; name: string }[] = [];
  for (const line of text.split("\n")) {
    const match = /^(.+): (.+) FOUND$/.exec(line.trim());
    if (match) out.push({ path: match[1], name: match[2] });
  }
  return out;
}

function underRoot(path: string, roots: string[]) {
  return roots.some((root) => root === "/" || path === root || path.startsWith(`${root}/`));
}

export function mergeScan(
  state: ClamState,
  roots: string[],
  found: { path: string; name: string }[],
  at: string,
  full: boolean,
): ClamState {
  const kept = state.threats.filter((item) => !underRoot(item.path, roots));
  const seen = found.map((item) => ({
    ...item,
    detectedAt:
      state.threats.find((old) => old.path === item.path && old.name === item.name)?.detectedAt ??
        at,
  }));
  return {
    quickScanAt: full ? state.quickScanAt : at,
    fullScanAt: full ? at : state.fullScanAt,
    threats: [...seen, ...kept].slice(0, MAX_THREATS),
  };
}

function lowPriority(command: string, args: string[], tools: { nice: boolean; ionice: boolean }) {
  let vector = [command, ...args];
  if (tools.ionice) vector = ["ionice", "-c", "3", ...vector];
  if (tools.nice) vector = ["nice", "-n", "19", ...vector];
  return { command: vector[0], args: vector.slice(1) };
}

function failure(result: CommandResult, label: string) {
  const detail = clip(result.stderr || result.stdout, 300);
  return detail ? `${label} failed: ${detail}` : `${label} failed (exit ${result.code})`;
}

async function existingRoots(deps: PostureDeps, roots: string[]) {
  const out: string[] = [];
  for (const root of roots) if (await deps.statMode(root)) out.push(root);
  return out;
}

async function clamScan(
  deps: PostureDeps,
  state: ClamState,
  full: boolean,
): Promise<{ state: ClamState; result: ActionResult }> {
  const action: AntivirusAction = full ? "full_scan" : "quick_scan";
  const units = await activeUnits(deps);
  const daemon = (units.has("clamav-daemon") || units.has("clamd@scan") || units.has("clamd")) &&
    await deps.hasCommand("clamdscan");
  if (!daemon) {
    const available = memInfoKb(await readProc(deps, "/proc/meminfo"), "MemAvailable");
    if (available === null || available < CLAMAV_MIN_AVAILABLE_MEMORY_KB) {
      return {
        state,
        result: {
          action,
          outcome: "failed",
          message: "Not enough free memory for a ClamAV scan (needs about 1.2 GB)",
        },
      };
    }
  }
  const roots = full ? ["/"] : await existingRoots(deps, QUICK_SCAN_PATHS);
  const args = daemon ? ["--multiscan", "--fdpass", "--infected", "--no-summary", ...roots] : [
    "-r",
    "--infected",
    "--no-summary",
    "--stdout",
    "--max-filesize=100M",
    "--max-scansize=200M",
    ...(full ? FULL_SCAN_EXCLUDES.map((dir) => `--exclude-dir=${dir}`) : []),
    ...roots,
  ];
  const tools = { nice: await deps.hasCommand("nice"), ionice: await deps.hasCommand("ionice") };
  const step = lowPriority(daemon ? "clamdscan" : "clamscan", args, tools);
  const result = await deps.run(
    step.command,
    step.args,
    full ? TIMEOUTS.fullScan : TIMEOUTS.quickScan,
  );
  const found = parseClamFindings(result.stdout);
  // Exit 0 = clean, 1 = infected files, 2 = errors (some files unreadable or the scan stopped).
  if (result.code !== 0 && result.code !== 1 && found.length === 0 && !result.stdout.trim()) {
    return {
      state,
      result: { action, outcome: "failed", message: failure(result, "ClamAV scan") },
    };
  }
  const next = mergeScan(state, roots, found, deps.now().toISOString(), full);
  await deps.writeText(deps.statePath, JSON.stringify(next));
  const outcome = result.code === 0 || result.code === 1 ? "success" : "partial";
  const message = found.length ? `${found.length} infected file(s) found` : "No threats found";
  return {
    state: next,
    result: {
      action,
      outcome,
      message: outcome === "partial" ? `${message}; some files could not be scanned` : message,
      infected: found.length,
    },
  };
}

async function clamUpdate(deps: PostureDeps): Promise<ActionResult> {
  const units = await activeUnits(deps);
  const service = units.has("clamav-freshclam");
  if (service) await deps.run("systemctl", ["stop", "clamav-freshclam"], TIMEOUTS.check);
  const result = await deps.run("freshclam", ["--stdout"], TIMEOUTS.update);
  if (service) await deps.run("systemctl", ["start", "clamav-freshclam"], TIMEOUTS.check);
  // freshclam: 0 = updated, 1 = already up to date.
  if (result.code === 0 || result.code === 1) {
    return {
      action: "update",
      outcome: "success",
      message: result.code === 1 ? "Signatures already up to date" : "Signatures updated",
    };
  }
  return { action: "update", outcome: "failed", message: failure(result, "freshclam") };
}

export function clamInstallSteps(manager: "dpkg" | "rpm" | "apk") {
  if (manager === "dpkg") {
    return [
      {
        label: "apt-get update",
        command: "env",
        args: ["DEBIAN_FRONTEND=noninteractive", "apt-get", "update"],
      },
      {
        label: "apt-get install",
        command: "env",
        args: [
          "DEBIAN_FRONTEND=noninteractive",
          "apt-get",
          "install",
          "-y",
          "--no-install-recommends",
          "clamav",
          "clamav-freshclam",
        ],
      },
    ];
  }
  if (manager === "rpm") {
    return [
      { label: "dnf install", command: "dnf", args: ["-y", "install", "clamav", "clamav-update"] },
      { label: "freshclam", command: "freshclam", args: ["--stdout"] },
    ];
  }
  return [
    { label: "apk add", command: "apk", args: ["add", "clamav-scanner", "freshclam"] },
    { label: "freshclam", command: "freshclam", args: ["--stdout"] },
  ];
}

async function clamInstall(deps: PostureDeps): Promise<ActionResult> {
  if (await deps.hasCommand("clamscan")) {
    return { action: "install", outcome: "success", message: "ClamAV is already installed" };
  }
  const total = memInfoKb(await readProc(deps, "/proc/meminfo"), "MemTotal");
  if (total === null || total < CLAMAV_MIN_TOTAL_MEMORY_KB) {
    return {
      action: "install",
      outcome: "failed",
      message: "ClamAV needs a server with at least 2 GB of memory",
    };
  }
  const manager = await deps.packageManager();
  if (manager === null || manager === "windows") {
    return {
      action: "install",
      outcome: "failed",
      message: "No supported package manager on this host",
    };
  }
  if (manager === "rpm" && !await deps.hasCommand("dnf")) {
    return {
      action: "install",
      outcome: "failed",
      message: "Installing ClamAV needs dnf (with EPEL on RHEL)",
    };
  }
  for (const step of clamInstallSteps(manager)) {
    const result = await deps.run(step.command, step.args, TIMEOUTS.install);
    // freshclam exit 1 = already up to date.
    if (result.code !== 0 && !(step.command === "freshclam" && result.code === 1)) {
      return { action: "install", outcome: "failed", message: failure(result, step.label) };
    }
  }
  // Packages do not always start the updater (dnf never does; Debian skips it under a
  // policy-rc.d), so enable it explicitly: without it no signatures are ever downloaded.
  if (manager !== "apk" && await deps.hasCommand("systemctl")) {
    await deps.run("systemctl", ["enable", "--now", "clamav-freshclam"], TIMEOUTS.check);
  }
  return {
    action: "install",
    outcome: "success",
    message: "ClamAV installed; signatures are downloading",
  };
}

// ---------------------------------------------------------------------------------------------
// Windows (one fixed PowerShell script for checks, Defender state and threats)

export const WINDOWS_POSTURE_SCRIPT = [
  "$ErrorActionPreference = 'SilentlyContinue'",
  "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
  "function Utc($d) { if ($d -and ([datetime]$d).Year -gt 2000) { ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }",
  "function Reg($path, $name) { $item = Get-ItemProperty -Path $path -Name $name; if ($null -eq $item) { $null } else { $item.$name } }",
  "$cv = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'",
  "$fw = @(Get-NetFirewallProfile | ForEach-Object { [ordered]@{ name = [string]$_.Name; enabled = [bool]$_.Enabled } })",
  "$smb = Get-SmbServerConfiguration",
  "$guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' } | Select-Object -First 1",
  "$cfg = Join-Path $env:TEMP ('mns-secpol-' + [guid]::NewGuid().ToString() + '.inf')",
  "secedit /export /cfg $cfg /areas SECURITYPOLICY | Out-Null",
  "$policy = @{}",
  "if (Test-Path $cfg) { foreach ($line in Get-Content $cfg) { if ($line -match '^\\s*(\\w+)\\s*=\\s*(.+)$') { $policy[$Matches[1]] = $Matches[2].Trim() } }; Remove-Item $cfg -Force }",
  "$facts = [ordered]@{",
  "  build = [int]$cv.CurrentBuild",
  "  firewall = $fw",
  "  smb1 = $(if ($smb) { [bool]$smb.EnableSMB1Protocol } else { $null })",
  "  smbSigning = $(if ($smb) { [bool]$smb.RequireSecuritySignature } else { $null })",
  "  rdpDenied = Reg 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' 'fDenyTSConnections'",
  "  rdpNla = Reg 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' 'UserAuthentication'",
  "  guestEnabled = $(if ($guest) { [bool]$guest.Enabled } else { $null })",
  "  minPasswordLength = $policy['MinimumPasswordLength']",
  "  passwordComplexity = $policy['PasswordComplexity']",
  "  lockoutThreshold = $policy['LockoutBadCount']",
  "  enableLua = Reg 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' 'EnableLUA'",
  "  llmnr = Reg 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' 'EnableMulticast'",
  "  autorun = Reg 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' 'NoDriveTypeAutoRun'",
  "  wuauserv = [string](Get-Service -Name wuauserv).StartType",
  "  tls10 = Reg 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' 'Enabled'",
  "  runAsPpl = Reg 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' 'RunAsPPL'",
  "  wdigest = Reg 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' 'UseLogonCredential'",
  "}",
  "$defender = $null",
  "$threats = @()",
  "if (Get-Command Get-MpComputerStatus) {",
  "  $mp = Get-MpComputerStatus",
  "  if ($mp) {",
  "    $defender = [ordered]@{ serviceEnabled = [bool]$mp.AMServiceEnabled; antivirusEnabled = [bool]$mp.AntivirusEnabled; realtime = [bool]$mp.RealTimeProtectionEnabled; mode = [string]$mp.AMRunningMode; engineVersion = [string]$mp.AMEngineVersion; signatureVersion = [string]$mp.AntivirusSignatureVersion; signatureUpdatedAt = Utc $mp.AntivirusSignatureLastUpdated; quickScanAt = Utc $mp.QuickScanEndTime; fullScanAt = Utc $mp.FullScanEndTime }",
  "    $names = @{}",
  "    foreach ($t in @(Get-MpThreat)) { $names[[string]$t.ThreatID] = @{ name = [string]$t.ThreatName; severity = [int]$t.SeverityID } }",
  "    $threats = @(Get-MpThreatDetection | Sort-Object InitialDetectionTime -Descending | Select-Object -First 200 | ForEach-Object { $n = $names[[string]$_.ThreatID]; [ordered]@{ id = [string]$_.ThreatID; name = $(if ($n) { $n.name } else { 'Threat ' + [string]$_.ThreatID }); severity = $(if ($n) { $n.severity } else { 0 }); statusId = [int]$_.ThreatStatusID; path = [string](@($_.Resources) | Select-Object -First 1); detectedAt = Utc $_.InitialDetectionTime } })",
  "  }",
  "}",
  "ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{ facts = $facts; defender = $defender; threats = $threats })",
].join("\n");

export type WindowsFacts = Record<string, unknown> & {
  firewall?: { name: string; enabled: boolean }[];
};

function windowsValue(facts: WindowsFacts, key: string): string | null {
  const value = facts[key];
  return value === null || value === undefined || value === "" ? null : String(value);
}

function registryCheck(
  facts: WindowsFacts,
  code: string,
  benchmark: string,
  severity: Severity,
  key: string,
  ok: (value: string | null) => boolean,
  label: string,
): HardeningCheck {
  const value = windowsValue(facts, key);
  return check(code, benchmark, severity, passIf(ok(value)), `${label} ${value ?? "not set"}`);
}

function windowsAccessChecks(facts: WindowsFacts): HardeningCheck[] {
  const profiles = Array.isArray(facts.firewall) ? facts.firewall : [];
  const off = profiles.filter((profile) => !profile.enabled).map((profile) => profile.name);
  const rdpOff = windowsValue(facts, "rdpDenied") === "1";
  return [
    profiles.length
      ? check(
        "win.firewall_profiles",
        "CIS 9",
        "high",
        passIf(off.length === 0),
        off.length ? `off: ${off.join(", ")}` : "all profiles on",
      )
      : check("win.firewall_profiles", "CIS 9", "high", "error", "firewall profiles not reported"),
    windowsValue(facts, "smb1") === null
      ? check("win.smb1_disabled", "CIS 18.4", "high", "not_applicable", "SMB server not available")
      : check(
        "win.smb1_disabled",
        "CIS 18.4",
        "high",
        passIf(windowsValue(facts, "smb1") === "false"),
        `SMB1 ${windowsValue(facts, "smb1")}`,
      ),
    windowsValue(facts, "smbSigning") === null
      ? check(
        "win.smb_signing",
        "CIS 2.3.9",
        "medium",
        "not_applicable",
        "SMB server not available",
      )
      : check(
        "win.smb_signing",
        "CIS 2.3.9",
        "medium",
        passIf(windowsValue(facts, "smbSigning") === "true"),
        `signing required ${windowsValue(facts, "smbSigning")}`,
      ),
    rdpOff
      ? check("win.rdp_nla", "CIS 18.10", "high", "not_applicable", "Remote Desktop is off")
      : registryCheck(facts, "win.rdp_nla", "CIS 18.10", "high", "rdpNla", (v) =>
        v === "1", "UserAuthentication"),
    windowsValue(facts, "guestEnabled") === null
      ? check("win.guest_disabled", "CIS 2.3.1", "medium", "not_applicable", "no Guest account")
      : check(
        "win.guest_disabled",
        "CIS 2.3.1",
        "medium",
        passIf(windowsValue(facts, "guestEnabled") === "false"),
        `Guest enabled ${windowsValue(facts, "guestEnabled")}`,
      ),
  ];
}

function windowsPolicyChecks(facts: WindowsFacts): HardeningCheck[] {
  const number = (value: string | null) => value === null ? Number.NaN : Number(value);
  return [
    registryCheck(
      facts,
      "win.password_length",
      "CIS 1.1",
      "medium",
      "minPasswordLength",
      (v) => number(v) >= 14,
      "MinimumPasswordLength",
    ),
    registryCheck(
      facts,
      "win.password_complexity",
      "CIS 1.1",
      "medium",
      "passwordComplexity",
      (v) => v === "1",
      "PasswordComplexity",
    ),
    registryCheck(
      facts,
      "win.lockout_threshold",
      "CIS 1.2",
      "medium",
      "lockoutThreshold",
      (v) => number(v) >= 1 && number(v) <= 5,
      "LockoutBadCount",
    ),
    registryCheck(
      facts,
      "win.uac_enabled",
      "CIS 2.3.17",
      "high",
      "enableLua",
      (v) => v === "1",
      "EnableLUA",
    ),
    registryCheck(
      facts,
      "win.llmnr_disabled",
      "CIS 18.6",
      "low",
      "llmnr",
      (v) => v === "0",
      "EnableMulticast",
    ),
    registryCheck(
      facts,
      "win.autorun_disabled",
      "CIS 18.10",
      "low",
      "autorun",
      (v) => v === "255",
      "NoDriveTypeAutoRun",
    ),
    registryCheck(
      facts,
      "win.update_service",
      "CIS 18.10",
      "medium",
      "wuauserv",
      (v) => v !== null && v !== "Disabled",
      "wuauserv",
    ),
    registryCheck(
      facts,
      "win.tls10_disabled",
      "CIS 18.4",
      "low",
      "tls10",
      // Windows 11 24H2 / Server 2025 (build 26100) turned TLS 1.0 off by default.
      (v) => v === "0" || (v === null && number(windowsValue(facts, "build")) >= 26100),
      "TLS 1.0 server Enabled",
    ),
    registryCheck(
      facts,
      "win.lsa_protection",
      "CIS 18.4",
      "low",
      "runAsPpl",
      (v) => v === "1" || v === "2",
      "RunAsPPL",
    ),
    registryCheck(
      facts,
      "win.wdigest_disabled",
      "CIS 18.4",
      "medium",
      "wdigest",
      (v) => v === null || v === "0",
      "UseLogonCredential",
    ),
  ];
}

export function evaluateWindows(facts: WindowsFacts): HardeningCheck[] {
  return [...windowsAccessChecks(facts), ...windowsPolicyChecks(facts)];
}

const DEFENDER_ACTIVE_STATUS = new Set([0, 1, 102, 103, 104, 105, 107]);
const DEFENDER_ACTION: Record<number, string> = {
  1: "none",
  2: "cleaned",
  3: "quarantined",
  4: "removed",
  5: "allowed",
  6: "blocked",
};
const DEFENDER_SEVERITY: Record<number, string> = { 1: "low", 2: "medium", 4: "high", 5: "severe" };

function text(value: unknown, limit = 200) {
  return clip(value, limit);
}

export function defenderState(raw: Record<string, unknown> | null): AntivirusState {
  if (!raw) {
    return {
      engine: "none",
      installed: 0,
      serviceRunning: 0,
      realtime: null,
      mode: null,
      engineVersion: null,
      signatureVersion: null,
      signatureUpdatedAt: null,
      quickScanAt: null,
      fullScanAt: null,
      installable: 0,
      note: "Microsoft Defender is not available on this server",
    };
  }
  const passive = /passive/i.test(String(raw.mode ?? ""));
  return {
    engine: "defender",
    installed: 1,
    serviceRunning: raw.serviceEnabled === true ? 1 : 0,
    realtime: raw.realtime === true ? 1 : 0,
    mode: text(raw.mode, 40),
    engineVersion: text(raw.engineVersion, 80),
    signatureVersion: text(raw.signatureVersion, 80),
    signatureUpdatedAt: text(raw.signatureUpdatedAt, 40),
    quickScanAt: text(raw.quickScanAt, 40),
    fullScanAt: text(raw.fullScanAt, 40),
    installable: 0,
    note: passive ? "Microsoft Defender is in passive mode (another antivirus is active)" : null,
  };
}

export async function defenderThreats(raw: unknown): Promise<Threat[]> {
  const items = Array.isArray(raw) ? raw : raw && typeof raw === "object" ? [raw] : [];
  const out: Threat[] = [];
  for (const item of items.slice(0, MAX_THREATS) as Record<string, unknown>[]) {
    const statusId = Number(item.statusId ?? 0);
    const name = text(item.name) ?? "Threat";
    const path = text(String(item.path ?? "").replace(/^\w+:_/, ""), 500);
    const detectedAt = text(item.detectedAt, 40);
    out.push({
      key: await threatKey("defender", String(item.id ?? ""), detectedAt ?? "", path ?? ""),
      engine: "defender",
      name,
      severity: DEFENDER_SEVERITY[Number(item.severity ?? 0)] ?? "unknown",
      path,
      status: DEFENDER_ACTIVE_STATUS.has(statusId) ? "active" : "resolved",
      action: DEFENDER_ACTION[statusId] ?? (statusId >= 100 ? "failed" : "none"),
      detectedAt,
    });
  }
  return out;
}

async function powershell(deps: PostureDeps, script: string, timeoutMs: number) {
  return await deps.run(deps.powershell(), [
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy",
    "Bypass",
    "-EncodedCommand",
    deps.encode(script),
  ], timeoutMs);
}

async function windowsPosture(deps: PostureDeps) {
  const result = await powershell(deps, WINDOWS_POSTURE_SCRIPT, TIMEOUTS.windowsPosture);
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(result.stdout.trim().split("\n").pop() ?? "") as Record<string, unknown>;
  } catch {
    throw new Error(failure(result, "Windows posture script"));
  }
  const facts =
    (parsed.facts && typeof parsed.facts === "object" ? parsed.facts : {}) as WindowsFacts;
  if (facts.firewall && !Array.isArray(facts.firewall)) facts.firewall = [facts.firewall];
  const defender = parsed.defender && typeof parsed.defender === "object"
    ? parsed.defender as Record<string, unknown>
    : null;
  return {
    checks: evaluateWindows(facts),
    antivirus: defenderState(defender),
    threats: await defenderThreats(parsed.threats),
  };
}

export const WINDOWS_ACTION_SCRIPTS: Record<Exclude<AntivirusAction, "install">, string> = {
  update: "$ErrorActionPreference = 'Stop'; Update-MpSignature",
  quick_scan: "$ErrorActionPreference = 'Stop'; Start-MpScan -ScanType QuickScan",
  full_scan: "$ErrorActionPreference = 'Stop'; Start-MpScan -ScanType FullScan",
};

async function windowsAction(deps: PostureDeps, action: AntivirusAction): Promise<ActionResult> {
  if (action === "install") {
    return {
      action,
      outcome: "failed",
      message: "Windows servers use Microsoft Defender; ClamAV is installed only on Linux",
    };
  }
  const timeout = action === "update"
    ? TIMEOUTS.update
    : action === "quick_scan"
    ? TIMEOUTS.quickScan
    : TIMEOUTS.fullScan;
  const result = await powershell(deps, WINDOWS_ACTION_SCRIPTS[action], timeout);
  if (result.code !== 0) {
    return { action, outcome: "failed", message: failure(result, "Microsoft Defender") };
  }
  const labels = {
    update: "Signatures updated",
    quick_scan: "Quick scan finished",
    full_scan: "Full scan finished",
  };
  return { action, outcome: "success", message: labels[action] };
}

// ---------------------------------------------------------------------------------------------
// Jobs

async function linuxAntivirus(deps: PostureDeps, state: ClamState) {
  const units = await activeUnits(deps);
  return { antivirus: await clamavState(deps, state, units), threats: await clamThreats(state) };
}

/** `cyber.security.posture.collect`: checks + antivirus state + threats. */
export async function collectPosture(deps: PostureDeps): Promise<PostureResult> {
  const started = deps.now().getTime();
  if (deps.windows) {
    const windows = await windowsPosture(deps);
    return {
      posture: 1,
      platform: "windows",
      ...windows,
      durationMs: deps.now().getTime() - started,
    };
  }
  const checks = evaluateLinux(await collectLinuxFacts(deps));
  const state = parseClamState(await deps.readText(deps.statePath));
  return {
    posture: 1,
    platform: "linux",
    checks,
    ...await linuxAntivirus(deps, state),
    durationMs: deps.now().getTime() - started,
  };
}

/** `cyber.security.antivirus.run`: one action, then the antivirus state (the checks are kept). */
export async function runAntivirusAction(
  deps: PostureDeps,
  action: AntivirusAction,
): Promise<PostureResult> {
  const started = deps.now().getTime();
  if (deps.windows) {
    const actionResult = await windowsAction(deps, action);
    const windows = await windowsPosture(deps);
    return {
      posture: 1,
      platform: "windows",
      antivirus: windows.antivirus,
      threats: windows.threats,
      actionResult,
      durationMs: deps.now().getTime() - started,
    };
  }
  let state = parseClamState(await deps.readText(deps.statePath));
  let actionResult: ActionResult;
  if (action === "install") {
    actionResult = await clamInstall(deps);
  } else if (!await deps.hasCommand("clamscan")) {
    actionResult = { action, outcome: "failed", message: "ClamAV is not installed on this server" };
  } else if (action === "update") {
    actionResult = await clamUpdate(deps);
  } else {
    const scan = await clamScan(deps, state, action === "full_scan");
    state = scan.state;
    actionResult = scan.result;
  }
  actionResult = { ...actionResult, message: actionResult.message.slice(0, MESSAGE_LIMIT) };
  return {
    posture: 1,
    platform: "linux",
    ...await linuxAntivirus(deps, state),
    actionResult,
    durationMs: deps.now().getTime() - started,
  };
}
