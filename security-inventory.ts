// Cyber Security software inventory, "Essential" profile (read-only).
//
// The Agent collects the operating system, installed packages (or Windows programs and KBs),
// listening ports and the reboot-pending flag at most once per 24 h (+ jitter) and when the package
// database changes. It never collects users, files or content. Collector commands are fixed
// argument vectors run under a resource cap (Linux `mnscloud-security.slice`, Windows Idle
// priority); their output is parsed, never executed. The heartbeat carries only the inventory hash;
// the full inventory goes to `POST /agent/inventory` only when the platform asks for it.

export const SECURITY_SLICE = "mnscloud-security.slice";
export const SECURITY_SLICE_FILE = `/etc/systemd/system/${SECURITY_SLICE}`;
// systemd nests a dashed slice under its prefix: mnscloud.slice/mnscloud-security.slice (cgroup v2).
export const SECURITY_SLICE_CGROUP = `/sys/fs/cgroup/mnscloud.slice/${SECURITY_SLICE}`;
export const INVENTORY_PATH = "/agent/inventory";
export const INVENTORY_CACHE_FILE = "security-inventory.json";

export const LIMITS = {
  packages: 20000,
  hotfixes: 2000,
  ports: 2000,
  name: 255,
  version: 128,
  arch: 32,
  source: 255,
  process: 128,
  payloadBytes: 4 * 1024 * 1024,
} as const;

export const COMMAND_TIMEOUT_MS = 120_000;
export const COLLECTION_TIMEOUT_MS = 10 * 60_000;
export const FULL_INTERVAL_MS = 24 * 60 * 60_000;
export const JITTER_MS = 60 * 60_000;
export const FIRST_DELAY_MS = 10 * 60_000;
/** A package database change triggers a collection only after it settled and spaced from the last attempt. */
export const PACKAGE_SETTLE_MS = 2 * 60_000;
export const PACKAGE_MIN_SPACING_MS = 10 * 60_000;
/** The API accepts one full inventory per Agent every 5 minutes. */
export const UPLOAD_MIN_SPACING_MS = 5 * 60_000;

/** Package databases whose change triggers a new collection (Linux). */
export const PACKAGE_DB_PATHS = [
  "/var/lib/dpkg/status",
  "/var/lib/rpm/rpmdb.sqlite",
  "/var/lib/rpm/Packages",
  "/usr/lib/sysimage/rpm/rpmdb.sqlite",
  "/lib/apk/db/installed",
];

export type InventoryOs = {
  family: "linux" | "windows";
  id: string | null;
  versionId: string | null;
  codename: string | null;
  name: string | null;
  kernel: string | null;
  arch: string | null;
  build: string | null;
  ubr: string | null;
  displayVersion: string | null;
};

export type PackageManager = "dpkg" | "rpm" | "apk" | "windows";

export type InventoryPackage = {
  name: string;
  version: string;
  arch: string | null;
  source: string | null;
};

export type InventoryPort = {
  protocol: "tcp" | "udp";
  address: string;
  port: number;
  process: string | null;
};

export type InventoryCore = {
  os: InventoryOs;
  packageManager: PackageManager | null;
  packages: InventoryPackage[];
  hotfixes: string[];
  ports: InventoryPort[];
  rebootRequired: boolean | null;
};

export type InventoryFootprint = {
  durationMs: number;
  cpuMs: number | null;
  memoryPeakBytes: number | null;
  payloadBytes: number;
};

export type InventoryPayload = InventoryCore & {
  hash: string;
  collectedAt: string;
  truncated: boolean;
  footprint: InventoryFootprint;
};

export type CommandResult = { code: number; stdout: string; stderr: string };
export type CommandRunner = (
  command: string,
  args: string[],
  timeoutMs: number,
) => Promise<CommandResult>;

// ---------------------------------------------------------------------------------------------
// Normalization

// deno-lint-ignore no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/g;

/** Trimmed text without control characters; null when empty. */
export function cleanText(value: unknown, limit: number): string | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const text = String(value).replace(CONTROL_CHARS, "").trim();
  if (!text) return null;
  return text.length > limit ? text.slice(0, limit).trim() : text;
}

/** Name and version must fit whole: a cut version would match the wrong release. */
function exactText(value: unknown, limit: number): string | null {
  const text = cleanText(value, Number.MAX_SAFE_INTEGER);
  return text && text.length <= limit ? text : null;
}

export function makePackage(
  name: unknown,
  version: unknown,
  arch: unknown,
  source: unknown,
): InventoryPackage | null {
  const cleanName = exactText(name, LIMITS.name);
  const cleanVersion = exactText(version, LIMITS.version);
  if (!cleanName || !cleanVersion) return null;
  return {
    name: cleanName,
    version: cleanVersion,
    arch: cleanText(arch, LIMITS.arch),
    source: cleanText(source, LIMITS.source),
  };
}

function compareText(a: string | null, b: string | null) {
  const left = a ?? "";
  const right = b ?? "";
  return left < right ? -1 : left > right ? 1 : 0;
}

function comparePackages(a: InventoryPackage, b: InventoryPackage) {
  return compareText(a.name, b.name) || compareText(a.version, b.version) ||
    compareText(a.arch, b.arch) || compareText(a.source, b.source);
}

function comparePorts(a: InventoryPort, b: InventoryPort) {
  return compareText(a.protocol, b.protocol) || compareText(a.address, b.address) ||
    a.port - b.port || compareText(a.process, b.process);
}

function sortedUnique<T>(items: T[], key: (item: T) => string, compare: (a: T, b: T) => number) {
  const unique = new Map<string, T>();
  for (const item of items) {
    const itemKey = key(item);
    if (!unique.has(itemKey)) unique.set(itemKey, item);
  }
  return [...unique.values()].sort(compare);
}

/** Sorted, deduplicated and capped inventory with the exact key order of the canonical hash. */
export function canonicalInventory(
  core: InventoryCore,
): { core: InventoryCore; truncated: boolean } {
  const packages = sortedUnique(
    core.packages,
    (item) => `${item.name}\u0000${item.version}\u0000${item.arch ?? ""}`,
    comparePackages,
  );
  const hotfixes = [...new Set(core.hotfixes)].sort((a, b) => compareText(a, b));
  const ports = sortedUnique(
    core.ports,
    (item) => `${item.protocol}\u0000${item.address}\u0000${item.port}\u0000${item.process ?? ""}`,
    comparePorts,
  );
  const truncated = packages.length > LIMITS.packages || hotfixes.length > LIMITS.hotfixes ||
    ports.length > LIMITS.ports;
  const os = core.os;
  return {
    truncated,
    core: {
      os: {
        family: os.family,
        id: os.id,
        versionId: os.versionId,
        codename: os.codename,
        name: os.name,
        kernel: os.kernel,
        arch: os.arch,
        build: os.build,
        ubr: os.ubr,
        displayVersion: os.displayVersion,
      },
      packageManager: core.packageManager,
      packages: packages.slice(0, LIMITS.packages).map((item) => ({
        name: item.name,
        version: item.version,
        arch: item.arch,
        source: item.source,
      })),
      hotfixes: hotfixes.slice(0, LIMITS.hotfixes),
      ports: ports.slice(0, LIMITS.ports).map((item) => ({
        protocol: item.protocol,
        address: item.address,
        port: item.port,
        process: item.process,
      })),
      rebootRequired: core.rebootRequired,
    },
  };
}

/** sha256 hex of JSON.stringify({os, packageManager, packages, hotfixes, ports, rebootRequired}). */
export async function inventoryHash(canonical: InventoryCore): Promise<string> {
  const text = JSON.stringify({
    os: canonical.os,
    packageManager: canonical.packageManager,
    packages: canonical.packages,
    hotfixes: canonical.hotfixes,
    ports: canonical.ports,
    rebootRequired: canonical.rebootRequired,
  });
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------------------------
// Linux parsers

export function parseOsRelease(text: string) {
  const values = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!match) continue;
    let value = match[2];
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1).replace(/\\(["$`\\])/g, "$1");
    }
    values.set(match[1], value);
  }
  return {
    id: cleanText(values.get("ID")?.toLowerCase(), 64),
    versionId: cleanText(values.get("VERSION_ID"), 64),
    codename: cleanText(values.get("VERSION_CODENAME") || values.get("UBUNTU_CODENAME"), 64),
    name: cleanText(values.get("PRETTY_NAME") || values.get("NAME"), 255),
  };
}

/** `dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\n'` */
export function parseDpkg(text: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  for (const line of text.split("\n")) {
    const fields = line.split("\t");
    if (fields.length < 4 || !fields[0].startsWith("ii")) continue;
    const item = makePackage(fields[1], fields[2], fields[3], fields[4]);
    if (item) packages.push(item);
  }
  return packages;
}

/** `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n'` */
export function parseRpm(text: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  const none = (value: string | undefined) => value === "(none)" ? null : value;
  for (const line of text.split("\n")) {
    const fields = line.split("\t");
    if (fields.length < 3 || fields[0].trim() === "gpg-pubkey") continue;
    const item = makePackage(fields[0], fields[1], none(fields[2]), none(fields[3]));
    if (item) packages.push(item);
  }
  return packages;
}

/** `/lib/apk/db/installed`: blank-line separated records with P (name), V, A and o (origin). */
export function parseApk(text: string): InventoryPackage[] {
  const packages: InventoryPackage[] = [];
  for (const block of text.split(/\n\s*\n/)) {
    const fields = new Map<string, string>();
    for (const line of block.split("\n")) {
      const match = line.match(/^([A-Za-z]):(.*)$/);
      if (match && !fields.has(match[1])) fields.set(match[1], match[2]);
    }
    const item = makePackage(fields.get("P"), fields.get("V"), fields.get("A"), fields.get("o"));
    if (item) packages.push(item);
  }
  return packages;
}

function splitAddressPort(value: string): { address: string; port: number } | null {
  const index = value.lastIndexOf(":");
  if (index <= 0) return null;
  const portText = value.slice(index + 1);
  if (!/^\d{1,5}$/.test(portText)) return null;
  const port = Number(portText);
  if (port > 65535) return null;
  let address = value.slice(0, index);
  if (address.startsWith("[") && address.endsWith("]")) address = address.slice(1, -1);
  address = address.replace(/%.*$/, "");
  const clean = cleanText(address, 64);
  return clean ? { address: clean, port } : null;
}

/** `ss -H -tulpn`: Netid State Recv-Q Send-Q Local:Port Peer:Port [users:(("name",pid=..,fd=..))] */
export function parseSs(text: string): InventoryPort[] {
  const ports: InventoryPort[] = [];
  for (const line of text.split("\n")) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 5) continue;
    const protocol = fields[0].toLowerCase();
    if (protocol !== "tcp" && protocol !== "udp") continue;
    const local = splitAddressPort(fields[4]);
    if (!local) continue;
    const process = line.match(/users:\(\("((?:[^"\\]|\\.)*)"/)?.[1] ?? null;
    ports.push({
      protocol,
      address: local.address,
      port: local.port,
      process: cleanText(process, LIMITS.process),
    });
  }
  return ports;
}

// ---------------------------------------------------------------------------------------------
// Windows

/** Fixed collector script (no external input). Runs at Idle priority and prints one JSON object. */
export const WINDOWS_INVENTORY_SCRIPT = [
  "$ErrorActionPreference = 'SilentlyContinue'",
  "try { [System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'Idle' } catch {}",
  "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
  "$cv = Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'",
  "$os = [ordered]@{ productName = [string]$cv.ProductName; displayVersion = [string]$cv.DisplayVersion; releaseId = [string]$cv.ReleaseId; currentBuild = [string]$cv.CurrentBuild; ubr = [string]$cv.UBR; installationType = [string]$cv.InstallationType; arch = [string]$env:PROCESSOR_ARCHITECTURE }",
  "$nativeArch = if ([Environment]::Is64BitOperatingSystem) { 'x64' } else { 'x86' }",
  "$programs = New-Object System.Collections.ArrayList",
  "$views = @(@{ path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; arch = $nativeArch }, @{ path = 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'; arch = 'x86' })",
  "foreach ($view in $views) { foreach ($entry in @(Get-ItemProperty -Path $view.path)) { if (-not $entry.DisplayName) { continue }; if ($entry.SystemComponent -eq 1) { continue }; [void]$programs.Add([ordered]@{ name = [string]$entry.DisplayName; version = [string]$entry.DisplayVersion; publisher = [string]$entry.Publisher; arch = $view.arch }) } }",
  "$hotfixes = @(Get-HotFix | ForEach-Object { [string]$_.HotFixID })",
  "$names = @{}",
  "foreach ($process in @(Get-Process)) { $names[[int]$process.Id] = [string]$process.ProcessName }",
  "$ports = New-Object System.Collections.ArrayList",
  "foreach ($c in @(Get-NetTCPConnection -State Listen)) { [void]$ports.Add([ordered]@{ protocol = 'tcp'; address = [string]$c.LocalAddress; port = [int]$c.LocalPort; process = $names[[int]$c.OwningProcess] }) }",
  "foreach ($c in @(Get-NetUDPEndpoint)) { [void]$ports.Add([ordered]@{ protocol = 'udp'; address = [string]$c.LocalAddress; port = [int]$c.LocalPort; process = $names[[int]$c.OwningProcess] }) }",
  "$reboot = (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') -or (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')",
  "ConvertTo-Json -Compress -Depth 5 -InputObject ([ordered]@{ os = $os; programs = $programs.ToArray(); hotfixes = $hotfixes; ports = $ports.ToArray(); rebootRequired = [bool]$reboot })",
].join("\n");

/** PowerShell -EncodedCommand argument (UTF-16LE base64), so no quoting reaches the command line. */
export function encodePowerShell(script: string) {
  const bytes = new Uint8Array(script.length * 2);
  for (let index = 0; index < script.length; index++) {
    const code = script.charCodeAt(index);
    bytes[index * 2] = code & 0xff;
    bytes[index * 2 + 1] = code >> 8;
  }
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function asArray(value: unknown): unknown[] {
  if (Array.isArray(value)) return value;
  return value === null || value === undefined ? [] : [value];
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function windowsArch(value: unknown) {
  const arch = typeof value === "string" ? value.trim().toUpperCase() : "";
  if (arch === "AMD64") return "x86_64";
  if (arch === "ARM64") return "aarch64";
  if (arch === "X86") return "x86";
  return cleanText(arch.toLowerCase(), LIMITS.arch);
}

/** Parses the Windows collector JSON into the inventory core (packages = installed programs). */
export function parseWindowsInventory(text: string): InventoryCore {
  const data = asRecord(JSON.parse(text.replace(/^﻿/, "")));
  const os = asRecord(data.os);
  const build = cleanText(os.currentBuild, 32);
  const server = (cleanText(os.installationType, 64) ?? "Client").toLowerCase() !== "client";
  let name = cleanText(os.productName, 255);
  // Windows 11 keeps "Windows 10" in ProductName; the build tells them apart.
  if (!server && name && build && Number(build) >= 22000) {
    name = name.replace(/^Windows 10\b/, "Windows 11");
  }
  const ubr = cleanText(os.ubr, 32);
  const packages: InventoryPackage[] = [];
  for (const entry of asArray(data.programs)) {
    const program = asRecord(entry);
    const item = makePackage(program.name, program.version, program.arch, program.publisher);
    if (item) packages.push(item);
  }
  const hotfixes = asArray(data.hotfixes)
    .map((value) => cleanText(value, 32)?.toUpperCase() ?? "")
    .filter((value) => /^KB\d{4,10}$/.test(value));
  const ports: InventoryPort[] = [];
  for (const entry of asArray(data.ports)) {
    const port = asRecord(entry);
    const protocol = port.protocol === "tcp" || port.protocol === "udp" ? port.protocol : null;
    const number = Number(port.port);
    const address = cleanText(port.address, 64)?.replace(/%.*$/, "") ?? null;
    if (!protocol || !address || !Number.isInteger(number) || number < 0 || number > 65535) {
      continue;
    }
    ports.push({
      protocol,
      address,
      port: number,
      process: cleanText(port.process, LIMITS.process),
    });
  }
  return {
    os: {
      family: "windows",
      id: server ? "windows-server" : "windows",
      versionId: build,
      codename: null,
      name,
      kernel: build ? `10.0.${build}${ubr ? `.${ubr}` : ""}` : null,
      arch: windowsArch(os.arch),
      build,
      ubr,
      displayVersion: cleanText(os.displayVersion, 32) ?? cleanText(os.releaseId, 32),
    },
    packageManager: "windows",
    packages,
    hotfixes,
    ports,
    rebootRequired: typeof data.rebootRequired === "boolean" ? data.rebootRequired : null,
  };
}

// ---------------------------------------------------------------------------------------------
// Command wrapping (Linux resource cap)

export type WrapperTools = {
  systemdRun: string | null;
  slice: boolean;
  nice: string | null;
  ionice: string | null;
};

/**
 * Argument vector of one collector command under the resource cap:
 * systemd-run scope in `mnscloud-security.slice` when available, else nice/ionice, else plain.
 */
export function wrapCommand(
  command: string,
  args: string[],
  tools: WrapperTools,
): [string, string[]] {
  const idleIo = tools.ionice ? [tools.ionice, "-c3"] : [];
  if (tools.systemdRun && tools.slice) {
    return [tools.systemdRun, [
      "--quiet",
      "--collect",
      "--scope",
      `--slice=${SECURITY_SLICE}`,
      "--nice=19",
      "-p",
      "IOWeight=10",
      "--",
      ...idleIo,
      command,
      ...args,
    ]];
  }
  if (tools.nice) return [tools.nice, ["-n", "19", ...idleIo, command, ...args]];
  if (tools.ionice) return [tools.ionice, ["-c3", command, ...args]];
  return [command, args];
}

async function exists(path: string) {
  try {
    await Deno.stat(path);
    return true;
  } catch {
    return false;
  }
}

/** Absolute path of an executable from PATH and the standard system directories; no shell. */
export async function findExecutable(name: string): Promise<string | null> {
  const dirs = [
    ...(Deno.env.get("PATH") ?? "").split(":"),
    "/usr/local/sbin",
    "/usr/local/bin",
    "/usr/sbin",
    "/usr/bin",
    "/sbin",
    "/bin",
  ].filter((dir) => dir.startsWith("/"));
  for (const dir of new Set(dirs)) {
    const path = `${dir.replace(/\/+$/, "")}/${name}`;
    try {
      const info = await Deno.stat(path);
      if (info.isFile && ((info.mode ?? 0o111) & 0o111)) return path;
    } catch { /* Not in this directory. */ }
  }
  return null;
}

export async function detectWrapperTools(): Promise<WrapperTools> {
  const systemd = await exists("/run/systemd/system");
  return {
    systemdRun: systemd ? await findExecutable("systemd-run") : null,
    slice: systemd && await exists(SECURITY_SLICE_FILE),
    nice: await findExecutable("nice"),
    ionice: await findExecutable("ionice"),
  };
}

async function readOptional(path: string) {
  try {
    return await Deno.readTextFile(path);
  } catch {
    return null;
  }
}

export function parseCpuStatUsec(text: string | null): number | null {
  const match = text?.match(/^usage_usec\s+(\d+)$/m);
  return match ? Number(match[1]) : null;
}

/** Fingerprint of the package databases (path, mtime, size); null when none exists. */
export async function packageDbStamp(
  paths = PACKAGE_DB_PATHS,
): Promise<{ stamp: string; mtimeMs: number } | null> {
  const parts: string[] = [];
  let latest = 0;
  for (const path of paths) {
    try {
      const info = await Deno.stat(path);
      const mtime = info.mtime?.getTime() ?? 0;
      latest = Math.max(latest, mtime);
      parts.push(`${path}:${mtime}:${info.size}`);
    } catch { /* Absent on this distribution. */ }
  }
  return parts.length ? { stamp: parts.join("|"), mtimeMs: latest } : null;
}

// ---------------------------------------------------------------------------------------------
// Collection

class Deadline {
  constructor(private readonly at: number) {}
  timeout() {
    const remaining = this.at - Date.now();
    if (remaining <= 0) throw new Error("Security inventory collection timed out.");
    return Math.min(COMMAND_TIMEOUT_MS, remaining);
  }
}

class CappedRunner {
  private scopeFailed = false;
  constructor(
    private readonly run: CommandRunner,
    private readonly tools: WrapperTools,
    private readonly deadline: Deadline,
  ) {}

  get usesSlice() {
    return Boolean(this.tools.systemdRun && this.tools.slice && !this.scopeFailed);
  }

  async exec(command: string, args: string[]): Promise<CommandResult> {
    const tools = this.scopeFailed ? { ...this.tools, systemdRun: null } : this.tools;
    const [wrapped, wrappedArgs] = wrapCommand(command, args, tools);
    const result = await this.run(wrapped, wrappedArgs, this.deadline.timeout());
    if (result.code === 124) throw new Error(`Security inventory command timed out: ${command}`);
    // systemd-run itself failed (no manager or slice): fall back to nice/ionice once.
    if (
      wrapped === this.tools.systemdRun && result.code !== 0 && !result.stdout &&
      /Failed to (start|create|connect)|transient/i.test(result.stderr)
    ) {
      this.scopeFailed = true;
      return await this.exec(command, args);
    }
    return result;
  }
}

async function collectLinux(runner: CappedRunner): Promise<InventoryCore> {
  const release = parseOsRelease(
    (await readOptional("/etc/os-release")) ?? (await readOptional("/usr/lib/os-release")) ?? "",
  );
  let kernel = cleanText(await readOptional("/proc/sys/kernel/osrelease"), 128);
  if (!kernel) {
    const uname = await runner.exec("uname", ["-r"]);
    kernel = uname.code === 0 ? cleanText(uname.stdout, 128) : null;
  }
  const machine = await runner.exec("uname", ["-m"]);
  const arch = machine.code === 0 ? cleanText(machine.stdout, LIMITS.arch) : null;

  let packageManager: PackageManager | null = null;
  let packages: InventoryPackage[] = [];
  let rebootRequired: boolean | null = null;
  const dpkgQuery = await exists("/var/lib/dpkg/status")
    ? await findExecutable("dpkg-query")
    : null;
  const rpm = dpkgQuery ? null : await findExecutable("rpm");
  if (dpkgQuery) {
    const result = await runner.exec(dpkgQuery, [
      "-W",
      "--showformat=${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\n",
    ]);
    if (result.code !== 0) throw new Error(`dpkg-query exited with ${result.code}.`);
    packageManager = "dpkg";
    packages = parseDpkg(result.stdout);
    rebootRequired = await exists("/var/run/reboot-required");
  } else if (rpm) {
    const result = await runner.exec(rpm, [
      "-qa",
      "--qf",
      "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n",
    ]);
    if (result.code !== 0) throw new Error(`rpm exited with ${result.code}.`);
    packageManager = "rpm";
    packages = parseRpm(result.stdout);
    const needsRestarting = await findExecutable("needs-restarting");
    if (needsRestarting) {
      const check = await runner.exec(needsRestarting, ["-r"]);
      rebootRequired = check.code === 1 ? true : check.code === 0 ? false : null;
    }
  } else {
    const apk = await readOptional("/lib/apk/db/installed");
    if (apk !== null) {
      packageManager = "apk";
      packages = parseApk(apk);
    }
  }

  let ports: InventoryPort[] = [];
  const ss = await findExecutable("ss");
  if (ss) {
    const result = await runner.exec(ss, ["-H", "-tulpn"]);
    if (result.code === 0) ports = parseSs(result.stdout);
  }

  return {
    os: {
      family: "linux",
      id: release.id,
      versionId: release.versionId,
      codename: release.codename,
      name: release.name,
      kernel,
      arch,
      build: null,
      ubr: null,
      displayVersion: null,
    },
    packageManager,
    packages,
    hotfixes: [],
    ports,
    rebootRequired,
  };
}

export type CollectOptions = {
  run: CommandRunner;
  windows: boolean;
  powershell: () => string;
  now?: () => number;
};

/** Collects one full inventory under the resource cap; throws on timeout or size overflow. */
export async function collectSecurityInventory(options: CollectOptions): Promise<InventoryPayload> {
  const now = options.now ?? Date.now;
  const started = now();
  const deadline = new Deadline(Date.now() + COLLECTION_TIMEOUT_MS);
  let core: InventoryCore;
  let cpuMs: number | null = null;
  let memoryPeakBytes: number | null = null;
  if (options.windows) {
    const result = await options.run(options.powershell(), [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-EncodedCommand",
      encodePowerShell(WINDOWS_INVENTORY_SCRIPT),
    ], deadline.timeout());
    if (result.code !== 0) throw new Error(`Windows inventory exited with ${result.code}.`);
    core = parseWindowsInventory(result.stdout);
  } else {
    const runner = new CappedRunner(options.run, await detectWrapperTools(), deadline);
    const cpuBefore = runner.usesSlice
      ? parseCpuStatUsec(await readOptional(`${SECURITY_SLICE_CGROUP}/cpu.stat`))
      : null;
    core = await collectLinux(runner);
    if (runner.usesSlice) {
      const cpuAfter = parseCpuStatUsec(await readOptional(`${SECURITY_SLICE_CGROUP}/cpu.stat`));
      if (cpuBefore !== null && cpuAfter !== null && cpuAfter >= cpuBefore) {
        cpuMs = Math.round((cpuAfter - cpuBefore) / 1000);
      }
      const peak = Number((await readOptional(`${SECURITY_SLICE_CGROUP}/memory.peak`))?.trim());
      memoryPeakBytes = Number.isFinite(peak) && peak > 0 ? peak : null;
    }
  }
  return await buildPayload(core, new Date(now()).toISOString(), {
    durationMs: Math.max(0, now() - started),
    cpuMs,
    memoryPeakBytes,
  });
}

/** Canonical payload with hash and footprint; throws when it does not fit the API body limit. */
export async function buildPayload(
  core: InventoryCore,
  collectedAt: string,
  footprint: Omit<InventoryFootprint, "payloadBytes">,
): Promise<InventoryPayload> {
  const canonical = canonicalInventory(core);
  const payload: InventoryPayload = {
    hash: await inventoryHash(canonical.core),
    collectedAt,
    ...canonical.core,
    truncated: canonical.truncated,
    footprint: { ...footprint, payloadBytes: 0 },
  };
  const bytes = new TextEncoder().encode(JSON.stringify(payload)).length;
  payload.footprint.payloadBytes = bytes;
  if (bytes > LIMITS.payloadBytes - 1024) {
    throw new Error(`Security inventory payload too large (${bytes} bytes).`);
  }
  return payload;
}

// ---------------------------------------------------------------------------------------------
// Scheduling, cache and platform answers

export type DueInput = {
  now: number;
  enabled: boolean;
  /** When the current enabled period started, and its random first delay. */
  enabledAt: number | null;
  firstDelayMs: number;
  /** Next scheduled collection (after a collection or a failed attempt); null before the first. */
  nextDueAt: number | null;
  lastAttemptAt: number;
  /** Package database fingerprint seen at the last attempt and now. */
  attemptStamp: string | null;
  currentStamp: { stamp: string; mtimeMs: number } | null;
};

export type DueReason = "first" | "schedule" | "packages" | null;

/** Whether a collection is due now, and why. Never inside the heartbeat path. */
export function collectionDue(input: DueInput): DueReason {
  if (!input.enabled) return null;
  if (input.nextDueAt === null) {
    const start = (input.enabledAt ?? input.now) + input.firstDelayMs;
    return input.now >= start ? "first" : null;
  }
  if (input.now >= input.nextDueAt) return "schedule";
  const current = input.currentStamp;
  if (
    current && input.attemptStamp !== null && current.stamp !== input.attemptStamp &&
    input.now - input.lastAttemptAt >= PACKAGE_MIN_SPACING_MS &&
    input.now - current.mtimeMs >= PACKAGE_SETTLE_MS
  ) {
    return "packages";
  }
  return null;
}

export function inventoryCachePath(agentTokenFile: string) {
  const index = Math.max(agentTokenFile.lastIndexOf("/"), agentTokenFile.lastIndexOf("\\"));
  const dir = index >= 0 ? agentTokenFile.slice(0, index) : ".";
  const separator = index >= 0 ? agentTokenFile[index] : "/";
  return `${dir}${separator}${INVENTORY_CACHE_FILE}`;
}

/** HTTP status from a jsonRequest error ("<path> returned HTTP 429: ..."). */
export function httpStatusOf(error: unknown): number | null {
  const match = String(error instanceof Error ? error.message : error).match(
    /returned HTTP (\d{3})/,
  );
  return match ? Number(match[1]) : null;
}

type CacheFile = {
  hash: string;
  collectedAt: string;
  dbStamp: string | null;
  payload: InventoryPayload;
};

export type SecurityInventoryAnswer = { enabled?: unknown; needsFull?: unknown } | null | undefined;
export type InventorySender = (payload: InventoryPayload) => Promise<unknown>;
type Logger = (level: "info" | "warn", message: string, extra?: unknown) => void;

export type SecurityInventoryOptions = {
  collect: () => Promise<InventoryPayload>;
  stamp: () => Promise<{ stamp: string; mtimeMs: number } | null>;
  log: Logger;
  windows: boolean;
  now?: () => number;
  random?: () => number;
};

export class SecurityInventory {
  private cachePath: string | null = null;
  private meta: { hash: string; collectedAt: string } | null = null;
  private enabled = false;
  private enabledAt: number | null = null;
  private firstDelayMs = 0;
  private nextDueAt: number | null = null;
  private lastAttemptAt = 0;
  private attemptStamp: string | null = null;
  private collecting = false;
  private uploading = false;
  private lastUploadAt = 0;
  private blockedHash: string | null = null;
  private readonly now: () => number;
  private readonly random: () => number;

  constructor(private readonly options: SecurityInventoryOptions) {
    this.now = options.now ?? Date.now;
    this.random = options.random ?? Math.random;
  }

  private scheduleNext(from: number) {
    this.nextDueAt = from + FULL_INTERVAL_MS + Math.floor(this.random() * JITTER_MS);
  }

  /** Restores the cached hash so a restart does not force a new collection. */
  async load(cachePath: string) {
    this.cachePath = cachePath;
    try {
      const cache = JSON.parse(await Deno.readTextFile(cachePath)) as CacheFile;
      const collectedAt = Date.parse(cache.collectedAt);
      if (!/^[0-9a-f]{64}$/.test(cache.hash) || !Number.isFinite(collectedAt)) throw new Error();
      this.meta = { hash: cache.hash, collectedAt: cache.collectedAt };
      this.attemptStamp = typeof cache.dbStamp === "string" ? cache.dbStamp : null;
      this.lastAttemptAt = Math.min(collectedAt, this.now());
      this.scheduleNext(this.lastAttemptAt);
    } catch {
      this.meta = null;
    }
  }

  /** Heartbeat field; sent by every build that supports the inventory, also while disabled. */
  heartbeatField() {
    return {
      supported: true,
      hash: this.meta?.hash ?? null,
      collectedAt: this.meta?.collectedAt ?? null,
    };
  }

  get state() {
    return {
      enabled: this.enabled,
      hash: this.meta?.hash ?? null,
      nextDueAt: this.nextDueAt,
      enabledAt: this.enabledAt,
      firstDelayMs: this.firstDelayMs,
      uploading: this.uploading,
    };
  }

  /**
   * Applies the heartbeat answer (only after a successful heartbeat). A missing field means an API
   * without the inventory: disabled. The upload runs detached from the heartbeat.
   */
  acknowledge(answer: SecurityInventoryAnswer, send: InventorySender): Promise<void> {
    const enabled = answer?.enabled === true;
    if (!enabled) {
      if (this.enabled || this.meta) this.disable();
      return Promise.resolve();
    }
    if (!this.enabled) {
      this.enabled = true;
      this.enabledAt = this.now();
      this.firstDelayMs = Math.floor(this.random() * FIRST_DELAY_MS);
    }
    if (answer?.needsFull === true) return this.upload(send);
    return Promise.resolve();
  }

  private disable() {
    this.enabled = false;
    this.enabledAt = null;
    this.nextDueAt = null;
    this.attemptStamp = null;
    this.lastAttemptAt = 0;
    this.blockedHash = null;
    if (this.meta) this.options.log("info", "Security inventory disabled; local cache removed.");
    this.meta = null;
    if (this.cachePath) {
      Deno.remove(this.cachePath).catch(() => undefined);
    }
  }

  private async upload(send: InventorySender) {
    const meta = this.meta;
    const now = this.now();
    if (
      !meta || !this.cachePath || this.uploading || meta.hash === this.blockedHash ||
      now - this.lastUploadAt < UPLOAD_MIN_SPACING_MS
    ) return;
    this.uploading = true;
    this.lastUploadAt = now;
    try {
      const cache = JSON.parse(await Deno.readTextFile(this.cachePath)) as CacheFile;
      if (cache.hash !== meta.hash) return;
      await send(cache.payload);
      this.options.log("info", "Security inventory sent.", {
        packages: cache.payload.packages.length,
        ports: cache.payload.ports.length,
      });
    } catch (error) {
      const status = httpStatusOf(error);
      if (status === 413) {
        this.blockedHash = meta.hash;
        this.options.log(
          "warn",
          "Security inventory rejected as too large; waiting for the next collection.",
        );
      } else if (status !== 409 && status !== 429) {
        this.options.log(
          "warn",
          "Security inventory upload failed; the next heartbeat asks again.",
          String(error),
        );
      }
    } finally {
      this.uploading = false;
    }
  }

  /** Background lane step: collects when due. Failures wait for the next scheduled time. */
  async tick(): Promise<DueReason> {
    if (!this.enabled || this.collecting || !this.cachePath) return null;
    const now = this.now();
    const current = this.options.windows ? null : await this.options.stamp();
    const reason = collectionDue({
      now,
      enabled: this.enabled,
      enabledAt: this.enabledAt,
      firstDelayMs: this.firstDelayMs,
      nextDueAt: this.nextDueAt,
      lastAttemptAt: this.lastAttemptAt,
      attemptStamp: this.attemptStamp,
      currentStamp: current,
    });
    if (!reason) return null;
    this.collecting = true;
    this.lastAttemptAt = now;
    this.attemptStamp = current?.stamp ?? "";
    this.scheduleNext(now);
    try {
      const payload = await this.options.collect();
      if (!this.enabled) return reason;
      await this.writeCache({
        hash: payload.hash,
        collectedAt: payload.collectedAt,
        dbStamp: this.attemptStamp,
        payload,
      });
      this.meta = { hash: payload.hash, collectedAt: payload.collectedAt };
      this.blockedHash = null;
      this.options.log("info", "Security inventory collected.", {
        reason,
        packages: payload.packages.length,
        ports: payload.ports.length,
        truncated: payload.truncated,
        footprint: payload.footprint,
      });
    } catch (error) {
      this.options.log(
        "warn",
        "Security inventory collection abandoned until the next scheduled time.",
        {
          reason,
          error: String(error instanceof Error ? error.message : error).slice(0, 300),
        },
      );
    } finally {
      this.collecting = false;
    }
    return reason;
  }

  private async writeCache(cache: CacheFile) {
    const path = this.cachePath!;
    const temporary = `${path}.tmp`;
    await Deno.writeTextFile(temporary, JSON.stringify(cache), { mode: 0o600 });
    if (!this.options.windows) await Deno.chmod(temporary, 0o600);
    await Deno.rename(temporary, path);
  }
}
