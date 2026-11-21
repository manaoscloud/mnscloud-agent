/**
 * Cyber Security patch simulation (E2b): one typed job, `cyber.security.patch.simulate`, that asks
 * the host package manager what a patch of the given packages would do, without installing,
 * downloading or refreshing anything. The campaign preview shows the answer (upgrades, new
 * dependencies, removals) before a person approves the campaign.
 *
 * Nothing is installed, removed or upgraded: `apt-get -s` with `Debug::NoLocking` and no binary
 * cache (no dpkg lock, no file written), `dnf/yum --assumeno -C` (cache only, answers "no"; the
 * package manager still writes its own log), `apk upgrade -s`, and on Windows a Windows Update
 * search with no download or install. Same package-name and KB validation as the patch job; the
 * package manager comes from the host. While a patch runs, the Agent answers at once with
 * `busySimulation` instead of running anything.
 *
 * Contract: docs/security-patch.md → Simulation.
 */
import type { CommandResult, CommandRunner } from "./security-inventory.ts";
import { MAX_KBS, MAX_PACKAGES, type PackageManager, PatchRequestError } from "./security-patch.ts";

export const SIMULATE_COMMAND = "cyber.security.patch.simulate";
export const SIMULATE_CAPABILITY = "cyber.security.patch.simulate.v1";

const PACKAGE_NAME = /^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,127}$/;
const KB = /^KB\d{4,8}$/;
const SIMULATION_UUID = /^[0-9a-fA-F-]{32,36}$/;
export const DEFAULT_SIMULATE_MINUTES = 10;
export const MAX_SIMULATE_MINUTES = 15;
/** Each list of the result is capped (the platform shows the first entries). */
export const MAX_LISTED = 300;
const OUTPUT_TAIL = 1800;

export type SimulateRequest = {
  simulationUUID: string;
  scope: "findings" | "security_all";
  packages: string[];
  kbs: string[];
  timeoutMinutes: number;
};

export type SimulatedChange = { name: string; from?: string; to?: string };

export type SimulationPlan = {
  upgrade: SimulatedChange[];
  install: SimulatedChange[];
  remove: SimulatedChange[];
};

export type SimulateResult = SimulationPlan & {
  simulate: true;
  simulationUUID: string;
  outcome: "ok" | "failed";
  packageManager: PackageManager | null;
  updates: { kb: string; title: string }[];
  rebootLikely: boolean;
  durationMs: number;
  output: string;
  error: string | null;
};

export type SimulateDeps = {
  run: CommandRunner;
  windows: boolean;
  powershell: () => string;
  encode: (script: string) => string;
  manager: () => Promise<PackageManager | null>;
  hasCommand: (name: string) => Promise<boolean>;
  now?: () => number;
};

function list(value: unknown, pattern: RegExp, max: number, label: string): string[] {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) throw new PatchRequestError(`${label} must be a list`);
  const out = new Set<string>();
  for (const item of value) {
    const text = typeof item === "string" ? item.trim() : "";
    if (!pattern.test(text)) throw new PatchRequestError(`Invalid ${label.replace(/s$/, "")}`);
    out.add(text);
  }
  if (out.size > max) throw new PatchRequestError(`Too many ${label}`);
  return [...out];
}

/** Strict payload check; a malformed request is refused before any command runs. */
export function parseSimulateRequest(raw: unknown): SimulateRequest {
  const value = raw && typeof raw === "object" && !Array.isArray(raw)
    ? raw as Record<string, unknown>
    : {};
  const simulationUUID = typeof value.simulationUUID === "string"
    ? value.simulationUUID.trim()
    : "";
  if (!SIMULATION_UUID.test(simulationUUID)) {
    throw new PatchRequestError("Invalid patch simulation");
  }
  const scope = value.scope === "security_all"
    ? "security_all"
    : value.scope === "findings"
    ? "findings"
    : null;
  if (!scope) throw new PatchRequestError("Invalid patch scope");
  const packages = list(value.packages, PACKAGE_NAME, MAX_PACKAGES, "packages");
  const kbs = list(value.kbs, KB, MAX_KBS, "KBs");
  const minutes = Number(value.timeoutMinutes ?? DEFAULT_SIMULATE_MINUTES);
  const timeoutMinutes = Number.isFinite(minutes)
    ? Math.min(Math.max(Math.round(minutes), 1), MAX_SIMULATE_MINUTES)
    : DEFAULT_SIMULATE_MINUTES;
  return { simulationUUID, scope, packages, kbs, timeoutMinutes };
}

export type SimulateStep = { command: string; args: string[] };

/** The single read-only command of the host's package manager (English output for the parsers). */
export function simulateStep(
  manager: PackageManager,
  packages: string[],
  dnf: "dnf" | "yum" = "dnf",
): SimulateStep {
  if (!packages.length) throw new PatchRequestError("No packages to simulate");
  if (manager === "dpkg") {
    return {
      command: "env",
      args: [
        "LC_ALL=C",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "-s",
        "-q",
        "-o",
        "Debug::NoLocking=1",
        "-o",
        "Dir::Cache::pkgcache=",
        "-o",
        "Dir::Cache::srcpkgcache=",
        "install",
        "--only-upgrade",
        "--",
        ...packages,
      ],
    };
  }
  if (manager === "rpm") {
    return {
      command: "env",
      args: [
        "LC_ALL=C",
        dnf,
        "--assumeno",
        "-C",
        "--setopt=color=never",
        "upgrade",
        "--",
        ...packages,
      ],
    };
  }
  if (manager === "apk") {
    return { command: "apk", args: ["upgrade", "-s", "--", ...packages] };
  }
  throw new PatchRequestError("Unsupported package manager");
}

function push(target: SimulatedChange[], change: SimulatedChange) {
  if (target.length < MAX_LISTED) target.push(change);
}

function emptyPlan(): SimulationPlan {
  return { upgrade: [], install: [], remove: [] };
}

/** `apt-get -s`: `Inst name [old] (new ...)` (no `[old]` = new package) and `Remv name [old]`. */
export function parseAptSimulation(text: string): SimulationPlan {
  const plan = emptyPlan();
  for (const line of text.split("\n")) {
    const inst = /^Inst (\S+) (?:\[([^\]]+)\] )?\((\S+)/.exec(line.trim());
    if (inst) {
      if (inst[2]) push(plan.upgrade, { name: inst[1], from: inst[2], to: inst[3] });
      else push(plan.install, { name: inst[1], to: inst[3] });
      continue;
    }
    const remv = /^Remv (\S+)(?: \[([^\]]+)\])?/.exec(line.trim());
    if (remv) push(plan.remove, remv[2] ? { name: remv[1], from: remv[2] } : { name: remv[1] });
  }
  return plan;
}

/**
 * dnf/yum transaction table: section headers (`Upgrading:`, `Installing dependencies:`,
 * `Removing:` ...) followed by `name arch version repo size` rows. A long name wraps onto its own
 * line before the columns; `replacing` lines are skipped.
 */
export function parseDnfSimulation(text: string): SimulationPlan {
  const plan = emptyPlan();
  let section: keyof SimulationPlan | null = null;
  let wrapped = "";
  for (const raw of text.replace(/\r/g, "").split("\n")) {
    const line = raw.trimEnd();
    const header =
      /^(Upgrading|Updating|Installing|Installing dependencies|Installing weak dependencies|Removing|Removing dependent packages|Removing unused dependencies|Erasing|Downgrading|Reinstalling)(?: [a-z ]+)?:\s*$/
        .exec(line.trim());
    if (header) {
      const word = header[1];
      section = /^(Upgrading|Updating|Downgrading|Reinstalling)/.test(word)
        ? "upgrade"
        : /^(Removing|Erasing)/.test(word)
        ? "remove"
        : "install";
      wrapped = "";
      continue;
    }
    if (
      /^(Transaction Summary|Total download size|Operation aborted|Dependencies resolved)/i.test(
        line.trim(),
      )
    ) {
      section = null;
      continue;
    }
    // Any other unindented "...:" header (skipped packages, groups, modules) ends the section.
    if (/^\S.*:\s*$/.test(line)) {
      section = null;
      wrapped = "";
      continue;
    }
    if (!section || !/^\s/.test(line)) continue;
    const cells = line.trim().split(/\s+/);
    if (cells[0] === "replacing" || cells[0] === "Package") continue;
    if (cells.length === 1) {
      wrapped = cells[0];
      continue;
    }
    const row = wrapped ? [wrapped, ...cells] : cells;
    wrapped = "";
    if (row.length < 3) continue;
    const change: SimulatedChange = section === "remove"
      ? { name: row[0], from: row[2] }
      : { name: row[0], to: row[2] };
    push(plan[section], change);
  }
  return plan;
}

/** `apk upgrade -s`: `(1/3) Upgrading musl (1.2.4-r1 -> 1.2.4-r2)`, `Installing x (1.0)`, `Purging x (1.0)`. */
export function parseApkSimulation(text: string): SimulationPlan {
  const plan = emptyPlan();
  for (const line of text.split("\n")) {
    const row =
      /^\(\d+\/\d+\) (Upgrading|Downgrading|Replacing|Installing|Purging|Deleting) (\S+) \(([^)]*)\)/
        .exec(line.trim());
    if (!row) continue;
    const [, action, name, versions] = row;
    if (action === "Installing") push(plan.install, { name, to: versions });
    else if (action === "Purging" || action === "Deleting") {
      push(plan.remove, { name, from: versions });
    } else {
      const [from, to] = versions.split(" -> ");
      push(plan.upgrade, to ? { name, from, to } : { name, to: from });
    }
  }
  return plan;
}

/** Packages whose update usually needs a reboot (kernel, C library, init). */
const REBOOT_PACKAGES =
  /^(linux-image|linux-generic|linux-modules|linux-lts|linux-virt|kernel|kernel-core|kernel-modules|libc6|glibc|musl|systemd|dbus)(\b|[-.:])/;

export function rebootLikely(plan: SimulationPlan): boolean {
  return [...plan.upgrade, ...plan.install].some((change) => REBOOT_PACKAGES.test(change.name));
}

/**
 * Windows Update search only (no download, no install): the pending updates the patch job would
 * select — the KBs asked, or the pending security and critical updates. Prints one JSON line.
 */
export function windowsSimulateScript(kbs: string[]): string {
  for (const kb of kbs) if (!KB.test(kb)) throw new PatchRequestError("Invalid KB");
  const wanted = kbs.length ? `@(${kbs.map((kb) => `'${kb}'`).join(",")})` : "@()";
  return [
    "$ErrorActionPreference = 'Stop'",
    `$wanted = ${wanted}`,
    "$session = New-Object -ComObject Microsoft.Update.Session",
    "$session.ClientApplicationID = 'MNSCloud Agent'",
    "$found = $session.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\")",
    "$items = @()",
    "foreach ($update in $found.Updates) {",
    "  $ids = @($update.KBArticleIDs | ForEach-Object { 'KB' + $_ })",
    "  $categories = @($update.Categories | ForEach-Object { $_.Name })",
    "  $security = ($categories -contains 'Security Updates') -or ($categories -contains 'Critical Updates')",
    "  $match = if ($wanted.Count -gt 0) { @($ids | Where-Object { $wanted -contains $_ }).Count -gt 0 } else { $security }",
    "  if ($match) { $items += [ordered]@{ kb = ($ids -join ','); title = [string]$update.Title; reboot = [int]$update.InstallationBehavior.RebootBehavior } }",
    "}",
    "ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ updates = @($items) })",
  ].join("\n");
}

export function parseWindowsSimulation(
  text: string,
): { kb: string; title: string; reboot: boolean }[] {
  const line = text.trim().split("\n").filter((row) => row.trim().startsWith("{")).pop() ?? "";
  const value = JSON.parse(line) as Record<string, unknown>;
  const items =
    (Array.isArray(value.updates) ? value.updates : value.updates ? [value.updates] : []) as Record<
      string,
      unknown
    >[];
  return items.slice(0, MAX_LISTED).map((item) => ({
    kb: String(item.kb ?? "").slice(0, 120),
    title: String(item.title ?? "").slice(0, 255),
    // InstallationBehavior.RebootBehavior: 0 never, 1 always, 2 can request.
    reboot: Number(item.reboot ?? 0) > 0,
  }));
}

function tail(text: string) {
  const clean = text.replace(/\r/g, "").trim();
  return clean.length > OUTPUT_TAIL ? clean.slice(clean.length - OUTPUT_TAIL) : clean;
}

function failure(result: CommandResult, label: string) {
  const detail = tail(result.stderr || result.stdout).split("\n").slice(-3).join(" ");
  return `${label} failed (exit ${result.code})${detail ? `: ${detail}` : ""}`;
}

/** Answer while a patch holds the package manager: nothing is run, the preview says why. */
export function busySimulation(request: SimulateRequest): SimulateResult {
  return {
    simulate: true,
    simulationUUID: request.simulationUUID,
    outcome: "failed",
    packageManager: null,
    upgrade: [],
    install: [],
    remove: [],
    updates: [],
    rebootLikely: false,
    durationMs: 0,
    output: "",
    error: "A security patch is running on this server; simulate again when it ends",
  };
}

/** Runs the simulation. Never throws for a host failure: the outcome says what happened. */
export async function simulatePatch(
  request: SimulateRequest,
  deps: SimulateDeps,
): Promise<SimulateResult> {
  const now = deps.now ?? Date.now;
  const started = now();
  const timeoutMs = request.timeoutMinutes * 60_000;
  const manager = deps.windows ? "windows" : await deps.manager();
  const done = (
    outcome: "ok" | "failed",
    plan: SimulationPlan,
    output: string,
    error: string | null,
    updates: { kb: string; title: string; reboot?: boolean }[] = [],
  ): SimulateResult => ({
    simulate: true,
    simulationUUID: request.simulationUUID,
    outcome,
    packageManager: manager,
    ...plan,
    updates: updates.map(({ kb, title }) => ({ kb, title })),
    rebootLikely: rebootLikely(plan) || updates.some((update) => update.reboot === true),
    durationMs: now() - started,
    output: tail(output),
    error,
  });

  if (!manager) return done("failed", emptyPlan(), "", "No supported package manager on this host");

  if (manager === "windows") {
    const result = await deps.run(deps.powershell(), [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-EncodedCommand",
      deps.encode(windowsSimulateScript(request.kbs)),
    ], timeoutMs);
    if (result.code !== 0) {
      return done(
        "failed",
        emptyPlan(),
        result.stdout + result.stderr,
        failure(result, "Windows Update search"),
      );
    }
    try {
      return done("ok", emptyPlan(), "", null, parseWindowsSimulation(result.stdout));
    } catch {
      return done(
        "failed",
        emptyPlan(),
        result.stdout,
        "Windows Update returned an unreadable result",
      );
    }
  }

  if (!request.packages.length) return done("ok", emptyPlan(), "", null);
  const dnf = manager === "rpm" && !(await deps.hasCommand("dnf")) ? "yum" : "dnf";
  let step: SimulateStep;
  try {
    step = simulateStep(manager, request.packages, dnf);
  } catch (error) {
    return done("failed", emptyPlan(), "", String((error as Error).message));
  }
  const result = await deps.run(step.command, step.args, timeoutMs);
  const output = result.stdout + (result.stderr ? `\n${result.stderr}` : "");
  if (manager === "rpm") {
    // --assumeno answers "no": exit 1 with "Operation aborted" (dnf, sometimes as "Error: Operation
    // aborted.") or "Exiting on user command" (yum) is the normal end of a transaction.
    const aborted = result.code === 1 && /Operation aborted|Exiting on user command/i.test(output);
    if (result.code !== 0 && !aborted) {
      return done("failed", emptyPlan(), output, failure(result, dnf));
    }
    return done("ok", parseDnfSimulation(result.stdout), output, null);
  }
  if (result.code !== 0) {
    return done(
      "failed",
      emptyPlan(),
      output,
      failure(result, manager === "dpkg" ? "apt-get" : "apk"),
    );
  }
  return done(
    "ok",
    manager === "dpkg" ? parseAptSimulation(result.stdout) : parseApkSimulation(result.stdout),
    output,
    null,
  );
}
