/**
 * Cyber Security patch management (V6): one typed job, `cyber.security.patch.apply`, that updates
 * the packages chosen by the platform (from vulnerability findings) or, on Windows, installs the
 * pending security updates. Fixed action list: no shell text from the platform reaches the host.
 * Every package name and KB is validated here again, argument vectors are built without a shell,
 * the package manager comes from the host (never from the payload), and the reboot follows the
 * explicit policy of the run (never, if_required or always) after the result is reported.
 *
 * Contract: docs/security-patch.md.
 */
import type { CommandResult, CommandRunner } from "./security-inventory.ts";

export const PATCH_COMMAND = "cyber.security.patch.apply";
export const PATCH_CAPABILITY = "cyber.security.patch.v1";

/** Same rule as the platform remediation helper (Debian/RPM/Alpine package names). */
const PACKAGE_NAME = /^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,127}$/;
const KB = /^KB\d{4,8}$/;
const RUN_UUID = /^[0-9a-fA-F-]{32,36}$/;
export const MAX_PACKAGES = 200;
export const MAX_KBS = 50;
export const DEFAULT_TIMEOUT_MINUTES = 90;
export const MAX_TIMEOUT_MINUTES = 150;
const OUTPUT_TAIL = 1800;

export type RebootPolicy = "never" | "if_required" | "always";
export type PackageManager = "dpkg" | "rpm" | "apk" | "windows";

export type PatchRequest = {
  runUUID: string;
  scope: "findings" | "security_all";
  packages: string[];
  kbs: string[];
  rebootPolicy: RebootPolicy;
  timeoutMinutes: number;
};

export class PatchRequestError extends Error {}

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

/** Strict payload check; anything unknown or malformed refuses the job before it touches the host. */
export function parsePatchRequest(raw: unknown): PatchRequest {
  const value = raw && typeof raw === "object" && !Array.isArray(raw)
    ? raw as Record<string, unknown>
    : {};
  const runUUID = typeof value.runUUID === "string" ? value.runUUID.trim() : "";
  if (!RUN_UUID.test(runUUID)) throw new PatchRequestError("Invalid patch run");
  const scope = value.scope === "security_all"
    ? "security_all"
    : value.scope === "findings"
    ? "findings"
    : null;
  if (!scope) throw new PatchRequestError("Invalid patch scope");
  const reboot = value.rebootPolicy;
  if (reboot !== "never" && reboot !== "if_required" && reboot !== "always") {
    throw new PatchRequestError("Invalid reboot policy");
  }
  const packages = list(value.packages, PACKAGE_NAME, MAX_PACKAGES, "packages");
  const kbs = list(value.kbs, KB, MAX_KBS, "KBs");
  const minutes = Number(value.timeoutMinutes ?? DEFAULT_TIMEOUT_MINUTES);
  const timeoutMinutes = Number.isFinite(minutes)
    ? Math.min(Math.max(Math.round(minutes), 5), MAX_TIMEOUT_MINUTES)
    : DEFAULT_TIMEOUT_MINUTES;
  return { runUUID, scope, packages, kbs, rebootPolicy: reboot, timeoutMinutes };
}

export type PatchStep = { label: string; command: string; args: string[] };

/**
 * Linux steps for the host's package manager. Only `--only-upgrade`/`upgrade` of installed
 * packages: a package that is not installed is never added.
 */
export function linuxPatchSteps(
  manager: PackageManager,
  packages: string[],
  dnf: "dnf" | "yum" = "dnf",
): PatchStep[] {
  if (!packages.length) throw new PatchRequestError("No packages to update");
  if (manager === "dpkg") {
    const apt = ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=a", "apt-get"];
    const lock = ["-o", "DPkg::Lock::Timeout=300"];
    return [
      { label: "refresh", command: apt[0], args: [...apt.slice(1), ...lock, "-q", "update"] },
      {
        label: "upgrade",
        command: apt[0],
        args: [
          ...apt.slice(1),
          ...lock,
          "-q",
          "-y",
          "-o",
          "Dpkg::Options::=--force-confdef",
          "-o",
          "Dpkg::Options::=--force-confold",
          "install",
          "--only-upgrade",
          "--",
          ...packages,
        ],
      },
    ];
  }
  if (manager === "rpm") {
    return [{
      label: "upgrade",
      command: dnf,
      args: ["-y", "-q", "--refresh", "upgrade", "--", ...packages],
    }];
  }
  if (manager === "apk") {
    return [
      { label: "refresh", command: "apk", args: ["update", "-q"] },
      { label: "upgrade", command: "apk", args: ["upgrade", "-q", "--", ...packages] },
    ];
  }
  throw new PatchRequestError("Unsupported package manager");
}

/** Installed versions of the packages (name -> version), for the before/after comparison. */
export function versionQuery(manager: PackageManager, packages: string[]): PatchStep | null {
  if (!packages.length) return null;
  if (manager === "dpkg") {
    return {
      label: "versions",
      command: "dpkg-query",
      args: ["-W", "-f=${Package}\\t${Version}\\n", "--", ...packages],
    };
  }
  if (manager === "rpm") {
    return {
      label: "versions",
      command: "rpm",
      args: ["-q", "--qf", "%{NAME}\\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\\n", "--", ...packages],
    };
  }
  if (manager === "apk") {
    return { label: "versions", command: "apk", args: ["info", "-v", "--", ...packages] };
  }
  return null;
}

export function parseVersions(manager: PackageManager, text: string, packages: string[]) {
  const wanted = new Set(packages);
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const row = line.trim();
    if (!row) continue;
    if (manager === "apk") {
      // name-version-rN: the version starts at the last "-<digit>" before "-r<digits>".
      const match = /^(.+)-(\d[^-]*-r\d+)$/.exec(row);
      if (match && wanted.has(match[1])) out[match[1]] = match[2];
      continue;
    }
    const [name, version] = row.split("\t");
    if (name && version && wanted.has(name) && !/not installed/i.test(row)) {
      out[name] = version.replace(/^0:/, "");
    }
  }
  return out;
}

export type PackageChange = { name: string; from: string | null; to: string | null };

export function packageChanges(
  before: Record<string, string>,
  after: Record<string, string>,
  packages: string[],
): { updated: PackageChange[]; unchanged: string[] } {
  const updated: PackageChange[] = [];
  const unchanged: string[] = [];
  for (const name of packages) {
    const from = before[name] ?? null;
    const to = after[name] ?? null;
    if (from !== to && to !== null) updated.push({ name, from, to });
    else unchanged.push(name);
  }
  return { updated, unchanged };
}

/**
 * Windows Update through the Windows Update Agent API (no module to install). With KBs, only the
 * pending updates of those KBs; without, the pending security and critical updates. Drivers and
 * feature upgrades are never selected. Prints one JSON line.
 */
export function windowsPatchScript(kbs: string[]): string {
  for (const kb of kbs) if (!KB.test(kb)) throw new PatchRequestError("Invalid KB");
  const wanted = kbs.length ? `@(${kbs.map((kb) => `'${kb}'`).join(",")})` : "@()";
  return [
    "$ErrorActionPreference = 'Stop'",
    `$wanted = ${wanted}`,
    "$session = New-Object -ComObject Microsoft.Update.Session",
    "$session.ClientApplicationID = 'MNSCloud Agent'",
    "$found = $session.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\")",
    "$selected = New-Object -ComObject Microsoft.Update.UpdateColl",
    "$items = @()",
    "foreach ($update in $found.Updates) {",
    "  $ids = @($update.KBArticleIDs | ForEach-Object { 'KB' + $_ })",
    "  $categories = @($update.Categories | ForEach-Object { $_.Name })",
    "  $security = ($categories -contains 'Security Updates') -or ($categories -contains 'Critical Updates')",
    "  $match = if ($wanted.Count -gt 0) { @($ids | Where-Object { $wanted -contains $_ }).Count -gt 0 } else { $security }",
    "  if ($match) {",
    "    if (-not $update.EulaAccepted) { $update.AcceptEula() }",
    "    [void]$selected.Add($update)",
    "    $items += [ordered]@{ kb = ($ids -join ','); title = [string]$update.Title }",
    "  }",
    "}",
    "$installed = @(); $rebootRequired = $false; $resultCode = 0",
    "if ($selected.Count -gt 0) {",
    "  $downloader = $session.CreateUpdateDownloader(); $downloader.Updates = $selected; [void]$downloader.Download()",
    "  $installer = $session.CreateUpdateInstaller(); $installer.Updates = $selected",
    "  $result = $installer.Install()",
    "  $resultCode = [int]$result.ResultCode; $rebootRequired = [bool]$result.RebootRequired",
    "  for ($i = 0; $i -lt $selected.Count; $i++) {",
    "    $installed += [ordered]@{ kb = $items[$i].kb; title = $items[$i].title; resultCode = [int]$result.GetUpdateResult($i).ResultCode }",
    "  }",
    "}",
    "$pending = (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\RebootPending') -or (Test-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update\\RebootRequired')",
    "ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ selected = $selected.Count; resultCode = $resultCode; installed = $installed; rebootRequired = ($rebootRequired -or $pending) })",
  ].join("\n");
}

export type WindowsPatchOutput = {
  selected: number;
  resultCode: number;
  installed: { kb: string; title: string; resultCode: number }[];
  rebootRequired: boolean;
};

/** OperationResultCode: 2 succeeded, 3 succeeded with errors, 4 failed, 5 aborted. */
export function parseWindowsPatch(text: string): WindowsPatchOutput {
  const line = text.trim().split("\n").filter((row) => row.trim().startsWith("{")).pop() ?? "";
  const value = JSON.parse(line) as Record<string, unknown>;
  const installed =
    (Array.isArray(value.installed)
      ? value.installed
      : value.installed
      ? [value.installed]
      : []) as Record<string, unknown>[];
  return {
    selected: Number(value.selected ?? 0) || 0,
    resultCode: Number(value.resultCode ?? 0) || 0,
    installed: installed.slice(0, 100).map((item) => ({
      kb: String(item.kb ?? "").slice(0, 120),
      title: String(item.title ?? "").slice(0, 255),
      resultCode: Number(item.resultCode ?? 0) || 0,
    })),
    rebootRequired: value.rebootRequired === true,
  };
}

export function shouldReboot(policy: RebootPolicy, rebootRequired: boolean, changed: boolean) {
  if (policy === "always") return changed || rebootRequired;
  if (policy === "if_required") return rebootRequired;
  return false;
}

/** Delayed reboot, so the job result and the new inventory reach the platform first. */
export function rebootStep(windows: boolean): PatchStep {
  return windows
    ? {
      label: "reboot",
      command: "shutdown.exe",
      args: ["/r", "/t", "120", "/c", "MNSCloud: reboot after security updates", "/d", "p:2:17"],
    }
    : {
      label: "reboot",
      command: "shutdown",
      args: ["-r", "+2", "MNSCloud: reboot after security updates"],
    };
}

export type PatchOutcome = "success" | "partial" | "failed" | "nothing";

export type PatchResult = {
  patch: true;
  runUUID: string;
  outcome: PatchOutcome;
  packageManager: PackageManager;
  updated: PackageChange[];
  unchanged: string[];
  windows: WindowsPatchOutput | null;
  rebootRequired: boolean;
  rebootPolicy: RebootPolicy;
  rebootScheduled: boolean;
  durationMs: number;
  output: string;
  error: string | null;
};

export type PatchProgress = (step: string, percent: number, message: string) => Promise<unknown>;

export type PatchDeps = {
  run: CommandRunner;
  windows: boolean;
  powershell: () => string;
  encode: (script: string) => string;
  manager: () => Promise<PackageManager | null>;
  rebootRequired: () => Promise<boolean>;
  hasCommand: (name: string) => Promise<boolean>;
  now?: () => number;
};

function tail(text: string) {
  const clean = text.replace(/\r/g, "").trim();
  return clean.length > OUTPUT_TAIL ? clean.slice(clean.length - OUTPUT_TAIL) : clean;
}

function failure(result: CommandResult, label: string) {
  const detail = tail(result.stderr || result.stdout).split("\n").slice(-3).join(" ");
  return `${label} failed (exit ${result.code})${detail ? `: ${detail}` : ""}`;
}

/** Runs the patch. Never throws for a host failure: the outcome says what happened. */
export async function applyPatch(
  request: PatchRequest,
  deps: PatchDeps,
  progress: PatchProgress,
): Promise<PatchResult> {
  const now = deps.now ?? Date.now;
  const started = now();
  const timeoutMs = request.timeoutMinutes * 60_000;
  const manager = deps.windows ? "windows" : await deps.manager();
  const base = {
    patch: true as const,
    runUUID: request.runUUID,
    packageManager: (manager ?? "dpkg") as PackageManager,
    updated: [] as PackageChange[],
    unchanged: [] as string[],
    windows: null as WindowsPatchOutput | null,
    rebootPolicy: request.rebootPolicy,
    rebootScheduled: false,
  };
  const done = (
    outcome: PatchOutcome,
    rebootRequired: boolean,
    output: string,
    error: string | null,
    extra: Partial<PatchResult> = {},
  ): PatchResult => ({
    ...base,
    ...extra,
    outcome,
    rebootRequired,
    durationMs: now() - started,
    output: tail(output),
    error,
  });

  if (!manager) return done("failed", false, "", "No supported package manager on this host");

  if (manager === "windows") {
    await progress("windows_update", 20, "Searching and installing Windows updates");
    const result = await deps.run(deps.powershell(), [
      "-NoProfile",
      "-NonInteractive",
      "-ExecutionPolicy",
      "Bypass",
      "-EncodedCommand",
      deps.encode(windowsPatchScript(request.kbs)),
    ], timeoutMs);
    if (result.code !== 0) {
      return done(
        "failed",
        false,
        result.stdout + result.stderr,
        failure(result, "Windows Update"),
      );
    }
    let output: WindowsPatchOutput;
    try {
      output = parseWindowsPatch(result.stdout);
    } catch {
      return done("failed", false, result.stdout, "Windows Update returned an unreadable result");
    }
    const outcome: PatchOutcome = output.selected === 0
      ? "nothing"
      : output.resultCode === 2
      ? "success"
      : output.resultCode === 3
      ? "partial"
      : "failed";
    return done(
      outcome,
      output.rebootRequired,
      "",
      outcome === "failed" ? "Windows Update did not install the updates" : null,
      {
        windows: output,
      },
    );
  }

  if (request.scope !== "findings" && !request.packages.length) {
    return done("nothing", await deps.rebootRequired(), "", null);
  }
  const dnf = manager === "rpm" && !(await deps.hasCommand("dnf")) ? "yum" : "dnf";
  let steps: PatchStep[];
  try {
    steps = linuxPatchSteps(manager, request.packages, dnf);
  } catch (error) {
    return done("failed", false, "", String((error as Error).message));
  }
  const query = versionQuery(manager, request.packages);
  const versions = async () => {
    if (!query) return {};
    const result = await deps.run(query.command, query.args, 60_000);
    return parseVersions(manager, result.stdout, request.packages);
  };
  const before = await versions();
  let output = "";
  for (const [index, step] of steps.entries()) {
    await progress(
      step.label,
      20 + Math.round((index / steps.length) * 60),
      `Running ${step.label}`,
    );
    const result = await deps.run(step.command, step.args, timeoutMs);
    output += `${result.stdout}\n${result.stderr}\n`;
    if (result.code !== 0) {
      const after = await versions();
      const changes = packageChanges(before, after, request.packages);
      return done(
        changes.updated.length ? "partial" : "failed",
        await deps.rebootRequired(),
        output,
        failure(result, step.label),
        changes,
      );
    }
  }
  await progress("verify", 85, "Checking the installed versions");
  const changes = packageChanges(before, await versions(), request.packages);
  return done(
    changes.updated.length ? "success" : "nothing",
    await deps.rebootRequired(),
    output,
    null,
    changes,
  );
}
