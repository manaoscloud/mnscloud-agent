// macOS Agent (V10a): inventory parsers and collector, hardening checks, XProtect state and the
// launchd update job. Fixtures are real command outputs of macOS 14/15 hosts (trimmed).
import { assert, assertEquals, assertMatch } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { MACOS_UPDATE_LABEL, macosUpdatePlist } from "./macos-agent.ts";
import {
  collectSecurityInventory,
  type CommandResult,
  parseLsof,
  parseMacApplications,
  parseSwVers,
} from "./security-inventory.ts";
import {
  collectPosture,
  evaluateMacos,
  type MacFacts,
  parseDefaults,
  parseLaunchdDisabled,
  parseSoftwareUpdates,
  type PostureDeps,
  runAntivirusAction,
  xprotectState,
} from "./security-posture.ts";

const SW_VERS = "ProductName:\t\tmacOS\nProductVersion:\t\t14.6.1\nBuildVersion:\t\t23G93\n";

const APPS = JSON.stringify({
  SPApplicationsDataType: [
    {
      _name: "Safari",
      arch_kind: "arch_arm_i64",
      path: "/Applications/Safari.app",
      version: "18.0",
    },
    {
      _name: "Google Chrome",
      arch_kind: "arch_arm_i64",
      path: "/Applications/Google Chrome.app",
      version: "130.0.6723.92",
    },
    {
      _name: "Safari",
      arch_kind: "arch_arm_i64",
      path: "/Applications/Safari.app",
      version: "18.0",
    },
    {
      _name: "Calculator",
      arch_kind: "arch_arm_i64",
      path: "/System/Applications/Calculator.app",
      version: "11.0",
    },
    {
      _name: "Old Tool",
      arch_kind: "arch_i64",
      path: "/Applications/Old Tool.app",
      version: "2.1",
    },
    { _name: "No Version", path: "/Applications/No Version.app" },
  ],
});

const LSOF = [
  "p1",
  "claunchd",
  "PTCP",
  "n*:22",
  "PTCP",
  "n[::]:22",
  "p512",
  "cmDNSResponder",
  "PUDP",
  "n*:5353",
  "PUDP",
  "n192.168.1.20:55001->17.253.1.1:443",
  "p700",
  "ccupsd",
  "PTCP",
  "n127.0.0.1:631",
  "PTCP",
  "n[::1]:631",
  "",
].join("\n");

Deno.test("macOS inventory parsers: sw_vers, applications and listening sockets", () => {
  assertEquals(parseSwVers(SW_VERS), { name: "macOS", version: "14.6.1", build: "23G93" });
  assertEquals(parseSwVers("ProductName: macOS\nProductVersion: beta\n").version, null);
  const apps = parseMacApplications(APPS);
  assertEquals(apps.map((app) => [app.name, app.version, app.arch, app.source]), [
    ["Safari", "18.0", "arm64", "/Applications"],
    ["Google Chrome", "130.0.6723.92", "arm64", "/Applications"],
    ["Calculator", "11.0", "arm64", "/System/Applications"],
    ["Old Tool", "2.1", "x86_64", "/Applications"],
  ]);
  assertEquals(parseMacApplications(""), []);
  assertEquals(parseLsof(LSOF), [
    { protocol: "tcp", address: "0.0.0.0", port: 22, process: "launchd" },
    { protocol: "tcp", address: "::", port: 22, process: "launchd" },
    { protocol: "udp", address: "0.0.0.0", port: 5353, process: "mDNSResponder" },
    { protocol: "tcp", address: "127.0.0.1", port: 631, process: "cupsd" },
    { protocol: "tcp", address: "::1", port: 631, process: "cupsd" },
  ]);
});

/** Answers by the fixed absolute command, wherever a wrapper (nice) put it. */
function fakeRunner(answers: Record<string, CommandResult | ((args: string[]) => CommandResult)>) {
  const calls: string[][] = [];
  const run = (command: string, args: string[]) => {
    const all = [command, ...args];
    const index = all.findIndex((part) => part in answers);
    calls.push(all);
    if (index < 0) return Promise.resolve({ code: 127, stdout: "", stderr: "not found" });
    const answer = answers[all[index]];
    return Promise.resolve(typeof answer === "function" ? answer(all.slice(index + 1)) : answer);
  };
  return { run, calls };
}

const ok = (stdout: string): CommandResult => ({ code: 0, stdout, stderr: "" });

Deno.test("macOS inventory collector: the release is the package macos, then the applications", async () => {
  const { run } = fakeRunner({
    "/usr/bin/sw_vers": ok(SW_VERS),
    "/usr/bin/uname": (args) => ok(args[0] === "-r" ? "23.6.0\n" : "arm64\n"),
    "/usr/sbin/system_profiler": ok(APPS),
    "/usr/sbin/lsof": { code: 1, stdout: LSOF, stderr: "" },
  });
  const payload = await collectSecurityInventory({
    run,
    windows: false,
    macos: true,
    powershell: () => "pwsh",
  });
  assertEquals(payload.os, {
    family: "macos",
    id: "macos",
    versionId: "14.6.1",
    codename: null,
    name: "macOS 14.6.1",
    kernel: "23.6.0",
    arch: "arm64",
    build: "23G93",
    ubr: null,
    displayVersion: null,
  });
  assertEquals(payload.packageManager, "macos");
  const names = payload.packages.map((item) => `${item.name}@${item.version}`);
  assert(names.includes("macos@14.6.1"), names.join(","));
  assert(names.includes("Safari@18.0"));
  assertEquals(payload.ports.length, 5);
  assertEquals(payload.rebootRequired, null);
  assertMatch(payload.hash, /^[0-9a-f]{64}$/);
});

const DEFAULTS_UPDATE = `{
    AutomaticCheckEnabled = 1;
    AutomaticDownload = 1;
    AutomaticallyInstallMacOSUpdates = 0;
    ConfigDataInstall = 1;
    CriticalUpdateInstall = 1;
    LastSuccessfulDate = "2026-11-09 10:12:33 +0000";
}`;

const DISABLED = `disabled services = {
	"com.apple.screensharing" => disabled
	"com.openssh.sshd" => enabled
	"com.apple.smbd" => disabled
}
login item associations = {
}`;

const UPDATES = `Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sonoma 14.7.1-23H222
	Title: macOS Sonoma 14.7.1, Version: 14.7.1, Size: 1612345KiB, Recommended: YES, Action: restart,
* Label: Safari18.1SonomaAuto-18.1
	Title: Safari, Version: 18.1, Size: 166784KiB, Recommended: YES,
`;

function facts(extra: Partial<MacFacts> = {}): MacFacts {
  return {
    fileVault: "FileVault is On.",
    firewall: "Firewall is enabled. (State = 1)",
    stealth: "Firewall stealth mode is on",
    gatekeeper: "assessments enabled",
    sip: "System Integrity Protection status: enabled.",
    softwareUpdate: parseDefaults(DEFAULTS_UPDATE),
    pendingUpdates: [],
    launchdDisabled: parseLaunchdDisabled(DISABLED),
    sshd: new Map([["passwordauthentication", "no"]]),
    loginWindow: new Map(),
    xprotectVersion: "5272",
    xprotectUpdatedAt: "2026-11-04T18:00:00.000Z",
    ...extra,
  };
}

Deno.test("macOS parsers: defaults, launchd services and pending updates", () => {
  const values = parseDefaults(DEFAULTS_UPDATE);
  assertEquals(values.get("AutomaticallyInstallMacOSUpdates"), "0");
  assertEquals(values.get("LastSuccessfulDate"), "2026-11-09 10:12:33 +0000");
  const disabled = parseLaunchdDisabled(DISABLED);
  assertEquals(disabled.get("com.apple.screensharing"), true);
  assertEquals(disabled.get("com.openssh.sshd"), false);
  assertEquals(
    parseLaunchdDisabled('\t"com.openssh.sshd" => true\n').get("com.openssh.sshd"),
    true,
  );
  assertEquals(parseSoftwareUpdates(UPDATES), [
    "macOS Sonoma 14.7.1-23H222",
    "Safari18.1SonomaAuto-18.1",
  ]);
  assertEquals(
    parseSoftwareUpdates(
      "Software Update Tool\n\nFinding available software\nNo new software available.\n",
    ),
    [],
  );
});

Deno.test("macOS checks: a well configured Mac passes except automatic macOS installs", () => {
  const checks = evaluateMacos(facts());
  const status = Object.fromEntries(checks.map((item) => [item.code, item.status]));
  assertEquals(status, {
    "mac.filevault": "pass",
    "mac.firewall": "pass",
    "mac.firewall_stealth": "pass",
    "mac.gatekeeper": "pass",
    "mac.sip": "pass",
    "mac.update_check": "pass",
    "mac.security_updates": "pass",
    "mac.auto_install": "fail",
    "mac.updates_pending": "pass",
    "mac.ssh_password_auth": "pass",
    "mac.screen_sharing": "pass",
    "mac.guest_account": "pass",
    "mac.auto_login": "pass",
  });
  assert(checks.every((item) => item.benchmark === "CIS macOS"));
});

Deno.test("macOS checks: weak settings fail, unknown answers are errors, defaults apply", () => {
  const weak = evaluateMacos(facts({
    fileVault: "FileVault is Off.",
    firewall: "Firewall is disabled. (State = 0)",
    stealth: "Firewall stealth mode is off",
    gatekeeper: "assessments disabled",
    sip: "System Integrity Protection status: disabled.",
    softwareUpdate: new Map([["CriticalUpdateInstall", "0"]]),
    pendingUpdates: parseSoftwareUpdates(UPDATES),
    launchdDisabled: parseLaunchdDisabled(
      '\t"com.apple.screensharing" => enabled\n\t"com.openssh.sshd" => enabled\n',
    ),
    sshd: new Map([["passwordauthentication", "yes"]]),
    loginWindow: new Map([["GuestEnabled", "1"], ["autoLoginUser", "admin"]]),
  }));
  const failed = weak.filter((item) => item.status === "fail").map((item) => item.code);
  assertEquals(failed, [
    "mac.filevault",
    "mac.firewall",
    "mac.firewall_stealth",
    "mac.gatekeeper",
    "mac.sip",
    "mac.security_updates",
    "mac.auto_install",
    "mac.updates_pending",
    "mac.ssh_password_auth",
    "mac.screen_sharing",
    "mac.guest_account",
    "mac.auto_login",
  ]);
  assertEquals(
    weak.find((item) => item.code === "mac.update_check")?.status,
    "pass",
    "absent key = macOS default on",
  );
  assertMatch(
    weak.find((item) => item.code === "mac.updates_pending")?.evidence ?? "",
    /macOS Sonoma 14\.7\.1/,
  );
  const unknown = evaluateMacos(
    facts({ fileVault: null, pendingUpdates: null, launchdDisabled: null }),
  );
  const byCode = Object.fromEntries(unknown.map((item) => [item.code, item.status]));
  assertEquals([
    byCode["mac.filevault"],
    byCode["mac.updates_pending"],
    byCode["mac.screen_sharing"],
  ], ["error", "error", "error"]);
  const noSsh = evaluateMacos(facts({ launchdDisabled: new Map() }));
  assertEquals(
    noSsh.find((item) => item.code === "mac.ssh_password_auth")?.status,
    "not_applicable",
  );
});

Deno.test("XProtect state: built in, no actions", () => {
  assertEquals(xprotectState(facts()), {
    engine: "xprotect",
    installed: 1,
    serviceRunning: 1,
    realtime: 1,
    mode: null,
    engineVersion: null,
    signatureVersion: "5272",
    signatureUpdatedAt: "2026-11-04T18:00:00.000Z",
    quickScanAt: null,
    fullScanAt: null,
    installable: 0,
    note: null,
  });
  assertEquals(xprotectState(facts({ xprotectVersion: null })).installed, 0);
});

function macDeps(run: PostureDeps["run"]): PostureDeps {
  return {
    run,
    windows: false,
    macos: true,
    powershell: () => "pwsh",
    encode: (script) => script,
    readText: () => Promise.resolve(null),
    statMode: () => Promise.resolve(null),
    hasCommand: () => Promise.resolve(true),
    writeText: () => Promise.resolve(),
    statePath: "/tmp/none",
    packageManager: () => Promise.resolve(null),
    now: () => new Date("2026-11-10T12:00:00Z"),
  };
}

Deno.test("macOS posture job: fixed commands, platform macos, XProtect; antivirus actions refused", async () => {
  const { run, calls } = fakeRunner({
    "/usr/bin/defaults": (args) =>
      ok(
        args[1].endsWith("SoftwareUpdate")
          ? DEFAULTS_UPDATE
          : args[1].endsWith("loginwindow")
          ? "{\n    GuestEnabled = 0;\n}"
          : "5272\n",
      ),
    "/bin/launchctl": ok(DISABLED),
    "/usr/sbin/sshd": ok("passwordauthentication no\npermitrootlogin no\n"),
    "/usr/sbin/softwareupdate": { code: 0, stdout: "", stderr: "No new software available.\n" },
    "/usr/bin/stat": ok("1762279200\n"),
    "/usr/bin/fdesetup": ok("FileVault is On.\n"),
    "/usr/libexec/ApplicationFirewall/socketfilterfw": (args) =>
      ok(
        args[0] === "--getglobalstate"
          ? "Firewall is enabled. (State = 1)\n"
          : "Firewall stealth mode is on\n",
      ),
    "/usr/sbin/spctl": ok("assessments enabled\n"),
    "/usr/bin/csrutil": ok("System Integrity Protection status: enabled.\n"),
  });
  const result = await collectPosture(macDeps(run));
  assertEquals(result.platform, "macos");
  assertEquals(result.checks?.length, 13);
  assertEquals(result.checks?.filter((item) => item.status !== "pass").map((item) => item.code), [
    "mac.auto_install",
  ]);
  assertEquals(result.antivirus.engine, "xprotect");
  assertEquals(result.antivirus.signatureUpdatedAt, "2025-11-04T18:00:00.000Z");
  assertEquals(result.threats, []);
  assert(calls.every((call) => call[0].startsWith("/")), "only absolute system commands");
  const action = await runAntivirusAction(macDeps(run), "quick_scan");
  assertEquals(action.actionResult, {
    action: "quick_scan",
    outcome: "failed",
    message: "macOS updates and runs XProtect by itself",
  });
});

Deno.test("macOS update job: one-shot launchd job that survives the Agent restart", () => {
  const plist = macosUpdatePlist("/opt/mnscloud/mnscloud-agent", "v1.0.181");
  assertMatch(plist, new RegExp(`<string>${MACOS_UPDATE_LABEL.replaceAll(".", "\\.")}</string>`));
  assertMatch(plist, /<key>AbandonProcessGroup<\/key><true\/>/);
  assertMatch(plist, /<key>LaunchOnlyOnce<\/key><true\/>/);
  assertMatch(
    plist,
    /sleep 2 &amp;&amp; cd '\/opt\/mnscloud\/mnscloud-agent' &amp;&amp; \/bin\/bash scripts\/update-agent-macos\.sh --ref 'v1\.0\.181'/,
  );
  assertMatch(macosUpdatePlist("/opt/x", "v1'x"), /--ref 'v1'\\''x'/, "the ref is shell quoted");
});

Deno.test("macOS inventory collector: Safari from its bundle when system_profiler leaves it out", async () => {
  const apps = JSON.stringify({
    SPApplicationsDataType: [{
      _name: "Notes",
      path: "/System/Applications/Notes.app",
      version: "4.11",
    }],
  });
  const { run } = fakeRunner({
    "/usr/bin/sw_vers": ok(SW_VERS),
    "/usr/bin/uname": (args) => ok(args[0] === "-r" ? "24.1.0\n" : "arm64\n"),
    "/usr/sbin/system_profiler": ok(apps),
    "/usr/sbin/lsof": ok(""),
    "/usr/bin/defaults": ok("18.1\n"),
  });
  const payload = await collectSecurityInventory({
    run,
    windows: false,
    macos: true,
    powershell: () => "pwsh",
  });
  const safari = payload.packages.find((item) => item.name === "Safari");
  assertEquals([safari?.version, safari?.source], ["18.1", "/Applications"]);
});
