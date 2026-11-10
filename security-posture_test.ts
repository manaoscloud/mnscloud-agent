import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  ANTIVIRUS_COMMAND,
  AntivirusRequestError,
  clamInstallSteps,
  collectLinuxFacts,
  collectPosture,
  defenderState,
  defenderThreats,
  evaluateLinux,
  evaluateWindows,
  type LinuxFacts,
  memInfoKb,
  mergeScan,
  parseAntivirusAction,
  parseClamFindings,
  parseClamVersion,
  parseSshdConfig,
  POSTURE_COMMAND,
  type PostureDeps,
  readProc,
  runAntivirusAction,
  threatKey,
  WINDOWS_POSTURE_SCRIPT,
} from "./security-posture.ts";

const MEMINFO_BIG = "MemTotal:        4000000 kB\nMemAvailable:    2500000 kB\n";
const MEMINFO_SMALL = "MemTotal:         460000 kB\nMemAvailable:     200000 kB\n";

type Call = { command: string; args: string[] };

function fakeDeps(options: {
  files?: Record<string, string>;
  commands?: string[];
  answers?: Record<string, { code: number; stdout?: string; stderr?: string }>;
  windows?: boolean;
  manager?: "dpkg" | "rpm" | "apk" | null;
}) {
  const calls: Call[] = [];
  const written: Record<string, string> = {};
  const files = { ...(options.files ?? {}) };
  const deps: PostureDeps = {
    run: (command, args) => {
      calls.push({ command, args });
      const key = [command, ...args].join(" ");
      const answer = Object.entries(options.answers ?? {}).find(([prefix]) =>
        key.startsWith(prefix)
      )?.[1];
      if (!answer && command === "cat" && args[0]?.startsWith("/proc/")) {
        const text = files[args[0]];
        return Promise.resolve({
          code: text === undefined ? 1 : 0,
          stdout: text ?? "",
          stderr: "",
        });
      }
      return Promise.resolve({
        code: answer?.code ?? 0,
        stdout: answer?.stdout ?? "",
        stderr: answer?.stderr ?? "",
      });
    },
    windows: options.windows ?? false,
    powershell: () => "powershell.exe",
    encode: (script) => `encoded:${script.length}`,
    // Deno 2 refuses direct /proc reads without --allow-all: /proc is served only through `cat`.
    readText: (path) =>
      Promise.resolve(path.startsWith("/proc/") ? null : files[path] ?? written[path] ?? null),
    statMode: (path) =>
      Promise.resolve(
        path === "/etc/shadow"
          ? { mode: 0o100640, uid: 0 }
          : path === "/etc/passwd"
          ? { mode: 0o100644, uid: 0 }
          : ["/tmp", "/home", "/root"].includes(path)
          ? { mode: 0o40755, uid: 0 }
          : null,
      ),
    hasCommand: (name) => Promise.resolve((options.commands ?? []).includes(name)),
    writeText: (path, text) => {
      written[path] = text;
      return Promise.resolve();
    },
    statePath: "/var/lib/mnscloud/security-antivirus.json",
    packageManager: () => Promise.resolve(options.manager === undefined ? "dpkg" : options.manager),
    now: () => new Date("2026-11-10T12:00:00Z"),
  };
  return { deps, calls, written };
}

function facts(overrides: Partial<LinuxFacts> = {}): LinuxFacts {
  return {
    sshd: parseSshdConfig(
      "permitrootlogin prohibit-password\npasswordauthentication no\npermitemptypasswords no\nmaxauthtries 3\nx11forwarding no\n",
    ),
    passwd: "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n",
    shadow: "root:$y$j9T$hash:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\n",
    loginDefs: "PASS_MAX_DAYS\t365\n",
    shadowStat: { mode: 0o100640, uid: 0 },
    passwdStat: { mode: 0o100644, uid: 0 },
    sysctl: {
      "kernel.randomize_va_space": "2",
      "fs.suid_dumpable": "0",
      "kernel.dmesg_restrict": "1",
      "net.ipv4.ip_forward": "0",
      "net.ipv4.conf.all.accept_redirects": "0",
      "net.ipv4.conf.all.send_redirects": "0",
      "net.ipv4.conf.all.accept_source_route": "0",
      "net.ipv4.conf.all.rp_filter": "1",
      "net.ipv4.tcp_syncookies": "1",
      "net.ipv6.conf.all.accept_redirects": "0",
    },
    activeUnits: new Set(["chrony", "auditd"]),
    firewall: "nftables input hook",
    ...overrides,
  };
}

Deno.test("commands and actions are a fixed list", () => {
  assertEquals(POSTURE_COMMAND, "cyber.security.posture.collect");
  assertEquals(ANTIVIRUS_COMMAND, "cyber.security.antivirus.run");
  assertEquals(parseAntivirusAction({ action: "quick_scan" }), "quick_scan");
  for (const bad of [{}, { action: "rm -rf /" }, null, ["update"], { action: "UPDATE" }]) {
    assertThrows(() => parseAntivirusAction(bad), AntivirusRequestError);
  }
});

Deno.test("a hardened Linux host passes every check", () => {
  const checks = evaluateLinux(facts());
  assertEquals(checks.length, 21);
  assertEquals(checks.filter((item) => item.status !== "pass"), []);
  assertEquals(new Set(checks.map((item) => item.code)).size, checks.length);
  for (const item of checks) assert(/^[a-z0-9][a-z0-9._]{0,59}$/.test(item.code), item.code);
});

Deno.test("weak Linux settings fail with evidence and never leak password hashes", () => {
  const checks = evaluateLinux(facts({
    sshd: parseSshdConfig(
      "permitrootlogin yes\npasswordauthentication yes\npermitemptypasswords no\nmaxauthtries 6\n",
    ),
    passwd: "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n",
    shadow: "root:$6$secret$hash:1::::::\nguest::19000::::::\n",
    loginDefs: "PASS_MAX_DAYS 99999\n",
    shadowStat: { mode: 0o100644, uid: 0 },
    sysctl: { ...facts().sysctl, "kernel.randomize_va_space": "0", "net.ipv4.ip_forward": "1" },
    activeUnits: new Set(),
    firewall: null,
  }));
  const status = Object.fromEntries(checks.map((item) => [item.code, item.status]));
  assertEquals(status["ssh.root_login"], "fail");
  assertEquals(status["ssh.password_auth"], "fail");
  assertEquals(status["ssh.max_auth_tries"], "fail");
  assertEquals(status["ssh.x11_forwarding"], "error");
  assertEquals(status["accounts.uid0"], "fail");
  assertEquals(status["accounts.empty_password"], "fail");
  assertEquals(status["accounts.pass_max_days"], "fail");
  assertEquals(status["files.shadow_permissions"], "fail");
  assertEquals(status["sysctl.aslr"], "fail");
  assertEquals(status["sysctl.send_redirects"], "not_applicable");
  assertEquals(status["firewall.active"], "fail");
  assertEquals(status["time.sync"], "fail");
  const evidence = checks.map((item) => item.evidence ?? "").join("\n");
  assert(!evidence.includes("$6$") && !evidence.includes("secret"), evidence);
  assertEquals(checks.find((item) => item.code === "accounts.empty_password")?.evidence, "guest");
  assertEquals(
    checks.find((item) => item.code === "files.shadow_permissions")?.evidence,
    "0644 uid 0",
  );
});

Deno.test("IPv6 redirects fail the redirects check and show in its evidence", () => {
  const base = facts();
  const result = evaluateLinux(
    facts({ sysctl: { ...base.sysctl, "net.ipv6.conf.all.accept_redirects": "1" } }),
  ).find((item) => item.code === "sysctl.accept_redirects");
  assertEquals(result?.status, "fail");
  assertEquals(
    result?.evidence,
    "net.ipv4.conf.all.accept_redirects = 0, net.ipv6.conf.all.accept_redirects = 1",
  );
});

Deno.test("no OpenSSH server = SSH checks not applicable", () => {
  const checks = evaluateLinux(facts({ sshd: null })).filter((item) =>
    item.code.startsWith("ssh.")
  );
  assertEquals(checks.map((item) => item.status), Array(5).fill("not_applicable"));
});

Deno.test("sysctl values and memory are read through cat, not a direct /proc read", async () => {
  const { deps, calls } = fakeDeps({
    files: {
      "/proc/sys/kernel/randomize_va_space": "2\n",
      "/proc/sys/net/ipv4/tcp_syncookies": "1\n",
    },
  });
  const linux = await collectLinuxFacts(deps);
  assertEquals(linux.sysctl["kernel.randomize_va_space"], "2");
  assertEquals(linux.sysctl["net.ipv4.tcp_syncookies"], "1");
  assertEquals(linux.sysctl["fs.suid_dumpable"], null);
  assert(
    calls.some((call) =>
      call.command === "cat" && call.args[0] === "/proc/sys/kernel/randomize_va_space"
    ),
  );
  assertEquals(memInfoKb(await readProc(deps, "/proc/meminfo"), "MemTotal"), null);
});

Deno.test("ClamAV version, findings and scan state", async () => {
  const version = parseClamVersion("ClamAV 1.0.7/27450/Sat Nov  9 08:21:26 2026\n");
  assertEquals(version.engineVersion, "1.0.7");
  assertEquals(version.signatureVersion, "27450");
  assert(version.signatureUpdatedAt?.startsWith("2026-11-09"));
  assertEquals(parseClamVersion("ClamAV 1.0.7").signatureVersion, null);
  const found = parseClamFindings("/home/u/eicar.txt: Win.Test.EICAR_HDB-1 FOUND\n/tmp/ok: OK\n");
  assertEquals(found, [{ path: "/home/u/eicar.txt", name: "Win.Test.EICAR_HDB-1" }]);
  const state = {
    quickScanAt: null,
    fullScanAt: null,
    threats: [
      { name: "Old", path: "/home/u/old.bin", detectedAt: "2026-11-01T00:00:00Z" },
      { name: "Elsewhere", path: "/opt/app/x", detectedAt: "2026-11-01T00:00:00Z" },
    ],
  };
  const quick = mergeScan(state, ["/home", "/tmp"], found, "2026-11-10T12:00:00Z", false);
  assertEquals(quick.threats.map((item) => item.name), ["Win.Test.EICAR_HDB-1", "Elsewhere"]);
  assertEquals(quick.quickScanAt, "2026-11-10T12:00:00Z");
  const full = mergeScan(quick, ["/"], [], "2026-11-10T13:00:00Z", true);
  assertEquals(full.threats, []);
  assertEquals(full.fullScanAt, "2026-11-10T13:00:00Z");
  assertEquals((await threatKey("clamav", "a", "b")).length, 64);
});

Deno.test("Linux posture without ClamAV reports it as installable on a large host", async () => {
  const { deps } = fakeDeps({
    files: {
      "/proc/meminfo": MEMINFO_BIG,
      "/etc/passwd": "root:x:0:0::/root:/bin/sh\n",
      "/etc/shadow": "root:*:1::::::\n",
    },
    commands: ["systemctl"],
    answers: { "systemctl is-active": { code: 3, stdout: "inactive\n" } },
  });
  const result = await collectPosture(deps);
  assertEquals(result.platform, "linux");
  assertEquals(result.antivirus.engine, "none");
  assertEquals(result.antivirus.installable, 1);
  assertEquals(result.threats, []);
  assert((result.checks ?? []).length === 21);
  assertEquals(result.checks?.find((item) => item.code === "firewall.active")?.status, "fail");
});

Deno.test("ClamAV install refuses small hosts and uses the host package manager", async () => {
  const small = fakeDeps({ files: { "/proc/meminfo": MEMINFO_SMALL } });
  const refused = await runAntivirusAction(small.deps, "install");
  assertEquals(refused.actionResult?.outcome, "failed");
  assertEquals(refused.antivirus.installable, 0);
  assertEquals(small.calls.filter((call) => call.command === "env"), []);
  const big = fakeDeps({ files: { "/proc/meminfo": MEMINFO_BIG }, commands: ["systemctl"] });
  const installed = await runAntivirusAction(big.deps, "install");
  assertEquals(installed.actionResult?.outcome, "success");
  assertEquals(
    big.calls.filter((call) => call.command === "env").map((call) => call.args.slice(1, 3)),
    [
      ["apt-get", "update"],
      ["apt-get", "install"],
    ],
  );
  assert(
    big.calls.some((call) =>
      call.command === "systemctl" && call.args.join(" ") === "enable --now clamav-freshclam"
    ),
  );
  assertEquals(clamInstallSteps("rpm")[0].args, ["-y", "install", "clamav", "clamav-update"]);
  assertEquals(clamInstallSteps("apk")[0].args, ["add", "clamav-scanner", "freshclam"]);
});

Deno.test("ClamAV quick scan runs at low priority on fixed paths and records threats", async () => {
  const { deps, calls, written } = fakeDeps({
    files: { "/proc/meminfo": MEMINFO_BIG },
    commands: ["clamscan", "systemctl", "nice", "ionice"],
    answers: {
      "systemctl is-active": { code: 0, stdout: "inactive\n" },
      "clamscan --version": { code: 0, stdout: "ClamAV 1.0.7/27450/Sat Nov  9 08:21:26 2026\n" },
      "nice -n 19 ionice -c 3 clamscan": {
        code: 1,
        stdout: "/home/u/eicar.txt: Win.Test.EICAR_HDB-1 FOUND\n",
      },
    },
  });
  const result = await runAntivirusAction(deps, "quick_scan");
  assertEquals(result.actionResult, {
    action: "quick_scan",
    outcome: "success",
    message: "1 infected file(s) found",
    infected: 1,
  });
  const scan = calls.find((call) => call.command === "nice");
  assertEquals(scan?.args.slice(0, 6), ["-n", "19", "ionice", "-c", "3", "clamscan"]);
  assertEquals(scan?.args.slice(-3), ["/tmp", "/home", "/root"]);
  assertEquals(result.threats.length, 1);
  assertEquals(result.threats[0].status, "active");
  assertEquals(result.antivirus.quickScanAt, "2026-11-10T12:00:00.000Z");
  assert(written["/var/lib/mnscloud/security-antivirus.json"].includes("EICAR"));
  assertEquals(result.checks, undefined, "an action keeps the checks");
});

Deno.test("ClamAV scan without enough free memory fails before scanning", async () => {
  const { deps, calls } = fakeDeps({
    files: { "/proc/meminfo": "MemTotal: 2000000 kB\nMemAvailable: 300000 kB\n" },
    commands: ["clamscan", "systemctl"],
  });
  const result = await runAntivirusAction(deps, "full_scan");
  assertEquals(result.actionResult?.outcome, "failed");
  assertEquals(calls.filter((call) => call.command === "clamscan" && call.args[0] === "-r"), []);
});

Deno.test("freshclam update stops and restarts the updater service", async () => {
  const { deps, calls } = fakeDeps({
    files: { "/proc/meminfo": MEMINFO_BIG },
    commands: ["clamscan", "systemctl"],
    answers: {
      "systemctl is-active": {
        code: 0,
        stdout:
          "inactive\ninactive\ninactive\ninactive\ninactive\ninactive\ninactive\ninactive\ninactive\nactive\n",
      },
      "freshclam": { code: 1 },
    },
  });
  const result = await runAntivirusAction(deps, "update");
  assertEquals(result.actionResult?.message, "Signatures already up to date");
  const order = calls.filter((call) => call.command !== "systemctl" || call.args[0] !== "is-active")
    .map((call) => [call.command, call.args[0]].join(" "));
  assertEquals(order.slice(0, 3), ["systemctl stop", "freshclam --stdout", "systemctl start"]);
});

Deno.test("Windows checks, Defender state and threats", async () => {
  const checks = evaluateWindows({
    build: 20348,
    firewall: [{ name: "Domain", enabled: true }, { name: "Private", enabled: true }, {
      name: "Public",
      enabled: false,
    }],
    smb1: false,
    smbSigning: false,
    rdpDenied: 0,
    rdpNla: 1,
    guestEnabled: false,
    minPasswordLength: "8",
    passwordComplexity: "1",
    lockoutThreshold: "0",
    enableLua: 1,
    llmnr: null,
    autorun: 255,
    wuauserv: "Manual",
    tls10: null,
    runAsPpl: null,
    wdigest: null,
  });
  const status = Object.fromEntries(checks.map((item) => [item.code, item.status]));
  assertEquals(checks.length, 15);
  assertEquals(status["win.firewall_profiles"], "fail");
  assertEquals(checks[0].evidence, "off: Public");
  assertEquals(status["win.smb1_disabled"], "pass");
  assertEquals(status["win.smb_signing"], "fail");
  assertEquals(status["win.rdp_nla"], "pass");
  assertEquals(status["win.password_length"], "fail");
  assertEquals(status["win.lockout_threshold"], "fail");
  assertEquals(status["win.uac_enabled"], "pass");
  assertEquals(status["win.tls10_disabled"], "fail");
  assertEquals(status["win.wdigest_disabled"], "pass");
  assertEquals(
    evaluateWindows({ rdpDenied: 1 }).find((item) => item.code === "win.rdp_nla")?.status,
    "not_applicable",
  );
  assertEquals(defenderState(null).engine, "none");
  const state = defenderState({
    serviceEnabled: true,
    realtime: true,
    mode: "Passive Mode",
    signatureVersion: "1.421.0.0",
  });
  assertEquals([state.engine, state.realtime, state.installable], ["defender", 1, 0]);
  assert(state.note?.includes("passive"));
  const threats = await defenderThreats([
    {
      id: "2147519003",
      name: "Virus:DOS/EICAR_Test_File",
      severity: 5,
      statusId: 3,
      path: "file:_C:\\Users\\a\\eicar.com",
      detectedAt: "2026-11-10T01:00:00Z",
    },
    {
      id: "1",
      name: "Trojan:Win32/X",
      severity: 4,
      statusId: 103,
      path: "file:_C:\\x.exe",
      detectedAt: "2026-11-10T02:00:00Z",
    },
  ]);
  assertEquals(threats.map((item) => [item.status, item.action, item.severity, item.path]), [
    ["resolved", "quarantined", "severe", "C:\\Users\\a\\eicar.com"],
    ["active", "failed", "high", "C:\\x.exe"],
  ]);
  assertEquals(new Set(threats.map((item) => item.key)).size, 2);
});

Deno.test("Windows posture runs the fixed encoded script and refuses ClamAV install", async () => {
  const output = JSON.stringify({
    facts: { build: 26100, firewall: { name: "Domain", enabled: true }, rdpDenied: 1 },
    defender: { serviceEnabled: true, realtime: true, mode: "Normal" },
    threats: [],
  });
  const { deps, calls } = fakeDeps({
    windows: true,
    answers: { "powershell.exe": { code: 0, stdout: output } },
  });
  const result = await collectPosture(deps);
  assertEquals(result.platform, "windows");
  assertEquals(result.antivirus.engine, "defender");
  assertEquals(
    result.checks?.find((item) => item.code === "win.firewall_profiles")?.status,
    "pass",
  );
  assertEquals(calls[0].args.slice(-2), [
    "-EncodedCommand",
    `encoded:${WINDOWS_POSTURE_SCRIPT.length}`,
  ]);
  const install = await runAntivirusAction(deps, "install");
  assertEquals(install.actionResult?.outcome, "failed");
  const broken = fakeDeps({
    windows: true,
    answers: { "powershell.exe": { code: 1, stderr: "denied" } },
  });
  await assertRejects(() => collectPosture(broken.deps), Error, "Windows posture script failed");
});
