import { assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  applyPatch,
  dpkgInconsistent,
  linuxPatchSteps,
  lowPriority,
  MIN_FREE_KIB,
  packageChanges,
  parseFreeKiB,
  parsePatchRequest,
  parseVersions,
  parseWindowsPatch,
  PatchRequestError,
  rebootStep,
  shouldReboot,
  windowsPatchScript,
} from "./security-patch.ts";
import type { CommandResult } from "./security-inventory.ts";

const RUN = "0b6c2c8e-1d4e-4c8f-9a51-6f1a2b3c4d5e";

Deno.test("patch request refuses anything outside the fixed contract", () => {
  const ok = parsePatchRequest({
    runUUID: RUN,
    scope: "findings",
    packages: ["openssl", "libssl3", "openssl"],
    rebootPolicy: "if_required",
    timeoutMinutes: 999,
  });
  assertEquals(ok.packages, ["openssl", "libssl3"]);
  assertEquals(ok.timeoutMinutes, 150);
  assertThrows(
    () => parsePatchRequest({ ...ok, packages: ["openssl; rm -rf /"] }),
    PatchRequestError,
  );
  assertThrows(() => parsePatchRequest({ ...ok, packages: ["-oAPT::x"] }), PatchRequestError);
  assertThrows(() => parsePatchRequest({ ...ok, kbs: ["5034441"] }), PatchRequestError);
  assertThrows(() => parsePatchRequest({ ...ok, rebootPolicy: "now" }), PatchRequestError);
  assertThrows(() => parsePatchRequest({ ...ok, scope: "everything" }), PatchRequestError);
  assertThrows(() => parsePatchRequest({ ...ok, runUUID: "x" }), PatchRequestError);
});

Deno.test("linux steps only upgrade installed packages, with no shell", () => {
  const apt = linuxPatchSteps("dpkg", ["openssl"]);
  assertEquals(apt[1].command, "env");
  assertEquals(apt[1].args.includes("--only-upgrade"), true);
  assertEquals(apt[1].args.slice(-2), ["--", "openssl"]);
  const dnf = linuxPatchSteps("rpm", ["openssl"], "yum");
  assertEquals(dnf[0].command, "yum");
  assertEquals(dnf[0].args.slice(-3), ["upgrade", "--", "openssl"]);
  assertEquals(linuxPatchSteps("apk", ["musl"])[1].args.slice(-2), ["--", "musl"]);
  assertThrows(() => linuxPatchSteps("dpkg", []), PatchRequestError);
  assertThrows(() => linuxPatchSteps("windows", ["x"]), PatchRequestError);
});

Deno.test("versions and changes per package manager", () => {
  assertEquals(
    parseVersions("dpkg", "openssl\t3.0.11-1~deb12u2\nlibssl3\t3.0.11-1~deb12u2\n", ["openssl"]),
    { openssl: "3.0.11-1~deb12u2" },
  );
  assertEquals(
    parseVersions("rpm", "openssl\t1:3.0.7-25.el9\nbash\t0:5.1.8-9.el9\n", ["openssl", "bash"]),
    { openssl: "1:3.0.7-25.el9", bash: "5.1.8-9.el9" },
  );
  assertEquals(parseVersions("apk", "musl-1.2.4-r2\n", ["musl"]), { musl: "1.2.4-r2" });
  assertEquals(
    packageChanges({ a: "1", b: "1" }, { a: "2", b: "1" }, ["a", "b", "c"]),
    { updated: [{ name: "a", from: "1", to: "2" }], unchanged: ["b", "c"] },
  );
});

Deno.test("windows script embeds only validated KBs and parses the result", () => {
  const script = windowsPatchScript(["KB5034441"]);
  assertEquals(script.includes("$wanted = @('KB5034441')"), true);
  assertEquals(windowsPatchScript([]).includes("$wanted = @()"), true);
  assertThrows(() => windowsPatchScript(["KB1'; Remove-Item"]), PatchRequestError);
  const out = parseWindowsPatch(
    'noise\n{"selected":1,"resultCode":2,"installed":{"kb":"KB5034441","title":"Security","resultCode":2},"rebootRequired":true}',
  );
  assertEquals(out.installed.length, 1);
  assertEquals(out.rebootRequired, true);
});

Deno.test("reboot follows the explicit policy", () => {
  assertEquals(shouldReboot("never", true, true), false);
  assertEquals(shouldReboot("if_required", true, false), true);
  assertEquals(shouldReboot("if_required", false, true), false);
  assertEquals(shouldReboot("always", false, true), true);
  assertEquals(shouldReboot("always", false, false), false);
  assertEquals(rebootStep(false).args[1], "+2");
  assertEquals(rebootStep(true).command, "shutdown.exe");
});

const DF_OK = {
  code: 0,
  stdout: "Filesystem 1024-blocks Used Available Capacity Mounted on\n" +
    "/dev/sda1 20000000 8000000 12000000 40% /\n/dev/sda1 20000000 8000000 12000000 40% /\n",
  stderr: "",
};

function runner(answers: Record<string, CommandResult>, calls: string[]) {
  return (command: string, args: string[]) => {
    const audits = calls.filter((c) => c === "audit").length;
    const key = command === "df"
      ? "df"
      : command === "dpkg" && args.includes("--audit")
      ? `audit${audits}`
      : args.includes("--configure")
      ? "recover"
      : args.includes("update") && !args.includes("--only-upgrade")
      ? "refresh"
      : command === "dpkg-query"
      ? `versions${calls.filter((c) => c === "dpkg-query").length}`
      : "upgrade";
    calls.push(
      key.startsWith("audit") ? "audit" : key === "df" || key === "recover" ? key : command,
    );
    const fallback = key === "df" ? DF_OK : { code: 0, stdout: "", stderr: "" };
    return Promise.resolve(answers[key] ?? fallback);
  };
}

const linuxDeps = (run: ReturnType<typeof runner>, tools = true) => ({
  run,
  windows: false,
  powershell: () => "powershell",
  encode: (s: string) => s,
  manager: () => Promise.resolve("dpkg" as const),
  rebootRequired: () => Promise.resolve(false),
  hasCommand: () => Promise.resolve(tools),
});

const request = () =>
  parsePatchRequest({
    runUUID: RUN,
    scope: "findings",
    packages: ["openssl"],
    rebootPolicy: "never",
  });

Deno.test("low priority wraps steps with nice and ionice when present", () => {
  const step = { label: "upgrade", command: "env", args: ["apt-get", "-y"] };
  assertEquals(lowPriority(step, { nice: true, ionice: true }).args, [
    "-n",
    "10",
    "ionice",
    "-c2",
    "-n7",
    "env",
    "apt-get",
    "-y",
  ]);
  assertEquals(lowPriority(step, { nice: true, ionice: false }).args, [
    "-n",
    "10",
    "env",
    "apt-get",
    "-y",
  ]);
  assertEquals(lowPriority(step, { nice: false, ionice: true }), step);
});

Deno.test("free space and dpkg audit parsing", () => {
  assertEquals(parseFreeKiB(DF_OK.stdout), 12000000);
  assertEquals(
    parseFreeKiB(
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/a 1 1 300 1% /var\n/b 1 1 9000 1% /\n",
    ),
    300,
  );
  assertEquals(parseFreeKiB("garbage"), null);
  assertEquals(dpkgInconsistent({ code: 0, stdout: "", stderr: "" }), false);
  assertEquals(
    dpkgInconsistent({
      code: 0,
      stdout: "The following packages are only half configured",
      stderr: "",
    }),
    true,
  );
  assertEquals(dpkgInconsistent({ code: 1, stdout: "", stderr: "" }), true);
});

Deno.test("apply refuses to start without free disk space and touches nothing", async () => {
  const calls: string[] = [];
  const small = `Filesystem 1024-blocks Used Available Capacity Mounted on\n/a 1 1 ${
    MIN_FREE_KIB - 1
  } 99% /var\n`;
  const result = await applyPatch(
    request(),
    linuxDeps(runner({ df: { code: 0, stdout: small, stderr: "" } }, calls)),
    () => Promise.resolve(),
  );
  assertEquals(result.outcome, "failed");
  assertEquals(result.error?.startsWith("Not enough free disk space"), true);
  assertEquals(calls, ["df"]);
});

Deno.test("apply repairs half-configured packages before updating", async () => {
  const calls: string[] = [];
  const result = await applyPatch(
    request(),
    linuxDeps(runner({
      audit0: { code: 0, stdout: "half configured: libc6", stderr: "" },
      versions0: { code: 0, stdout: "openssl\t3.0.11-1\n", stderr: "" },
      versions1: { code: 0, stdout: "openssl\t3.0.15-1\n", stderr: "" },
    }, calls)),
    () => Promise.resolve(),
  );
  assertEquals(result.outcome, "success");
  assertEquals(result.recovery, { attempted: true, repaired: true });
  assertEquals(calls.slice(0, 4), ["df", "audit", "recover", "audit"]);
});

Deno.test("apply stops when dpkg cannot be repaired", async () => {
  const calls: string[] = [];
  const broken = { code: 1, stdout: "half configured: libc6", stderr: "" };
  const result = await applyPatch(
    request(),
    linuxDeps(runner({ audit0: broken, audit1: broken }, calls)),
    () => Promise.resolve(),
  );
  assertEquals(result.outcome, "failed");
  assertEquals(result.recovery, { attempted: true, repaired: false });
  assertEquals(calls.includes("nice"), false);
});

Deno.test("apply finishes interrupted dpkg configuration after a killed upgrade", async () => {
  const calls: string[] = [];
  const result = await applyPatch(
    request(),
    linuxDeps(runner({
      upgrade: { code: 137, stdout: "", stderr: "killed" },
      audit1: { code: 0, stdout: "half configured: openssl", stderr: "" },
    }, calls)),
    () => Promise.resolve(),
  );
  assertEquals(result.outcome, "failed");
  assertEquals(result.recovery, { attempted: true, repaired: true });
  assertEquals(calls.slice(-4), ["audit", "recover", "audit", "dpkg-query"]);
});

Deno.test("apply reports success with the updated versions", async () => {
  const calls: string[] = [];
  const result = await applyPatch(
    parsePatchRequest({
      runUUID: RUN,
      scope: "findings",
      packages: ["openssl"],
      rebootPolicy: "never",
    }),
    {
      run: runner({
        versions0: { code: 0, stdout: "openssl\t3.0.11-1\n", stderr: "" },
        versions1: { code: 0, stdout: "openssl\t3.0.15-1\n", stderr: "" },
      }, calls),
      windows: false,
      powershell: () => "powershell",
      encode: (s) => s,
      manager: () => Promise.resolve("dpkg"),
      rebootRequired: () => Promise.resolve(true),
      hasCommand: () => Promise.resolve(true),
    },
    () => Promise.resolve(),
  );
  assertEquals(result.outcome, "success");
  assertEquals(result.updated, [{ name: "openssl", from: "3.0.11-1", to: "3.0.15-1" }]);
  assertEquals(result.rebootRequired, true);
  assertEquals(calls, ["df", "audit", "dpkg-query", "nice", "nice", "dpkg-query"]);
});

Deno.test("apply turns a failed upgrade into a failed outcome without throwing", async () => {
  const result = await applyPatch(
    parsePatchRequest({
      runUUID: RUN,
      scope: "findings",
      packages: ["openssl"],
      rebootPolicy: "always",
    }),
    {
      run: runner({ upgrade: { code: 100, stdout: "", stderr: "E: Unable to lock" } }, []),
      windows: false,
      powershell: () => "powershell",
      encode: (s) => s,
      manager: () => Promise.resolve("dpkg"),
      rebootRequired: () => Promise.resolve(false),
      hasCommand: () => Promise.resolve(true),
    },
    () => Promise.resolve(),
  );
  assertEquals(result.outcome, "failed");
  assertEquals(result.error?.includes("Unable to lock"), true);
});

Deno.test("reboot scope is accepted only without packages or KBs", () => {
  const ok = parsePatchRequest({
    runUUID: RUN,
    scope: "reboot",
    packages: [],
    kbs: [],
    rebootPolicy: "always",
  });
  assertEquals(ok.scope, "reboot");
  assertThrows(
    () => parsePatchRequest({ ...ok, packages: ["openssl"] }),
    PatchRequestError,
  );
  assertThrows(() => parsePatchRequest({ ...ok, kbs: ["KB5034441"] }), PatchRequestError);
});

Deno.test("reboot scope runs no update command and still reboots under always", async () => {
  const calls: string[] = [];
  const req = parsePatchRequest({
    runUUID: RUN,
    scope: "reboot",
    packages: [],
    kbs: [],
    rebootPolicy: "always",
  });
  for (const windows of [false, true]) {
    const result = await applyPatch(
      req,
      { ...linuxDeps(runner({}, calls)), windows },
      () => Promise.resolve(),
    );
    assertEquals(result.outcome, "nothing");
    assertEquals(result.error, null);
  }
  assertEquals(calls, []);
  assertEquals(shouldReboot("always", false, false, "reboot"), true);
  assertEquals(shouldReboot("never", true, true, "reboot"), false);
  assertEquals(shouldReboot("always", false, false, "findings"), false);
});
