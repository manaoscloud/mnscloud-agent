import { assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  parseApkSimulation,
  parseAptSimulation,
  parseDnfSimulation,
  parseSimulateRequest,
  parseWindowsSimulation,
  rebootLikely,
  simulatePatch,
  simulateStep,
  windowsSimulateScript,
} from "./security-patch-simulate.ts";
import { PatchRequestError } from "./security-patch.ts";
import type { CommandResult } from "./security-inventory.ts";

const SIM = "0b6c2c8e-1d4e-4c8f-9a51-6f1a2b3c4d5e";

Deno.test("simulation request keeps the patch job's validation", () => {
  const ok = parseSimulateRequest({
    simulationUUID: SIM,
    scope: "findings",
    packages: ["openssl", "libssl3", "openssl"],
    timeoutMinutes: 99,
  });
  assertEquals(ok.packages, ["openssl", "libssl3"]);
  assertEquals(ok.timeoutMinutes, 15);
  assertThrows(
    () => parseSimulateRequest({ ...ok, packages: ["openssl; reboot"] }),
    PatchRequestError,
  );
  assertThrows(() => parseSimulateRequest({ ...ok, packages: ["-oAPT::x"] }), PatchRequestError);
  assertThrows(() => parseSimulateRequest({ ...ok, scope: "reboot" }), PatchRequestError);
  assertThrows(() => parseSimulateRequest({ ...ok, simulationUUID: "x" }), PatchRequestError);
  assertThrows(() => parseSimulateRequest({ ...ok, kbs: ["123"] }), PatchRequestError);
});

Deno.test("simulation commands never install, refresh or lock", () => {
  const apt = simulateStep("dpkg", ["openssl"]);
  assertEquals(apt.command, "env");
  assertEquals(apt.args.includes("-s"), true);
  assertEquals(apt.args.includes("Debug::NoLocking=1"), true);
  assertEquals(apt.args.includes("-y"), false);
  assertEquals(apt.args.includes("update"), false);
  assertEquals(apt.args.slice(-2), ["--", "openssl"]);
  const dnf = simulateStep("rpm", ["openssl"], "yum");
  assertEquals(dnf.args.slice(0, 4), ["LC_ALL=C", "yum", "--assumeno", "-C"]);
  assertEquals(dnf.args.includes("-y"), false);
  assertEquals(simulateStep("apk", ["musl"]).args, ["upgrade", "-s", "--", "musl"]);
  assertThrows(() => simulateStep("dpkg", []), PatchRequestError);
  assertThrows(() => simulateStep("windows", ["x"]), PatchRequestError);
});

Deno.test("apt simulation lists upgrades, new packages and removals", () => {
  const plan = parseAptSimulation([
    "NOTE: This is only a simulation!",
    "Inst libssl3 [3.0.11-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])",
    "Inst openssl [3.0.11-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])",
    "Inst libnew1 (2.0-1 Debian:12/stable [amd64])",
    "Remv oldpkg [0.9-1]",
    "Conf libssl3 (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])",
  ].join("\n"));
  assertEquals(plan.upgrade, [
    { name: "libssl3", from: "3.0.11-1~deb12u1", to: "3.0.15-1~deb12u1" },
    { name: "openssl", from: "3.0.11-1~deb12u1", to: "3.0.15-1~deb12u1" },
  ]);
  assertEquals(plan.install, [{ name: "libnew1", to: "2.0-1" }]);
  assertEquals(plan.remove, [{ name: "oldpkg", from: "0.9-1" }]);
});

Deno.test("dnf simulation reads the transaction table", () => {
  const plan = parseDnfSimulation([
    "Dependencies resolved.",
    "================================================================================",
    " Package              Arch     Version              Repository          Size",
    "================================================================================",
    "Upgrading:",
    " openssl              x86_64   1:3.0.7-27.el9       baseos             1.2 M",
    " openssl-libs-very-long-name-that-wraps",
    "                      x86_64   1:3.0.7-27.el9       baseos             2.1 M",
    "     replacing  openssl-libs.x86_64 1:3.0.7-25.el9",
    "Installing dependencies:",
    " libnew               x86_64   2.0-1.el9            appstream           50 k",
    "Removing dependent packages:",
    " legacy-tool          x86_64   0.9-3.el9            @baseos            100 k",
    "",
    "Transaction Summary",
    "================================================================================",
    "Upgrade  2 Packages",
    "Operation aborted.",
  ].join("\n"));
  assertEquals(plan.upgrade, [
    { name: "openssl", to: "1:3.0.7-27.el9" },
    { name: "openssl-libs-very-long-name-that-wraps", to: "1:3.0.7-27.el9" },
  ]);
  assertEquals(plan.install, [{ name: "libnew", to: "2.0-1.el9" }]);
  assertEquals(plan.remove, [{ name: "legacy-tool", from: "0.9-3.el9" }]);
});

Deno.test("apk simulation and the reboot hint", () => {
  const plan = parseApkSimulation([
    "(1/3) Upgrading musl (1.2.4-r1 -> 1.2.4-r2)",
    "(2/3) Installing libnew (2.0-r0)",
    "(3/3) Purging oldpkg (0.9-r0)",
    "OK: 10 MiB in 20 packages",
  ].join("\n"));
  assertEquals(plan.upgrade, [{ name: "musl", from: "1.2.4-r1", to: "1.2.4-r2" }]);
  assertEquals(plan.install, [{ name: "libnew", to: "2.0-r0" }]);
  assertEquals(plan.remove, [{ name: "oldpkg", from: "0.9-r0" }]);
  assertEquals(rebootLikely(plan), true);
  assertEquals(rebootLikely({ upgrade: [{ name: "curl" }], install: [], remove: [] }), false);
  assertEquals(
    rebootLikely({ upgrade: [{ name: "linux-image-6.1.0-28-amd64" }], install: [], remove: [] }),
    true,
  );
});

Deno.test("windows simulation searches only", () => {
  const script = windowsSimulateScript(["KB5034441"]);
  assertEquals(script.includes("CreateUpdateSearcher"), true);
  assertEquals(script.includes("Download"), false);
  assertEquals(script.includes("Install()"), false);
  assertThrows(() => windowsSimulateScript(["5034441"]), PatchRequestError);
  assertEquals(
    parseWindowsSimulation('{"updates":{"kb":"KB5034441","title":"Security Update","reboot":2}}'),
    [{ kb: "KB5034441", title: "Security Update", reboot: true }],
  );
});

function deps(answer: CommandResult, calls: string[][], manager: "dpkg" | "rpm" | null = "dpkg") {
  return {
    run: (command: string, args: string[]) => {
      calls.push([command, ...args]);
      return Promise.resolve(answer);
    },
    windows: false,
    powershell: () => "powershell.exe",
    encode: (text: string) => text,
    manager: () => Promise.resolve(manager),
    hasCommand: () => Promise.resolve(true),
    now: () => 1000,
  };
}

Deno.test("simulatePatch runs exactly one read-only command", async () => {
  const calls: string[][] = [];
  const result = await simulatePatch(
    parseSimulateRequest({ simulationUUID: SIM, scope: "findings", packages: ["openssl"] }),
    deps({ code: 0, stdout: "Inst openssl [1] (2 x [amd64])\n", stderr: "" }, calls),
  );
  assertEquals(calls.length, 1);
  assertEquals(calls[0].includes("-s"), true);
  assertEquals(result.outcome, "ok");
  assertEquals(result.simulate, true);
  assertEquals(result.upgrade, [{ name: "openssl", from: "1", to: "2" }]);
  assertEquals(result.simulationUUID, SIM);
});

Deno.test("simulatePatch: dnf --assumeno abort is normal, a real error fails", async () => {
  const ok = await simulatePatch(
    parseSimulateRequest({ simulationUUID: SIM, scope: "findings", packages: ["openssl"] }),
    deps(
      {
        code: 1,
        stdout: "Upgrading:\n openssl x86_64 2 baseos 1 M\nOperation aborted.\n",
        stderr: "",
      },
      [],
      "rpm",
    ),
  );
  assertEquals(ok.outcome, "ok");
  assertEquals(ok.upgrade, [{ name: "openssl", to: "2" }]);
  const bad = await simulatePatch(
    parseSimulateRequest({ simulationUUID: SIM, scope: "findings", packages: ["openssl"] }),
    deps(
      { code: 1, stdout: "", stderr: "Error: Cache-only enabled but no cache for 'baseos'" },
      [],
      "rpm",
    ),
  );
  assertEquals(bad.outcome, "failed");
  const none = await simulatePatch(
    parseSimulateRequest({ simulationUUID: SIM, scope: "findings", packages: ["openssl"] }),
    deps({ code: 0, stdout: "", stderr: "" }, [], null),
  );
  assertEquals(none.outcome, "failed");
});
