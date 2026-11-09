import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  applyPatch,
  linuxPatchSteps,
  packageChanges,
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

function runner(answers: Record<string, CommandResult>, calls: string[]) {
  return (command: string, args: string[]) => {
    const key = args.includes("update") && !args.includes("--only-upgrade")
      ? "refresh"
      : command === "dpkg-query"
      ? `versions${calls.filter((c) => c === "dpkg-query").length}`
      : "upgrade";
    calls.push(command);
    return Promise.resolve(answers[key] ?? { code: 0, stdout: "", stderr: "" });
  };
}

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
  assertEquals(calls, ["dpkg-query", "env", "env", "dpkg-query"]);
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
