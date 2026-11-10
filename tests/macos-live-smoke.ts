// Live macOS smoke test (CI macOS runner, run as root): the real inventory and posture collectors
// against the host, plus the launchd property lists. Writes the results to the path given as the
// first argument (CI artifact; a runner holds no customer data).
import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { macosUpdatePlist } from "../macos-agent.ts";
import { collectSecurityInventory, type CommandResult } from "../security-inventory.ts";
import { collectPosture } from "../security-posture.ts";

assertEquals(Deno.build.os, "darwin", "run this smoke test on macOS");

async function run(command: string, args: string[], timeoutMs: number): Promise<CommandResult> {
  const child = new Deno.Command(command, { args, stdin: "null", stdout: "piped", stderr: "piped" })
    .spawn();
  const timer = setTimeout(() => {
    try {
      child.kill("SIGKILL");
    } catch { /* Exited. */ }
  }, timeoutMs);
  const output = await child.output();
  clearTimeout(timer);
  const decoder = new TextDecoder();
  return {
    code: output.code,
    stdout: decoder.decode(output.stdout),
    stderr: decoder.decode(output.stderr),
  };
}

const swVers = (await run("/usr/bin/sw_vers", ["-productVersion"], 10_000)).stdout.trim();
const inventory = await collectSecurityInventory({
  run,
  windows: false,
  macos: true,
  powershell: () => "pwsh",
});
assertEquals(inventory.os.family, "macos");
assertEquals(inventory.os.versionId, swVers);
assertEquals(inventory.packageManager, "macos");
const names = inventory.packages.map((item) => item.name);
assert(names.includes("macos"), "the release is a package");
assert(names.includes("Safari"), `Safari is listed (${inventory.packages.length} packages)`);
assert(inventory.os.build, "build version");

const posture = await collectPosture({
  run,
  windows: false,
  macos: true,
  powershell: () => "pwsh",
  encode: (script) => script,
  readText: (path) => Deno.readTextFile(path).catch(() => null),
  statMode: () => Promise.resolve(null),
  hasCommand: () => Promise.resolve(true),
  writeText: () => Promise.resolve(),
  statePath: "/tmp/mnscloud-antivirus.json",
  packageManager: () => Promise.resolve(null),
  now: () => new Date(),
});
assertEquals(posture.platform, "macos");
assertEquals(posture.checks?.length, 13);
const errors =
  posture.checks?.filter((item) => item.status === "error").map((item) =>
    `${item.code}: ${item.evidence}`
  ) ?? [];
// softwareupdate may be unreachable on a runner; every local check must answer.
assert(errors.every((item) => item.startsWith("mac.updates_pending")), errors.join("; "));
assertEquals(posture.antivirus.engine, "xprotect");
assertEquals(posture.antivirus.installed, 1, "XProtect is built in");

const plist = await Deno.makeTempFile({ suffix: ".plist" });
await Deno.writeTextFile(plist, macosUpdatePlist("/opt/mnscloud/mnscloud-agent", "v1.0.0"));
assertEquals(
  (await run("/usr/bin/plutil", ["-lint", plist], 10_000)).code,
  0,
  "update plist is valid",
);

const summary = {
  os: inventory.os,
  packages: inventory.packages.length,
  ports: inventory.ports.length,
  checks: Object.fromEntries((posture.checks ?? []).map((item) => [item.code, item.status])),
  antivirus: posture.antivirus,
  durationMs: { inventory: inventory.footprint.durationMs, posture: posture.durationMs },
};
console.log(JSON.stringify(summary, null, 2));
if (Deno.args[0]) {
  await Deno.writeTextFile(Deno.args[0], JSON.stringify({ inventory, posture }, null, 2));
}
