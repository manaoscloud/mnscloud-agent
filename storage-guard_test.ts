import { assert, assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  type CommandResult,
  ensureDiskForUpdate,
  HOUSEKEEPING_INTERVAL_MS,
  HousekeepingCycle,
  insufficientDiskMessage,
  MIN_FREE_BYTES,
  parseDfAvailable,
  parseHousekeepingOutput,
  ProductLocks,
  requiredFreeBytes,
  runHousekeeping,
} from "./storage-guard.ts";

const df = (available: number) =>
  `Filesystem 1-blocks Used Available Capacity Mounted on\n/dev/sda1 21474836480 1 ${available} 88% /\n`;

/** Fake command runner: df answers from a queue, bash (housekeeping) from a fixed result. */
function fakeRun(
  dfQueue: number[],
  housekeeping: CommandResult = { code: 0, stdout: "", stderr: "" },
) {
  const calls: string[][] = [];
  const run = (command: string, args: string[]) => {
    calls.push([command, ...args]);
    if (command === "df") {
      const value = dfQueue.length > 1 ? dfQueue.shift()! : dfQueue[0];
      return Promise.resolve({ code: 0, stdout: df(value), stderr: "" });
    }
    return Promise.resolve(housekeeping);
  };
  return { run, calls };
}

const exists = (present: string[]) => (path: string) =>
  Promise.resolve(present.some((p) => path === p));

Deno.test("parseDfAvailable reads the POSIX available column", () => {
  assertEquals(parseDfAvailable(df(123456)), 123456);
  assertEquals(parseDfAvailable("Filesystem\n"), null);
  assertEquals(parseDfAvailable("h\n/dev/sda1 1 2 x 3% /"), null);
});

Deno.test("required free space is at least 1 GiB or three releases", () => {
  assertEquals(requiredFreeBytes(), MIN_FREE_BYTES);
  assertEquals(requiredFreeBytes(1024 ** 3), 3 * 1024 ** 3);
  assertEquals(requiredFreeBytes(Number.NaN), MIN_FREE_BYTES);
});

Deno.test("housekeeping output keeps only JSON object lines", () => {
  const out = parseHousekeepingOutput(
    'log line\n{"path":"/a","freedBytes":10}\n[1,2]\n{broken\n{"freedBytes":5}\n',
  );
  assertEquals(out.length, 2);
  assertEquals(out[0].path, "/a");
});

Deno.test("enough space: no housekeeping before the update", async () => {
  const { run, calls } = fakeRun([5 * MIN_FREE_BYTES]);
  const check = await ensureDiskForUpdate("mnscloud-app", "/opt/app", {
    run,
    exists: exists(["/opt/app", "/opt/app/scripts/housekeeping.sh"]),
  });
  assert(check.ok);
  assertEquals(check.path, "/opt/app");
  assertEquals(calls.filter((c) => c[0] === "bash").length, 0);
});

Deno.test("short space: housekeeping runs first and the update proceeds when it freed enough", async () => {
  const { run, calls } = fakeRun([100, 2 * MIN_FREE_BYTES], {
    code: 0,
    stdout: '{"freedBytes":2147483548}\n',
    stderr: "",
  });
  const check = await ensureDiskForUpdate("mnscloud-app", "/opt/app", {
    run,
    exists: exists(["/opt/app", "/opt/app/scripts/housekeeping.sh"]),
  });
  assert(check.ok);
  assertEquals(check.freeBytesBefore, 100);
  assertEquals(check.housekeeping?.freedBytes, 2147483548);
  const bash = calls.find((c) => c[0] === "bash")!;
  assert(bash.at(-1)!.includes("cd '/opt/app' && exec bash scripts/housekeeping.sh --apply"));
});

Deno.test("still short: the update is refused with a clear message", async () => {
  const { run } = fakeRun([100]);
  const check = await ensureDiskForUpdate("mnscloud-api", "/opt/api", {
    run,
    exists: exists(["/opt/api"]),
  });
  assert(!check.ok);
  assertEquals(check.housekeeping, null);
  const message = insufficientDiskMessage("API", check);
  assert(message.includes("1.0 GiB required"));
  assert(message.includes("running version was not changed"));
});

Deno.test("unmeasurable disk never blocks the update", async () => {
  const run = () => Promise.resolve({ code: 1, stdout: "", stderr: "df failed" });
  const check = await ensureDiskForUpdate("mnscloud-app", "/opt/app", {
    run,
    exists: exists(["/opt/app"]),
  });
  assert(check.ok);
  assertEquals(check.freeBytesBefore, null);
});

Deno.test("a release without housekeeping script is skipped", async () => {
  const { run } = fakeRun([0]);
  assertEquals(await runHousekeeping("x", "/opt/x", { run, exists: exists([]) }), null);
});

Deno.test("a failing housekeeping reports its error", async () => {
  const { run } = fakeRun([0], { code: 2, stdout: "", stderr: "boom\n" });
  const report = await runHousekeeping("x", "/opt/x", {
    run,
    exists: exists(["/opt/x/scripts/housekeeping.sh"]),
  });
  assertEquals(report?.ok, false);
  assertEquals(report?.message, "boom");
});

Deno.test("locks serialize one product and let others run", async () => {
  const locks = new ProductLocks();
  const order: string[] = [];
  let release!: () => void;
  const first = locks.run("a", async () => {
    order.push("a1-start");
    await new Promise<void>((resolve) => (release = resolve));
    order.push("a1-end");
  });
  assert(locks.busy("a"));
  assertEquals(await locks.tryRun("a", () => Promise.resolve("x")), undefined);
  assertEquals(await locks.tryRun("b", () => Promise.resolve("b")), "b");
  const second = locks.run("a", () => {
    order.push("a2");
    return Promise.resolve();
  });
  release();
  await Promise.all([first, second]);
  assertEquals(order, ["a1-start", "a1-end", "a2"]);
  assert(!locks.busy("a"));
});

Deno.test("cycle runs once per day, persists its state and skips busy products", async () => {
  let now = 1_000_000_000_000;
  const files = new Map<string, string>();
  const { run, calls } = fakeRun([0], { code: 0, stdout: '{"freedBytes":7}\n', stderr: "" });
  const locks = new ProductLocks();
  const logs: string[] = [];
  const cycle = new HousekeepingCycle({
    products: () =>
      Promise.resolve([
        { product: "mnscloud-app", repoDir: "/opt/app" },
        { product: "mnscloud-api", repoDir: "/opt/api" },
      ]),
    extra: () =>
      Promise.resolve([{
        product: "mnscloud-db",
        ok: true,
        code: 0,
        freedBytes: 0,
        results: [],
        message: null,
      }]),
    run,
    exists: exists(["/opt/app/scripts/housekeeping.sh", "/opt/api/scripts/housekeeping.sh"]),
    locks,
    log: (_level, message) => logs.push(message),
    stateFile: "/state.json",
    now: () => now,
    random: () => 0,
    readText: (path) =>
      files.has(path) ? Promise.resolve(files.get(path)!) : Promise.reject(new Error("none")),
    writeText: (path, text) => {
      files.set(path, text);
      return Promise.resolve();
    },
  });
  // First start without state: due right away (jitter 0).
  let release!: () => void;
  const busy = locks.run("mnscloud-api", () => new Promise<void>((resolve) => (release = resolve)));
  const reports = await cycle.tick();
  assertEquals(reports.map((r) => r.product), ["mnscloud-app", "mnscloud-db"]);
  assert(logs.includes("Housekeeping skipped: product update in progress."));
  assertEquals(JSON.parse(files.get("/state.json")!).lastRunAt, now);
  release();
  await busy;
  // Not due again before 24 h.
  now += HOUSEKEEPING_INTERVAL_MS - 1;
  assertEquals(await cycle.tick(), []);
  now += 1;
  assertEquals((await cycle.tick()).length, 3);
  assertEquals(calls.filter((c) => c[0] === "bash").length, 3);
});

Deno.test("cycle restarted after a recent run waits for the next day", async () => {
  const now = 2_000_000_000_000;
  const cycle = new HousekeepingCycle({
    products: () => Promise.reject(new Error("must not run")),
    run: fakeRun([0]).run,
    exists: exists([]),
    locks: new ProductLocks(),
    log: () => undefined,
    stateFile: "/s",
    now: () => now,
    random: () => 0,
    readText: () => Promise.resolve(JSON.stringify({ lastRunAt: now - 3_600_000 })),
    writeText: () => Promise.resolve(),
  });
  assertEquals(await cycle.tick(), []);
});
