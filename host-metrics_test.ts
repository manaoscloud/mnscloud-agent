import { assert, assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  collectHostMetrics,
  cpuUsage,
  parseLinuxCpu,
  parseLinuxMemory,
  parseRootDisk,
} from "./main.ts";

Deno.test("CPU deltas exclude double-counted guest time and reject counter resets", () => {
  assertEquals(parseLinuxCpu("cpu 10 0 10 80 0 0 0 0 15 0"), { total: 100, idle: 80 });
  assertEquals(cpuUsage({ total: 200, idle: 150 }, { total: 100, idle: 80 }), 30.000000000000004);
  assertEquals(cpuUsage({ total: 100, idle: 80 }, null), null);
  assertEquals(cpuUsage({ total: 1, idle: 1 }, { total: 100, idle: 80 }), null);
  assertThrows(() => parseLinuxCpu("cpu invalid"));
});
Deno.test("memory uses MemAvailable and disk uses available blocks", () => {
  assertEquals(parseLinuxMemory("MemTotal: 1000 kB\nMemFree: 10 kB\nMemAvailable: 700 kB\n"), {
    memoryTotalBytes: 1024000,
    memoryAvailableBytes: 716800,
  });
  assertEquals(
    parseRootDisk(
      "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 300 650 30% /",
    ),
    { diskTotalBytes: 1024000, diskAvailableBytes: 665600 },
  );
  assertThrows(() => parseLinuxMemory("MemTotal: 10 kB"));
  assertThrows(() => parseRootDisk("bad output"));
});
Deno.test({
  name: "Host collection returns bounded physical resources",
  ignore: !["linux", "windows"].includes(Deno.build.os),
  async fn() {
    const sample = await collectHostMetrics();
    assert(sample);
    assert(sample.memoryTotalBytes > 0);
    assert(sample.memoryAvailableBytes <= sample.memoryTotalBytes);
    assert(sample.diskTotalBytes > 0);
    assert(sample.diskAvailableBytes <= sample.diskTotalBytes);
  },
});

Deno.test({
  name: "Host collection works with the service permission flags",
  ignore: !["linux", "windows"].includes(Deno.build.os),
  async fn() {
    const child = new Deno.Command(Deno.execPath(), {
      args: [
        "run",
        "--allow-read",
        "--allow-write",
        "--allow-net",
        "--allow-run",
        "--allow-env",
        "-",
      ],
      stdin: "piped",
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    const writer = child.stdin.getWriter();
    const moduleURL = new URL("./main.ts", import.meta.url).href;
    await writer.write(new TextEncoder().encode(
      `import { collectHostMetrics } from ${
        JSON.stringify(moduleURL)
      }; const m=await collectHostMetrics(); if(!m || m.memoryTotalBytes<=0 || m.diskTotalBytes<=0) Deno.exit(1); console.log("collection-ok");`,
    ));
    await writer.close();
    const result = await child.output();
    assertEquals(result.code, 0, new TextDecoder().decode(result.stderr));
    assert(new TextDecoder().decode(result.stdout).includes("collection-ok"));
  },
});
