import { parseFilesystems, parseNetworkCounters } from "./host-resources.ts";
function check(value: unknown) {
  if (!value) throw new Error("Assertion failed");
}
Deno.test("network deltas omit warmup, resets and disappeared interfaces", () => {
  const cache = new Map();
  const line = (bytes: number) => `eth0: ${bytes} 10 0 0 0 0 0 0 ${bytes} 20 0 0 0 0 0 0`;
  check(Object.keys(parseNetworkCounters(line(100), 1000, cache)[0].values).length === 0);
  check(parseNetworkCounters(line(1100), 11000, cache)[0].values.rx_bps === 800);
  check(Object.keys(parseNetworkCounters(line(0), 21000, cache)[0].values).length === 0);
  parseNetworkCounters("", 22000, cache);
  check(cache.size === 0);
});
Deno.test("filesystem counters preserve mount names and reject invalid totals", () => {
  const rows = parseFilesystems(
    "Filesystem Blocks Used Available Capacity Mounted\n/dev/sda 100 40 60 40% /data files\n/dev/bad 0 0 0 0% /bad",
  );
  check(rows.length === 1 && rows[0].name === "/data files");
  check(rows[0].values.usage_percent === 40);
});

Deno.test("interface recreation invalidates deltas even when counters increase", () => {
  const cache = new Map();
  const line = (n: number) => `eth0: ${n} 0 0 0 0 0 0 0 ${n} 0 0 0 0 0 0 0`;
  parseNetworkCounters(line(100), 1000, cache, new Map([["eth0", { index: 1, up: 1 }]]));
  const sample =
    parseNetworkCounters(line(10000), 11000, cache, new Map([["eth0", { index: 2, up: 1 }]]))[0];
  check(sample.values.rx_bps === undefined && sample.values.link_up === 1);
});
