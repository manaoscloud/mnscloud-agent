import {
  parseFilesystems,
  parseNetworkCounters,
  parsePrivateAddresses,
  parsePublicIpv6Addresses,
} from "./host-resources.ts";
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

Deno.test("private addresses come from ip -j addr, private ranges only", () => {
  const sample = JSON.stringify([
    {
      ifname: "lo",
      addr_info: [{ family: "inet", local: "127.0.0.1" }, { family: "inet6", local: "::1" }],
    },
    {
      ifname: "eth0",
      addr_info: [
        { family: "inet", local: "172.17.0.198" },
        { family: "inet", local: "203.0.113.7" },
        { family: "inet6", local: "fe80::1" },
        { family: "inet6", local: "fd00::198" },
        { family: "inet", local: "172.17.0.198" },
      ],
    },
    { ifname: "docker0", addr_info: [{ family: "inet", local: "10.88.0.1" }] },
  ]);
  const found = parsePrivateAddresses(sample);
  check(JSON.stringify(found) === JSON.stringify(["172.17.0.198", "fd00::198", "10.88.0.1"]));
  check(parsePrivateAddresses("not json").length === 0);
  check(parsePrivateAddresses("{}").length === 0);
});

Deno.test("public IPv6: stable global unicast only, no temporary, deprecated, ULA or link-local", () => {
  const sample = JSON.stringify([
    {
      ifname: "eth0",
      addr_info: [
        { family: "inet", local: "192.0.2.13", scope: "global" },
        {
          family: "inet6",
          local: "2001:DB8:1000:3:BE24:11FF:FE5F:892F",
          scope: "global",
          dynamic: true,
        },
        { family: "inet6", local: "2001:db8:1000:3::abcd", scope: "global", temporary: true },
        { family: "inet6", local: "2001:db8:1000:3::dead", scope: "global", deprecated: true },
        { family: "inet6", local: "fd00::1", scope: "global" },
        { family: "inet6", local: "fe80::1", scope: "link" },
        { family: "inet6", local: "2001:db8:1000:3:be24:11ff:fe5f:892f", scope: "global" },
      ],
    },
  ]);
  const found = parsePublicIpv6Addresses(sample);
  if (JSON.stringify(found) !== JSON.stringify(["2001:db8:1000:3:be24:11ff:fe5f:892f"])) {
    throw new Error(JSON.stringify(found));
  }
  if (parsePublicIpv6Addresses("x").length !== 0) throw new Error("invalid input");
});
