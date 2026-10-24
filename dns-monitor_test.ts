import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { type MonitorDeps, runDnsMonitor } from "./dns-monitor.ts";

function deps(overrides: Partial<MonitorDeps> = {}) {
  const calls: string[] = [];
  let clock = 0;
  const value: MonitorDeps = {
    resolve: (name, type, server) => {
      calls.push(`resolve ${name} ${type} ${server ?? "system"}`);
      return Promise.resolve(type === "A" ? ["142.250.0.1"] : []);
    },
    connect: () => Promise.resolve({ tcpMs: 5, tls: { status: "ok", ms: 7 } }),
    http: () => Promise.resolve(200),
    egress: () => {
      calls.push("egress");
      return Promise.resolve({ ipv4: "168.0.230.243", ipv6: null });
    },
    query: (name, type, server) => {
      calls.push(`query ${name} ${type} ${server}`);
      return Promise.resolve(server === "9.9.9.9" ? 0 : 3);
    },
    now: () => (clock += 10),
    ...overrides,
  };
  return { value, calls };
}

const uuid = (n: number) => `00000000-0000-0000-0000-00000000000${n}`;

Deno.test("a cycle measures services without public resolvers and resolvers with one query", async () => {
  const { value, calls } = deps();
  const cycle = await runDnsMonitor([
    { targetUUID: uuid(1), kind: "service", target: "https://www.google.com/" },
    {
      targetUUID: uuid(2),
      kind: "resolver",
      target: "1.1.1.1",
      queryName: "www.google.com",
      queryType: "A",
    },
    { targetUUID: uuid(3), kind: "resolver", target: "9.9.9.9", queryName: ".", queryType: "NS" },
  ], value);
  assertEquals(cycle.egress.ipv4, "168.0.230.243");
  assertEquals(calls.filter((call) => call === "egress").length, 1);
  assertEquals(
    calls.filter((call) => call.startsWith("resolve")).every((call) => call.endsWith("system")),
    true,
  );
  const [service, cf, quad9] = cycle.results;
  assertEquals(service.service?.resolution.length, 2);
  assertEquals(service.service?.http?.code, 200);
  assertEquals(service.service?.egress.ipv4, "168.0.230.243");
  assertEquals([cf.resolver?.status, cf.resolver?.answers], ["ok", 3]);
  assertEquals(quad9.resolver?.status, "nodata");
});

Deno.test("private resolvers, bad types and invalid entries never run", async () => {
  const { value, calls } = deps();
  const cycle = await runDnsMonitor([
    {
      targetUUID: uuid(1),
      kind: "resolver",
      target: "10.0.0.1",
      queryName: "a.com",
      queryType: "A",
    },
    {
      targetUUID: uuid(2),
      kind: "resolver",
      target: "8.8.8.8",
      queryName: "a.com",
      queryType: "TXT",
    },
    { targetUUID: uuid(3), kind: "service", target: "ftp://example.com" },
    { targetUUID: "bad", kind: "service", target: "example.com" },
    null,
  ], value);
  assertEquals(cycle.results.map((result) => result.error), [
    "invalid_target",
    "invalid_target",
    "invalid_target",
  ]);
  assertEquals(calls.filter((call) => call.startsWith("query")), []);
});

Deno.test("a failing query reports its status", async () => {
  const { value } = deps({
    query: () => {
      const error = new Error("timed out");
      error.name = "TimeoutError";
      return Promise.reject(error);
    },
  });
  const cycle = await runDnsMonitor([
    {
      targetUUID: uuid(1),
      kind: "resolver",
      target: "8.8.8.8",
      queryName: "a.com",
      queryType: "A",
    },
  ], value);
  assertEquals(cycle.results[0].resolver?.status, "timeout");
});
