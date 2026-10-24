import { assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  isPublicAddress,
  parseTarget,
  type ProbeDeps,
  PUBLIC_RESOLVERS,
  runDnsProbe,
} from "./dns-probe.ts";

function fakeDeps(answers: Record<string, string[] | Error>, calls: string[] = []): ProbeDeps {
  let clock = 0;
  return {
    resolve: (name, type, server) => {
      const value = answers[`${server ?? "system"}/${type}`] ?? answers[type] ?? [];
      calls.push(`resolve ${name} ${type} ${server ?? "system"}`);
      return value instanceof Error ? Promise.reject(value) : Promise.resolve(value);
    },
    connect: (address, port, tlsName) => {
      calls.push(`connect ${address} ${port} ${tlsName ?? "-"}`);
      return Promise.resolve({ tcpMs: 5, tls: tlsName ? { status: "ok", ms: 7 } : null });
    },
    http: (url) => {
      calls.push(`http ${url}`);
      return Promise.resolve(200);
    },
    egress: () => Promise.resolve({ ipv4: "198.51.100.20", ipv6: null }),
    now: () => clock += 1,
  };
}

Deno.test("targets: host names, http(s) URLs and IPs only", () => {
  assertEquals(parseTarget(" Example.COM. "), {
    kind: "name",
    host: "example.com",
    port: 443,
    url: "https://example.com/",
  });
  assertEquals(parseTarget("http://example.com:8080/x").port, 8080);
  assertEquals(parseTarget("2001:4860:4860::8888").kind, "ip");
  for (
    const bad of ["", "ftp://example.com", "https://user:pw@example.com/", "a b", "x".repeat(300)]
  ) {
    assertThrows(() => parseTarget(bad));
  }
});

Deno.test("only globally routable unicast addresses are public", () => {
  for (const address of ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888", "2a04:4e42::810"]) {
    assertEquals(isPublicAddress(address), true, address);
  }
  for (
    const address of [
      "10.1.2.3",
      "172.20.0.1",
      "192.168.1.1",
      "127.0.0.1",
      "169.254.1.1",
      "100.64.0.1",
      "0.0.0.0",
      "224.0.0.1",
      "198.51.100.1",
      "::1",
      "fe80::1",
      "fd00::1",
      "ff02::1",
      "2001:db8::1",
      "::ffff:10.0.0.1",
      "not-an-ip",
    ]
  ) {
    assertEquals(isPublicAddress(address), false, address);
  }
});

Deno.test("a name is resolved by the system and every public resolver, then reached over v4 and v6", async () => {
  const calls: string[] = [];
  const result = await runDnsProbe(
    parseTarget("example.com"),
    fakeDeps({ A: ["93.184.215.14"], AAAA: ["2606:2800:21f:cb07:6820:80da:af6b:8b2c"] }, calls),
  );
  assertEquals(result.egress, {
    address: "198.51.100.20",
    ipv4: "198.51.100.20",
    ipv6: null,
    status: "ok",
  });
  assertEquals(result.resolution.length, (PUBLIC_RESOLVERS.length + 1) * 2);
  assertEquals(result.resolution.every((step) => step.status === "ok"), true);
  assertEquals(result.connect.map((step) => [step.family, step.tcp.status, step.tls?.status]), [
    [4, "ok", "ok"],
    [6, "ok", "ok"],
  ]);
  assertEquals(result.http?.code, 200);
  assertEquals(calls.filter((call) => call.startsWith("connect")).length, 2);
});

Deno.test("resolver failures are classified and never stop the other steps", async () => {
  const nx = new Error("no record found");
  nx.name = "NotFound";
  const result = await runDnsProbe(
    parseTarget("example.com"),
    fakeDeps({
      "system/A": ["93.184.215.14"],
      "system/AAAA": [],
      "1.1.1.1/A": nx,
      A: ["93.184.215.14"],
    }),
  );
  const status = (resolver: string, type: string) =>
    result.resolution.find((step) => step.resolver === resolver && step.type === type)?.status;
  assertEquals(status("system", "AAAA"), "nodata");
  assertEquals(status("1.1.1.1", "A"), "nxdomain");
  assertEquals(status("8.8.8.8", "A"), "ok");
  assertEquals(result.connect.length, 1);
});

Deno.test("private answers are never contacted (SSRF guard)", async () => {
  const calls: string[] = [];
  const result = await runDnsProbe(
    parseTarget("https://internal.example.com/"),
    fakeDeps({ "system/A": ["10.0.0.5"], "system/AAAA": [] }, calls),
  );
  assertEquals(result.connect[0].tcp.status, "blocked");
  assertEquals(result.http?.status, "blocked");
  assertEquals(calls.some((call) => call.startsWith("connect") || call.startsWith("http")), false);
  const ip = await runDnsProbe(parseTarget("192.168.0.1"), fakeDeps({}, calls));
  assertEquals([ip.resolution.length, ip.connect[0].tcp.status], [0, "blocked"]);
});
