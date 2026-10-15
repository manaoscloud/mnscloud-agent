import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import dgram from "node:dgram";

import {
  lastAsteriskFailure,
  lastFreeswitchFailure,
  parseAsteriskRegistration,
  parseAsteriskTransports,
  parseFreeswitchContactBinding,
  parseFreeswitchGateway,
  parseSipResponse,
  probeRegistrar,
  readFileTail,
  sipTarget,
} from "./pabx-registration-insight.ts";

const NAME = "trunk-4e061cebc8c611f19300bc2411f7dd2d";

const GATEWAY =
  `=================================================================================================
Name    \t${NAME}
Profile \texternal
Scheme  \tDigest
Realm   \tsip1.example.test
Username\t1000-202011
Password\tyes
From    \t<sip:1000-202011@sip1.example.test>
Contact \t<sip:1000-202011@203.0.113.10:5080;transport=udp;gw=${NAME}>
Exten   \t1000-202011
To      \tsip:1000-202011@sip1.example.test
Proxy   \tsip:sip1.example.test
State   \tFAIL_WAIT
Status  \tDOWN
=================================================================================================`;

Deno.test("parses the FreeSWITCH gateway runtime fields", () => {
  const runtime = parseFreeswitchGateway(GATEWAY);
  assertEquals(runtime.proxy, "sip:sip1.example.test");
  assertEquals(runtime.realm, "sip1.example.test");
  assertEquals(runtime.username, "1000-202011");
  assertEquals(runtime.transport, "udp");
  assertEquals(parseFreeswitchContactBinding(runtime.contact), {
    host: "203.0.113.10",
    port: 5080,
    transport: "udp",
  });
});

Deno.test("reads the last FreeSWITCH failure of the gateway with its retry", () => {
  const log = [
    `2026-10-15 15:36:15.242910 98.63% [ERR] sofia_reg.c:2661 ${NAME} Failed Registration with status Service Unavailable [503]. failure #5`,
    `2026-10-15 15:36:16.242878 98.67% [WARNING] sofia_reg.c:520 ${NAME} Failed Registration [503], setting retry to 30 seconds.`,
    `2026-10-15 15:44:51.202887 97.17% [ERR] sofia_reg.c:2661 trunk-00000000000000000000000000000000 Failed Registration with status Not Found [404]. failure #1`,
    `2026-10-15 15:47:57.542957 96.13% [ERR] sofia_reg.c:2661 ${NAME} Failed Registration with status Forbidden [403]. failure #4`,
    `2026-10-15 15:47:58.542929 96.10% [WARNING] sofia_reg.c:520 ${NAME} Failed Registration [403], setting retry to 120 seconds.`,
  ].join("\n");
  const failure = lastFreeswitchFailure(log, NAME);
  assertEquals(failure?.code, 403);
  assertEquals(failure?.phrase, "Forbidden");
  assertEquals(failure?.failures, 4);
  assertEquals(failure?.retrySeconds, 120);
  assertEquals(typeof failure?.at, "string");
  assertEquals(lastFreeswitchFailure(log, "trunk-11111111111111111111111111111111"), null);
});

Deno.test("parses the Asterisk registration, transports and last failure", () => {
  const output =
    ` <Registration/ServerURI..............................>  <Auth....................>  <Status.......>
==========================================================================================

 ${NAME}/sip:198.51.100.7:5060                         ${NAME}-auth                Rejected
`;
  const runtime = parseAsteriskRegistration(output, NAME);
  assertEquals(runtime.serverUri, "sip:198.51.100.7:5060");
  assertEquals(sipTarget(runtime.serverUri), {
    host: "198.51.100.7",
    port: 5060,
    transport: "udp",
  });

  const transports =
    `Transport:  <TransportId........>  <Type>  <cos>  <tos>  <BindAddress....................>
==========================================================================================
Transport:  transport-tcp             tcp      0      0  0.0.0.0:5060
Transport:  transport-udp             udp      0      0  0.0.0.0:5060
`;
  assertEquals(parseAsteriskTransports(transports, "udp"), {
    host: "0.0.0.0",
    port: 5060,
    transport: "udp",
  });

  const log = [
    "[2026-10-15 15:40:00] WARNING[812] res_pjsip_outbound_registration.c: No response received from 'sip:198.51.100.7:5060' on registration attempt to 'sip:1000@198.51.100.7:5060', retrying in '60'",
    "[2026-10-15 15:41:03] WARNING[812] res_pjsip_outbound_registration.c: Fatal response '403' received from 'sip:198.51.100.7:5060' on registration attempt to 'sip:1000@198.51.100.7:5060', stopping outbound registration",
  ].join("\n");
  const failure = lastAsteriskFailure(log, "sip:198.51.100.7:5060");
  assertEquals(failure?.code, 403);
  assertEquals(failure?.failures, 2);
  assertEquals(lastAsteriskFailure(log.split("\n")[0], "sip:198.51.100.7:5060")?.code, 408);
});

Deno.test("parses SIP targets and responses", () => {
  assertEquals(sipTarget("sip:sip1.example.test"), {
    host: "sip1.example.test",
    port: null,
    transport: "udp",
  });
  assertEquals(sipTarget("sip:[2001:db8::1]:5070;transport=tcp"), {
    host: "2001:db8::1",
    port: 5070,
    transport: "tcp",
  });
  assertEquals(sipTarget(""), null);
  assertEquals(
    parseSipResponse(
      'SIP/2.0 401 Unauthorized\r\nServer: Example\r\nWWW-Authenticate: Digest algorithm=MD5, realm="sip1.example.test", nonce="1"\r\n\r\n',
    ),
    { code: 401, phrase: "Unauthorized", realm: "sip1.example.test", server: "Example" },
  );
});

Deno.test("probes a UDP registrar without credentials", async () => {
  const registrar = dgram.createSocket("udp4");
  let request = "";
  await new Promise<void>((resolve) => registrar.bind(0, "127.0.0.1", () => resolve()));
  registrar.on("message", (message: Uint8Array, remote: { port: number; address: string }) => {
    request = new TextDecoder().decode(message);
    const reply =
      'SIP/2.0 401 Unauthorized\r\nServer: Test\r\nWWW-Authenticate: Digest realm="registrar.test", nonce="x"\r\nContent-Length: 0\r\n\r\n';
    registrar.send(new TextEncoder().encode(reply), remote.port, remote.address);
  });
  try {
    const port = registrar.address().port;
    const probe = await probeRegistrar(
      { host: "127.0.0.1", port, transport: "udp" },
      "1000",
      2_000,
    );
    assertEquals(probe.outcome, "response");
    assertEquals(probe.code, 401);
    assertEquals(probe.realm, "registrar.test");
    assertEquals(probe.target, `127.0.0.1:${port}`);
    assertEquals(/^Expires: 0$/m.test(request.replace(/\r/g, "")), true);
    assertEquals(/Authorization/i.test(request), false);
  } finally {
    registrar.close();
  }
});

Deno.test("reports a timeout when the registrar does not answer", async () => {
  const silent = dgram.createSocket("udp4");
  await new Promise<void>((resolve) => silent.bind(0, "127.0.0.1", () => resolve()));
  try {
    const probe = await probeRegistrar(
      { host: "127.0.0.1", port: silent.address().port, transport: "udp" },
      "1000",
      300,
    );
    assertEquals(probe.outcome, "timeout");
    assertEquals(probe.code, null);
  } finally {
    silent.close();
  }
});

Deno.test("reads only the tail of a log file from a line boundary", async () => {
  const path = await Deno.makeTempFile();
  try {
    await Deno.writeTextFile(path, "first line\nsecond line\nthird line\n");
    assertEquals(await readFileTail(path, 16), "third line\n");
    assertEquals(await readFileTail(path, 1024), "first line\nsecond line\nthird line\n");
  } finally {
    await Deno.remove(path);
  }
});
