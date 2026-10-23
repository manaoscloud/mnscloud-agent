import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  amiEndpointFromManagerConf,
  coalesce,
  eslPasswordFromConfig,
  listenPabxEvents,
  type PresenceEventEngine,
} from "./pabx-events.ts";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

async function waitFor(check: () => boolean, ms = 3000) {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function readSome(conn: Deno.Conn) {
  const buffer = new Uint8Array(4096);
  const read = await conn.read(buffer);
  return read === null ? "" : decoder.decode(buffer.subarray(0, read));
}

Deno.test("manager.conf gives the MNSCloud AMI account on the bound address", () => {
  const conf = [
    "[general]",
    "enabled=yes",
    "port=5038",
    "bindaddr=192.0.2.10",
    "",
    "[mnscloud]",
    "secret=abc123 ; local",
    "read=system,call",
  ].join("\n");
  assertEquals(amiEndpointFromManagerConf(conf), {
    engine: "asterisk",
    hostname: "192.0.2.10",
    port: 5038,
    username: "mnscloud",
    secret: "abc123",
  });
  assertEquals(
    amiEndpointFromManagerConf("[general]\nbindaddr=0.0.0.0\n[mnscloud]\nsecret=x")?.hostname,
    "127.0.0.1",
  );
  assertEquals(amiEndpointFromManagerConf("[general]\nport=5038\n"), null);
  assertEquals(
    eslPasswordFromConfig(
      '<param name="listen-port" value="8021"/>\n<param name="password" value="s3cret"/>',
    ),
    "s3cret",
  );
});

Deno.test("AMI ContactStatus events wake the presence report and the listener reconnects", async () => {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  const events: PresenceEventEngine[] = [];
  let logins = 0;
  const serve = (async () => {
    for (let round = 0; round < 2; round++) {
      const conn = await listener.accept();
      await conn.write(encoder.encode("Asterisk Call Manager/9.0.0\r\n"));
      const loginText = await readSome(conn);
      if (loginText.includes("Secret: right")) logins++;
      // Login reply and the first event in one write: the event must not be lost with the reply.
      await conn.write(encoder.encode(
        "Response: Success\r\nMessage: Authentication accepted\r\n\r\n" +
          "Event: ContactStatus\r\nContactStatus: Created\r\nAOR: 7001@pbx\r\n\r\n",
      ));
      await new Promise((resolve) => setTimeout(resolve, 50));
      conn.close();
    }
  })();
  const handle = listenPabxEvents({
    resolve: () =>
      Promise.resolve({
        engine: "asterisk",
        hostname: "127.0.0.1",
        port,
        username: "mnscloud",
        secret: "right",
      }),
    onEvent: (engine) => events.push(engine),
    log: () => {},
    retryMs: 20,
    maxRetryMs: 100,
  });
  // connect (1) + ContactStatus (1), twice: the second round proves the reconnect.
  await waitFor(() => events.length >= 4);
  await handle.stop();
  await serve;
  listener.close();
  assertEquals(logins, 2);
  assertEquals(new Set(events), new Set(["asterisk"]));
});

Deno.test("ESL authenticates and subscribes to sofia registration events", async () => {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = (listener.addr as Deno.NetAddr).port;
  const events: PresenceEventEngine[] = [];
  let subscription = "";
  const serve = (async () => {
    const conn = await listener.accept();
    await conn.write(encoder.encode("Content-Type: auth/request\n\n"));
    const auth = await readSome(conn);
    await conn.write(encoder.encode(
      auth.startsWith("auth pw\n")
        ? "Content-Type: command/reply\nReply-Text: +OK accepted\n\n"
        : "Content-Type: command/reply\nReply-Text: -ERR invalid\n\n",
    ));
    subscription = await readSome(conn);
    const body = "Event-Name: CUSTOM\nEvent-Subclass: sofia%3A%3Aexpire\n\n";
    await conn.write(
      encoder.encode(`Content-Length: ${body.length}\nContent-Type: text/event-plain\n\n${body}`),
    );
    await new Promise((resolve) => setTimeout(resolve, 200));
    conn.close();
  })();
  const handle = listenPabxEvents({
    resolve: () =>
      Promise.resolve({ engine: "freeswitch", hostname: "127.0.0.1", port, secret: "pw" }),
    onEvent: (engine) => events.push(engine),
    log: () => {},
    retryMs: 5000,
  });
  await waitFor(() => events.length >= 2);
  await handle.stop();
  await serve;
  listener.close();
  assertEquals(
    subscription,
    "event plain CUSTOM sofia::register sofia::unregister sofia::expire\n\n",
  );
});

Deno.test("wake signals are coalesced and spaced", async () => {
  const runs: number[] = [];
  const wake = coalesce(
    async () => {
      runs.push(Date.now());
      await new Promise((resolve) => setTimeout(resolve, 30));
    },
    20,
    150,
  );
  for (let i = 0; i < 10; i++) wake.trigger();
  await waitFor(() => runs.length === 1);
  wake.trigger();
  wake.trigger();
  await waitFor(() => runs.length === 2);
  assertEquals(runs[1] - runs[0] >= 140, true);
  wake.cancel();
});
