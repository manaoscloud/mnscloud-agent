import { assertEquals, assertThrows } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { VoipEventFrames, VoipRateWindow } from "./voip-rate.ts";
Deno.test("rate waits for a complete healthy window and loses authority on disconnect or stale ping", () => {
  const rate = new VoipRateWindow();
  assertEquals(rate.sample(0), null);
  rate.connect(0);
  rate.record(1000);
  rate.record(1001);
  rate.record(1002);
  rate.acknowledge(60000);
  assertEquals(rate.sample(60000), null);
  assertEquals(rate.sample(61000), 3);
  assertEquals(rate.sample(76000), null);
  rate.acknowledge(77000);
  assertEquals(rate.sample(77000), 0);
  rate.disconnect();
  assertEquals(rate.sample(78000), null);
  rate.connect(80000);
  assertEquals(rate.sample(81000), null);
});
Deno.test("AMI fragmented frames count each creation once and recognize only our ping", () => {
  const parser = new VoipEventFrames("asterisk");
  const bytes = new TextEncoder().encode(
    "Event: Newchannel\r\nCallerIDName: Example\r\n\r\nEvent: Newchannel\r\n\r\nActionID: mnscloud-load-health\r\nPing: Pong\r\n\r\n",
  );
  let calls = 0, acks = 0;
  for (const byte of bytes) {
    const result = parser.push(new Uint8Array([byte]));
    calls += result.channelStarts;
    acks += result.acknowledgements;
  }
  assertEquals(calls, 2);
  assertEquals(acks, 1);
});
Deno.test("ESL uses byte content length including Unicode and handles multiple frames", () => {
  const parser = new VoipEventFrames("freeswitch");
  const body = "Event-Name: CHANNEL_CREATE\nCaller-Name: João\n\n";
  const encoder = new TextEncoder();
  const frame = encoder.encode(
    `Content-Type: text/event-plain\nContent-Length: ${encoder.encode(body).length}\n\n${body}`,
  );
  assertEquals(parser.push(frame.subarray(0, frame.length - 1)).channelStarts, 0);
  assertEquals(parser.push(frame.subarray(frame.length - 1)).channelStarts, 1);
  assertEquals(
    parser.push(encoder.encode("Content-Type: api/response\nContent-Length: 3\n\n123"))
      .acknowledgements,
    1,
  );
  assertThrows(() => parser.push(new Uint8Array(262145)), Error, "budget");
});
