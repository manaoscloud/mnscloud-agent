import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { parseAsteriskLoad, parseFreeSwitchLoad } from "./voip-load.ts";
const observedAt = "2026-11-03T12:00:00.000Z";
Deno.test("Asterisk aggregate parsing keeps calls and channels distinct and CPS unknown", () => {
  assertEquals(
    parseAsteriskLoad("4 active channels\n2 active calls\n39 calls processed\n", observedAt),
    {
      engine: "asterisk",
      observedAt,
      activeCalls: 2,
      activeChannels: 4,
      sessionsPerSecond: null,
    },
  );
  assertEquals(parseAsteriskLoad("0 active channels\n0 active calls\n", observedAt).activeCalls, 0);
});
Deno.test("FreeSWITCH session rate is not a call arrival rate", () => {
  const status =
    "FreeSWITCH (Version test) is ready\n100 session(s) since startup\n4 session(s) - peak 10\n2 session(s) per Sec out of max 30\n";
  assertEquals(parseFreeSwitchLoad("2 total.\n", status, observedAt), {
    engine: "freeswitch",
    observedAt,
    activeCalls: 2,
    activeChannels: 4,
    sessionsPerSecond: 2,
  });
  assertEquals(
    parseFreeSwitchLoad("2 total.", status.replace("is ready", "is not ready"), observedAt)
      .activeCalls,
    null,
  );
});
Deno.test("failed, duplicate, overflowing and oversized outputs remain unknown", () => {
  for (
    const output of [
      "error",
      "-1 active calls",
      "999999999999999999999 active calls",
      "1 active calls\n2 active calls",
      " ".repeat(16385) + "0 active calls",
    ]
  ) {
    assertEquals(parseAsteriskLoad(output, observedAt).activeCalls, null);
  }
});
