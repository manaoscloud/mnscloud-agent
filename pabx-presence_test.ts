import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { PabxPresenceTracker, parseAsteriskPjsipContacts } from "./pabx-presence.ts";

const fs = (username: string, extra: Record<string, string> = {}) => ({
  engine: "freeswitch" as const,
  username,
  domain: "a.example.com",
  ...extra,
});

Deno.test("first report is complete, then only changes are sent", () => {
  const tracker = new PabxPresenceTracker(600_000);
  const first = tracker.build({ freeswitch: [fs("1001"), fs("1002")] }, 1_000);
  assertEquals(first.report.full, true);
  assertEquals(first.report.registrations.length, 2);
  tracker.acknowledge(first, { applied: true, needsFull: false });

  const same = tracker.build({ freeswitch: [fs("1001"), fs("1002")] }, 61_000);
  assertEquals(same.report, {
    full: false,
    engines: ["freeswitch"],
    registrations: [],
    removed: [],
  });
  tracker.acknowledge(same, { applied: true });

  const delta = tracker.build({
    freeswitch: [fs("1001", { networkIP: "198.51.100.9" }), fs("1003")],
  }, 121_000);
  assertEquals(delta.report.full, false);
  assertEquals(
    delta.report.registrations.map((item) => item.username).sort((a, b) => a.localeCompare(b)),
    ["1001", "1003"],
  );
  assertEquals(delta.report.removed, [{
    engine: "freeswitch",
    username: "1002",
    domain: "a.example.com",
  }]);
});

Deno.test("rejected or failed heartbeat and API request force a complete report", () => {
  const tracker = new PabxPresenceTracker(600_000);
  const first = tracker.build({ freeswitch: [fs("1001")] }, 0);
  tracker.acknowledge(first, { applied: true });
  const lost = tracker.build({ freeswitch: [] }, 60_000);
  assertEquals(lost.report.removed.length, 1);
  tracker.acknowledge(lost, undefined);
  assertEquals(tracker.build({ freeswitch: [] }, 120_000).report.full, true);

  const again = new PabxPresenceTracker(600_000);
  again.acknowledge(again.build({ freeswitch: [] }, 0), { applied: true, needsFull: true });
  assertEquals(again.build({ freeswitch: [] }, 60_000).report.full, true);
  const periodic = new PabxPresenceTracker(600_000);
  periodic.acknowledge(periodic.build({ freeswitch: [] }, 0), { applied: true });
  assertEquals(periodic.build({ freeswitch: [] }, 600_000).report.full, true);
});

Deno.test("an engine that could not be read is neither reported nor removed", () => {
  const tracker = new PabxPresenceTracker(600_000);
  const first = tracker.build({ freeswitch: [fs("1001")], asterisk: [] }, 0);
  tracker.acknowledge(first, { applied: true });
  const failed = tracker.build({ asterisk: [] }, 60_000);
  assertEquals(failed.report, {
    full: false,
    engines: ["asterisk"],
    registrations: [],
    removed: [],
  });
  tracker.acknowledge(failed, { applied: true });
  const back = tracker.build({ freeswitch: [fs("1001")], asterisk: [] }, 120_000);
  assertEquals(back.report.registrations, []);
});

Deno.test("Asterisk contacts identify the extension by AOR, not by the device address", () => {
  const output = [
    "  Contact:  <Aor/ContactUri..............................> <Hash....> <Status> <RTT(ms)..>",
    "==========================================================================================",
    "",
    "  Contact:  2001@pbx.example.com/sip:zoiper123@198.51.100.7:5060;ob  5d8e9a0b1c Avail  21.310",
    "  Contact:  2001@pbx.example.com/sip:2001@[2001:db8::7]:5061;transport=tls  aa11 Avail  9.1",
    "  Contact:  2002/sip:2002@203.0.113.4  bb22 Unavail  nan",
    "",
    "Objects found: 3",
  ].join("\n");
  const reports = parseAsteriskPjsipContacts(output);
  assertEquals(reports.map((item) => [item.username, item.domain, item.networkIP]), [
    ["2001", "pbx.example.com", "198.51.100.7"],
    ["2001", "pbx.example.com", "2001:db8::7"],
    ["2002", "203.0.113.4", "203.0.113.4"],
  ]);
  const tracker = new PabxPresenceTracker();
  const report = tracker.build({ asterisk: reports }, 0).report;
  assertEquals(report.registrations.find((item) => item.username === "2001")?.contactCount, 2);
  assertEquals(parseAsteriskPjsipContacts("No objects found.\n"), []);
});
