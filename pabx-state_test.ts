import { trunkRegistrationStatus } from "./pabx-state.ts";

Deno.test("FreeSWITCH registration is independent of OPTIONS reachability", () => {
  for (
    const [output, expected] of [
      ["State REGED\nStatus DOWN\nFailedCallsIN 3", "registered"],
      ["State REGED\nStatus UP", "registered"],
      ["State DOWN\nStatus DOWN", "not_registered"],
      ["State TRYING\nStatus UP", "registering"],
      ["State FAIL_WAIT\nStatus UP", "failed"],
      ["State EXPIRED\nStatus UP", "failed"],
      ["Invalid Gateway!", "not_configured"],
    ]
  ) {
    if (trunkRegistrationStatus("freeswitch", output, 0) !== expected) {
      throw new Error(`Unexpected interpretation: ${output}`);
    }
  }
});

Deno.test("Asterisk reports registration separately from CLI execution", () => {
  for (
    const [output, expected] of [
      ["trunk-test Registered", "registered"],
      ["trunk-test Unregistered", "not_registered"],
      ["trunk-test Rejected", "failed"],
      ["No objects found.", "not_configured"],
    ]
  ) {
    if (trunkRegistrationStatus("asterisk", output, 0) !== expected) throw new Error(output);
  }
});
