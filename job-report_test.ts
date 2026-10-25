import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { JOB_REPORT_PATH, transientReportError } from "./job-report.ts";

Deno.test("only job results are retried, and only for transient failures", () => {
  assertEquals(JOB_REPORT_PATH.test("/agent/jobs/ABC/complete"), true);
  assertEquals(JOB_REPORT_PATH.test("/agent/jobs/ABC/fail"), true);
  assertEquals(JOB_REPORT_PATH.test("/agent/jobs/lease"), false);
  assertEquals(JOB_REPORT_PATH.test("/agent/heartbeat"), false);
  for (const status of [502, 503, 504]) {
    assertEquals(
      transientReportError(new Error(`/agent/jobs/A/fail returned HTTP ${status}`)),
      true,
    );
  }
  assertEquals(
    transientReportError(new TypeError("error sending request: connection refused")),
    true,
  );
  for (const status of [400, 404, 409, 500]) {
    assertEquals(
      transientReportError(new Error(`/agent/jobs/A/complete returned HTTP ${status}: x`)),
      false,
    );
  }
});
