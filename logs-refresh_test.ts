import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { LOGS_CONFIG_UNIT, runLogsRefresh } from "./logs-refresh.ts";

Deno.test("logs refresh starts only the node configuration unit, without blocking", async () => {
  const calls: string[][] = [];
  const started = await runLogsRefresh(
    async (args) => {
      calls.push(args);
      return true;
    },
    async (path) => path === `/etc/systemd/system/${LOGS_CONFIG_UNIT}`,
  );
  assertEquals(started, true);
  assertEquals(calls, [["systemctl", "start", "--no-block", "mnscloud-logs-config.service"]]);
});

Deno.test("logs refresh does nothing on a host without the Logs node", async () => {
  const calls: string[][] = [];
  const started = await runLogsRefresh(async (args) => {
    calls.push(args);
    return true;
  }, async () => false);
  assertEquals([started, calls], [false, []]);
});
