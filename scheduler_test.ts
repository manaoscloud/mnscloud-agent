import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { JOB_LONG_POLL_MAX_SECONDS, jobLongPollSeconds, runLane } from "./scheduler.ts";

Deno.test("job long-poll window is bounded by the API maximum and the request timeout", () => {
  assertEquals(jobLongPollSeconds(20, 30_000), 20);
  assertEquals(jobLongPollSeconds(60, 120_000), JOB_LONG_POLL_MAX_SECONDS);
  assertEquals(jobLongPollSeconds(20, 15_000), 5);
  assertEquals(jobLongPollSeconds(20, 5_000), 0);
  assertEquals(jobLongPollSeconds(0, 30_000), 0);
  assertEquals(jobLongPollSeconds(Number.NaN, 30_000), 0);
});

Deno.test("a lane reads its interval after each run, so a long-poll lane re-leases at once", async () => {
  const stop = new AbortController();
  const intervals: number[] = [];
  let longPoll = false;
  let runs = 0;
  const started = performance.now();
  await runLane(
    () => {
      runs++;
      longPoll = runs > 1;
      if (runs === 4) stop.abort();
      return Promise.resolve();
    },
    () => {
      const interval = longPoll ? 1 : 50;
      intervals.push(interval);
      return interval;
    },
    () => {},
    stop.signal,
  );
  assertEquals(runs, 4);
  assertEquals(intervals, [50, 1, 1]);
  assertEquals(performance.now() - started < 1000, true);
});
