/** One in-flight operation per lane; independent lanes cannot block heartbeats. */
export async function runLane(
  operation: () => Promise<void>,
  intervalMs: number | (() => number),
  onError: (error: unknown) => void,
  signal?: AbortSignal,
) {
  let failures = 0;
  while (!signal?.aborted) {
    try {
      await operation();
      failures = 0;
    } catch (error) {
      failures = Math.min(failures + 1, 4);
      onError(error);
    }
    if (signal?.aborted) break;
    const interval = typeof intervalMs === "function" ? intervalMs() : intervalMs;
    const delay = failures
      ? Math.min(60000, interval * 2 ** failures) * (0.8 + Math.random() * 0.2)
      : interval;
    await new Promise<void>((resolve) => {
      const done = () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", done);
        resolve();
      };
      const timer = setTimeout(done, delay);
      signal?.addEventListener("abort", done, { once: true });
      if (signal?.aborted) done();
    });
  }
}

/** Highest job lease long-poll the API honors (`POST /agent/jobs/lease` waitSeconds). */
export const JOB_LONG_POLL_MAX_SECONDS = 20;

/**
 * Job lease long-poll window: the configured `job_wait_seconds` (0 disables), capped by the API
 * maximum and kept 10 s under the request timeout so the lease itself still fits in the request.
 */
export function jobLongPollSeconds(requested: number, requestTimeoutMs: number): number {
  if (!Number.isFinite(requested) || requested <= 0) return 0;
  const fit = Math.floor((requestTimeoutMs - 10_000) / 1000);
  return Math.max(0, Math.min(JOB_LONG_POLL_MAX_SECONDS, Math.floor(requested), fit));
}
