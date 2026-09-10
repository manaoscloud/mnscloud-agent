/** One in-flight operation per lane; independent lanes cannot block heartbeats. */
export async function runLane(
  operation: () => Promise<void>,
  intervalMs: number,
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
    const delay = failures
      ? Math.min(60000, intervalMs * 2 ** failures) * (0.8 + Math.random() * 0.2)
      : intervalMs;
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
