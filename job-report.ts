/** Job results (complete/fail) are retried across a short API restart (rollout) so a finished job is
 * never left "running" until its lease expires; a lost report blocked queues behind it. */
export const JOB_REPORT_PATH = /^\/agent\/jobs\/[^/]+\/(complete|fail)$/;
export const JOB_REPORT_RETRY_DELAYS_MS = [2000, 5000, 10000, 20000, 45000] as const;

/** Transient when the API restarts or the network drops; never for a business refusal (4xx, 500). */
export function transientReportError(error: unknown): boolean {
  const text = String(error);
  return /returned HTTP 50[234]\b/.test(text) || !/returned HTTP \d{3}/.test(text);
}
