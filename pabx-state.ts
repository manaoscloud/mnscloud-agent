export function trunkRegistrationStatus(engine: string, output: string, exitCode: number) {
  const normalized = output.toLowerCase();
  if (/invalid gateway!|not found|no objects found|no outbound registration/.test(normalized)) {
    return "not_configured";
  }
  if (exitCode !== 0) return "failed";

  if (engine === "freeswitch") {
    // `sofia status gateway` includes counters such as FailedCallsIN even when a
    // gateway is registered. Read its explicit state fields instead of scanning
    // the whole command output for generic failure words.
    const valueFor = (label: string) =>
      output.match(new RegExp(`^\\s*${label}\\s+(.+?)\\s*$`, "im"))?.[1]?.trim().toLowerCase() ??
        "";
    const state = valueFor("State");
    const status = valueFor("Status");

    if (state === "reged") return "registered";
    if (state === "failed" || state === "fail_wait" || state === "expired") return "failed";
    if (
      state === "register" || state === "trying" || state === "registering" ||
      status === "trying"
    ) return "registering";
    if (state === "unreged" || status === "down") return "not_registered";
    if (/^\s*-err\b|^\s*error\s*:/im.test(output)) return "failed";
    return "unknown";
  }

  if (/error|fail|unreachable|timeout|forbidden|rejected/.test(normalized)) return "failed";
  if (engine === "asterisk") {
    if (/unregistered|not registered|rejected|failed|unavailable/.test(normalized)) {
      return "not_registered";
    }
    if (/registered|available|success/.test(normalized)) return "registered";
  }
  return "unknown";
}
