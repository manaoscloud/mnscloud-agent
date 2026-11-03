/** Aggregate observations only. Counts do not establish cluster configuration or failover readiness. */
export type VoipLoad = {
  engine: "freeswitch" | "asterisk";
  observedAt: string;
  activeCalls: number | null;
  activeChannels: number | null;
  sessionsPerSecond: number | null;
};
function count(output: string, pattern: RegExp): number | null {
  if (output.length > 16384) return null;
  const matches = [...output.matchAll(pattern)];
  if (matches.length !== 1) return null;
  const value = Number(matches[0][1]);
  return Number.isSafeInteger(value) && value >= 0 && value <= 1000000000 ? value : null;
}
export function parseAsteriskLoad(output: string, observedAt: string): VoipLoad {
  return {
    engine: "asterisk",
    observedAt,
    activeCalls: count(output, /^\s*(\d+) active calls?\s*$/gm),
    activeChannels: count(output, /^\s*(\d+) active channels?\s*$/gm),
    // Processed-call counters are not a measurement of offered calls per second.
    sessionsPerSecond: null,
  };
}
export function parseFreeSwitchLoad(calls: string, status: string, observedAt: string): VoipLoad {
  const ready = /FreeSWITCH .* is ready\s*$/m.test(status);
  return {
    engine: "freeswitch",
    observedAt,
    activeCalls: ready ? count(calls, /^\s*(\d+) total\.?\s*$/gm) : null,
    activeChannels: ready ? count(status, /^\s*(\d+) session\(s\)\s+-.*$/gm) : null,
    // Sessions include call legs. Never relabel this value as offered call CPS.
    sessionsPerSecond: ready ? count(status, /^\s*(\d+) session\(s\) per Sec .*$/gm) : null,
  };
}
