/** Local operating-system observations; authorization remains in the API. */
export type ResourceSample = {
  kind: "network" | "filesystem";
  name: string;
  values: Record<string, number>;
};

type CounterSample = { at: number; values: bigint[]; identity?: number };
const previous = new Map<string, CounterSample>();

export function parseNetworkCounters(
  text: string,
  at: number,
  cache = previous,
  links = new Map<string, { index: number; up: number | null }>(),
): ResourceSample[] {
  const found = new Set<string>();
  const result: ResourceSample[] = [];
  for (const line of text.split("\n")) {
    const match = /^\s*([^:\s]{1,64}):\s*(.*)$/.exec(line);
    if (!match || match[1] === "lo" || result.length >= 32) continue;
    const name = match[1];
    const fields = match[2].trim().split(/\s+/);
    if (fields.length < 16 || fields.some((value) => !/^\d+$/.test(value))) continue;
    const counters = [0, 8, 1, 9, 2, 10, 3, 11].map((index) => BigInt(fields[index]));
    found.add(name);
    const old = cache.get(name);
    const link = links.get(name);
    cache.set(name, { at, values: counters, identity: link?.index });
    const values: Record<string, number> = {};
    if (link?.up !== null && link?.up !== undefined) values.link_up = link.up;
    const elapsed = old ? (at - old.at) / 1000 : 0;
    if (
      old && old.identity === link?.index && elapsed >= 1 && elapsed <= 300 &&
      counters.every((value, i) => value >= old.values[i])
    ) {
      const keys = [
        "rx_bps",
        "tx_bps",
        "rx_pps",
        "tx_pps",
        "rx_errors_ps",
        "tx_errors_ps",
        "rx_drops_ps",
        "tx_drops_ps",
      ];
      counters.forEach((value, i) => {
        const delta = value - old.values[i];
        if (delta <= BigInt(Number.MAX_SAFE_INTEGER)) {
          values[keys[i]] = Number(delta) / elapsed * (i < 2 ? 8 : 1);
        }
      });
    }
    result.push({ kind: "network", name, values });
  }
  for (const name of cache.keys()) if (!found.has(name)) cache.delete(name);
  return result;
}

export function parseFilesystems(text: string): ResourceSample[] {
  const result: ResourceSample[] = [];
  for (const line of text.split("\n").slice(1)) {
    // POSIX df columns: filesystem, blocks, used, available, capacity, mounted-on.
    const fields = /^\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+%\s+(.+)$/.exec(line.trim());
    if (!fields || result.length >= 32) continue;
    const total = Number(fields[1]) * 1024;
    const available = Number(fields[3]) * 1024;
    const name = fields[4];
    if (
      name.length > 190 || !name.startsWith("/") || !Number.isSafeInteger(total) || total <= 0 ||
      !Number.isSafeInteger(available) || available > total
    ) continue;
    result.push({
      kind: "filesystem",
      name,
      values: {
        total_bytes: total,
        available_bytes: available,
        usage_percent: 100 * (total - available) / total,
      },
    });
  }
  return result;
}

export function parseNetworkLinks(text: string) {
  const result = new Map<string, { index: number; up: number | null }>();
  try {
    const rows = JSON.parse(text);
    if (!Array.isArray(rows)) return result;
    for (const row of rows.slice(0, 128)) {
      if (typeof row.ifname === "string" && Number.isInteger(row.ifindex)) {
        result.set(row.ifname, {
          index: row.ifindex,
          up: row.operstate === "UP"
            ? 1
            : ["DOWN", "LOWERLAYERDOWN", "NOTPRESENT", "DORMANT"].includes(row.operstate)
            ? 0
            : null,
        });
      }
    }
  } catch { /* Interface state is optional; do not invent a state. */ }
  return result;
}
