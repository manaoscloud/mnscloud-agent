/**
 * Disk guard of runtime updates and per-product housekeeping.
 *
 * - Before a runtime update the Agent checks the free space of the product's filesystem. When it is
 *   short, the product's own housekeeping runs first; if still short, the job is refused with
 *   INSUFFICIENT_DISK and the running version is never touched.
 * - After a successful update and once a day (24 h + jitter) the Agent runs the housekeeping script
 *   the product release ships (`scripts/housekeeping.sh --apply`, JSON summary lines on stdout).
 *   Products without the script are skipped. Retention rules live in each product (and the shared
 *   runtime-kit helper), never here.
 * - Updates and housekeeping of the same product never run at the same time.
 */

export type CommandResult = { code: number; stdout: string; stderr: string };
export type Run = (command: string, args: string[], timeoutMs: number) => Promise<CommandResult>;
export type Exists = (path: string) => Promise<boolean>;
export type LogFn = (level: "info" | "warn" | "error", message: string, extra?: unknown) => void;

export const MIN_FREE_BYTES = 1024 ** 3;
export const HOUSEKEEPING_SCRIPT = "scripts/housekeeping.sh";
export const HOUSEKEEPING_TIMEOUT_MS = 600_000;
export const HOUSEKEEPING_INTERVAL_MS = 24 * 3_600_000;
export const HOUSEKEEPING_JITTER_MS = 2 * 3_600_000;
const MAX_SUMMARIES = 20;
const MAX_SUMMARY_CHARS = 2000;

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

/** Available bytes from `df -P -B1 PATH` (POSIX columns: fs, blocks, used, available, ...). */
export function parseDfAvailable(text: string): number | null {
  const lines = text.trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return null;
  const fields = lines[lines.length - 1].trim().split(/\s+/);
  const value = Number(fields[3]);
  return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export async function freeBytes(path: string, run: Run): Promise<number | null> {
  try {
    const result = await run("df", ["-P", "-B1", path], 10_000);
    return result.code === 0 ? parseDfAvailable(result.stdout) : null;
  } catch {
    return null;
  }
}

/** Free space an update needs: at least 1 GiB, or three times the release when it is known. */
export function requiredFreeBytes(releaseBytes = 0) {
  const release = Number.isFinite(releaseBytes) && releaseBytes > 0 ? releaseBytes : 0;
  return Math.max(MIN_FREE_BYTES, Math.ceil(release * 3));
}

/** JSON object lines of a housekeeping run (bounded), ignoring every other line. */
export function parseHousekeepingOutput(stdout: string): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const text = line.trim();
    if (!text.startsWith("{") || text.length > MAX_SUMMARY_CHARS) continue;
    try {
      const value = JSON.parse(text);
      if (value && typeof value === "object" && !Array.isArray(value)) out.push(value);
    } catch { /* Not a summary line. */ }
    if (out.length >= MAX_SUMMARIES) break;
  }
  return out;
}

export function freedBytesOf(results: Record<string, unknown>[]) {
  return results.reduce((total, item) => {
    const value = Number(item.freedBytes ?? 0);
    return total + (Number.isSafeInteger(value) && value > 0 ? value : 0);
  }, 0);
}

export type HousekeepingReport = {
  product: string;
  ok: boolean;
  code: number;
  freedBytes: number;
  results: Record<string, unknown>[];
  message: string | null;
};

/** Runs the product's housekeeping; null when the installed release ships none. */
export async function runHousekeeping(
  product: string,
  repoDir: string,
  deps: { run: Run; exists: Exists; mode?: "apply" | "dry-run" },
): Promise<HousekeepingReport | null> {
  if (!await deps.exists(`${repoDir}/${HOUSEKEEPING_SCRIPT}`)) return null;
  const mode = deps.mode === "dry-run" ? "--dry-run" : "--apply";
  let result: CommandResult;
  try {
    result = await deps.run(
      "bash",
      ["-c", `cd ${shellQuote(repoDir)} && exec bash ${HOUSEKEEPING_SCRIPT} ${mode}`],
      HOUSEKEEPING_TIMEOUT_MS,
    );
  } catch (error) {
    result = {
      code: -1,
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error),
    };
  }
  const results = parseHousekeepingOutput(result.stdout);
  const stderr = result.stderr.trim();
  return {
    product,
    ok: result.code === 0,
    code: result.code,
    freedBytes: freedBytesOf(results),
    results,
    message: result.code === 0 ? null : (stderr.slice(-1000) || `exit code ${result.code}`),
  };
}

export type DiskCheck = {
  ok: boolean;
  path: string;
  requiredBytes: number;
  freeBytesBefore: number | null;
  freeBytesAfter: number | null;
  housekeeping: HousekeepingReport | null;
};

/**
 * Pre-update check. An unmeasurable filesystem never blocks the update (the updater then fails
 * on its own as before); a short one runs housekeeping once and measures again.
 */
export async function ensureDiskForUpdate(
  product: string,
  repoDir: string,
  deps: { run: Run; exists: Exists; requiredBytes?: number },
): Promise<DiskCheck> {
  const requiredBytes = deps.requiredBytes ?? requiredFreeBytes();
  const path = await deps.exists(repoDir) ? repoDir : "/";
  const before = await freeBytes(path, deps.run);
  if (before === null || before >= requiredBytes) {
    return {
      ok: true,
      path,
      requiredBytes,
      freeBytesBefore: before,
      freeBytesAfter: before,
      housekeeping: null,
    };
  }
  const housekeeping = await runHousekeeping(product, repoDir, deps);
  const after = housekeeping ? await freeBytes(path, deps.run) : before;
  return {
    ok: after !== null && after >= requiredBytes,
    path,
    requiredBytes,
    freeBytesBefore: before,
    freeBytesAfter: after,
    housekeeping,
  };
}

export function formatBytes(value: number | null) {
  if (value === null) return "unknown";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = value;
  let unit = 0;
  while (amount >= 1024 && unit < units.length - 1) {
    amount /= 1024;
    unit++;
  }
  return `${amount.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

export function insufficientDiskMessage(label: string, check: DiskCheck) {
  return [
    `${label} update refused: ${formatBytes(check.freeBytesAfter)} free on ${check.path}, ` +
    `${formatBytes(check.requiredBytes)} required. The running version was not changed.`,
    check.housekeeping
      ? `Housekeeping ran first and freed ${formatBytes(check.housekeeping.freedBytes)}` +
        (check.housekeeping.ok ? "." : ` (failed: ${check.housekeeping.message}).`)
      : "This release ships no housekeeping script.",
    "Guidance: free space on the host (or grow the disk), then retry the same version.",
  ].join("\n");
}

/** Serializes work per product: updates wait, housekeeping cycles skip a busy product. */
export class ProductLocks {
  #held = new Map<string, Promise<void>>();

  busy(product: string) {
    return this.#held.has(product);
  }

  async run<T>(product: string, task: () => Promise<T>): Promise<T> {
    while (this.#held.has(product)) await this.#held.get(product);
    let release!: () => void;
    this.#held.set(product, new Promise<void>((resolve) => (release = resolve)));
    try {
      return await task();
    } finally {
      this.#held.delete(product);
      release();
    }
  }

  async tryRun<T>(product: string, task: () => Promise<T>): Promise<T | undefined> {
    if (this.#held.has(product)) return undefined;
    return await this.run(product, task);
  }
}

export type InstalledProduct = { product: string; repoDir: string };

/** Daily housekeeping of every installed product; state survives restarts. */
export class HousekeepingCycle {
  #nextAt: number | null = null;

  constructor(
    private readonly deps: {
      products: () => Promise<InstalledProduct[]>;
      /** Agent-owned housekeeping (for example DB schema artifacts) run in the same cycle. */
      extra?: () => Promise<HousekeepingReport[]>;
      run: Run;
      exists: Exists;
      locks: ProductLocks;
      log: LogFn;
      stateFile: string;
      now?: () => number;
      random?: () => number;
      readText?: (path: string) => Promise<string>;
      writeText?: (path: string, text: string) => Promise<void>;
    },
  ) {}

  #now() {
    return (this.deps.now ?? Date.now)();
  }

  async #lastRunAt(): Promise<number> {
    try {
      const read = this.deps.readText ?? Deno.readTextFile;
      const value = Number(JSON.parse(await read(this.deps.stateFile)).lastRunAt);
      return Number.isFinite(value) && value > 0 ? value : 0;
    } catch {
      return 0;
    }
  }

  /** Runs when due; returns the reports of the products processed (empty when not due). */
  async tick(): Promise<HousekeepingReport[]> {
    const now = this.#now();
    if (this.#nextAt === null) {
      const jitter = Math.floor((this.deps.random ?? Math.random)() * HOUSEKEEPING_JITTER_MS);
      const last = await this.#lastRunAt();
      // A clock that went backwards (last in the future) never postpones housekeeping for long.
      const base = last > now ? now : last;
      this.#nextAt = last ? base + HOUSEKEEPING_INTERVAL_MS + jitter : now + jitter;
    }
    if (now < this.#nextAt) return [];
    this.#nextAt = now + HOUSEKEEPING_INTERVAL_MS +
      Math.floor((this.deps.random ?? Math.random)() * HOUSEKEEPING_JITTER_MS);
    try {
      const write = this.deps.writeText ?? Deno.writeTextFile;
      await write(this.deps.stateFile, JSON.stringify({ lastRunAt: now }) + "\n");
    } catch (error) {
      this.deps.log("warn", "Housekeeping state not saved.", String(error));
    }
    const reports: HousekeepingReport[] = [];
    for (const item of await this.deps.products()) {
      const report = await this.deps.locks.tryRun(
        item.product,
        () => runHousekeeping(item.product, item.repoDir, this.deps),
      );
      if (report === undefined) {
        this.deps.log("info", "Housekeeping skipped: product update in progress.", {
          product: item.product,
        });
        continue;
      }
      if (!report) continue;
      reports.push(report);
      this.deps.log(report.ok ? "info" : "warn", "Housekeeping completed.", {
        product: report.product,
        ok: report.ok,
        freedBytes: report.freedBytes,
        results: report.results,
        message: report.message,
      });
    }
    for (const report of this.deps.extra ? await this.deps.extra() : []) {
      reports.push(report);
      this.deps.log(report.ok ? "info" : "warn", "Housekeeping completed.", report);
    }
    return reports;
  }
}
