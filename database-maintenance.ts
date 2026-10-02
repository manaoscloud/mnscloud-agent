// database.table.maintenance helpers: allowlist, credential env parsing, disk guard
// and MariaDB output parsing. Execution lives in main.ts.

export const DATABASE_MAINTENANCE_CAPABILITY = "mnscloud.database.table.maintenance.v1";
export const DATABASE_MAINTENANCE_ENV_PATH = "/etc/mnscloud/db-migration.env";
// The Agent never trusts the job payload: only these high-churn tables can be touched.
export const DATABASE_MAINTENANCE_TABLES = [
  "FreeSwitchCdr",
  "AsteriskCdr",
  "AsteriskCel",
  "VoipPabxRecordingUploadJob",
  "VoipCdrDiagnosticAttachment",
  "VoipSbcCdr",
  "VoipSoftswitchCdr",
] as const;
// A rebuild copies the table; require this much free space relative to its file size.
export const DATABASE_MAINTENANCE_DISK_FACTOR = 1.2;

export type DatabaseMaintenanceEnv = { password: string; database: string };

export function selectMaintenanceTables(requested: unknown): string[] {
  const allowed = new Set<string>(DATABASE_MAINTENANCE_TABLES);
  if (requested === undefined || requested === null) return [...DATABASE_MAINTENANCE_TABLES];
  if (!Array.isArray(requested) || !requested.length) {
    throw new Error("Maintenance table list must be a non-empty array.");
  }
  const tables = [...new Set(requested.map((item) => String(item)))];
  const rejected = tables.filter((table) => !allowed.has(table));
  if (rejected.length) {
    throw new Error(`Table is not allowlisted for maintenance: ${rejected.join(", ")}`);
  }
  return tables;
}

export function parseMaintenanceEnv(text: string): DatabaseMaintenanceEnv {
  const values: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const index = line.indexOf("=");
    const key = line.slice(0, index).replace(/^export\s+/, "").trim();
    let value = line.slice(index + 1).trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1);
    }
    values[key] = value;
  }
  const password = values.DB_ROOT_PASSWORD ?? "";
  const database = values.DB_NAME ?? "";
  if (!password) throw new Error("DB_ROOT_PASSWORD is missing from the migration env.");
  if (!/^[A-Za-z0-9_]{1,64}$/.test(database)) {
    throw new Error("DB_NAME is missing or invalid in the migration env.");
  }
  return { password, database };
}

export function hasRebuildDiskSpace(freeBytes: number, tableBytes: number): boolean {
  if (!Number.isFinite(freeBytes) || !Number.isFinite(tableBytes)) return false;
  return freeBytes >= tableBytes * DATABASE_MAINTENANCE_DISK_FACTOR;
}

/** Parses tab-separated `mariadb -N --batch` output into rows. */
export function parseBatchRows(stdout: string): string[][] {
  return stdout.split("\n").filter((line) => line.length).map((line) => line.split("\t"));
}

/** OPTIMIZE TABLE reports `status OK` (InnoDB adds a "recreate + analyze" note). */
export function optimizeSucceeded(rows: string[][]): { ok: boolean; message: string } {
  const status = rows.find((row) => row[2]?.toLowerCase() === "status");
  const error = rows.find((row) => row[2]?.toLowerCase() === "error");
  if (error) return { ok: false, message: error[3] ?? "OPTIMIZE TABLE reported an error." };
  if (status && status[3]?.toUpperCase() === "OK") return { ok: true, message: "OK" };
  return { ok: false, message: status?.[3] ?? "OPTIMIZE TABLE returned no status." };
}

/** Parses `df -B1 --output=avail <path>` into free bytes. */
export function parseDfAvailable(stdout: string): number {
  const value = stdout.trim().split(/\s+/).filter((item) => /^\d+$/.test(item)).pop();
  return value ? Number(value) : Number.NaN;
}
