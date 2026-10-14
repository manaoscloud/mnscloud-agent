/** Per-app inventory of an mnscloud-webapps host (read-only); the API stores it and decides alerts. */
export type WebappSyncStatus = "ok" | "failed" | "unknown";
export type WebappStatus = {
  app: string;
  basePath: string;
  source: string;
  ref: string;
  installedVersion: string | null;
  resolvedRef: string | null;
  lastSyncStatus: WebappSyncStatus;
  lastSyncAt: string | null;
  lastError: string | null;
};

export const WEBAPPS_STATUS_SCRIPT = "/opt/mnscloud/mnscloud-webapps/scripts/status-webapps.sh";
export const WEBAPPS_ENV_FILE = "/etc/mnscloud/webapps/webapps.env";
const MAX_APPS = 30;

function text(value: unknown, pattern: RegExp, max: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().slice(0, max);
  return trimmed && pattern.test(trimmed) ? trimmed : null;
}

function oneLine(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const clean = [...value].filter((char) => char.charCodeAt(0) >= 32).join("").trim();
  return clean ? clean.slice(0, 500) : null;
}

/** Validates `status-webapps.sh --json` output; anything unexpected is dropped, never trusted. */
export function parseWebappsStatus(output: string): WebappStatus[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(output);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const apps: WebappStatus[] = [];
  for (const item of parsed.slice(0, MAX_APPS)) {
    if (!item || typeof item !== "object" || Array.isArray(item)) continue;
    const record = item as Record<string, unknown>;
    const app = text(record.app, /^[a-z0-9][a-z0-9_-]{0,62}$/, 63);
    if (!app) continue;
    const status = record.lastSyncStatus === "ok" || record.lastSyncStatus === "failed"
      ? record.lastSyncStatus
      : "unknown";
    const lastSyncAt = text(record.lastSyncAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/, 20);
    apps.push({
      app,
      basePath: text(record.basePath, /^\/[A-Za-z0-9._/-]*$/, 120) ?? "",
      source: text(record.source, /^(release|build)$/, 10) ?? "",
      ref: text(record.ref, /^[A-Za-z0-9._/@+-]+$/, 80) ?? "",
      installedVersion: text(record.installedVersion, /^[A-Za-z0-9._+-]+$/, 40),
      resolvedRef: text(record.resolvedRef, /^[A-Za-z0-9._/@+-]+$/, 80),
      lastSyncStatus: status,
      lastSyncAt,
      lastError: status === "failed" ? oneLine(record.lastError) : null,
    });
  }
  return apps;
}

export type WebappsStatusDeps = {
  exists: (path: string) => Promise<boolean>;
  run: (script: string, envFile: string) => Promise<string | null>;
};

const defaultDeps: WebappsStatusDeps = {
  exists: async (path) => {
    try {
      return (await Deno.stat(path)).isFile;
    } catch {
      return false;
    }
  },
  run: async (script, envFile) => {
    try {
      const result = await new Deno.Command("bash", {
        args: [script, "--json", "--env", envFile],
        stdout: "piped",
        stderr: "null",
        signal: AbortSignal.timeout(15_000),
      }).output();
      return result.success ? new TextDecoder().decode(result.stdout) : null;
    } catch {
      return null;
    }
  },
};

/** Returns null when this host has no webapps runtime or the status script is unavailable. */
export async function collectWebappsStatus(
  deps: WebappsStatusDeps = defaultDeps,
): Promise<WebappStatus[] | null> {
  if (!(await deps.exists(WEBAPPS_STATUS_SCRIPT))) return null;
  const output = await deps.run(WEBAPPS_STATUS_SCRIPT, WEBAPPS_ENV_FILE);
  return output === null ? null : parseWebappsStatus(output);
}
