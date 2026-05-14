type AgentConfig = {
  apiBase: string;
  name: string;
  hostname: string;
  version: string;
  pollIntervalMs: number;
  heartbeatIntervalMs: number;
  agentUUIDFile: string;
  agentTokenFile: string;
  recordingsRoots: string[];
  recordingMounts: Array<{ hostRoot: string; containerRoot: string }>;
  deleteAfterUpload: boolean;
  mediaRoots: string[];
  mediaMounts: Array<{ hostRoot: string; containerRoot: string }>;
};

type LeaseJob = {
  jobUUID: string;
  jobType?: "recording_upload" | "media_file_sync" | string | null;
  action?: "sync" | "delete" | string | null;
  localPath: string;
  downloadUrl?: string | null;
  downloadMethod?: string | null;
  downloadHeaders?: Record<string, string> | null;
  uploadUrl?: string | null;
  uploadMethod?: string | null;
  uploadHeaders?: Record<string, string> | null;
};

type IniConfig = Record<string, Record<string, string>>;

const CONFIG_PATH = "/etc/mnscloud/agent/agent.conf";

function parseList(value: string) {
  return value.split(",").map((item) => item.trim()).filter(Boolean);
}

function parseRecordingMounts(value: string) {
  return parseList(value).map((entry) => {
    const [hostRoot, containerRoot] = entry.split("=").map((item) =>
      item?.trim()
    );
    return hostRoot && containerRoot ? { hostRoot, containerRoot } : null;
  }).filter((item): item is { hostRoot: string; containerRoot: string } =>
    item !== null
  );
}

function parseIni(text: string): IniConfig {
  const config: IniConfig = { default: {} };
  let section = "default";
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sectionMatch = line.match(/^\[([a-zA-Z0-9_.-]+)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1];
      config[section] ??= {};
      continue;
    }
    const separator = line.indexOf("=");
    if (separator < 0) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (key) config[section][key] = value;
  }
  return config;
}

function getConfigValue(
  config: IniConfig,
  section: string,
  key: string,
  fallback: string,
) {
  return config[section]?.[key] ?? config.default?.[key] ?? fallback;
}

function getNumber(
  config: IniConfig,
  section: string,
  key: string,
  fallback: number,
) {
  const value = Number(getConfigValue(config, section, key, String(fallback)));
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function getBoolean(
  config: IniConfig,
  section: string,
  key: string,
  fallback: boolean,
) {
  const value = getConfigValue(config, section, key, String(fallback)).trim()
    .toLowerCase();
  if (["1", "true", "yes", "y", "sim", "on"].includes(value)) return true;
  if (["0", "false", "no", "n", "nao", "não", "off"].includes(value)) {
    return false;
  }
  return fallback;
}

async function loadConfig(): Promise<AgentConfig> {
  const parsed = parseIni(await Deno.readTextFile(CONFIG_PATH));
  return {
    apiBase: getConfigValue(
      parsed,
      "agent",
      "api_base",
      "https://dev1.publichost.cloud",
    ),
    name: getConfigValue(parsed, "agent", "name", "mnscloud-agent"),
    hostname: getConfigValue(parsed, "agent", "hostname", "mnscloud-agent"),
    version: getConfigValue(parsed, "agent", "version", "0.1.0"),
    pollIntervalMs: getNumber(parsed, "agent", "poll_interval_ms", 15_000),
    heartbeatIntervalMs: getNumber(
      parsed,
      "agent",
      "heartbeat_interval_ms",
      60_000,
    ),
    agentUUIDFile: getConfigValue(
      parsed,
      "identity",
      "agent_uuid_file",
      "/var/lib/mnscloud/agent/agent.uuid",
    ),
    agentTokenFile: getConfigValue(
      parsed,
      "identity",
      "agent_token_file",
      "/var/lib/mnscloud/agent/agent.token",
    ),
    recordingsRoots: parseList(
      getConfigValue(
        parsed,
        "recordings",
        "roots",
        "/recordings/freeswitch,/recordings/asterisk",
      ),
    ),
    recordingMounts: parseRecordingMounts(
      getConfigValue(
        parsed,
        "recordings",
        "mounts",
        "/var/lib/freeswitch/recordings=/recordings/freeswitch,/var/spool/asterisk/monitor=/recordings/asterisk",
      ),
    ),
    deleteAfterUpload: getBoolean(
      parsed,
      "recordings",
      "delete_after_upload",
      true,
    ),
    mediaRoots: parseList(
      getConfigValue(
        parsed,
        "media_files",
        "roots",
        "/media-files",
      ),
    ),
    mediaMounts: parseRecordingMounts(
      getConfigValue(
        parsed,
        "media_files",
        "mounts",
        "/var/lib/mnscloud/pabx/media-files=/media-files",
      ),
    ),
  };
}

function log(
  level: "info" | "warn" | "error",
  message: string,
  extra?: unknown,
) {
  const suffix = extra === undefined ? "" : ` ${JSON.stringify(extra)}`;
  console[level](
    `[mnscloud-agent] ${new Date().toISOString()} ${message}${suffix}`,
  );
}

function apiUrl(config: AgentConfig, path: string) {
  return `${config.apiBase.replace(/\/+$/, "")}/api/v1${path}`;
}

async function readText(path: string) {
  return (await Deno.readTextFile(path)).trim();
}

async function optionalRead(path: string) {
  try {
    return await readText(path);
  } catch {
    return "";
  }
}

function bearerHeaders(token: string, agentUUID: string) {
  return {
    "content-type": "application/json",
    authorization: `Bearer ${token}`,
    "x-mnscloud-agent-uuid": agentUUID,
  };
}

async function jsonRequest<T>(
  config: AgentConfig,
  path: string,
  token: string,
  agentUUID: string,
  body: Record<string, unknown>,
) {
  const response = await fetch(apiUrl(config, path), {
    method: "POST",
    headers: bearerHeaders(token, agentUUID),
    body: JSON.stringify(body),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      typeof payload?.error === "string"
        ? payload.error
        : `HTTP ${response.status}`,
    );
  }
  return payload as T;
}

async function heartbeat(
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  await jsonRequest(config, "/agent/heartbeat", agentToken, agentUUID, {
    name: config.name,
    hostname: config.hostname,
    version: config.version,
    uptimeSeconds: Math.floor(performance.now() / 1000),
    recordingsRoots: config.recordingsRoots,
    recordingMounts: config.recordingMounts,
    mediaRoots: config.mediaRoots,
    mediaMounts: config.mediaMounts,
  });
}

function normalizePath(path: string) {
  return path.replaceAll("\\", "/").replace(/\/+/g, "/");
}

function isAllowedLocalPath(path: string, roots: string[]) {
  const normalized = normalizePath(path);
  return roots.some((root) => {
    const normalizedRoot = normalizePath(root).replace(/\/+$/, "");
    return normalized === normalizedRoot ||
      normalized.startsWith(`${normalizedRoot}/`);
  });
}

function resolveReadablePath(path: string, config: AgentConfig) {
  const normalized = normalizePath(path);
  for (const mount of config.recordingMounts) {
    const hostRoot = normalizePath(mount.hostRoot).replace(/\/+$/, "");
    const containerRoot = normalizePath(mount.containerRoot).replace(
      /\/+$/,
      "",
    );
    if (normalized === hostRoot || normalized.startsWith(`${hostRoot}/`)) {
      const suffix = normalized.slice(hostRoot.length).replace(/^\/+/, "");
      const candidate = suffix ? `${containerRoot}/${suffix}` : containerRoot;
      return isAllowedLocalPath(candidate, config.recordingsRoots)
        ? candidate
        : null;
    }
  }
  return isAllowedLocalPath(normalized, config.recordingsRoots)
    ? normalized
    : null;
}

function resolveMediaPath(path: string, config: AgentConfig) {
  const normalized = normalizePath(path);
  for (const mount of config.mediaMounts) {
    const hostRoot = normalizePath(mount.hostRoot).replace(/\/+$/, "");
    const containerRoot = normalizePath(mount.containerRoot).replace(
      /\/+$/,
      "",
    );
    if (normalized === hostRoot || normalized.startsWith(`${hostRoot}/`)) {
      const suffix = normalized.slice(hostRoot.length).replace(/^\/+/, "");
      const candidate = suffix ? `${containerRoot}/${suffix}` : containerRoot;
      return isAllowedLocalPath(candidate, config.mediaRoots)
        ? candidate
        : null;
    }
  }
  return isAllowedLocalPath(normalized, config.mediaRoots) ? normalized : null;
}

async function ensureParentDirectory(path: string) {
  const normalized = normalizePath(path);
  const separator = normalized.lastIndexOf("/");
  if (separator <= 0) return;
  await Deno.mkdir(normalized.slice(0, separator), { recursive: true });
}

async function failJob(
  config: AgentConfig,
  jobUUID: string,
  agentUUID: string,
  agentToken: string,
  code: string,
  message: string,
  jobType = "recording_upload",
) {
  await jsonRequest(
    config,
    `/agent/jobs/${jobUUID}/fail`,
    agentToken,
    agentUUID,
    {
      jobType,
      errorCode: code,
      message,
    },
  ).catch((error) =>
    log("warn", "Failed to report job failure.", String(error))
  );
}

async function uploadJob(
  job: LeaseJob,
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const readablePath = resolveReadablePath(job.localPath, config);
  if (!readablePath) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "PATH_NOT_ALLOWED",
      job.localPath,
    );
    return;
  }
  if (!job.uploadUrl) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "UPLOAD_URL_MISSING",
      "No signed upload URL was provided.",
    );
    return;
  }

  let file: Uint8Array;
  try {
    file = await Deno.readFile(readablePath);
  } catch (error) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "FILE_NOT_FOUND",
      String(error),
    );
    return;
  }

  const response = await fetch(job.uploadUrl, {
    method: job.uploadMethod || "PUT",
    headers: job.uploadHeaders ?? {},
    body: file,
  });
  if (!response.ok) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "UPLOAD_FAILED",
      `HTTP ${response.status}`,
    );
    return;
  }

  await jsonRequest(
    config,
    `/agent/jobs/${job.jobUUID}/complete`,
    agentToken,
    agentUUID,
    {
      size: file.byteLength,
    },
  );

  if (config.deleteAfterUpload) {
    try {
      await Deno.remove(readablePath);
      log("info", "Local recording removed after successful upload.", {
        jobUUID: job.jobUUID,
        path: readablePath,
      });
    } catch (error) {
      log("warn", "Uploaded recording could not be removed locally.", {
        jobUUID: job.jobUUID,
        path: readablePath,
        error: String(error),
      });
    }
  }
}

async function syncMediaFileJob(
  job: LeaseJob,
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const localPath = resolveMediaPath(job.localPath, config);
  if (!localPath) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "PATH_NOT_ALLOWED",
      job.localPath,
      "media_file_sync",
    );
    return;
  }

  if (job.action === "delete") {
    try {
      await Deno.remove(localPath);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) {
        await failJob(
          config,
          job.jobUUID,
          agentUUID,
          agentToken,
          "DELETE_FAILED",
          String(error),
          "media_file_sync",
        );
        return;
      }
    }
    await jsonRequest(
      config,
      `/agent/jobs/${job.jobUUID}/complete`,
      agentToken,
      agentUUID,
      { jobType: "media_file_sync", action: "delete" },
    );
    log("info", "Offline media file removed.", {
      jobUUID: job.jobUUID,
      path: localPath,
    });
    return;
  }

  if (!job.downloadUrl) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "DOWNLOAD_URL_MISSING",
      "No download URL was provided.",
      "media_file_sync",
    );
    return;
  }

  const downloadUrl = job.downloadUrl.startsWith("/")
    ? `${config.apiBase.replace(/\/+$/, "")}${job.downloadUrl}`
    : job.downloadUrl;
  const headers = { ...(job.downloadHeaders ?? {}) };
  const sameApi = downloadUrl.startsWith(apiUrl(config, "/"));
  if (sameApi) {
    Object.assign(headers, bearerHeaders(agentToken, agentUUID));
  }

  const response = await fetch(downloadUrl, {
    method: job.downloadMethod || "GET",
    headers,
  });
  if (!response.ok) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "DOWNLOAD_FAILED",
      `HTTP ${response.status}`,
      "media_file_sync",
    );
    return;
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  await ensureParentDirectory(localPath);
  const tmpPath = `${localPath}.tmp-${crypto.randomUUID()}`;
  await Deno.writeFile(tmpPath, bytes);
  await Deno.rename(tmpPath, localPath);

  await jsonRequest(
    config,
    `/agent/jobs/${job.jobUUID}/complete`,
    agentToken,
    agentUUID,
    { jobType: "media_file_sync", action: "sync", size: bytes.byteLength },
  );
  log("info", "Offline media file synced.", {
    jobUUID: job.jobUUID,
    path: localPath,
    size: bytes.byteLength,
  });
}

async function pollJobs(
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const result = await jsonRequest<{ data?: { jobs?: LeaseJob[] } }>(
    config,
    "/agent/jobs/lease",
    agentToken,
    agentUUID,
    { limit: 3 },
  );
  for (const job of result.data?.jobs ?? []) {
    if (job.jobType === "media_file_sync") {
      await syncMediaFileJob(job, config, agentUUID, agentToken);
    } else {
      await uploadJob(job, config, agentUUID, agentToken);
    }
  }
}

async function main() {
  const config = await loadConfig();
  const agentUUID = await readText(config.agentUUIDFile);
  log("info", "Agent started.", {
    config: CONFIG_PATH,
    name: config.name,
    agentUUID,
  });

  let lastHeartbeat = 0;
  while (true) {
    try {
      const agentToken = await optionalRead(config.agentTokenFile);
      if (!agentToken) {
        log("warn", "Agent is installed but not activated.", {
          agentUUID,
          tokenFile: config.agentTokenFile,
        });
        await new Promise((resolve) =>
          setTimeout(resolve, config.heartbeatIntervalMs)
        );
        continue;
      }

      const now = Date.now();
      if (now - lastHeartbeat >= config.heartbeatIntervalMs) {
        await heartbeat(config, agentUUID, agentToken);
        lastHeartbeat = now;
      }
      await pollJobs(config, agentUUID, agentToken);
    } catch (error) {
      log("warn", "Agent loop failed.", String(error));
    }
    await new Promise((resolve) => setTimeout(resolve, config.pollIntervalMs));
  }
}

if (import.meta.main) {
  main().catch((error) => {
    log("error", "Fatal agent error.", String(error));
    Deno.exit(1);
  });
}
