type AgentConfig = {
  os: "linux" | "windows" | "other";
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
  capabilities: Record<string, boolean>;
  nginxEdgeConfigDir: string;
  nginxEdgeAcmeRoot: string;
  nginxEdgeSslLiveDir: string;
  nginxEdgeSslArchiveDir: string;
  nginxEdgeSslRenewalDir: string;
  nginxEdgeAppUpstream: string;
  nginxEdgeApiUpstream: string;
  nginxEdgeTestCommand: string;
  nginxEdgeReloadCommand: string;
  certbotCommand: string;
  certbotDefaultEmail: string;
  webrtcEdgeSyncCommand: string;
  asteriskCli: string;
  freeswitchCli: string;
  asteriskAmiHost: string;
  asteriskAmiPort: number;
  asteriskAmiUsername: string;
  asteriskAmiSecret: string;
  freeswitchEslHost: string;
  freeswitchEslPort: number;
  freeswitchEslPassword: string;
  commandTimeoutMs: number;
};

type LeaseJob = {
  jobUUID: string;
  jobType?:
    | "recording_upload"
    | "media_file_sync"
    | "pabx_command"
    | "cyber_security"
    | "nginx_edge"
    | "certbot"
    | "webrtc_edge"
    | string
    | null;
  action?: "sync" | "delete" | string | null;
  localPath?: string | null;
  engine?: string | null;
  commandType?: string | null;
  payload?: Record<string, unknown> | null;
  downloadUrl?: string | null;
  downloadMethod?: string | null;
  downloadHeaders?: Record<string, string> | null;
  uploadUrl?: string | null;
  uploadMethod?: string | null;
  uploadHeaders?: Record<string, string> | null;
};

type PabxRegistrationReport = {
  engine: "freeswitch";
  username: string;
  domain?: string;
  contact?: string;
  userAgent?: string;
  networkIP?: string;
  expiresAt?: string;
};

type IniConfig = Record<string, Record<string, string>>;

const IS_WINDOWS = Deno.build.os === "windows";
const AGENT_OS: AgentConfig["os"] = IS_WINDOWS
  ? "windows"
  : Deno.build.os === "linux"
  ? "linux"
  : "other";
const PROGRAM_DATA = Deno.env.get("ProgramData") ?? "C:\\ProgramData";
const CONFIG_PATH = Deno.env.get("MNSCLOUD_AGENT_CONFIG") ??
  (IS_WINDOWS
    ? `${PROGRAM_DATA}\\MNSCloud\\Agent\\agent.conf`
    : "/etc/mnscloud/agent/agent.conf");

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

function capabilitiesFromConfig(config: IniConfig) {
  const capabilities: Record<string, boolean> = {};
  for (const key of Object.keys(config.capabilities ?? {})) {
    capabilities[key] = getBoolean(config, "capabilities", key, false);
  }
  return capabilities;
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
  if (["1", "true", "yes", "y", "on"].includes(value)) return true;
  if (["0", "false", "no", "n", "off"].includes(value)) {
    return false;
  }
  return fallback;
}

async function loadConfig(): Promise<AgentConfig> {
  const parsed = parseIni(await Deno.readTextFile(CONFIG_PATH));
  const defaultStateDir = IS_WINDOWS
    ? `${PROGRAM_DATA}\\MNSCloud\\Agent`
    : "/var/lib/mnscloud/agent";
  const defaultRecordingRoots = IS_WINDOWS
    ? `${PROGRAM_DATA}\\MNSCloud\\Recordings`
    : "/var/lib/freeswitch/recordings,/var/spool/asterisk/monitor";
  const defaultMediaRoots = IS_WINDOWS
    ? `${PROGRAM_DATA}\\MNSCloud\\MediaFiles`
    : "/var/lib/mnscloud/pabx/media-files";
  return {
    os: AGENT_OS,
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
      `${defaultStateDir}${IS_WINDOWS ? "\\" : "/"}agent.uuid`,
    ),
    agentTokenFile: getConfigValue(
      parsed,
      "identity",
      "agent_token_file",
      `${defaultStateDir}${IS_WINDOWS ? "\\" : "/"}agent.token`,
    ),
    recordingsRoots: parseList(
      getConfigValue(
        parsed,
        "recordings",
        "roots",
        defaultRecordingRoots,
      ),
    ),
    recordingMounts: parseRecordingMounts(
      getConfigValue(
        parsed,
        "recordings",
        "mounts",
        "",
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
        defaultMediaRoots,
      ),
    ),
    mediaMounts: parseRecordingMounts(
      getConfigValue(
        parsed,
        "media_files",
        "mounts",
        "",
      ),
    ),
    capabilities: capabilitiesFromConfig(parsed),
    nginxEdgeConfigDir: getConfigValue(
      parsed,
      "nginx_edge",
      "config_dir",
      "/etc/nginx/mnscloud/theme-domains",
    ),
    nginxEdgeAcmeRoot: getConfigValue(
      parsed,
      "nginx_edge",
      "acme_root",
      "/var/www/certbot",
    ),
    nginxEdgeSslLiveDir: getConfigValue(
      parsed,
      "nginx_edge",
      "ssl_live_dir",
      "/etc/letsencrypt/live",
    ),
    nginxEdgeSslArchiveDir: getConfigValue(
      parsed,
      "nginx_edge",
      "ssl_archive_dir",
      "/etc/letsencrypt/archive",
    ),
    nginxEdgeSslRenewalDir: getConfigValue(
      parsed,
      "nginx_edge",
      "ssl_renewal_dir",
      "/etc/letsencrypt/renewal",
    ),
    nginxEdgeAppUpstream: getConfigValue(
      parsed,
      "nginx_edge",
      "app_upstream",
      "$app_upstream",
    ),
    nginxEdgeApiUpstream: getConfigValue(
      parsed,
      "nginx_edge",
      "api_upstream",
      "$api_upstream",
    ),
    nginxEdgeTestCommand: getConfigValue(
      parsed,
      "nginx_edge",
      "test_command",
      "nginx -t",
    ),
    nginxEdgeReloadCommand: getConfigValue(
      parsed,
      "nginx_edge",
      "reload_command",
      "systemctl reload nginx",
    ),
    certbotCommand: getConfigValue(
      parsed,
      "certbot",
      "command",
      "certbot",
    ),
    certbotDefaultEmail: getConfigValue(parsed, "certbot", "default_email", ""),
    webrtcEdgeSyncCommand: getConfigValue(
      parsed,
      "webrtc_edge",
      "sync_command",
      "/opt/mnscloud/kamailio-webrtc/scripts/update-kamailio-webrtc.sh",
    ),
    asteriskCli: getConfigValue(parsed, "commands", "asterisk_cli", "asterisk"),
    freeswitchCli: getConfigValue(
      parsed,
      "commands",
      "freeswitch_cli",
      "fs_cli",
    ),
    asteriskAmiHost: getConfigValue(
      parsed,
      "commands",
      "asterisk_ami_host",
      "127.0.0.1",
    ),
    asteriskAmiPort: getNumber(parsed, "commands", "asterisk_ami_port", 5038),
    asteriskAmiUsername: getConfigValue(
      parsed,
      "commands",
      "asterisk_ami_username",
      "",
    ),
    asteriskAmiSecret: getConfigValue(
      parsed,
      "commands",
      "asterisk_ami_secret",
      "",
    ),
    freeswitchEslHost: getConfigValue(
      parsed,
      "commands",
      "freeswitch_esl_host",
      "127.0.0.1",
    ),
    freeswitchEslPort: getNumber(
      parsed,
      "commands",
      "freeswitch_esl_port",
      8021,
    ),
    freeswitchEslPassword: getConfigValue(
      parsed,
      "commands",
      "freeswitch_esl_password",
      "",
    ),
    commandTimeoutMs: getNumber(parsed, "commands", "timeout_ms", 15_000),
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

async function reportJobProgress(
  config: AgentConfig,
  jobUUID: string,
  agentUUID: string,
  agentToken: string,
  step: string,
  percent: number,
  message: string,
  extra: Record<string, unknown> = {},
) {
  try {
    await jsonRequest(
      config,
      `/agent/jobs/${jobUUID}/progress`,
      agentToken,
      agentUUID,
      {
        jobType: "cyber_security",
        step,
        percent,
        message,
        ...extra,
      },
    );
  } catch (error) {
    log("warn", "Failed to report job progress.", {
      jobUUID,
      step,
      error: error instanceof Error ? error.message : String(error),
    });
  }
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

function recordString(
  row: Record<string, unknown>,
  aliases: string[],
): string | undefined {
  const values = new Map<string, unknown>();
  for (const [key, value] of Object.entries(row)) {
    values.set(key.toLowerCase(), value);
  }
  for (const alias of aliases) {
    const value = values.get(alias.toLowerCase());
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number" && Number.isFinite(value)) {
      return String(value);
    }
  }
  return undefined;
}

function isoDateFromFreeSwitch(value: string | undefined) {
  if (!value) return undefined;
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 1_000_000_000) {
    return new Date(numeric * 1000).toISOString();
  }
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : undefined;
}

function normalizeFreeSwitchRegistrationRow(
  row: Record<string, unknown>,
): PabxRegistrationReport | null {
  const username = recordString(row, [
    "reg_user",
    "user",
    "username",
    "sip_auth_username",
    "sip_user",
  ]);
  if (!username) return null;
  return {
    engine: "freeswitch",
    username,
    domain: recordString(row, ["realm", "domain", "host"]),
    contact: recordString(row, ["url", "contact", "uri"]),
    userAgent: recordString(row, ["user_agent", "userAgent"]),
    networkIP: recordString(row, ["network_ip", "networkIP", "ip"]),
    expiresAt: isoDateFromFreeSwitch(
      recordString(row, ["expires", "expires_at", "expiresAt"]),
    ),
  };
}

function rowsFromJsonPayload(payload: unknown): Record<string, unknown>[] {
  if (Array.isArray(payload)) {
    return payload.filter((item): item is Record<string, unknown> =>
      item !== null && typeof item === "object" && !Array.isArray(item)
    );
  }
  if (
    payload !== null && typeof payload === "object" && !Array.isArray(payload)
  ) {
    const object = payload as Record<string, unknown>;
    for (const key of ["rows", "data", "registrations"]) {
      const value = object[key];
      if (Array.isArray(value)) {
        return value.filter((item): item is Record<string, unknown> =>
          item !== null && typeof item === "object" && !Array.isArray(item)
        );
      }
    }
  }
  return [];
}

function parseFreeSwitchRegistrationsText(
  output: string,
): PabxRegistrationReport[] {
  const lines = output.split(/\r?\n/).map((line) => line.trim()).filter(
    Boolean,
  );
  const registrations: PabxRegistrationReport[] = [];
  for (const line of lines) {
    if (/^(reg_user|total|=|-|name\b)/i.test(line)) continue;
    const parts = line.includes("|")
      ? line.split("|").map((part) => part.trim())
      : line.includes(",")
      ? line.split(",").map((part) => part.trim())
      : line.split(/\s+/).map((part) => part.trim());
    if (parts.length < 2) continue;
    const row = normalizeFreeSwitchRegistrationRow({
      reg_user: parts[0],
      realm: parts[1],
      url: parts[2],
      expires: parts[3],
      network_ip: parts[4],
      user_agent: parts.slice(5).join(" "),
    });
    if (row) registrations.push(row);
  }
  return registrations;
}

async function collectPabxRegistrations(config: AgentConfig) {
  if (!config.capabilities["voip.freeswitch.manage"]) return [];
  try {
    const result = await runLocalCommand(
      config.freeswitchCli,
      ["-x", "show registrations as json"],
      config.commandTimeoutMs,
    );
    if (result.code === 0 && result.stdout) {
      const rows = rowsFromJsonPayload(JSON.parse(result.stdout));
      return rows.map(normalizeFreeSwitchRegistrationRow)
        .filter((item): item is PabxRegistrationReport => item !== null);
    }
  } catch (error) {
    log(
      "warn",
      "FreeSWITCH registration JSON collection failed.",
      String(error),
    );
  }

  try {
    const result = await runLocalCommand(
      config.freeswitchCli,
      ["-x", "show registrations"],
      config.commandTimeoutMs,
    );
    if (result.code === 0 && result.stdout) {
      return parseFreeSwitchRegistrationsText(result.stdout);
    }
  } catch (error) {
    log(
      "warn",
      "FreeSWITCH registration text collection failed.",
      String(error),
    );
  }
  return [];
}

async function heartbeat(
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const pabxRegistrations = await collectPabxRegistrations(config);
  await jsonRequest(config, "/agent/heartbeat", agentToken, agentUUID, {
    name: config.name,
    hostname: config.hostname,
    version: config.version,
    os: config.os,
    uptimeSeconds: Math.floor(performance.now() / 1000),
    recordingsRoots: config.recordingsRoots,
    recordingMounts: config.recordingMounts,
    mediaRoots: config.mediaRoots,
    mediaMounts: config.mediaMounts,
    capabilities: config.capabilities,
    pabxRegistrations,
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
  const localPath = typeof job.localPath === "string" ? job.localPath : "";
  const readablePath = resolveReadablePath(localPath, config);
  if (!readablePath) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "PATH_NOT_ALLOWED",
      localPath,
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
  const requestedPath = typeof job.localPath === "string" ? job.localPath : "";
  const localPath = resolveMediaPath(requestedPath, config);
  if (!localPath) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "PATH_NOT_ALLOWED",
      requestedPath,
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

async function runLocalCommand(
  command: string,
  args: string[],
  timeoutMs: number,
) {
  if (IS_WINDOWS) {
    const process = new Deno.Command(command, {
      args,
      stdout: "piped",
      stderr: "piped",
    }).spawn();
    let timedOut = false;
    const timeout = setTimeout(() => {
      timedOut = true;
      try {
        process.kill("SIGKILL");
      } catch {
        // Process may already have exited.
      }
    }, timeoutMs);
    try {
      const output = await process.output();
      const stderr = new TextDecoder().decode(output.stderr).trim();
      return {
        code: output.code,
        stdout: new TextDecoder().decode(output.stdout).trim(),
        stderr: timedOut
          ? [stderr, `Command timed out after ${timeoutMs}ms.`].filter(Boolean)
            .join("\n")
          : stderr,
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  const script = `exec setsid ${[command, ...args].map(shellQuote).join(" ")}`;
  const process = new Deno.Command("sh", {
    args: ["-lc", script],
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    try {
      Deno.kill(-process.pid, "SIGKILL");
    } catch {
      // The command may not be a process-group leader anymore.
    }
    try {
      process.kill("SIGKILL");
    } catch {
      // Process may already have exited.
    }
  }, timeoutMs);
  try {
    const output = await process.output();
    const stderr = new TextDecoder().decode(output.stderr).trim();
    return {
      code: output.code,
      stdout: new TextDecoder().decode(output.stdout).trim(),
      stderr: timedOut
        ? [stderr, `Command timed out after ${timeoutMs}ms.`].filter(Boolean)
          .join("\n")
        : stderr,
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function readFromConnection(
  conn: Deno.Conn,
  timeoutMs: number,
  stopWhen?: (text: string) => boolean,
) {
  const decoder = new TextDecoder();
  const chunks: string[] = [];
  const buffer = new Uint8Array(8192);
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const remaining = Math.max(100, deadline - Date.now());
    const readPromise = conn.read(buffer);
    const timeoutPromise = new Promise<null>((resolve) =>
      setTimeout(() => resolve(null), remaining)
    );
    const count = await Promise.race([readPromise, timeoutPromise]);
    if (count === null || count === 0) break;
    chunks.push(decoder.decode(buffer.subarray(0, count)));
    const text = chunks.join("");
    if (stopWhen?.(text)) break;
  }

  return chunks.join("");
}

async function writeToConnection(conn: Deno.Conn, text: string) {
  await conn.write(new TextEncoder().encode(text));
}

async function runAsteriskAmiValidate(config: AgentConfig) {
  const conn = await Deno.connect({
    hostname: config.asteriskAmiHost,
    port: config.asteriskAmiPort,
  });
  try {
    await readFromConnection(
      conn,
      config.commandTimeoutMs,
      (text) => text.includes("Asterisk Call Manager"),
    );
    await writeToConnection(
      conn,
      [
        "Action: Login",
        `Username: ${config.asteriskAmiUsername}`,
        `Secret: ${config.asteriskAmiSecret}`,
        "Events: off",
        "",
        "Action: Command",
        "Command: core show uptime",
        "",
        "Action: Logoff",
        "",
      ].join("\r\n"),
    );
    const output = await readFromConnection(
      conn,
      config.commandTimeoutMs,
      (text) =>
        text.includes("Message: Goodbye") || text.includes("Response: Error"),
    );
    const success = output.includes("Response: Success") &&
      !output.includes("Authentication failed");
    return {
      code: success ? 0 : 1,
      stdout: output.trim(),
      stderr: success ? "" : output.trim(),
      method: "ami",
    };
  } finally {
    conn.close();
  }
}

async function runFreeswitchEslValidate(config: AgentConfig) {
  const conn = await Deno.connect({
    hostname: config.freeswitchEslHost,
    port: config.freeswitchEslPort,
  });
  try {
    await readFromConnection(
      conn,
      config.commandTimeoutMs,
      (text) => text.includes("auth/request"),
    );
    await writeToConnection(conn, `auth ${config.freeswitchEslPassword}\n\n`);
    const auth = await readFromConnection(
      conn,
      config.commandTimeoutMs,
      (text) => text.includes("+OK accepted") || text.includes("-ERR"),
    );
    if (!auth.includes("+OK accepted")) {
      return {
        code: 1,
        stdout: auth.trim(),
        stderr: auth.trim(),
        method: "esl",
      };
    }
    await writeToConnection(conn, "api status\n\n");
    const output = await readFromConnection(
      conn,
      config.commandTimeoutMs,
      (text) => text.includes("UP ") || text.includes("ERR"),
    );
    const success = !output.includes("-ERR") && output.trim().length > 0;
    return {
      code: success ? 0 : 1,
      stdout: output.trim(),
      stderr: success ? "" : output.trim(),
      method: "esl",
    };
  } finally {
    conn.close();
  }
}

async function executePabxCommandJob(
  job: LeaseJob,
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const engine = String(job.engine ?? "").toLowerCase();
  const commandType = String(job.commandType ?? "");
  if (commandType !== "server.health.validate") {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "COMMAND_NOT_ALLOWED",
      `Unsupported PABX command type: ${commandType || "empty"}`,
      "pabx_command",
    );
    return;
  }

  let command = "";
  let args: string[] = [];
  let result: { code: number; stdout: string; stderr: string; method?: string };
  try {
    if (engine === "asterisk") {
      if (config.asteriskAmiUsername && config.asteriskAmiSecret) {
        result = await runAsteriskAmiValidate(config);
        command = "ami";
      } else {
        command = config.asteriskCli;
        args = ["-rx", "core show uptime"];
        result = await runLocalCommand(command, args, config.commandTimeoutMs);
      }
    } else if (engine === "freeswitch") {
      if (config.freeswitchEslPassword) {
        result = await runFreeswitchEslValidate(config);
        command = "esl";
      } else {
        command = config.freeswitchCli;
        args = ["-x", "status"];
        result = await runLocalCommand(command, args, config.commandTimeoutMs);
      }
    } else {
      await failJob(
        config,
        job.jobUUID,
        agentUUID,
        agentToken,
        "ENGINE_NOT_SUPPORTED",
        `Unsupported PABX engine: ${engine || "empty"}`,
        "pabx_command",
      );
      return;
    }

    if (result.code !== 0) {
      await failJob(
        config,
        job.jobUUID,
        agentUUID,
        agentToken,
        "COMMAND_FAILED",
        result.stderr || result.stdout || `Exit code ${result.code}`,
        "pabx_command",
      );
      return;
    }

    await jsonRequest(
      config,
      `/agent/jobs/${job.jobUUID}/complete`,
      agentToken,
      agentUUID,
      {
        jobType: "pabx_command",
        result: {
          engine,
          commandType,
          command,
          args,
          method: result.method ?? "cli",
          exitCode: result.code,
          stdout: result.stdout,
          stderr: result.stderr,
        },
      },
    );
    log("info", "PABX command completed.", {
      jobUUID: job.jobUUID,
      engine,
      commandType,
    });
  } catch (error) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "COMMAND_EXECUTION_FAILED",
      String(error),
      "pabx_command",
    );
  }
}

function payloadString(
  payload: Record<string, unknown> | null | undefined,
  key: string,
  fallback = "",
) {
  const value = payload?.[key];
  return typeof value === "string" ? value.trim() : fallback;
}

function normalizeDomain(value: string) {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function assertSafeDomain(domain: string) {
  if (
    !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/
      .test(domain)
  ) {
    throw new Error(`Invalid domain: ${domain || "empty"}`);
  }
}

function nginxEdgeConfigPath(config: AgentConfig, domain: string) {
  const filename = `${domain.replace(/[^a-z0-9._-]/g, "_")}.conf`;
  return `${config.nginxEdgeConfigDir.replace(/\/+$/, "")}/${filename}`;
}

async function fileExists(path: string) {
  try {
    const stat = await Deno.stat(path);
    return stat.isFile;
  } catch {
    return false;
  }
}

async function pathExists(path: string) {
  try {
    await Deno.stat(path);
    return true;
  } catch {
    return false;
  }
}

async function writeAtomic(path: string, content: string) {
  await ensureParentDirectory(path);
  const tmpPath = `${path}.tmp-${crypto.randomUUID()}`;
  await Deno.writeTextFile(tmpPath, content);
  await Deno.rename(tmpPath, path);
}

async function removePathIfExists(path: string, recursive = false) {
  if (await pathExists(path)) await Deno.remove(path, { recursive });
}

async function runConfiguredShell(command: string, timeoutMs: number) {
  const result = await runLocalCommand("sh", ["-lc", command], timeoutMs);
  if (result.code !== 0) {
    throw new Error(
      result.stderr || result.stdout || `Command failed: ${command}`,
    );
  }
  return result;
}

async function testNginxEdge(config: AgentConfig) {
  return await runConfiguredShell(
    config.nginxEdgeTestCommand,
    config.commandTimeoutMs,
  );
}

async function reloadNginxEdge(config: AgentConfig) {
  return await runConfiguredShell(
    config.nginxEdgeReloadCommand,
    config.commandTimeoutMs,
  );
}

async function nginxEdgeHasCertificate(config: AgentConfig, domain: string) {
  const base = `${config.nginxEdgeSslLiveDir.replace(/\/+$/, "")}/${domain}`;
  return await fileExists(`${base}/fullchain.pem`) &&
    await fileExists(`${base}/privkey.pem`);
}

function renderNginxEdgeDomainConfig(
  config: AgentConfig,
  domain: string,
  sslEnabled: boolean,
) {
  const acmeRoot = config.nginxEdgeAcmeRoot;
  const appUpstream = config.nginxEdgeAppUpstream;
  const apiUpstream = config.nginxEdgeApiUpstream;
  const envJsBlock = `location = /env.js {
    default_type application/javascript;
    add_header Cache-Control "no-store";
    alias /etc/nginx/mnscloud/runtime/env.js;
  }`;
  const httpAppLocation = sslEnabled
    ? "location / { return 301 https://$host$request_uri; }"
    : `location / {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_pass ${appUpstream};
  }`;

  const httpBlock = `server {
  listen 80;
  server_name ${domain};

  if ($request_uri ~ "^//") {
    return 404;
  }

  location = /healthz {
    return 200 'ok';
    add_header Content-Type text/plain;
  }

  location ^~ /.well-known/acme-challenge/ {
    root ${acmeRoot};
    default_type "text/plain";
    try_files $uri =404;
    access_log off;
  }

  location ~* ^/https?://[^/]+/favicon\\.ico$ {
    return 301 /favicon.ico;
  }

  ${envJsBlock}

  location /api/ {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_pass ${apiUpstream};
  }

  ${httpAppLocation}
}
`;

  if (!sslEnabled) return httpBlock;

  const sslBase = `${config.nginxEdgeSslLiveDir.replace(/\/+$/, "")}/${domain}`;
  const httpsBlock = `server {
  listen 443 ssl;
  http2 on;
  server_name ${domain};

  if ($request_uri ~ "^//") {
    return 404;
  }

  ssl_certificate ${sslBase}/fullchain.pem;
  ssl_certificate_key ${sslBase}/privkey.pem;

  add_header Strict-Transport-Security "max-age=31536000" always;
  ssl_session_cache shared:SSL:10m;
  ssl_session_timeout 10m;
  ssl_protocols TLSv1.2 TLSv1.3;

  location = /healthz {
    return 200 'ok';
    add_header Content-Type text/plain;
  }

  location ^~ /.well-known/acme-challenge/ {
    root ${acmeRoot};
    default_type "text/plain";
    try_files $uri =404;
    access_log off;
  }

  location ~* ^/https?://[^/]+/favicon\\.ico$ {
    return 301 /favicon.ico;
  }

  ${envJsBlock}

  location /api/ {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_pass ${apiUpstream};
  }

  location / {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_pass ${appUpstream};
  }
}
`;

  return `${httpBlock}\n${httpsBlock}`;
}

async function activateNginxEdgeDomain(config: AgentConfig, domain: string) {
  assertCapability(config, "nginx-edge.manage");
  assertSafeDomain(domain);
  await Deno.mkdir(config.nginxEdgeConfigDir, { recursive: true });
  await Deno.mkdir(config.nginxEdgeAcmeRoot, { recursive: true });
  const path = nginxEdgeConfigPath(config, domain);
  const previous = await fileExists(path)
    ? await Deno.readTextFile(path)
    : null;
  const sslEnabled = await nginxEdgeHasCertificate(config, domain);
  await writeAtomic(
    path,
    renderNginxEdgeDomainConfig(config, domain, sslEnabled),
  );
  try {
    await testNginxEdge(config);
  } catch (error) {
    if (previous === null) {
      await Deno.remove(path).catch(() => undefined);
    } else {
      await writeAtomic(path, previous);
    }
    throw error;
  }
  await reloadNginxEdge(config);
  return { domain, path, sslEnabled };
}

async function removeNginxEdgeDomain(config: AgentConfig, domain: string) {
  assertCapability(config, "nginx-edge.manage");
  assertSafeDomain(domain);
  const path = nginxEdgeConfigPath(config, domain);
  const previous = await fileExists(path)
    ? await Deno.readTextFile(path)
    : null;
  if (previous !== null) await Deno.remove(path);
  try {
    await testNginxEdge(config);
  } catch (error) {
    if (previous !== null) await writeAtomic(path, previous);
    throw error;
  }
  await reloadNginxEdge(config);
  await removePathIfExists(
    `${config.nginxEdgeSslLiveDir.replace(/\/+$/, "")}/${domain}`,
    true,
  );
  await removePathIfExists(
    `${config.nginxEdgeSslArchiveDir.replace(/\/+$/, "")}/${domain}`,
    true,
  );
  await removePathIfExists(
    `${config.nginxEdgeSslRenewalDir.replace(/\/+$/, "")}/${domain}.conf`,
  );
  return { domain, path, removed: previous !== null };
}

async function inspectNginxEdgeDomain(config: AgentConfig, domain: string) {
  assertCapability(config, "nginx-edge.manage");
  assertSafeDomain(domain);
  const path = nginxEdgeConfigPath(config, domain);
  return {
    domain,
    configPath: path,
    configExists: await fileExists(path),
    sslEnabled: await nginxEdgeHasCertificate(config, domain),
  };
}

async function executeNginxEdgeJob(
  job: LeaseJob,
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const command = String(
    job.commandType ?? job.payload?.command ?? job.payload?.["command"] ?? "",
  );
  const domain = normalizeDomain(payloadString(job.payload, "domain"));
  try {
    let result: Record<string, unknown>;
    if (command === "nginx.edge.domain.activate") {
      result = await activateNginxEdgeDomain(config, domain);
    } else if (command === "nginx.edge.domain.remove") {
      result = await removeNginxEdgeDomain(config, domain);
    } else if (command === "nginx.edge.domain.inspect") {
      result = await inspectNginxEdgeDomain(config, domain);
    } else if (command === "nginx.edge.config.test") {
      const test = await testNginxEdge(config);
      result = { command, exitCode: test.code, stdout: test.stdout };
    } else if (command === "nginx.edge.reload") {
      const reload = await reloadNginxEdge(config);
      result = { command, exitCode: reload.code, stdout: reload.stdout };
    } else {
      await failJob(
        config,
        job.jobUUID,
        agentUUID,
        agentToken,
        "NGINX_EDGE_COMMAND_NOT_IMPLEMENTED",
        `${command || "unknown"} is not implemented by this agent version.`,
        "nginx_edge",
      );
      return;
    }
    await jsonRequest(
      config,
      `/agent/jobs/${job.jobUUID}/complete`,
      agentToken,
      agentUUID,
      { jobType: "nginx_edge", result },
    );
    log("info", "Nginx edge job completed.", { jobUUID: job.jobUUID, result });
  } catch (error) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "NGINX_EDGE_COMMAND_FAILED",
      error instanceof Error ? error.message : String(error),
      "nginx_edge",
    );
  }
}

async function issueCertbotCertificate(
  config: AgentConfig,
  payload: Record<string, unknown>,
) {
  assertCapability(config, "certbot.manage");
  const domain = normalizeDomain(payloadString(payload, "domain"));
  assertSafeDomain(domain);
  const email = payloadString(payload, "email", config.certbotDefaultEmail);
  if (!email) throw new Error("Certificate email is required.");

  await activateNginxEdgeDomain(config, domain);
  const command = [
    shellQuote(config.certbotCommand),
    "certonly",
    "--webroot",
    "-w",
    shellQuote(config.nginxEdgeAcmeRoot),
    "-d",
    shellQuote(domain),
    "--email",
    shellQuote(email),
    "--agree-tos",
    "--non-interactive",
    "--keep-until-expiring",
  ].join(" ");
  const issue = await runConfiguredShell(
    command,
    Math.max(config.commandTimeoutMs, 180_000),
  );
  const activation = await activateNginxEdgeDomain(config, domain);
  return { ...activation, email, stdout: issue.stdout };
}

async function renewCertbotCertificates(config: AgentConfig) {
  assertCapability(config, "certbot.manage");
  const deployHook =
    `${config.nginxEdgeTestCommand} && ${config.nginxEdgeReloadCommand}`;
  const command = [
    shellQuote(config.certbotCommand),
    "renew",
    "--webroot",
    "-w",
    shellQuote(config.nginxEdgeAcmeRoot),
    "--deploy-hook",
    shellQuote(deployHook),
  ].join(" ");
  const result = await runConfiguredShell(
    command,
    Math.max(config.commandTimeoutMs, 180_000),
  );
  return { stdout: result.stdout, stderr: result.stderr };
}

async function inspectCertbotCertificate(
  config: AgentConfig,
  payload: Record<string, unknown>,
) {
  assertCapability(config, "certbot.manage");
  const domain = normalizeDomain(payloadString(payload, "domain"));
  assertSafeDomain(domain);
  return {
    domain,
    sslEnabled: await nginxEdgeHasCertificate(config, domain),
    livePath: `${config.nginxEdgeSslLiveDir.replace(/\/+$/, "")}/${domain}`,
    renewalPath: `${
      config.nginxEdgeSslRenewalDir.replace(/\/+$/, "")
    }/${domain}.conf`,
  };
}

async function executeCertbotJob(
  job: LeaseJob,
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const command = String(
    job.commandType ?? job.payload?.command ?? job.payload?.["command"] ?? "",
  );
  try {
    let result: Record<string, unknown>;
    if (command === "certbot.certificate.issue") {
      result = await issueCertbotCertificate(config, job.payload ?? {});
    } else if (command === "certbot.certificates.renew") {
      result = await renewCertbotCertificates(config);
    } else if (command === "certbot.certificate.inspect") {
      result = await inspectCertbotCertificate(config, job.payload ?? {});
    } else {
      await failJob(
        config,
        job.jobUUID,
        agentUUID,
        agentToken,
        "CERTBOT_COMMAND_NOT_IMPLEMENTED",
        `${command || "unknown"} is not implemented by this agent version.`,
        "certbot",
      );
      return;
    }
    await jsonRequest(
      config,
      `/agent/jobs/${job.jobUUID}/complete`,
      agentToken,
      agentUUID,
      { jobType: "certbot", result },
    );
    log("info", "Certbot job completed.", { jobUUID: job.jobUUID, result });
  } catch (error) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "CERTBOT_COMMAND_FAILED",
      error instanceof Error ? error.message : String(error),
      "certbot",
    );
  }
}

async function executeWebRtcEdgeJob(
  job: LeaseJob,
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const command = String(
    job.commandType ?? job.payload?.command ?? job.payload?.["command"] ?? "",
  );
  try {
    assertCapability(config, "webrtc.kamailio.manage");
    if (command !== "webrtc.edge.sync") {
      await failJob(
        config,
        job.jobUUID,
        agentUUID,
        agentToken,
        "WEBRTC_EDGE_COMMAND_NOT_IMPLEMENTED",
        `${command || "unknown"} is not implemented by this agent version.`,
        "webrtc_edge",
      );
      return;
    }
    const result = await runConfiguredShell(
      config.webrtcEdgeSyncCommand,
      Math.max(config.commandTimeoutMs, 180_000),
    );
    await jsonRequest(
      config,
      `/agent/jobs/${job.jobUUID}/complete`,
      agentToken,
      agentUUID,
      {
        jobType: "webrtc_edge",
        result: {
          command,
          stdout: result.stdout,
          stderr: result.stderr,
          serverUUID: payloadString(job.payload, "serverUUID"),
          domainUUID: payloadString(job.payload, "domainUUID"),
          domain: payloadString(job.payload, "domain"),
        },
      },
    );
    log("info", "WebRTC edge job completed.", { jobUUID: job.jobUUID });
  } catch (error) {
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "WEBRTC_EDGE_COMMAND_FAILED",
      error instanceof Error ? error.message : String(error),
      "webrtc_edge",
    );
  }
}

async function commandAvailable(command: string) {
  if (IS_WINDOWS) {
    const result = await runPowerShell(
      `($cmd = Get-Command ${
        powerShellQuote(command)
      } -ErrorAction SilentlyContinue) | ForEach-Object { $_.Source }`,
      3000,
    );
    return result.code === 0 && result.stdout
      ? result.stdout.split(/\r?\n/)[0] || command
      : null;
  }

  const result = await runLocalCommand(
    "sh",
    ["-lc", `command -v ${command}`],
    3000,
  );
  return result.code === 0 ? result.stdout.split(/\r?\n/)[0] || command : null;
}

async function commandText(command: string, fallback = "") {
  if (IS_WINDOWS) {
    const result = await runPowerShell(command, 8000);
    return result.code === 0 ? result.stdout : fallback;
  }

  const result = await runLocalCommand("sh", ["-lc", command], 8000);
  return result.code === 0 ? result.stdout : fallback;
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function powerShellQuote(value: string) {
  return `'${value.replaceAll("'", "''")}'`;
}

function powerShellExecutable() {
  return Deno.env.get("MNSCLOUD_POWERSHELL") ?? "powershell.exe";
}

async function runPowerShell(script: string, timeoutMs: number) {
  return await runLocalCommand(powerShellExecutable(), [
    "-NoProfile",
    "-ExecutionPolicy",
    "Bypass",
    "-Command",
    script,
  ], timeoutMs);
}

function payloadStringArray(
  payload: Record<string, unknown> | null | undefined,
  key: string,
  fallback: string[],
) {
  const value = payload?.[key];
  if (!Array.isArray(value)) return fallback;
  const items = value
    .map((item) => typeof item === "string" ? item.trim() : "")
    .filter((item) => item && /^[a-zA-Z0-9_./:-]+$/.test(item));
  return items.length ? [...new Set(items)] : fallback;
}

function stringArrayFromUnknown(value: unknown) {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => typeof item === "string" ? item.trim() : "")
    .filter((item) => item);
}

function crowdSecAcquisitionType(slug: string) {
  const map: Record<string, string> = {
    apache: "apache2",
    asterisk: "asterisk",
    dovecot: "dovecot",
    freeswitch: "freeswitch",
    mariadb: "mysql",
    nginx: "nginx",
    opensips: "opensips",
    postfix: "postfix",
    postgresql: "postgresql",
    ssh: "syslog",
  };
  return map[slug] ?? slug;
}

async function writeCrowdSecProfileAcquisition(services: unknown[]) {
  const entries = services.flatMap((service) => {
    if (!service || typeof service !== "object") return [];
    const record = service as Record<string, unknown>;
    const slug = typeof record["slug"] === "string"
      ? record["slug"].trim()
      : "";
    const logPaths = stringArrayFromUnknown(record["logPaths"]);
    if (!slug || logPaths.length === 0) return [];
    return [{
      slug,
      logPaths,
      type: crowdSecAcquisitionType(slug),
    }];
  });

  const path = "/etc/crowdsec/acquis.d/mnscloud-profile.yaml";
  await ensureParentDirectory(path);
  if (entries.length === 0) {
    await Deno.writeTextFile(path, "# Managed by MNSCloud Agent.\n");
    await Deno.chmod(path, 0o644).catch(() => undefined);
    return entries;
  }

  const content = entries.map((entry) =>
    [
      "filenames:",
      ...entry.logPaths.map((logPath) => `  - ${JSON.stringify(logPath)}`),
      "labels:",
      `  type: ${JSON.stringify(entry.type)}`,
    ].join("\n")
  ).join("\n---\n") + "\n";
  await Deno.writeTextFile(path, content);
  await Deno.chmod(path, 0o644).catch(() => undefined);
  return entries;
}

function crowdSecCollectionInstallCommand(collection: string) {
  const quotedCollection = shellQuote(collection);
  return [
    "set -eu",
    "command -v jq >/dev/null 2>&1",
    `cscli collections install ${quotedCollection} --force`,
    `inspect="$(cscli collections inspect ${quotedCollection} -o json)"`,
    `printf '%s\\n' "$inspect" | jq -r '.parsers[]?' | while IFS= read -r item; do if [ -n "$item" ]; then cscli parsers inspect "$item" -o json | jq -e '.installed == true and (.tainted | not)' >/dev/null 2>&1 || cscli parsers install "$item" --force; fi; done`,
    `printf '%s\\n' "$inspect" | jq -r '.scenarios[]?' | while IFS= read -r item; do if [ -n "$item" ]; then cscli scenarios inspect "$item" -o json | jq -e '.installed == true and (.tainted | not)' >/dev/null 2>&1 || cscli scenarios install "$item" --force; fi; done`,
    `cscli collections install ${quotedCollection} --force`,
    `cscli collections inspect ${quotedCollection} -o json | jq -e '.installed == true and (.tainted | not)' >/dev/null`,
  ].join("\n");
}

type LinuxPackageFamily = "debian" | "rhel" | "unsupported";

async function detectLinuxPackageFamily() {
  const osID = await commandText(
    '. /etc/os-release 2>/dev/null && printf "%s" "${ID:-}"',
  );
  const osLike = await commandText(
    '. /etc/os-release 2>/dev/null && printf "%s" "${ID_LIKE:-}"',
  );
  const combined = `${osID} ${osLike}`.toLowerCase();
  const family: LinuxPackageFamily = /\b(debian|ubuntu)\b/.test(combined)
    ? "debian"
    : /\b(rhel|rocky|almalinux|centos|fedora)\b/.test(combined)
    ? "rhel"
    : "unsupported";
  return { family, osID, osLike };
}

function packagesInstalledForFamilyCommand(
  packages: string[],
  family: LinuxPackageFamily,
) {
  if (family === "rhel") {
    const checks = packages
      .map((pkg) => `rpm -q ${shellQuote(pkg)} >/dev/null 2>&1`)
      .join(" && ");
    return `! (${checks})`;
  }

  const checks = packages
    .map((pkg) =>
      `dpkg-query -W -f='\\${"${Status}"}' ${
        shellQuote(pkg)
      } 2>/dev/null | grep -qx 'install ok installed'`
    )
    .join(" && ");
  return `! (${checks})`;
}

async function commandOk(command: string, timeoutMs = 5000) {
  const result = await runLocalCommand("sh", ["-lc", command], timeoutMs);
  return result.code === 0;
}

function stepResult(label: string, stdout: string) {
  return { label, code: 0, stdout, stderr: "" };
}

function metadataRefreshCommand(family: LinuxPackageFamily) {
  if (family === "rhel") return "dnf -y makecache";
  return "DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::ForceIPv4=true update -y";
}

function packageInstallCommand(
  packages: string[],
  family: LinuxPackageFamily,
) {
  const quotedPackages = packages.map(shellQuote).join(" ");
  if (family === "rhel") {
    return `dnf install -y ${quotedPackages}`;
  }
  return `DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ${quotedPackages}`;
}

function parseJsonArray(text: string) {
  if (!text.trim()) return [];
  try {
    const parsed = JSON.parse(text);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

async function collectCrowdSecSecurityEvents(config: AgentConfig) {
  const cscli = await commandAvailable("cscli");
  if (!cscli) return { alerts: [], decisions: [] };

  const alertsResult = await runLocalCommand("sh", [
    "-lc",
    "cscli alerts list -o json 2>/dev/null || cscli alerts list --output json 2>/dev/null || true",
  ], config.commandTimeoutMs);
  const decisionsResult = await runLocalCommand("sh", [
    "-lc",
    "cscli decisions list -o json 2>/dev/null || cscli decisions list --output json 2>/dev/null || true",
  ], config.commandTimeoutMs);

  return {
    alerts: parseJsonArray(alertsResult.stdout).slice(0, 200),
    decisions: parseJsonArray(decisionsResult.stdout).slice(0, 500),
  };
}

function assertCapability(config: AgentConfig, capability: string) {
  if (!config.capabilities[capability]) {
    throw new Error(`Capability is disabled: ${capability}`);
  }
}

async function runInstallStep(
  label: string,
  command: string,
  timeoutMs: number,
  allowFailure = false,
) {
  const timeoutSeconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  const result = await runLocalCommand(
    "flock",
    [
      "-w",
      "10",
      "/var/run/mnscloud-agent-cyber-security.lock",
      "timeout",
      "-k",
      "10s",
      `${timeoutSeconds}s`,
      "sh",
      "-lc",
      command,
    ],
    timeoutMs + 15_000,
  );
  const diagnostic = result.code !== 0 && label.includes("CrowdSec")
    ? await runLocalCommand(
      "sh",
      [
        "-lc",
        [
          "systemctl status crowdsec.service --no-pager -l 2>&1 || true",
          "journalctl -u crowdsec.service -n 80 --no-pager 2>&1 || true",
          "crowdsec -t 2>&1 || true",
          "find /etc/crowdsec -maxdepth 3 -type f \\( -path '*/mnscloud/*' -o -name 'mnscloud-profile.yaml' \\) -print 2>/dev/null || true",
        ].join("; echo '---'; "),
      ],
      20_000,
    )
    : null;
  const failureDetails = [
    result.stderr,
    result.stdout,
    diagnostic?.stdout,
    diagnostic?.stderr,
  ].filter(Boolean).join("\n").slice(-6000);
  const step = {
    label,
    code: result.code,
    stdout: [result.stdout, diagnostic?.stdout].filter(Boolean).join("\n")
      .slice(-2000),
    stderr: [result.stderr, diagnostic?.stderr].filter(Boolean).join("\n")
      .slice(-2000),
  };
  if (result.code !== 0 && !allowFailure) {
    throw new Error(
      `${label} failed: ${failureDetails || `exit ${result.code}`}`,
    );
  }
  return step;
}

async function packageAvailable(
  packageName: string,
  family: LinuxPackageFamily,
) {
  if (family === "rhel") {
    const result = await runLocalCommand(
      "sh",
      ["-lc", `dnf -q list ${shellQuote(packageName)} >/dev/null 2>&1`],
      10_000,
    );
    return result.code === 0;
  }

  const result = await runLocalCommand(
    "sh",
    [
      "-lc",
      `apt-cache policy ${
        shellQuote(packageName)
      } | awk '/Candidate:/ {print $2}'`,
    ],
    10_000,
  );
  return result.code === 0 && result.stdout && result.stdout !== "(none)";
}

async function officialCrowdSecRepositoryConfigured(
  family: LinuxPackageFamily,
) {
  const command = family === "rhel"
    ? "find /etc/yum.repos.d -maxdepth 1 -type f -name '*.repo' -print0 2>/dev/null | xargs -0 grep -Eiq 'packagecloud.io/.*/crowdsec|crowdsec/crowdsec|install.crowdsec.net'"
    : "find /etc/apt/sources.list /etc/apt/sources.list.d -maxdepth 1 -type f -print0 2>/dev/null | xargs -0 grep -Eiq 'packagecloud.io/.*/crowdsec|crowdsec/crowdsec|install.crowdsec.net'";
  return await commandOk(command, 10_000);
}

async function ensureCrowdSecRepository(
  family: LinuxPackageFamily,
  timeoutMs: number,
) {
  if (await officialCrowdSecRepositoryConfigured(family)) {
    return {
      label: "Official CrowdSec repository already configured",
      code: 0,
      stdout: "",
      stderr: "",
    };
  }
  return await runInstallStep(
    "Add CrowdSec package repository",
    "curl -fsSL https://install.crowdsec.net | sh",
    timeoutMs,
  );
}

async function ensureCrowdSecHubReady(timeoutMs: number) {
  if (
    await commandOk(
      "test -d /var/lib/crowdsec/data/hub && find /var/lib/crowdsec/data/hub -type f | grep -q .",
    )
  ) {
    return await stepResult(
      "CrowdSec Hub already ready",
      "CrowdSec Hub cache already exists.",
    );
  }
  return await runInstallStep(
    "Update CrowdSec Hub",
    "cscli hub update",
    timeoutMs,
    true,
  );
}

async function resolveCrowdSecFirewallBouncerPackage(
  family: LinuxPackageFamily,
) {
  const candidates = family === "rhel"
    ? ["crowdsec-firewall-bouncer-iptables", "crowdsec-firewall-bouncer"]
    : ["crowdsec-firewall-bouncer-nftables", "crowdsec-firewall-bouncer"];
  for (const packageName of candidates) {
    if (await packageAvailable(packageName, family)) return packageName;
  }
  throw new Error(
    `No CrowdSec firewall bouncer package is available. Checked: ${
      candidates.join(", ")
    }`,
  );
}

async function configureCrowdSecFirewallBouncer(
  timeoutMs: number,
  mode: "iptables" | "nftables",
) {
  const configPath = "/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml";
  const configExists = await runLocalCommand("test", ["-f", configPath], 3000);
  if (configExists.code !== 0) {
    return {
      label: "Configure CrowdSec firewall bouncer",
      code: 0,
      stdout:
        "Bouncer configuration file not found; package defaults will be used.",
      stderr: "",
    };
  }

  const hasApiKey = await runLocalCommand(
    "sh",
    [
      "-lc",
      `grep -Eq '^api_key:[[:space:]]*[A-Za-z0-9_-]+' ${
        shellQuote(configPath)
      }`,
    ],
    3000,
  );
  let apiKey = "";
  if (hasApiKey.code !== 0) {
    const keyResult = await runLocalCommand(
      "sh",
      [
        "-lc",
        "cscli bouncers add mnscloud-firewall-bouncer -o raw 2>/dev/null || true",
      ],
      timeoutMs,
    );
    apiKey = keyResult.stdout.trim();
    if (!apiKey) {
      const hostSuffix = await commandText(
        "hostname -s 2>/dev/null || hostname",
        "host",
      );
      const fallback = await runLocalCommand(
        "sh",
        [
          "-lc",
          `cscli bouncers add ${
            shellQuote(`mnscloud-firewall-bouncer-${hostSuffix}`)
          } -o raw`,
        ],
        timeoutMs,
      );
      if (fallback.code !== 0 || !fallback.stdout.trim()) {
        throw new Error(
          fallback.stderr || "Unable to create CrowdSec bouncer API key.",
        );
      }
      apiKey = fallback.stdout.trim();
    }
  }

  const apiKeyScript = apiKey
    ? `if grep -q '^api_key:' ${
      shellQuote(configPath)
    }; then sed -i 's#^api_key:.*#api_key: ${apiKey}#' ${
      shellQuote(configPath)
    }; else printf '\\napi_key: ${apiKey}\\n' >> ${shellQuote(configPath)}; fi`
    : ":";
  const script = [
    `cp -a ${shellQuote(configPath)} ${
      shellQuote(`${configPath}.mnscloud.bak`)
    } 2>/dev/null || true`,
    `if grep -q '^api_url:' ${
      shellQuote(configPath)
    }; then sed -i 's#^api_url:.*#api_url: http://127.0.0.1:8080/#' ${
      shellQuote(configPath)
    }; else printf '\\napi_url: http://127.0.0.1:8080/\\n' >> ${
      shellQuote(configPath)
    }; fi`,
    apiKeyScript,
    `if grep -q '^mode:' ${
      shellQuote(configPath)
    }; then sed -i 's#^mode:.*#mode: ${mode}#' ${
      shellQuote(configPath)
    }; else printf '\\nmode: ${mode}\\n' >> ${shellQuote(configPath)}; fi`,
  ].join(" && ");

  return await runInstallStep(
    "Configure CrowdSec firewall bouncer",
    script,
    Math.min(timeoutMs, 60_000),
  );
}

async function installCyberSecurityStack(
  config: AgentConfig,
  payload: Record<string, unknown> | null | undefined,
  progress: (
    step: string,
    percent: number,
    message: string,
    extra?: Record<string, unknown>,
  ) => Promise<void>,
) {
  if (IS_WINDOWS) {
    return await installWindowsCyberSecurityStack(config, payload, progress);
  }

  assertCapability(config, "linux.package.install");
  assertCapability(config, "linux.service.manage");
  assertCapability(config, "security.nftables.manage");
  assertCapability(config, "security.crowdsec.manage");

  const packageInfo = await detectLinuxPackageFamily();
  if (packageInfo.family === "unsupported") {
    throw new Error(
      `Unsupported Linux distribution for automatic install: ${
        packageInfo.osID || "unknown"
      }. Supported automatic Linux cyber security install requires Debian 12/13, RHEL 9/10, Rocky Linux 9/10, or AlmaLinux 9/10.`,
    );
  }
  const packageFamily = packageInfo.family;

  const timeoutMs = Math.max(
    120_000,
    Math.min(Number(payload?.["timeoutMs"] ?? 900_000), 1_800_000),
  );
  const collections = payloadStringArray(payload, "collections", [
    "crowdsecurity/linux",
    "crowdsecurity/sshd",
  ]);
  const basePackages = packageFamily === "rhel"
    ? ["ca-certificates", "curl", "jq", "nftables", "dnf-plugins-core"]
    : ["ca-certificates", "curl", "gnupg", "jq", "nftables"];
  const steps = [];
  const runStep = async (
    percent: number,
    label: string,
    command: string,
    allowFailure = false,
    stepTimeoutMs = timeoutMs,
  ) => {
    await progress(label, percent, `${label} started.`);
    const result = await runInstallStep(
      label,
      command,
      stepTimeoutMs,
      allowFailure,
    );
    await progress(
      label,
      percent,
      result.code === 0
        ? `${label} completed.`
        : `${label} completed with warnings.`,
      {
        status: result.code === 0 ? "running" : "warning",
        output: result.stdout || result.stderr,
      },
    );
    return result;
  };

  await progress(
    "Validate operating system",
    5,
    `Using ${packageFamily} package management for ${packageInfo.osID}.`,
    {
      osID: packageInfo.osID,
      osLike: packageInfo.osLike,
      packageFamily,
    },
  );

  steps.push(
    await runStep(
      10,
      "Refresh package metadata",
      `if ${
        packagesInstalledForFamilyCommand(
          [...basePackages, "crowdsec"],
          packageFamily,
        )
      }; then ${
        metadataRefreshCommand(packageFamily)
      }; else echo 'Package metadata refresh skipped; required packages are already installed.'; fi`,
      true,
      75_000,
    ),
  );
  steps.push(
    await runStep(
      20,
      "Install base packages",
      `if ${
        packagesInstalledForFamilyCommand(basePackages, packageFamily)
      }; then ${
        packageInstallCommand(basePackages, packageFamily)
      }; else echo 'Base packages already installed.'; fi`,
      false,
      90_000,
    ),
  );
  await progress(
    "Prepare CrowdSec repository",
    32,
    "Checking CrowdSec package repository.",
  );
  steps.push(
    await ensureCrowdSecRepository(packageFamily, Math.min(timeoutMs, 90_000)),
  );
  steps.push(
    await runStep(
      42,
      "Refresh CrowdSec package metadata",
      metadataRefreshCommand(packageFamily),
      true,
      75_000,
    ),
  );
  const bouncerPackage = await resolveCrowdSecFirewallBouncerPackage(
    packageFamily,
  );
  const bouncerMode = bouncerPackage.includes("nftables")
    ? "nftables"
    : "iptables";
  const securityPackages = ["crowdsec", bouncerPackage, "nftables"];
  await progress(
    "Select CrowdSec firewall bouncer package",
    48,
    "Detecting available CrowdSec firewall bouncer package.",
  );
  await progress(
    "Select CrowdSec firewall bouncer package",
    48,
    `Using ${bouncerPackage}.`,
    { package: bouncerPackage },
  );
  steps.push(
    await runStep(
      55,
      "Install CrowdSec and firewall bouncer",
      packageInstallCommand(securityPackages, packageFamily),
      false,
      120_000,
    ),
  );
  steps.push(
    await runStep(
      68,
      "Enable nftables",
      "systemctl enable --now nftables",
      true,
      90_000,
    ),
  );
  steps.push(
    await runStep(
      74,
      "Enable CrowdSec",
      [
        "systemctl enable crowdsec",
        "systemctl reset-failed crowdsec || true",
        "timeout 75s systemctl start crowdsec",
        "systemctl is-active crowdsec",
      ].join(" && "),
      false,
      90_000,
    ),
  );
  await progress(
    "Configure CrowdSec firewall bouncer",
    80,
    "Configuring local bouncer credentials.",
  );
  steps.push(
    await configureCrowdSecFirewallBouncer(
      Math.min(timeoutMs, 60_000),
      bouncerMode,
    ),
  );
  steps.push(await ensureCrowdSecHubReady(Math.min(timeoutMs, 75_000)));
  for (const collection of collections) {
    steps.push(
      await runStep(
        90,
        `Install CrowdSec collection ${collection}`,
        crowdSecCollectionInstallCommand(collection),
        false,
        60_000,
      ),
    );
  }
  steps.push(
    await runStep(
      95,
      "Restart CrowdSec",
      [
        "if command -v crowdsec >/dev/null 2>&1; then",
        "  crowdsec -t >/tmp/mnscloud-crowdsec-test.log 2>&1 || {",
        "    if grep -q 'mnscloud-profile.yaml\\|/etc/crowdsec/acquis.d/mnscloud-profile.yaml' /tmp/mnscloud-crowdsec-test.log 2>/dev/null; then",
        "      mv /etc/crowdsec/acquis.d/mnscloud-profile.yaml /etc/crowdsec/acquis.d/mnscloud-profile.yaml.disabled.$(date +%s) 2>/dev/null || true;",
        "    fi;",
        "  };",
        "fi;",
        "systemctl reset-failed crowdsec || true",
        "timeout 75s systemctl restart crowdsec",
        "systemctl is-active crowdsec",
      ].join(" "),
      false,
      90_000,
    ),
  );
  steps.push(
    await runStep(
      98,
      "Restart CrowdSec firewall bouncer",
      [
        "systemctl reset-failed crowdsec-firewall-bouncer || true",
        "timeout 45s systemctl restart crowdsec-firewall-bouncer",
        "systemctl is-active crowdsec-firewall-bouncer",
      ].join(" && "),
      false,
      60_000,
    ),
  );

  await progress(
    "Collect protection status",
    99,
    "Collecting final security service status.",
  );
  const status = await collectCyberSecurityStatus(config);
  return {
    ...status,
    protectionStatus: status.firewallStatus === "running" &&
        status.crowdsecStatus === "running" &&
        status.bouncerStatus === "running"
      ? "protected"
      : status.protectionStatus,
    installedPackages: [
      "nftables",
      "crowdsec",
      bouncerPackage,
    ],
    installedCollections: collections,
    steps,
  };
}

async function installChocolateyIfAllowed(
  payload: Record<string, unknown> | null | undefined,
  timeoutMs: number,
) {
  if (await commandAvailable("choco")) {
    return await stepResult(
      "Chocolatey already available",
      "Chocolatey is already installed.",
    );
  }
  if (payload?.["installChocolatey"] !== true) {
    throw new Error(
      "Chocolatey is required to install CrowdSec on Windows. Install Chocolatey first or pass installChocolatey=true in the job payload.",
    );
  }
  return await runPowerShellInstallStep(
    "Install Chocolatey",
    "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))",
    timeoutMs,
  );
}

async function runPowerShellInstallStep(
  label: string,
  script: string,
  timeoutMs: number,
  allowFailure = false,
) {
  const result = await runPowerShell(script, timeoutMs);
  const step = {
    label,
    code: result.code,
    stdout: result.stdout.slice(-2000),
    stderr: result.stderr.slice(-2000),
  };
  if (result.code !== 0 && !allowFailure) {
    throw new Error(
      `${label} failed: ${
        [result.stderr, result.stdout].filter(Boolean).join("\n").slice(-6000)
      }`,
    );
  }
  return step;
}

async function installWindowsCyberSecurityStack(
  config: AgentConfig,
  payload: Record<string, unknown> | null | undefined,
  progress: (
    step: string,
    percent: number,
    message: string,
    extra?: Record<string, unknown>,
  ) => Promise<void>,
) {
  assertCapability(config, "windows.package.install");
  assertCapability(config, "windows.service.manage");
  assertCapability(config, "security.crowdsec.manage");
  assertCapability(config, "security.windows.firewall.manage");

  const timeoutMs = Math.max(
    120_000,
    Math.min(Number(payload?.["timeoutMs"] ?? 900_000), 1_800_000),
  );
  const collections = payloadStringArray(payload, "collections", [
    "crowdsecurity/windows",
  ]);
  const steps = [];
  const runStep = async (
    percent: number,
    label: string,
    script: string,
    allowFailure = false,
    stepTimeoutMs = timeoutMs,
  ) => {
    await progress(label, percent, `${label} started.`);
    const result = await runPowerShellInstallStep(
      label,
      script,
      stepTimeoutMs,
      allowFailure,
    );
    await progress(
      label,
      percent,
      result.code === 0
        ? `${label} completed.`
        : `${label} completed with warnings.`,
      {
        status: result.code === 0 ? "running" : "warning",
        output: result.stdout || result.stderr,
      },
    );
    return result;
  };

  await progress(
    "Validate operating system",
    5,
    "Validating Windows host.",
  );
  steps.push(
    await installChocolateyIfAllowed(payload, Math.min(timeoutMs, 180_000)),
  );
  steps.push(
    await runStep(
      35,
      "Install CrowdSec Security Engine",
      "choco install crowdsec -y --no-progress",
      false,
      300_000,
    ),
  );
  steps.push(
    await runStep(
      55,
      "Install CrowdSec Windows Firewall bouncer",
      "choco install crowdsec-windows-firewall-bouncer -y --no-progress",
      false,
      300_000,
    ),
  );
  for (const collection of collections) {
    steps.push(
      await runStep(
        75,
        `Install CrowdSec collection ${collection}`,
        `if (Get-Command cscli -ErrorAction SilentlyContinue) { cscli collections install ${
          powerShellQuote(collection)
        }; cscli hub update } else { Write-Output 'cscli not found; collection install skipped.' }`,
        true,
        90_000,
      ),
    );
  }
  steps.push(
    await runStep(
      90,
      "Enable Windows Firewall profiles",
      "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
      false,
      60_000,
    ),
  );
  steps.push(
    await runStep(
      95,
      "Start CrowdSec services",
      "$services = @('crowdsec','cs-windows-firewall-bouncer','crowdsec-windows-firewall-bouncer'); foreach ($name in $services) { $svc = Get-Service -Name $name -ErrorAction SilentlyContinue; if ($svc) { Set-Service -Name $svc.Name -StartupType Automatic; Start-Service -Name $svc.Name -ErrorAction SilentlyContinue } }",
      false,
      90_000,
    ),
  );

  await progress(
    "Collect protection status",
    99,
    "Collecting final Windows security service status.",
  );
  const status = await collectCyberSecurityStatus(config);
  return {
    ...status,
    installedPackages: ["crowdsec", "crowdsec-windows-firewall-bouncer"],
    installedCollections: collections,
    steps,
  };
}

async function applyCyberSecurityProfile(
  config: AgentConfig,
  payload: Record<string, unknown> | null | undefined,
  progress: (
    step: string,
    percent: number,
    message: string,
    extra?: Record<string, unknown>,
  ) => Promise<void>,
) {
  if (IS_WINDOWS) {
    return await applyWindowsCyberSecurityProfile(config, payload, progress);
  }

  assertCapability(config, "linux.service.manage");
  assertCapability(config, "security.crowdsec.manage");

  const timeoutMs = Math.max(
    120_000,
    Math.min(Number(payload?.["timeoutMs"] ?? 600_000), 1_800_000),
  );
  const profileName = typeof payload?.["profileName"] === "string"
    ? payload["profileName"]
    : "Security profile";
  const services = Array.isArray(payload?.["services"])
    ? payload["services"]
    : [];
  const collections = payloadStringArray(payload, "collections", []);
  const serviceLabels = services.map((service) => {
    if (!service || typeof service !== "object") return "";
    const record = service as Record<string, unknown>;
    const label = record["name"] ?? record["slug"];
    return typeof label === "string" ? label.trim() : "";
  }).filter(Boolean);
  const steps = [];
  const runStep = async (
    percent: number,
    label: string,
    command: string,
    allowFailure = false,
    stepTimeoutMs = timeoutMs,
  ) => {
    await progress(label, percent, `${label} started.`);
    const result = await runInstallStep(
      label,
      command,
      stepTimeoutMs,
      allowFailure,
    );
    await progress(
      label,
      percent,
      result.code === 0
        ? `${label} completed.`
        : `${label} completed with warnings.`,
      {
        status: result.code === 0 ? "running" : "warning",
        output: result.stdout || result.stderr,
      },
    );
    return result;
  };

  await progress(
    "Validate CrowdSec profile prerequisites",
    10,
    `Preparing to apply ${profileName}.`,
    { services, collections },
  );
  const cscli = await commandAvailable("cscli");
  if (!cscli) {
    throw new Error(
      "CrowdSec cscli is not available. Install protection first.",
    );
  }

  await progress(
    "Resolve selected profile services",
    18,
    serviceLabels.length
      ? `Selected services: ${serviceLabels.join(", ")}.`
      : "No services selected in this profile.",
    { services, collections },
  );

  await progress(
    "Configure CrowdSec log acquisition",
    22,
    "Writing log acquisition for selected services.",
  );
  const acquisition = await writeCrowdSecProfileAcquisition(services);
  await progress(
    "Configure CrowdSec log acquisition",
    22,
    acquisition.length
      ? `Configured log acquisition for ${
        acquisition.map((entry) => entry.slug).join(", ")
      }.`
      : "No log acquisition paths configured for selected services.",
    { acquisition },
  );

  steps.push(await ensureCrowdSecHubReady(Math.min(timeoutMs, 75_000)));
  const installedCollections = [];
  let percent = 35;
  if (collections.length === 0) {
    await progress(
      "Install CrowdSec collections",
      70,
      "No CrowdSec collections configured for the selected services.",
      { services, collections, status: "skipped" },
    );
  } else {
    for (const collection of collections) {
      steps.push(
        await runStep(
          Math.min(percent, 85),
          `Install CrowdSec collection ${collection}`,
          crowdSecCollectionInstallCommand(collection),
          false,
          60_000,
        ),
      );
      installedCollections.push(collection);
      percent += Math.max(5, Math.floor(45 / Math.max(collections.length, 1)));
    }
    steps.push(
      await runStep(
        90,
        "Reload CrowdSec",
        "timeout 45s systemctl reload crowdsec || timeout 75s systemctl restart crowdsec",
        false,
        90_000,
      ),
    );
  }

  await progress(
    "Collect protection status",
    98,
    "Collecting security service status after profile apply.",
  );
  const status = await collectCyberSecurityStatus(config);
  return {
    ...status,
    protectionStatus: status.firewallStatus === "running" &&
        status.crowdsecStatus === "running" &&
        status.bouncerStatus === "running"
      ? "protected"
      : status.protectionStatus,
    profileName,
    mode: payload?.["mode"] ?? "monitor",
    services,
    installedCollections,
    steps,
  };
}

async function applyWindowsCyberSecurityProfile(
  config: AgentConfig,
  payload: Record<string, unknown> | null | undefined,
  progress: (
    step: string,
    percent: number,
    message: string,
    extra?: Record<string, unknown>,
  ) => Promise<void>,
) {
  assertCapability(config, "windows.service.manage");
  assertCapability(config, "security.crowdsec.manage");

  const timeoutMs = Math.max(
    120_000,
    Math.min(Number(payload?.["timeoutMs"] ?? 600_000), 1_800_000),
  );
  const profileName = typeof payload?.["profileName"] === "string"
    ? payload["profileName"]
    : "Windows security profile";
  const collections = payloadStringArray(payload, "collections", [
    "crowdsecurity/windows",
  ]);
  const steps = [];

  await progress(
    "Validate CrowdSec profile prerequisites",
    10,
    `Preparing to apply ${profileName}.`,
    { collections },
  );
  if (!(await commandAvailable("cscli"))) {
    throw new Error(
      "CrowdSec cscli is not available. Install protection first.",
    );
  }

  let percent = 35;
  for (const collection of collections) {
    await progress(
      `Install CrowdSec collection ${collection}`,
      Math.min(percent, 85),
      `Installing ${collection}.`,
    );
    steps.push(
      await runPowerShellInstallStep(
        `Install CrowdSec collection ${collection}`,
        `cscli collections install ${
          powerShellQuote(collection)
        }; cscli hub update`,
        Math.min(timeoutMs, 90_000),
        true,
      ),
    );
    percent += Math.max(5, Math.floor(45 / Math.max(collections.length, 1)));
  }
  steps.push(
    await runPowerShellInstallStep(
      "Restart CrowdSec services",
      "$services = @('crowdsec','cs-windows-firewall-bouncer','crowdsec-windows-firewall-bouncer'); foreach ($name in $services) { $svc = Get-Service -Name $name -ErrorAction SilentlyContinue; if ($svc) { Restart-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue } }",
      90_000,
      true,
    ),
  );

  await progress(
    "Collect protection status",
    98,
    "Collecting Windows security service status after profile apply.",
  );
  const status = await collectCyberSecurityStatus(config);
  return {
    ...status,
    profileName,
    mode: payload?.["mode"] ?? "monitor",
    installedCollections: collections,
    steps,
  };
}

async function collectCyberSecurityStatus(config: AgentConfig) {
  if (IS_WINDOWS) return await collectWindowsCyberSecurityStatus(config);

  const nft = await commandAvailable("nft");
  const crowdsec = await commandAvailable("crowdsec");
  const cscli = await commandAvailable("cscli");
  const bouncer = await commandAvailable("crowdsec-firewall-bouncer");
  const hostname = await commandText("hostname -f 2>/dev/null || hostname");
  const kernelVersion = await commandText("uname -r");
  const osName = await commandText(
    '. /etc/os-release 2>/dev/null && printf "%s" "${NAME:-Linux}"',
    "Linux",
  );
  const osVersion = await commandText(
    '. /etc/os-release 2>/dev/null && printf "%s" "${VERSION_ID:-}"',
  );
  const privateIP = await commandText(
    "ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"src\") {print $(i+1); exit}}'",
  );
  const nftRules = nft
    ? await runLocalCommand("nft", ["list", "ruleset"], config.commandTimeoutMs)
    : null;
  const crowdsecActive = await runLocalCommand("sh", [
    "-lc",
    "systemctl is-active crowdsec 2>/dev/null || true",
  ], 3000);
  const bouncerActive = await runLocalCommand("sh", [
    "-lc",
    "systemctl is-active crowdsec-firewall-bouncer 2>/dev/null || true",
  ], 3000);
  const firewallStatus = nft
    ? (nftRules?.code === 0 ? "running" : "error")
    : "missing";
  const crowdsecStatus = crowdsec || cscli
    ? (crowdsecActive.stdout === "active" ? "running" : "stopped")
    : "missing";
  const bouncerStatus = bouncer
    ? (bouncerActive.stdout === "active" ? "running" : "stopped")
    : "missing";
  const protectionStatus = firewallStatus === "running" &&
      crowdsecStatus === "running" && bouncerStatus === "running"
    ? "protected"
    : nft && (crowdsec || cscli) && bouncer
    ? "partial"
    : "unprotected";
  const securityEvents = await collectCrowdSecSecurityEvents(config);

  return {
    hostname,
    privateIP,
    osName,
    osVersion,
    kernelVersion,
    firewallBackend: "nftables",
    firewallStatus,
    crowdsecStatus,
    bouncerStatus,
    protectionStatus,
    crowdsecAlerts: securityEvents.alerts,
    crowdsecDecisions: securityEvents.decisions,
    binaries: { nft, crowdsec, cscli, bouncer },
  };
}

async function collectWindowsCrowdSecSecurityEvents(config: AgentConfig) {
  const cscli = await commandAvailable("cscli");
  if (!cscli) return { alerts: [], decisions: [] };

  const alertsResult = await runPowerShell(
    "try { cscli alerts list -o json 2>$null } catch { '[]' }",
    config.commandTimeoutMs,
  );
  const decisionsResult = await runPowerShell(
    "try { cscli decisions list -o json 2>$null } catch { '[]' }",
    config.commandTimeoutMs,
  );

  return {
    alerts: parseJsonArray(alertsResult.stdout).slice(0, 200),
    decisions: parseJsonArray(decisionsResult.stdout).slice(0, 500),
  };
}

async function windowsServiceStatus(serviceNames: string[]) {
  const names = serviceNames.map(powerShellQuote).join(",");
  const result = await runPowerShell(
    `$names = @(${names}); $svc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $names -contains $_.Name -or $names -contains $_.DisplayName } | Select-Object -First 1; if ($svc) { $svc.Status.ToString().ToLowerInvariant() } else { 'missing' }`,
    5000,
  );
  if (result.code !== 0 || !result.stdout) return "missing";
  const status = result.stdout.trim().toLowerCase();
  return status === "running"
    ? "running"
    : status === "missing"
    ? "missing"
    : "stopped";
}

async function collectWindowsCyberSecurityStatus(config: AgentConfig) {
  const crowdsec = await commandAvailable("crowdsec");
  const cscli = await commandAvailable("cscli");
  const bouncer = await commandAvailable("cs-windows-firewall-bouncer") ??
    await commandAvailable("crowdsec-windows-firewall-bouncer");
  const choco = await commandAvailable("choco");

  const hostname = await commandText("[System.Net.Dns]::GetHostName()");
  const osName = await commandText(
    "(Get-CimInstance Win32_OperatingSystem).Caption",
    "Windows",
  );
  const osVersion = await commandText(
    "(Get-CimInstance Win32_OperatingSystem).Version",
  );
  const kernelVersion = await commandText(
    "[System.Environment]::OSVersion.VersionString",
  );
  const privateIP = await commandText(
    "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' } | Select-Object -First 1 -ExpandProperty IPAddress",
  );
  const firewallProfiles = await runPowerShell(
    "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress",
    config.commandTimeoutMs,
  );
  const anyFirewallEnabled = firewallProfiles.code === 0 &&
    /"Enabled":true/i.test(firewallProfiles.stdout);
  const crowdsecStatus = crowdsec || cscli
    ? await windowsServiceStatus(["crowdsec", "CrowdSec"])
    : "missing";
  const bouncerStatus = bouncer
    ? await windowsServiceStatus([
      "cs-windows-firewall-bouncer",
      "crowdsec-windows-firewall-bouncer",
      "CrowdSec Windows Firewall Bouncer",
    ])
    : "missing";
  const firewallStatus = anyFirewallEnabled ? "running" : "stopped";
  const protectionStatus = firewallStatus === "running" &&
      crowdsecStatus === "running" && bouncerStatus === "running"
    ? "protected"
    : (crowdsec || cscli) && bouncer
    ? "partial"
    : "unprotected";
  const securityEvents = await collectWindowsCrowdSecSecurityEvents(config);

  return {
    hostname,
    privateIP,
    osName,
    osVersion,
    kernelVersion,
    firewallBackend: "windows-firewall",
    firewallStatus,
    crowdsecStatus,
    bouncerStatus,
    protectionStatus,
    crowdsecAlerts: securityEvents.alerts,
    crowdsecDecisions: securityEvents.decisions,
    binaries: { crowdsec, cscli, bouncer, choco },
    firewallProfiles: firewallProfiles.stdout,
  };
}

async function executeCyberSecurityJob(
  job: LeaseJob,
  config: AgentConfig,
  agentUUID: string,
  agentToken: string,
) {
  const command = String(
    job.commandType ?? job.payload?.command ?? job.payload?.["command"] ?? "",
  );
  const leasedCommand = String(
    (job as Record<string, unknown>)["command"] ?? command,
  );
  try {
    if (leasedCommand === "cyber.security.status") {
      const result = await collectCyberSecurityStatus(config);
      await jsonRequest(
        config,
        `/agent/jobs/${job.jobUUID}/complete`,
        agentToken,
        agentUUID,
        {
          jobType: "cyber_security",
          result,
        },
      );
      log("info", "Cyber Security status collected.", {
        jobUUID: job.jobUUID,
        result,
      });
      return;
    }

    if (leasedCommand === "cyber.security.install") {
      const result = await installCyberSecurityStack(
        config,
        job.payload,
        (step, percent, message, extra = {}) =>
          reportJobProgress(
            config,
            job.jobUUID,
            agentUUID,
            agentToken,
            step,
            percent,
            message,
            extra,
          ),
      );
      await jsonRequest(
        config,
        `/agent/jobs/${job.jobUUID}/complete`,
        agentToken,
        agentUUID,
        {
          jobType: "cyber_security",
          result,
        },
      );
      log("info", "Cyber Security stack installed.", {
        jobUUID: job.jobUUID,
        result,
      });
      return;
    }

    if (leasedCommand === "cyber.security.profile.apply") {
      const result = await applyCyberSecurityProfile(
        config,
        job.payload,
        (step, percent, message, extra = {}) =>
          reportJobProgress(
            config,
            job.jobUUID,
            agentUUID,
            agentToken,
            step,
            percent,
            message,
            extra,
          ),
      );
      await jsonRequest(
        config,
        `/agent/jobs/${job.jobUUID}/complete`,
        agentToken,
        agentUUID,
        {
          jobType: "cyber_security",
          result,
        },
      );
      log("info", "Cyber Security profile applied.", {
        jobUUID: job.jobUUID,
        result,
      });
      return;
    }

    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "CYBER_COMMAND_NOT_IMPLEMENTED",
      `${
        leasedCommand || "unknown"
      } is modeled but not implemented by this agent version yet.`,
      "cyber_security",
    );
  } catch (error) {
    if (
      leasedCommand === "cyber.security.install" ||
      leasedCommand === "cyber.security.profile.apply"
    ) {
      await reportJobProgress(
        config,
        job.jobUUID,
        agentUUID,
        agentToken,
        "failed",
        100,
        error instanceof Error ? error.message : String(error),
        {
          status: "failed",
          error: error instanceof Error ? error.message : String(error),
        },
      );
    }
    await failJob(
      config,
      job.jobUUID,
      agentUUID,
      agentToken,
      "CYBER_COMMAND_FAILED",
      error instanceof Error ? error.message : String(error),
      "cyber_security",
    );
  }
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
    } else if (job.jobType === "pabx_command") {
      await executePabxCommandJob(job, config, agentUUID, agentToken);
    } else if (job.jobType === "cyber_security") {
      await executeCyberSecurityJob(job, config, agentUUID, agentToken);
    } else if (job.jobType === "nginx_edge") {
      await executeNginxEdgeJob(job, config, agentUUID, agentToken);
    } else if (job.jobType === "certbot") {
      await executeCertbotJob(job, config, agentUUID, agentToken);
    } else if (job.jobType === "webrtc_edge") {
      await executeWebRtcEdgeJob(job, config, agentUUID, agentToken);
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
