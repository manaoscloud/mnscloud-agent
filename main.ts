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
  capabilities: Record<string, boolean>;
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

function capabilitiesFromConfig(config: IniConfig) {
  const capabilities: Record<string, boolean> = {};
  for (const [key, value] of Object.entries(config.capabilities ?? {})) {
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
        "/var/lib/freeswitch/recordings,/var/spool/asterisk/monitor",
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
        "/var/lib/mnscloud/pabx/media-files",
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
    capabilities: config.capabilities,
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
  const process = new Deno.Command(command, {
    args,
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const timeout = setTimeout(() => {
    try {
      process.kill("SIGKILL");
    } catch {
      // Process may already have exited.
    }
  }, timeoutMs);
  try {
    const output = await process.output();
    return {
      code: output.code,
      stdout: new TextDecoder().decode(output.stdout).trim(),
      stderr: new TextDecoder().decode(output.stderr).trim(),
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

async function commandAvailable(command: string) {
  const result = await runLocalCommand(
    "sh",
    ["-lc", `command -v ${command}`],
    3000,
  );
  return result.code === 0 ? result.stdout.split(/\r?\n/)[0] || command : null;
}

async function commandText(command: string, fallback = "") {
  const result = await runLocalCommand("sh", ["-lc", command], 8000);
  return result.code === 0 ? result.stdout : fallback;
}

function shellQuote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`;
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
  const regularInstall =
    `cscli collections install ${quotedCollection} || cscli collections inspect ${quotedCollection} >/dev/null`;
  if (collection !== "crowdsecurity/freeswitch") return regularInstall;

  const baseUrl = "https://raw.githubusercontent.com/crowdsecurity/hub/master";
  const manualInstall = [
    "mkdir -p /etc/crowdsec/parsers/s01-parse/mnscloud /etc/crowdsec/scenarios/mnscloud",
    `curl -fsSL ${
      shellQuote(`${baseUrl}/parsers/s01-parse/crowdsecurity/freeswitch.yaml`)
    } -o /etc/crowdsec/parsers/s01-parse/mnscloud/freeswitch.yaml`,
    `curl -fsSL ${
      shellQuote(`${baseUrl}/scenarios/crowdsecurity/freeswitch-bf.yaml`)
    } -o /etc/crowdsec/scenarios/mnscloud/freeswitch-bf.yaml`,
    `curl -fsSL ${
      shellQuote(
        `${baseUrl}/scenarios/crowdsecurity/freeswitch-user-enumeration.yaml`,
      )
    } -o /etc/crowdsec/scenarios/mnscloud/freeswitch-user-enumeration.yaml`,
    `curl -fsSL ${
      shellQuote(
        `${baseUrl}/scenarios/crowdsecurity/freeswitch-acl-reject.yaml`,
      )
    } -o /etc/crowdsec/scenarios/mnscloud/freeswitch-acl-reject.yaml`,
  ].join(" && ");

  return `(${regularInstall}) || (cscli hub update --force >/dev/null 2>&1 || true; ${regularInstall}) || (${manualInstall})`;
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
  const wrappedCommand = `timeout -k 10s ${timeoutSeconds}s sh -lc ${
    shellQuote(command)
  }`;
  const result = await runLocalCommand(
    "sh",
    ["-lc", wrappedCommand],
    timeoutMs + 15_000,
  );
  const step = {
    label,
    code: result.code,
    stdout: result.stdout.slice(-2000),
    stderr: result.stderr.slice(-2000),
  };
  if (result.code !== 0 && !allowFailure) {
    throw new Error(
      `${label} failed: ${
        result.stderr || result.stdout || `exit ${result.code}`
      }`,
    );
  }
  return step;
}

async function debianPackageAvailable(packageName: string) {
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

async function ensureCrowdSecRepository(timeoutMs: number) {
  if (await debianPackageAvailable("crowdsec")) {
    return {
      label: "CrowdSec repository already available",
      code: 0,
      stdout: "",
      stderr: "",
    };
  }
  return await runInstallStep(
    "Add CrowdSec package repository",
    "curl -fsSL https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash",
    timeoutMs,
  );
}

async function resolveCrowdSecFirewallBouncerPackage() {
  const candidates = [
    "crowdsec-firewall-bouncer-nftables",
    "crowdsec-firewall-bouncer",
  ];
  for (const packageName of candidates) {
    if (await debianPackageAvailable(packageName)) return packageName;
  }
  throw new Error(
    `No CrowdSec firewall bouncer package is available. Checked: ${
      candidates.join(", ")
    }`,
  );
}

async function configureCrowdSecFirewallBouncer(timeoutMs: number) {
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
    }; then sed -i 's#^mode:.*#mode: nftables#' ${
      shellQuote(configPath)
    }; else printf '\\nmode: nftables\\n' >> ${shellQuote(configPath)}; fi`,
  ].join(" && ");

  return await runInstallStep(
    "Configure CrowdSec firewall bouncer",
    script,
    timeoutMs,
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
  assertCapability(config, "linux.package.install");
  assertCapability(config, "linux.service.manage");
  assertCapability(config, "security.nftables.manage");
  assertCapability(config, "security.crowdsec.manage");

  const osID = await commandText(
    '. /etc/os-release 2>/dev/null && printf "%s" "${ID:-}"',
  );
  const osLike = await commandText(
    '. /etc/os-release 2>/dev/null && printf "%s" "${ID_LIKE:-}"',
  );
  if (!`${osID} ${osLike}`.match(/\b(debian|ubuntu)\b/i)) {
    throw new Error(
      `Unsupported Linux distribution for automatic install: ${
        osID || "unknown"
      }`,
    );
  }

  const timeoutMs = Math.max(
    120_000,
    Math.min(Number(payload?.["timeoutMs"] ?? 900_000), 1_800_000),
  );
  const collections = payloadStringArray(payload, "collections", [
    "crowdsecurity/linux",
    "crowdsecurity/sshd",
  ]);
  const steps = [];
  const runStep = async (
    percent: number,
    label: string,
    command: string,
    allowFailure = false,
  ) => {
    await progress(label, percent, `${label} started.`);
    const result = await runInstallStep(
      label,
      command,
      timeoutMs,
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
    "Validating Linux distribution.",
  );

  steps.push(
    await runStep(
      10,
      "Refresh APT metadata",
      "DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::ForceIPv4=true update -y",
    ),
  );
  steps.push(
    await runStep(
      20,
      "Install base packages",
      "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates curl gnupg jq nftables",
    ),
  );
  await progress(
    "Prepare CrowdSec repository",
    32,
    "Checking CrowdSec package repository.",
  );
  steps.push(await ensureCrowdSecRepository(timeoutMs));
  steps.push(
    await runStep(
      42,
      "Refresh CrowdSec APT metadata",
      "DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::ForceIPv4=true update -y",
    ),
  );
  await progress(
    "Select CrowdSec firewall bouncer package",
    48,
    "Detecting available CrowdSec firewall bouncer package.",
  );
  const bouncerPackage = await resolveCrowdSecFirewallBouncerPackage();
  await progress(
    "Select CrowdSec firewall bouncer package",
    48,
    `Using ${bouncerPackage}.`,
    { package: bouncerPackage },
  );
  steps.push(
    await runStep(
      55,
      "Install CrowdSec and nftables firewall bouncer",
      `DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends crowdsec ${
        shellQuote(bouncerPackage)
      } nftables`,
    ),
  );
  steps.push(
    await runStep(
      68,
      "Enable nftables",
      "systemctl enable --now nftables",
      true,
    ),
  );
  steps.push(
    await runStep(
      74,
      "Enable CrowdSec",
      "systemctl enable --now crowdsec",
    ),
  );
  await progress(
    "Configure CrowdSec firewall bouncer",
    80,
    "Configuring local bouncer credentials.",
  );
  steps.push(await configureCrowdSecFirewallBouncer(timeoutMs));
  steps.push(
    await runStep(
      86,
      "Update CrowdSec Hub",
      "cscli hub update",
      true,
    ),
  );
  for (const collection of collections) {
    steps.push(
      await runStep(
        90,
        `Install CrowdSec collection ${collection}`,
        `${crowdSecCollectionInstallCommand(collection)} || true`,
        true,
      ),
    );
  }
  steps.push(
    await runStep(
      95,
      "Restart CrowdSec",
      "systemctl restart crowdsec",
    ),
  );
  steps.push(
    await runStep(
      98,
      "Restart CrowdSec firewall bouncer",
      "systemctl restart crowdsec-firewall-bouncer",
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
  ) => {
    await progress(label, percent, `${label} started.`);
    const result = await runInstallStep(
      label,
      command,
      timeoutMs,
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

  steps.push(
    await runStep(25, "Update CrowdSec Hub", "cscli hub update", true),
  );
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
        ),
      );
      installedCollections.push(collection);
      percent += Math.max(5, Math.floor(45 / Math.max(collections.length, 1)));
    }
    steps.push(
      await runStep(
        90,
        "Reload CrowdSec",
        "systemctl reload crowdsec || systemctl restart crowdsec",
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

async function collectCyberSecurityStatus(config: AgentConfig) {
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
    binaries: { nft, crowdsec, cscli, bouncer },
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
