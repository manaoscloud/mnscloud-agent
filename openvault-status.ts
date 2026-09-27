/** Local OpenBao observation on an OpenVault host; the API stores it and decides alerts. */
export type OpenVaultState = "unsealed" | "sealed" | "uninitialized" | "unreachable";
export type OpenVaultStatus = {
  state: OpenVaultState;
  sealType: string | null;
  tlsNotAfter: string | null;
};

export const OPENVAULT_ENV_FILE = "/etc/mnscloud/openvault.env";

/** Minimal KEY=VALUE reader (comments, `export`, single/double quotes); never logs values. */
export function parseEnv(text: string): Record<string, string> {
  const values: Record<string, string> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim().replace(/^export\s+/, "");
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match || line.startsWith("#")) continue;
    let value = match[2].trim();
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0]) {
      value = value.slice(1, -1);
    }
    values[match[1]] = value;
  }
  return values;
}

export function stateFromSealStatus(
  body: unknown,
): { state: OpenVaultState; sealType: string | null } {
  const status = body && typeof body === "object" ? body as Record<string, unknown> : {};
  const sealType = typeof status.type === "string" && /^[a-z0-9_-]{1,20}$/.test(status.type)
    ? status.type
    : null;
  if (status.initialized === false) return { state: "uninitialized", sealType };
  if (status.sealed === true) return { state: "sealed", sealType };
  if (status.sealed === false) return { state: "unsealed", sealType };
  return { state: "unreachable", sealType };
}

/** `openssl x509 -enddate` output such as `notAfter=Oct 27 03:25:50 2026 GMT` → ISO UTC. */
export function parseOpenSslEndDate(output: string): string | null {
  const match = /notAfter=(.+GMT)/.exec(output);
  const time = match ? Date.parse(match[1]) : NaN;
  return Number.isNaN(time) ? null : new Date(time).toISOString().replace(/\.\d{3}Z$/, "Z");
}

async function certificateEndDate(file: string): Promise<string | null> {
  try {
    const result = await new Deno.Command("openssl", {
      args: ["x509", "-in", file, "-noout", "-enddate"],
      stdout: "piped",
      stderr: "null",
      signal: AbortSignal.timeout(5_000),
    }).output();
    return result.success ? parseOpenSslEndDate(new TextDecoder().decode(result.stdout)) : null;
  } catch {
    return null;
  }
}

export type OpenVaultStatusDeps = {
  readTextFile: (path: string) => Promise<string>;
  sealStatus: (url: string, caPEM: string | null) => Promise<unknown>;
  endDate: (file: string) => Promise<string | null>;
};

const defaultDeps: OpenVaultStatusDeps = {
  readTextFile: (path) => Deno.readTextFile(path),
  sealStatus: async (url, caPEM) => {
    const client = caPEM ? Deno.createHttpClient({ caCerts: [caPEM] }) : undefined;
    try {
      const response = await fetch(url, { client, signal: AbortSignal.timeout(5_000) });
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`HTTP ${response.status}`);
      }
      return await response.json();
    } finally {
      client?.close();
    }
  },
  endDate: certificateEndDate,
};

/** Returns null when this host has no OpenVault configuration. Never throws. */
export async function collectOpenVaultStatus(
  envFile = OPENVAULT_ENV_FILE,
  deps: OpenVaultStatusDeps = defaultDeps,
): Promise<OpenVaultStatus | null> {
  let env: Record<string, string>;
  try {
    env = parseEnv(await deps.readTextFile(envFile));
  } catch {
    return null;
  }
  // Same derivation as mnscloud-openvault normalize_openvault_env: most hosts only set
  // OPENVAULT_PRIVATE_HOST and the installer builds the API address from it.
  const tlsDisabled = env.OPENVAULT_TLS_DISABLE === "true" || env.OPENVAULT_TLS_MODE === "disabled";
  const address = env.OPENVAULT_API_ADDR ||
    (env.OPENVAULT_PRIVATE_HOST
      ? `${tlsDisabled ? "http" : "https"}://${env.OPENVAULT_PRIVATE_HOST}:8200`
      : "");
  if (!address || !/^https?:\/\/[^\s/]+$/.test(address.replace(/\/+$/, ""))) return null;
  const tls = !tlsDisabled && address.startsWith("https://");
  const certFile = env.OPENVAULT_TLS_CERT_FILE || "/etc/mnscloud/openvault/tls/server.crt";
  const caFile = env.OPENVAULT_TLS_CA_FILE || certFile;
  let caPEM: string | null = null;
  if (tls) {
    try {
      caPEM = await deps.readTextFile(caFile);
    } catch {
      caPEM = null;
    }
  }
  const tlsNotAfter = tls ? await deps.endDate(certFile) : null;
  try {
    if (tls && !caPEM) throw new Error("CA unavailable");
    const body = await deps.sealStatus(`${address.replace(/\/+$/, "")}/v1/sys/seal-status`, caPEM);
    return { ...stateFromSealStatus(body), tlsNotAfter };
  } catch {
    return { state: "unreachable", sealType: env.OPENVAULT_SEAL || null, tlsNotAfter };
  }
}
