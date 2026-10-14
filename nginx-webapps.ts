// Effective ThemeDomain webapps settings from /etc/mnscloud/nginx.env and agent.conf overrides.

export const DEFAULT_NGINX_EDGE_WEBAPPS_PATHS = "/phoneweb/,/pulse/,/customer-portal/";

export type NginxEdgeWebappsIni = {
  enabled: string | null;
  upstream: string | null;
  paths: string;
};

export type NginxEdgeWebappsSettings = {
  nginxEdgeWebappsEnabled: boolean;
  nginxEdgeWebappsUpstream: string;
  nginxEdgeWebappsPaths: string[];
};

function list(value: string | undefined) {
  return (value ?? "").split(",").map((item) => item.trim()).filter(Boolean);
}

function flag(value: string | null | undefined, fallback: boolean) {
  const normalized = (value ?? "").trim().toLowerCase();
  if (["1", "true", "yes", "y", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "n", "off"].includes(normalized)) return false;
  return fallback;
}

function envPaths(env: Record<string, string>) {
  return [
    ...list(env.MNSCLOUD_PHONEWEB_PATH),
    ...list(env.MNSCLOUD_PULSE_PATH),
    ...list(env.MNSCLOUD_CUSTOMER_PORTAL_PATH),
    ...list(env.MNSCLOUD_WEBAPPS_PATHS),
  ];
}

/**
 * When nginx.env declares MNSCLOUD_ENABLE_WEBAPPS_PROXY the edge env is authoritative (it is
 * managed by the `nginx.webapps` runtime reconcile): ThemeDomains publish exactly the edge paths,
 * so an unpublished path disappears everywhere. Hosts without that key keep the legacy merge of
 * agent.conf paths (defaulting to every known webapp) and env paths.
 */
export function nginxEdgeWebapps(
  ini: NginxEdgeWebappsIni,
  env: Record<string, string>,
): NginxEdgeWebappsSettings {
  const upstream = ini.upstream ?? env.MNSCLOUD_WEBAPPS_UPSTREAM ?? "$webapps_upstream";
  if ((env.MNSCLOUD_ENABLE_WEBAPPS_PROXY ?? "").trim()) {
    return {
      nginxEdgeWebappsEnabled: flag(env.MNSCLOUD_ENABLE_WEBAPPS_PROXY, false),
      nginxEdgeWebappsUpstream: env.MNSCLOUD_WEBAPPS_UPSTREAM ?? upstream,
      nginxEdgeWebappsPaths: [...new Set(envPaths(env))],
    };
  }
  const envEnabled = flag(env.MNSCLOUD_ENABLE_WEBAPPS_PROXY, false);
  return {
    nginxEdgeWebappsEnabled: flag(ini.enabled, envEnabled) || envEnabled,
    nginxEdgeWebappsUpstream: upstream,
    nginxEdgeWebappsPaths: [...list(ini.paths), ...envPaths(env)],
  };
}
