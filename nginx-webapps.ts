// Effective ThemeDomain webapps settings from /etc/mnscloud/nginx.env and agent.conf overrides.

export const DEFAULT_NGINX_EDGE_WEBAPPS_PATHS = "/phoneweb/,/pulse/,/customer-portal/,/pos/";

export type NginxEdgeWebappsIni = {
  enabled: string | null;
  upstream: string | null;
  paths: string;
};

export type NginxEdgeWebappsSettings = {
  nginxEdgeWebappsEnabled: boolean;
  nginxEdgeWebappsUpstream: string;
  nginxEdgeWebappsPaths: string[];
  /** Softphone clients (PhoneWeb): microphone allowed and framable by the App of the same origin. */
  nginxEdgeSoftphonePaths: string[];
  /** Barcode scanning clients (POS): camera allowed for their own origin, nothing else opened. */
  nginxEdgeScannerPaths: string[];
  /** Time clock clients (Pulse): geolocation of their own origin for the punch position. */
  nginxEdgeTimeclockPaths: string[];
  /** Field clients (InfraGIS): geolocation and camera of their own origin (asset position, photos). */
  nginxEdgeFieldPaths: string[];
};

/**
 * Bumped whenever the rendered ThemeDomain server block changes in a way existing vhosts must
 * pick up: the Agent re-renders every vhost once when its stored revision differs.
 */
export const NGINX_EDGE_RENDER_REVISION = "2026-11-06.website-hardening";

export type EdgeSurface =
  | "app"
  | "softphone"
  | "scanner"
  | "timeclock"
  | "field"
  | "webapp"
  | "site";

const CSP_BASE =
  "default-src 'self'; base-uri 'self'; object-src 'none'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://www.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; media-src 'self' data: blob: https:; connect-src 'self' https: wss:; form-action 'self'; upgrade-insecure-requests";

/**
 * Published website snapshots (storefront): static HTML and one stylesheet, no script and no inline
 * style, images from the site or https (tenant logo), forms posting to the same origin only.
 */
const CSP_SITE =
  "default-src 'none'; base-uri 'none'; object-src 'none'; script-src 'none'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; manifest-src 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";

/**
 * nginx drops the server-level `add_header` (HSTS) in every location that sets its own headers, so
 * HSTS travels with the per-location set. Browsers ignore it over plain HTTP (RFC 6797 section 8.1).
 */
const HSTS = "max-age=31536000";

/** The App plays tutorial videos (beside Report problem) from this origin only. */
const APP_FRAME_SRC = "frame-src 'self' https://www.youtube-nocookie.com";

/**
 * Security headers per edge surface. The App hosts the PhoneWeb dock, so it may use the
 * microphone itself (and in same-origin frames), and frames tutorial videos from
 * youtube-nocookie.com; a softphone may use the microphone and be framed only by its own origin;
 * a scanner (POS web) may use the camera of its own origin to read barcodes; a time clock (Pulse)
 * may read the geolocation of its own origin for the punch position; a field client (InfraGIS)
 * may use both the geolocation and the camera of its own origin; other web clients keep
 * geolocation, microphone, camera and framing closed.
 */
export function edgeSecurityHeaders(surface: EdgeSurface, indent = "    ") {
  if (surface === "site") {
    return [
      `${indent}add_header Content-Security-Policy "${CSP_SITE}" always;`,
      `${indent}add_header X-Content-Type-Options "nosniff" always;`,
      `${indent}add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
      `${indent}add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;`,
      `${indent}add_header Strict-Transport-Security "${HSTS}" always;`,
    ].join("\n");
  }
  const frameAncestors = surface === "softphone" ? "'self'" : "'none'";
  const microphone = surface === "app" || surface === "softphone" ? "(self)" : "()";
  const camera = surface === "scanner" || surface === "field" ? "(self)" : "()";
  const geolocation = surface === "timeclock" || surface === "field" ? "(self)" : "()";
  const frameSrc = surface === "app" ? `; ${APP_FRAME_SRC}` : "";
  return [
    `${indent}add_header Content-Security-Policy "${CSP_BASE}${frameSrc}; frame-ancestors ${frameAncestors}" always;`,
    `${indent}add_header X-Content-Type-Options "nosniff" always;`,
    `${indent}add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
    `${indent}add_header Permissions-Policy "geolocation=${geolocation}, microphone=${microphone}, camera=${camera}" always;`,
    `${indent}add_header Strict-Transport-Security "${HSTS}" always;`,
  ].join("\n");
}

function normalizePath(value: string) {
  let path = value.trim();
  if (!path) return "";
  if (!path.startsWith("/")) path = `/${path}`;
  if (!path.endsWith("/")) path = `${path}/`;
  return path;
}

function softphonePaths(env: Record<string, string>) {
  const configured = list(env.MNSCLOUD_PHONEWEB_PATH).map(normalizePath).filter(Boolean);
  return configured.length ? configured : ["/phoneweb/"];
}

function scannerPaths(env: Record<string, string>) {
  const configured = list(env.MNSCLOUD_POS_PATH).map(normalizePath).filter(Boolean);
  return configured.length ? configured : ["/pos/"];
}

function timeclockPaths(env: Record<string, string>) {
  const configured = list(env.MNSCLOUD_PULSE_PATH).map(normalizePath).filter(Boolean);
  return configured.length ? configured : ["/pulse/"];
}

function fieldPaths(env: Record<string, string>) {
  const configured = list(env.MNSCLOUD_INFRAGIS_PATH).map(normalizePath).filter(Boolean);
  // Never /infragis/: that prefix belongs to the App InfraGIS pages.
  return configured.length ? configured : ["/infragis-mobile/"];
}

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
    ...list(env.MNSCLOUD_POS_PATH),
    ...list(env.MNSCLOUD_INFRAGIS_PATH),
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
      nginxEdgeSoftphonePaths: softphonePaths(env),
      nginxEdgeScannerPaths: scannerPaths(env),
      nginxEdgeTimeclockPaths: timeclockPaths(env),
      nginxEdgeFieldPaths: fieldPaths(env),
    };
  }
  const envEnabled = flag(env.MNSCLOUD_ENABLE_WEBAPPS_PROXY, false);
  return {
    nginxEdgeWebappsEnabled: flag(ini.enabled, envEnabled) || envEnabled,
    nginxEdgeWebappsUpstream: upstream,
    nginxEdgeWebappsPaths: [...new Set([...list(ini.paths), ...envPaths(env)])],
    nginxEdgeSoftphonePaths: softphonePaths(env),
    nginxEdgeScannerPaths: scannerPaths(env),
    nginxEdgeTimeclockPaths: timeclockPaths(env),
    nginxEdgeFieldPaths: fieldPaths(env),
  };
}
