/** Builds the update-webapps.sh invocation for a mnscloud-webapps runtime.update job. */

const APP_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;
const REF_PATTERN = /^[A-Za-z0-9._/@+-]+$/;
const TAG_PATTERN = /^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;

function quote(value: string) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function field(payload: Record<string, unknown> | null | undefined, key: string) {
  const value = payload?.[key];
  return typeof value === "string" ? value.trim() : "";
}

/**
 * Returns the shell fragment run after the runtime checkout. A catalog digest
 * (appArtifactSha256) pins a single-app install; a runtime checkout without
 * --app-sha256 support fails the job instead of installing unverified.
 */
export function webappsUpdateScript(payload: Record<string, unknown> | null | undefined) {
  const app = field(payload, "app");
  const appRef = field(payload, "appRef");
  const sha256 = field(payload, "appArtifactSha256").toLowerCase();
  if (app && !APP_PATTERN.test(app)) throw new Error(`Invalid webapp name: ${app}`);
  if (appRef && !REF_PATTERN.test(appRef)) throw new Error(`Invalid webapp ref: ${appRef}`);
  if (sha256) {
    if (!SHA256_PATTERN.test(sha256)) throw new Error("Invalid webapp artifact SHA-256");
    if (!app || !TAG_PATTERN.test(appRef)) {
      throw new Error("A webapp artifact SHA-256 requires an app and a release tag");
    }
  }
  const args = ["--env", "/etc/mnscloud/webapps/webapps.env"];
  if (app) args.push("--app", app);
  if (appRef) args.push("--app-ref", appRef);
  if (sha256) args.push("--app-sha256", sha256);
  const run = `bash scripts/update-webapps.sh ${args.map(quote).join(" ")}`;
  if (!sha256) return run;
  return `{ grep -q -- '--app-sha256' scripts/update-webapps.sh || ` +
    `{ echo 'webapps runtime does not support catalog SHA-256 pins; update mnscloud-webapps first' >&2; exit 1; }; } && ${run}`;
}
