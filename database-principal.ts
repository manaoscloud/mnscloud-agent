// Per-module database principals (mnscloud-db docs/db-patterns.md → Per-module database principals).
// The DB host runs the release-owned scripts/database-principal.py of the applied mnscloud-db
// release; a module host runs the scripts/apply-database-credential.py of its installed checkout.
// The job never chooses a command, path or SQL: the step and the profile select a fixed adapter.

export const DATABASE_PRINCIPAL_JOB_TYPE = "database.principal";
export const DATABASE_PRINCIPAL_CAPABILITY = "mnscloud.database.principal.v1";
export const MODULE_DATABASE_CREDENTIAL_CAPABILITY = "mnscloud.module.database.credential.v1";

export type ModuleCredentialAdapter = { repo: string; adapter: string; envPath: string };

export const MODULE_DATABASE_CREDENTIAL_ADAPTERS: Record<string, ModuleCredentialAdapter> = {
  api: {
    repo: "/opt/mnscloud/mnscloud-api",
    adapter: "scripts/apply-database-credential.py",
    envPath: "/etc/mnscloud/api.env",
  },
  workers: {
    repo: "/opt/mnscloud/mnscloud-workers",
    adapter: "scripts/apply-database-credential.py",
    envPath: "/etc/mnscloud/workers.env",
  },
};

/** Codes an adapter may report; anything else becomes the generic code of its step. */
const FORWARDED_CODES = new Set([
  "DATABASE_PRINCIPAL_HOST_MISMATCH",
  "MODULE_DATABASE_CREDENTIAL_INVALID",
  "MODULE_DATABASE_CREDENTIAL_UNHEALTHY",
  "MODULE_DATABASE_ENDPOINT_MISMATCH",
  "MODULE_DATABASE_ENV_UNSAFE",
  "MODULE_DATABASE_ENV_UNSUPPORTED",
  "MODULE_DATABASE_RESTART_FAILED",
]);

export type DatabasePrincipalStep = "create" | "deliver" | "revoke";

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$|^[a-f0-9]{32}$/i;

export function parseDatabasePrincipalJob(
  job: { jobUUID: string; payload?: Record<string, unknown> },
) {
  const leaseUUID = String(job.payload?.leaseUUID ?? "");
  const step = String(job.payload?.step ?? "");
  if (!UUID.test(job.jobUUID) || !UUID.test(leaseUUID)) throw new Error("Invalid principal job");
  if (step !== "create" && step !== "deliver" && step !== "revoke") {
    throw new Error("Invalid principal step");
  }
  return { jobUUID: job.jobUUID, leaseUUID, step: step as DatabasePrincipalStep };
}

export function genericErrorCode(step: DatabasePrincipalStep): string {
  return step === "deliver"
    ? "MODULE_DATABASE_CREDENTIAL_FAILED"
    : "DATABASE_PRINCIPAL_PROVISION_FAILED";
}

/** Only fixed codes cross the boundary; adapter text never does. */
export function forwardedErrorCode(step: DatabasePrincipalStep, value: unknown): string {
  return typeof value === "string" && FORWARDED_CODES.has(value) ? value : genericErrorCode(step);
}

/** stdin of the DB host adapter: never the release paths or anything the adapter does not read. */
export function databaseAdapterInput(material: Record<string, unknown>, step: "create" | "revoke") {
  const input: Record<string, unknown> = {
    principalUUID: material.principalUUID,
    step,
    profile: material.profile,
    username: material.username,
    host: material.host,
    databaseName: material.databaseName,
    databaseHost: material.databaseHost,
  };
  if (step === "create") input.password = material.password;
  return input;
}

/** stdin of the module adapter: the credential and the endpoint it must already use. */
export function moduleAdapterInput(material: Record<string, unknown>) {
  return {
    username: material.username,
    password: material.password,
    databaseHost: material.databaseHost,
    databasePort: material.databasePort,
    databaseName: material.databaseName,
  };
}
