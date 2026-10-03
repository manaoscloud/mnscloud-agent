// runtime.reconcile helpers: product registry, job validation and release preparation.
// Execution lives in main.ts. The Agent never runs a path or command taken from the job: the
// product selects a release-owned adapter, and the adapter owns files, fields and services.

export const RUNTIME_RECONCILE_CAPABILITY = "mnscloud.runtime.reconcile.v1";
export const RUNTIME_RECONCILE_JOB_TYPE = "runtime.reconcile";

export type RuntimeReconcileProduct = {
  repo: string;
  origin: RegExp;
  adapter: string;
  envPath: string;
  resources: readonly string[];
};

export const RUNTIME_RECONCILE_PRODUCTS: Record<string, RuntimeReconcileProduct> = {
  "mnscloud-db": {
    repo: "/opt/mnscloud/mnscloud-db",
    origin: /^https:\/\/github\.com\/manaoscloud\/mnscloud-db(?:\.git)?\/?$/,
    adapter: "scripts/reconcile-runtime-config.py",
    envPath: "/etc/mnscloud/db-migration.env",
    resources: ["mariadb.server"],
  },
};

/** A product is available when its checkout (`.git` directory or worktree file) and env exist. */
export async function runtimeReconcileProductAvailable(
  product: RuntimeReconcileProduct,
): Promise<boolean> {
  const stat = async (path: string) => await Deno.stat(path).catch(() => null);
  const git = await stat(`${product.repo}/.git`);
  const env = await stat(product.envPath);
  return Boolean(git && (git.isDirectory || git.isFile) && env?.isFile);
}

export type RuntimeReconcileRequest = {
  product: string;
  releaseTag: string;
  resource: string;
  stage: "inspect" | "plan" | "apply";
  desired: Record<string, string> | null;
  resolution: "adopt-desired" | null;
  planDigest: string | null;
};

function text(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

export function parseRuntimeReconcileJob(job: Record<string, unknown>): RuntimeReconcileRequest {
  const product = text(job.product);
  const registry = RUNTIME_RECONCILE_PRODUCTS[product];
  if (!registry) throw new Error(`Runtime reconcile product is not supported: ${product || "-"}`);
  const resource = text(job.resource);
  if (!registry.resources.includes(resource)) {
    throw new Error(`Runtime reconcile resource is not supported: ${resource || "-"}`);
  }
  const releaseTag = text(job.releaseTag);
  if (!/^v\d+\.\d+\.\d+$/.test(releaseTag)) {
    throw new Error("Runtime reconcile release must be an explicit semver tag.");
  }
  const stage = text(job.stage);
  if (stage !== "inspect" && stage !== "plan" && stage !== "apply") {
    throw new Error("Unsupported runtime reconcile stage.");
  }
  const resolutionText = text(job.resolution);
  if (resolutionText && resolutionText !== "adopt-desired") {
    throw new Error("Unsupported runtime reconcile resolution.");
  }
  let desired: Record<string, string> | null = null;
  const rawDesired = typeof job.desiredJson === "string" && job.desiredJson
    ? JSON.parse(job.desiredJson)
    : job.desired ?? null;
  if (rawDesired !== null) {
    if (typeof rawDesired !== "object" || Array.isArray(rawDesired)) {
      throw new Error("Runtime reconcile desired state must be an object.");
    }
    desired = {};
    for (const [key, value] of Object.entries(rawDesired as Record<string, unknown>)) {
      if (!/^[a-z0-9][a-z0-9_.-]{0,79}$/i.test(key) || typeof value !== "string") {
        throw new Error("Runtime reconcile desired fields must be simple string values.");
      }
      desired[key] = value;
    }
  }
  if (stage === "plan" && (!desired || !Object.keys(desired).length)) {
    throw new Error("Runtime reconcile plan requires desired fields.");
  }
  const planDigest = text(job.planDigest) || null;
  if (stage === "apply" && !/^[a-f0-9]{64}$/.test(planDigest ?? "")) {
    throw new Error("Runtime reconcile apply requires the approved plan digest.");
  }
  return {
    product,
    releaseTag,
    resource,
    stage,
    desired,
    resolution: resolutionText ? "adopt-desired" : null,
    planDigest,
  };
}

export type GitRunner = (args: string[]) => Promise<{ code: number; stdout: string }>;

/** Prepare a clean detached checkout of an exact module release tag and return its path. */
export async function prepareModuleRelease(
  registry: RuntimeReconcileProduct,
  releaseTag: string,
  runGit: GitRunner,
): Promise<string> {
  const git = async (directory: string, ...args: string[]) => {
    const result = await runGit(["-C", directory, ...args]);
    if (result.code !== 0) {
      throw new Error("Unable to prepare the approved module release checkout.");
    }
    return result.stdout.trim();
  };
  if (!registry.origin.test(await git(registry.repo, "remote", "get-url", "origin"))) {
    throw new Error("Module checkout origin is not the canonical repository.");
  }
  // No force: a moved tag must fail instead of silently changing approved source.
  await git(
    registry.repo,
    "fetch",
    "--no-tags",
    "origin",
    `refs/tags/${releaseTag}:refs/tags/${releaseTag}`,
  );
  const commit = await git(
    registry.repo,
    "rev-parse",
    "--verify",
    `refs/tags/${releaseTag}^{commit}`,
  );
  if (!/^[a-f0-9]{40,64}$/.test(commit)) throw new Error("Invalid module release commit.");
  const directory = `${registry.repo}-releases/${releaseTag}-${commit.slice(0, 12)}`;
  let exists = false;
  try {
    await Deno.lstat(directory);
    exists = true;
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  if (!exists) {
    await Deno.mkdir(`${registry.repo}-releases`, { recursive: true, mode: 0o700 });
    await git(registry.repo, "worktree", "add", "--detach", directory, commit);
  }
  if (
    (await git(directory, "rev-parse", "HEAD")) !== commit ||
    (await git(directory, "status", "--porcelain", "--untracked-files=normal")) !== ""
  ) {
    throw new Error("Module release checkout changed; refusing runtime reconcile.");
  }
  const adapter = await Deno.lstat(`${directory}/${registry.adapter}`).catch(() => null);
  if (!adapter?.isFile) {
    throw new Error("Module release does not provide the runtime reconcile adapter.");
  }
  return directory;
}

/** Command arguments for the adapter; values are passed as discrete argv entries. */
export function adapterArgs(
  request: RuntimeReconcileRequest,
  registry: RuntimeReconcileProduct,
  adapterPath: string,
  desiredPath: string | null,
  resultPath: string,
): string[] {
  const args = [
    adapterPath,
    "--stage",
    request.stage,
    "--resource",
    request.resource,
    "--env",
    registry.envPath,
    "--result-json",
    resultPath,
  ];
  if (request.stage === "plan" && desiredPath) args.push("--desired-json", desiredPath);
  if (request.stage === "plan" && request.resolution) args.push("--resolution", request.resolution);
  if (request.stage === "apply" && request.planDigest) {
    args.push("--plan-digest", request.planDigest);
  }
  return args;
}
