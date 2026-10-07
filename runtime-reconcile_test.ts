import {
  assertEquals,
  assertRejects,
  assertThrows,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  adapterArgs,
  type GitRunner,
  parseRuntimeReconcileJob,
  prepareModuleRelease,
  RUNTIME_RECONCILE_PRODUCTS,
  type RuntimeReconcileProduct,
  runtimeReconcileProductAvailable,
} from "./runtime-reconcile.ts";

const base = {
  product: "mnscloud-db",
  releaseTag: "v0.1.400",
  resource: "mariadb.server",
};

Deno.test("runtime reconcile accepts only registered products, resources and stages", () => {
  const plan = parseRuntimeReconcileJob({
    ...base,
    stage: "plan",
    desiredJson: '{"character-set-collations":"utf8mb4=utf8mb4_unicode_ci"}',
    resolution: "adopt-desired",
  });
  assertEquals(plan.desired, { "character-set-collations": "utf8mb4=utf8mb4_unicode_ci" });
  assertEquals(plan.resolution, "adopt-desired");
  assertThrows(() =>
    parseRuntimeReconcileJob({ ...base, product: "mnscloud-api", stage: "inspect" })
  );
  assertThrows(() =>
    parseRuntimeReconcileJob({ ...base, resource: "nginx.edge", stage: "inspect" })
  );
  assertThrows(() => parseRuntimeReconcileJob({ ...base, releaseTag: "main", stage: "inspect" }));
  assertThrows(() => parseRuntimeReconcileJob({ ...base, stage: "exec" }));
  assertThrows(() => parseRuntimeReconcileJob({ ...base, stage: "plan" }));
  assertThrows(() => parseRuntimeReconcileJob({ ...base, stage: "plan", desired: { "a b": "x" } }));
  assertThrows(() => parseRuntimeReconcileJob({ ...base, stage: "plan", desired: { key: 1 } }));
  assertThrows(() => parseRuntimeReconcileJob({ ...base, stage: "apply", planDigest: "abc" }));
  assertThrows(() => parseRuntimeReconcileJob({ ...base, stage: "inspect", resolution: "force" }));
});

Deno.test("runtime reconcile adapter arguments are discrete and stage specific", () => {
  const registry = RUNTIME_RECONCILE_PRODUCTS["mnscloud-db"];
  const apply = parseRuntimeReconcileJob({ ...base, stage: "apply", planDigest: "a".repeat(64) });
  assertEquals(adapterArgs(apply, registry, "/r/adapter.py", null, "/w/result.json"), [
    "/r/adapter.py",
    "--stage",
    "apply",
    "--resource",
    "mariadb.server",
    "--env",
    "/etc/mnscloud/db-migration.env",
    "--result-json",
    "/w/result.json",
    "--plan-digest",
    "a".repeat(64),
  ]);
  const plan = parseRuntimeReconcileJob({
    ...base,
    stage: "plan",
    desired: { "collation-server": "x" },
  });
  assertEquals(adapterArgs(plan, registry, "/r/a.py", "/w/d.json", "/w/r.json").slice(-2), [
    "--desired-json",
    "/w/d.json",
  ]);
});

Deno.test("module release checkout requires canonical origin, exact tag, clean tree and adapter", async () => {
  const root = await Deno.makeTempDir();
  const registry: RuntimeReconcileProduct = {
    ...RUNTIME_RECONCILE_PRODUCTS["mnscloud-db"],
    repo: `${root}/mnscloud-db`,
  };
  await Deno.mkdir(registry.repo);
  const commit = "c".repeat(40);
  let origin = "https://github.com/manaoscloud/mnscloud-db.git";
  let dirty = false;
  let withAdapter = true;
  const run: GitRunner = async (args) => {
    const [, directory, ...command] = args;
    if (command[0] === "remote") return { code: 0, stdout: origin };
    if (command[0] === "fetch") {
      assertEquals(command, [
        "fetch",
        "--no-tags",
        "origin",
        "refs/tags/v0.1.400:refs/tags/v0.1.400",
      ]);
      return { code: 0, stdout: "" };
    }
    if (command[0] === "rev-parse" && command[1] === "--verify") return { code: 0, stdout: commit };
    if (command[0] === "worktree") {
      await Deno.mkdir(`${command[3]}/scripts`, { recursive: true });
      if (withAdapter) {
        await Deno.writeTextFile(`${command[3]}/scripts/reconcile-runtime-config.py`, "#");
      }
      return { code: 0, stdout: "" };
    }
    if (command[0] === "rev-parse") return { code: 0, stdout: commit };
    if (command[0] === "status") return { code: 0, stdout: dirty ? " M x" : "" };
    throw new Error(`unexpected git ${directory} ${command.join(" ")}`);
  };
  const directory = await prepareModuleRelease(registry, "v0.1.400", run);
  assertEquals(directory, `${registry.repo}-releases/v0.1.400-${commit.slice(0, 12)}`);
  dirty = true;
  await assertRejects(() => prepareModuleRelease(registry, "v0.1.400", run), Error, "changed");
  dirty = false;
  origin = "https://github.com/someone/mnscloud-db.git";
  await assertRejects(() => prepareModuleRelease(registry, "v0.1.400", run), Error, "canonical");
  origin = "https://github.com/manaoscloud/mnscloud-db.git";
  await Deno.remove(`${registry.repo}-releases`, { recursive: true });
  withAdapter = false;
  await assertRejects(() => prepareModuleRelease(registry, "v0.1.400", run), Error, "adapter");
  await Deno.remove(root, { recursive: true });
});

Deno.test("runtime reconcile product detection accepts a .git directory or worktree file", async () => {
  const root = await Deno.makeTempDir();
  const product: RuntimeReconcileProduct = {
    ...RUNTIME_RECONCILE_PRODUCTS["mnscloud-db"],
    repo: `${root}/mnscloud-db`,
    envPath: `${root}/db-migration.env`,
  };
  assertEquals(await runtimeReconcileProductAvailable(product), false);
  await Deno.mkdir(`${product.repo}/.git`, { recursive: true });
  assertEquals(await runtimeReconcileProductAvailable(product), false);
  await Deno.writeTextFile(product.envPath, "DB_NAME=clouddb\n");
  assertEquals(await runtimeReconcileProductAvailable(product), true);
  await Deno.remove(`${product.repo}/.git`, { recursive: true });
  await Deno.writeTextFile(`${product.repo}/.git`, "gitdir: /elsewhere\n");
  assertEquals(await runtimeReconcileProductAvailable(product), true);
  await Deno.remove(root, { recursive: true });
});

Deno.test("Workers reconcile selects the module-owned adapter and fixed env", () => {
  const request = parseRuntimeReconcileJob({
    product: "mnscloud-workers",
    releaseTag: "v0.1.28",
    resource: "workers.handlers",
    stage: "plan",
    desired: { WORKER_HANDLERS: "dns" },
  });
  const registry = RUNTIME_RECONCILE_PRODUCTS[request.product];
  assertEquals(registry.repo, "/opt/mnscloud/mnscloud-workers");
  assertEquals(registry.envPath, "/etc/mnscloud/workers.env");
  assertEquals(registry.adapter, "scripts/reconcile-runtime-config.py");
  assertThrows(() => parseRuntimeReconcileJob({ ...request, resource: "arbitrary.command" }));
});
