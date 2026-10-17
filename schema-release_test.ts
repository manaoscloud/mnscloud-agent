import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  prepareSchemaRelease,
  pruneSchemaArtifacts,
  type SchemaGitRunner,
} from "./schema-release.ts";
Deno.test("schema release validates tag and origin before checkout, preserves base and verifies repeated stages", async () => {
  const root = await Deno.makeTempDir();
  const repo = root + "/db";
  await Deno.mkdir(repo);
  const schema = "-- canonical fixture\n";
  const digest = Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(schema)),
    ),
  ).map((x) => x.toString(16).padStart(2, "0")).join("");
  let origin = "https://github.com/manaoscloud/mnscloud-db.git";
  let dirty = false;
  let adds = 0;
  const run: SchemaGitRunner = async (args) => {
    const [, dir, ...cmd] = args;
    if (cmd[0] === "remote") return { code: 0, stdout: origin };
    if (cmd[0] === "fetch") {
      assertEquals(cmd, [
        "fetch",
        "--no-tags",
        "origin",
        "refs/tags/v0.1.1:refs/tags/v0.1.1",
      ]);
      return { code: 0, stdout: "" };
    }
    if (cmd[0] === "rev-parse") return { code: 0, stdout: "a".repeat(40) };
    if (cmd[0] === "status") {
      return {
        code: 0,
        stdout: dirty ? " M scripts/reconcile-database-schema.py" : "",
      };
    }
    assertEquals(cmd.slice(0, 3), ["worktree", "add", "--detach"]);
    assertEquals(dir, repo);
    adds++;
    await Deno.mkdir(cmd[3] + "/sql", { recursive: true });
    await Deno.writeTextFile(cmd[3] + "/sql/clouddb-schema.sql", schema);
    return { code: 0, stdout: "" };
  };
  try {
    await assertRejects(
      () => prepareSchemaRelease(repo, "main", digest, run),
      Error,
      "semver",
    );
    await assertRejects(() =>
      prepareSchemaRelease(repo, "v0.1.1;touch x", digest, run)
    );
    origin = "https://example.invalid/other.git";
    await assertRejects(
      () => prepareSchemaRelease(repo, "v0.1.1", digest, run),
      Error,
      "canonical",
    );
    origin = "https://github.com/manaoscloud/mnscloud-db.git";
    const selected = await prepareSchemaRelease(repo, "v0.1.1", digest, run);
    assertEquals(
      selected,
      await prepareSchemaRelease(repo, "v0.1.1", digest, run),
    );
    assertEquals(adds, 1);
    assertEquals([...Deno.readDirSync(repo)].length, 0);
    dirty = true;
    await assertRejects(
      () => prepareSchemaRelease(repo, "v0.1.1", digest, run),
      Error,
      "changed",
    );
    dirty = false;
    await assertRejects(
      () => prepareSchemaRelease(repo, "v0.1.1", "b".repeat(64), run),
      Error,
      "digest mismatch",
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("schema artifact pruning keeps newest and recent entries and the current job", async () => {
  const root = await Deno.makeTempDir();
  const repo = root + "/mnscloud-db";
  const backups = root + "/backups";
  const now = Date.now();
  const day = 86_400_000;
  const make = async (path: string, ageDays: number) => {
    await Deno.mkdir(path, { recursive: true });
    const at = new Date(now - ageDays * day);
    await Deno.utime(path, at, at);
  };
  const release = (n: number) => `${repo}-releases/v0.1.${n}-${"a".repeat(64)}`;
  for (let n = 1; n <= 8; n++) await make(release(n), 20 - n);
  await make(`${repo}-releases/v0.1.99-${"b".repeat(64)}`, 1);
  await make(`${repo}-releases/unrelated`, 30);
  const backup = (n: number) => `${backups}/schema-reconcile-tmp${String(n).padStart(5, "0")}`;
  for (let n = 1; n <= 14; n++) await make(backup(n), 30 - n);
  await make(`${backups}/schema-dns-keepme00`, 40);
  const gitCalls: string[][] = [];
  const run: SchemaGitRunner = async (args) => {
    gitCalls.push(args);
    if (args[3] === "remove") await Deno.remove(args[5], { recursive: true });
    return { code: 0, stdout: "" };
  };
  try {
    const removed = await pruneSchemaArtifacts(
      repo,
      backups,
      { releaseDirectory: release(1), planDirectory: backup(2) },
      run,
      { keepReleases: 5, keepBackups: 10, minAgeDays: 3, now },
    );
    // Releases: newest 5 are v0.1.99 and v0.1.8..5; v0.1.1 is current; v0.1.2..4 go.
    for (const n of [2, 3, 4]) assertEquals(removed.includes(release(n)), true);
    for (const n of [1, 5, 6, 7, 8]) await Deno.stat(release(n));
    await Deno.stat(`${repo}-releases/unrelated`);
    assertEquals(gitCalls.at(-1), ["-C", repo, "worktree", "prune"]);
    // Backups: newest 10 are 14..5; 2 is the current plan; 1, 3 and 4 go.
    for (const n of [1, 3, 4]) assertEquals(removed.includes(backup(n)), true);
    for (const n of [2, 5, 14]) await Deno.stat(backup(n));
    await Deno.stat(`${backups}/schema-dns-keepme00`);
    assertEquals(removed.length, 6);
    // Missing directories are a no-op.
    assertEquals(
      await pruneSchemaArtifacts(root + "/none", root + "/none-backups", {}, run),
      [],
    );
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});
