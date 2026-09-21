import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  prepareSchemaRelease,
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
