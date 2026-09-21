/** Select an immutable DB release for the existing, API-authorized schema job. */
export type SchemaGitRunner = (
  args: string[],
) => Promise<{ code: number; stdout: string }>;
export async function prepareSchemaRelease(
  repo: string,
  releaseTag: string,
  expectedSha256: string,
  runGit: SchemaGitRunner,
): Promise<string> {
  if (!/^v\d+\.\d+\.\d+$/.test(releaseTag)) {
    throw new Error("DB release must be an explicit semver tag.");
  }
  if (!/^[a-f0-9]{64}$/i.test(expectedSha256)) {
    throw new Error("Invalid DB schema digest.");
  }
  const git = async (directory: string, ...args: string[]) => {
    const result = await runGit(["-C", directory, ...args]);
    if (result.code !== 0) {
      throw new Error("Unable to prepare the approved DB release checkout.");
    }
    return result.stdout.trim();
  };
  const origin = await git(repo, "remote", "get-url", "origin");
  if (
    !/^https:\/\/github\.com\/manaoscloud\/mnscloud-db(?:\.git)?\/?$/.test(
      origin,
    )
  ) {
    throw new Error("DB checkout origin is not the canonical repository.");
  }
  // No force: a moved tag must fail instead of silently changing approved source.
  await git(
    repo,
    "fetch",
    "--no-tags",
    "origin",
    `refs/tags/${releaseTag}:refs/tags/${releaseTag}`,
  );
  const commit = await git(
    repo,
    "rev-parse",
    "--verify",
    `refs/tags/${releaseTag}^{commit}`,
  );
  if (!/^[a-f0-9]{40,64}$/.test(commit)) {
    throw new Error("Invalid DB release commit.");
  }
  const directory =
    `${repo}-releases/${releaseTag}-${expectedSha256.toLowerCase()}`;
  let exists = false;
  try {
    await Deno.lstat(directory);
    exists = true;
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  if (!exists) {
    await Deno.mkdir(`${repo}-releases`, { recursive: true, mode: 0o700 });
    await git(repo, "worktree", "add", "--detach", directory, commit);
  }
  if (
    (await git(directory, "rev-parse", "HEAD")) !== commit ||
    (await git(
        directory,
        "status",
        "--porcelain",
        "--untracked-files=normal",
      )) !== ""
  ) {
    throw new Error("DB release checkout changed; refusing schema execution.");
  }
  const bytes = await Deno.readFile(`${directory}/sql/clouddb-schema.sql`);
  const digest = Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
  )
    .map((value) => value.toString(16).padStart(2, "0")).join("");
  if (digest !== expectedSha256.toLowerCase()) {
    throw new Error("DB release schema digest mismatch.");
  }
  return directory;
}
