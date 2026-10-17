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

const RELEASE_DIRECTORY = /^v\d+\.\d+\.\d+-[a-f0-9]{64}$/;
const BACKUP_DIRECTORY = /^schema-reconcile-[A-Za-z0-9_]{8,64}$/;
const DAY_MS = 86_400_000;

async function entriesByAge(parent: string, pattern: RegExp) {
  const entries: { path: string; mtime: number }[] = [];
  try {
    for await (const entry of Deno.readDir(parent)) {
      if (!entry.isDirectory || !pattern.test(entry.name)) continue;
      const path = `${parent}/${entry.name}`;
      const info = await Deno.lstat(path);
      entries.push({ path, mtime: info.mtime?.getTime() ?? 0 });
    }
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return [];
    throw error;
  }
  return entries.sort((a, b) => b.mtime - a.mtime);
}

/** Entries beyond the newest `keep` that are older than `minAgeDays`, never `current`. */
function expired(
  entries: { path: string; mtime: number }[],
  keep: number,
  minAgeDays: number,
  current: string,
  now: number,
) {
  return entries.slice(keep).filter((entry) =>
    entry.path !== current && now - entry.mtime > minAgeDays * DAY_MS
  ).map((entry) => entry.path);
}

/**
 * Bound the DB host disk: remove old approved release worktrees (through git, so the base checkout
 * forgets them) and old reconcile work directories (plans, results, pre-apply dumps). The newest
 * entries and anything recent stay, so a plan/apply pair and recent rollback dumps are untouched.
 */
export async function pruneSchemaArtifacts(
  repo: string,
  backupsDirectory: string,
  current: { releaseDirectory?: string; planDirectory?: string },
  runGit: SchemaGitRunner,
  options = { keepReleases: 5, keepBackups: 10, minAgeDays: 3, now: Date.now() },
): Promise<string[]> {
  const removed: string[] = [];
  const releases = expired(
    await entriesByAge(`${repo}-releases`, RELEASE_DIRECTORY),
    options.keepReleases,
    options.minAgeDays,
    current.releaseDirectory ?? "",
    options.now,
  );
  for (const directory of releases) {
    const result = await runGit(["-C", repo, "worktree", "remove", "--force", directory]);
    if (result.code !== 0) continue;
    removed.push(directory);
  }
  if (releases.length > 0) await runGit(["-C", repo, "worktree", "prune"]);
  const backups = expired(
    await entriesByAge(backupsDirectory, BACKUP_DIRECTORY),
    options.keepBackups,
    options.minAgeDays,
    current.planDirectory ?? "",
    options.now,
  );
  for (const directory of backups) {
    await Deno.remove(directory, { recursive: true });
    removed.push(directory);
  }
  return removed;
}
