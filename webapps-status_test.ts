import { collectWebappsStatus, parseWebappsStatus } from "./webapps-status.ts";

function assertEquals(actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

Deno.test("parseWebappsStatus keeps valid apps and normalizes fields", () => {
  const apps = parseWebappsStatus(JSON.stringify([
    {
      app: "customer-portal",
      basePath: "/customer-portal/",
      source: "release",
      ref: "latest",
      installedVersion: "v0.1.5",
      resolvedRef: "v0.1.5",
      lastSyncStatus: "ok",
      lastSyncAt: "2026-10-14T13:00:00Z",
      lastError: "ignored when ok",
    },
    {
      app: "pulse",
      basePath: "/pulse/",
      source: "release",
      ref: "v1.0.2",
      installedVersion: "",
      resolvedRef: "",
      lastSyncStatus: "failed",
      lastSyncAt: "bad",
      lastError: "cannot resolve the latest release",
    },
    { app: "../etc", basePath: "/x/" },
    "not-an-object",
  ]));
  assertEquals(apps.length, 2);
  assertEquals(apps[0].installedVersion, "v0.1.5");
  assertEquals(apps[0].lastError, null);
  assertEquals(apps[1].installedVersion, null);
  assertEquals(apps[1].lastSyncAt, null);
  assertEquals(apps[1].lastError, "cannot resolve the latest release");
});

Deno.test("parseWebappsStatus rejects non-array or invalid JSON", () => {
  assertEquals(parseWebappsStatus("{}"), []);
  assertEquals(parseWebappsStatus("not json"), []);
});

Deno.test("collectWebappsStatus is null without the webapps runtime", async () => {
  assertEquals(
    await collectWebappsStatus({
      exists: () => Promise.resolve(false),
      run: () => Promise.resolve("[]"),
    }),
    null,
  );
  assertEquals(
    await collectWebappsStatus({
      exists: () => Promise.resolve(true),
      run: () => Promise.resolve(null),
    }),
    null,
  );
  assertEquals(
    await collectWebappsStatus({
      exists: () => Promise.resolve(true),
      run: () => Promise.resolve("[]"),
    }),
    [],
  );
});
