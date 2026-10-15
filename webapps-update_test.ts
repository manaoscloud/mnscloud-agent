import { webappsUpdateScript } from "./webapps-update.ts";

function assertEquals(actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertThrows(fn: () => unknown, message: string) {
  try {
    fn();
  } catch (error) {
    if (String(error).includes(message)) return;
    throw new Error(`expected "${message}", got ${error}`);
  }
  throw new Error(`expected "${message}" to be thrown`);
}

const SHA = "a".repeat(64);

Deno.test("webappsUpdateScript keeps full and single-app updates unchanged", () => {
  assertEquals(
    webappsUpdateScript({}),
    "bash scripts/update-webapps.sh '--env' '/etc/mnscloud/webapps/webapps.env'",
  );
  assertEquals(
    webappsUpdateScript({ app: "pulse", appRef: "latest" }),
    "bash scripts/update-webapps.sh '--env' '/etc/mnscloud/webapps/webapps.env' '--app' 'pulse' '--app-ref' 'latest'",
  );
});

Deno.test("webappsUpdateScript pins the catalog digest behind a runtime support guard", () => {
  const script = webappsUpdateScript({
    app: "customer-portal",
    appRef: "v0.1.10",
    appArtifactSha256: SHA.toUpperCase(),
  });
  if (!script.startsWith("{ grep -q -- '--app-sha256' scripts/update-webapps.sh || ")) {
    throw new Error(`missing support guard: ${script}`);
  }
  if (!script.endsWith(`'--app-ref' 'v0.1.10' '--app-sha256' '${SHA}'`)) {
    throw new Error(`missing pinned digest: ${script}`);
  }
});

Deno.test("webappsUpdateScript rejects unsafe or incomplete pins", () => {
  assertThrows(() => webappsUpdateScript({ app: "Bad;app" }), "Invalid webapp name");
  assertThrows(() => webappsUpdateScript({ app: "pulse", appRef: "v1;rm" }), "Invalid webapp ref");
  assertThrows(
    () => webappsUpdateScript({ app: "pulse", appRef: "v1.0.3", appArtifactSha256: "abc" }),
    "Invalid webapp artifact SHA-256",
  );
  assertThrows(
    () => webappsUpdateScript({ app: "pulse", appRef: "latest", appArtifactSha256: SHA }),
    "requires an app and a release tag",
  );
  assertThrows(
    () => webappsUpdateScript({ appRef: "v1.0.3", appArtifactSha256: SHA }),
    "requires an app and a release tag",
  );
});
