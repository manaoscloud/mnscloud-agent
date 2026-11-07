import {
  assert,
  assertEquals,
  assertMatch,
  assertRejects,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  buildPayload,
  canonicalInventory,
  cleanText,
  collectionDue,
  type DueInput,
  encodePowerShell,
  FIRST_DELAY_MS,
  FULL_INTERVAL_MS,
  httpStatusOf,
  inventoryCachePath,
  type InventoryCore,
  inventoryHash,
  type InventoryPayload,
  LIMITS,
  PACKAGE_MIN_SPACING_MS,
  PACKAGE_SETTLE_MS,
  parseApk,
  parseCpuStatUsec,
  parseDpkg,
  parseOsRelease,
  parseRpm,
  parseSs,
  parseWindowsInventory,
  SecurityInventory,
  UPLOAD_MIN_SPACING_MS,
  WINDOWS_INVENTORY_SCRIPT,
  wrapCommand,
} from "./security-inventory.ts";

const LINUX_OS = {
  family: "linux" as const,
  id: "debian",
  versionId: "12",
  codename: "bookworm",
  name: "Debian GNU/Linux 12 (bookworm)",
  kernel: "6.1.0-26-amd64",
  arch: "x86_64",
  build: null,
  ubr: null,
  displayVersion: null,
};

function core(overrides: Partial<InventoryCore> = {}): InventoryCore {
  return {
    os: LINUX_OS,
    packageManager: "dpkg",
    packages: [
      { name: "openssl", version: "3.0.15-1~deb12u1", arch: "amd64", source: "openssl" },
      { name: "bash", version: "5.2.15-2+b7", arch: "amd64", source: "bash" },
    ],
    hotfixes: [],
    ports: [
      { protocol: "udp", address: "127.0.0.53", port: 53, process: "systemd-resolve" },
      { protocol: "tcp", address: "0.0.0.0", port: 22, process: "sshd" },
    ],
    rebootRequired: false,
    ...overrides,
  };
}

Deno.test("os-release parsing reads quoted values and the codename", () => {
  const debian = parseOsRelease(`PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
`);
  assertEquals(debian, {
    id: "debian",
    versionId: "12",
    codename: "bookworm",
    name: "Debian GNU/Linux 12 (bookworm)",
  });
  const rocky = parseOsRelease(`NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
VERSION_ID="9.4"
PRETTY_NAME="Rocky Linux 9.4 (Blue Onyx)"
`);
  assertEquals(rocky.id, "rocky");
  assertEquals(rocky.versionId, "9.4");
  assertEquals(rocky.codename, null);
  const ubuntu = parseOsRelease('ID=ubuntu\nVERSION_ID="24.04"\nUBUNTU_CODENAME=noble\n');
  assertEquals(ubuntu.codename, "noble");
});

Deno.test("dpkg-query output keeps only installed packages", () => {
  const packages = parseDpkg([
    "ii \topenssl\t3.0.15-1~deb12u1\tamd64\topenssl",
    "rc \told-config\t1.0\tamd64\told-config",
    "ii \tlibc6\t2.36-9+deb12u8\tamd64\tglibc",
    "iU \thalf\t1.0\tall\thalf",
    "ii \tbroken",
  ].join("\n"));
  assertEquals(packages, [
    { name: "openssl", version: "3.0.15-1~deb12u1", arch: "amd64", source: "openssl" },
    { name: "libc6", version: "2.36-9+deb12u8", arch: "amd64", source: "glibc" },
  ]);
});

Deno.test("rpm output keeps the epoch form and drops gpg-pubkey", () => {
  const packages = parseRpm([
    "openssl-libs\t1:3.0.7-27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm",
    "gpg-pubkey\t0:fd431d51-4ae0493b\t(none)\t(none)",
    "bash\t0:5.1.8-9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm",
    "tzdata\t0:2024a-1.el9\tnoarch\t(none)",
  ].join("\n"));
  assertEquals(packages, [
    {
      name: "openssl-libs",
      version: "1:3.0.7-27.el9",
      arch: "x86_64",
      source: "openssl-3.0.7-27.el9.src.rpm",
    },
    { name: "bash", version: "0:5.1.8-9.el9", arch: "x86_64", source: "bash-5.1.8-9.el9.src.rpm" },
    { name: "tzdata", version: "0:2024a-1.el9", arch: "noarch", source: null },
  ]);
});

Deno.test("apk installed database records", () => {
  const packages = parseApk(`C:Q1abc=
P:musl
V:1.2.5-r0
A:x86_64
S:400000
o:musl
t:1700000000

C:Q1def=
P:busybox
V:1.36.1-r29
A:x86_64
o:busybox
F:bin
R:busybox

P:incomplete
`);
  assertEquals(packages, [
    { name: "musl", version: "1.2.5-r0", arch: "x86_64", source: "musl" },
    { name: "busybox", version: "1.36.1-r29", arch: "x86_64", source: "busybox" },
  ]);
});

Deno.test("ss listening sockets with addresses, scopes and process names", () => {
  const ports = parseSs([
    'udp   UNCONN 0      0       127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=601,fd=13))',
    'tcp   LISTEN 0      4096          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=812,fd=3),("sshd",pid=900,fd=3))',
    "tcp   LISTEN 0      4096             [::]:22            [::]:*",
    'tcp   LISTEN 0      511                 *:443              *:*    users:(("nginx",pid=1,fd=6))',
    "tcp   LISTEN 0      128   [fe80::1%eth0]:8080            [::]:*",
    "u_str LISTEN 0 4096 /run/x 123 * 0",
    "garbage",
  ].join("\n"));
  assertEquals(ports, [
    { protocol: "udp", address: "127.0.0.53", port: 53, process: "systemd-resolve" },
    { protocol: "tcp", address: "0.0.0.0", port: 22, process: "sshd" },
    { protocol: "tcp", address: "::", port: 22, process: null },
    { protocol: "tcp", address: "*", port: 443, process: "nginx" },
    { protocol: "tcp", address: "fe80::1", port: 8080, process: null },
  ]);
});

Deno.test("Windows collector JSON maps programs, KBs, ports and the server product", () => {
  const server = parseWindowsInventory(JSON.stringify({
    os: {
      productName: "Windows Server 2022 Standard",
      displayVersion: "21H2",
      releaseId: "2009",
      currentBuild: "20348",
      ubr: "2700",
      installationType: "Server",
      arch: "AMD64",
    },
    programs: [
      { name: "7-Zip 23.01 (x64)", version: "23.01", publisher: "Igor Pavlov", arch: "x64" },
      { name: "No version", version: "", publisher: "X", arch: "x86" },
    ],
    hotfixes: ["KB5044284", "kb5012170", "File 1", ""],
    ports: [
      { protocol: "tcp", address: "0.0.0.0", port: 3389, process: "svchost" },
      { protocol: "udp", address: "::", port: 500, process: null },
      { protocol: "icmp", address: "::", port: 1, process: null },
    ],
    rebootRequired: true,
  }));
  assertEquals(server.os, {
    family: "windows",
    id: "windows-server",
    versionId: "20348",
    codename: null,
    name: "Windows Server 2022 Standard",
    kernel: "10.0.20348.2700",
    arch: "x86_64",
    build: "20348",
    ubr: "2700",
    displayVersion: "21H2",
  });
  assertEquals(server.packageManager, "windows");
  assertEquals(server.packages, [
    { name: "7-Zip 23.01 (x64)", version: "23.01", arch: "x64", source: "Igor Pavlov" },
  ]);
  assertEquals(server.hotfixes, ["KB5044284", "KB5012170"]);
  assertEquals(server.ports.length, 2);
  assertEquals(server.rebootRequired, true);

  // PowerShell 5.1 collapses single-element arrays; Windows 11 still says "Windows 10".
  const client = parseWindowsInventory(
    "\uFEFF" + JSON.stringify({
      os: { productName: "Windows 10 Pro", currentBuild: "22631", installationType: "Client" },
      programs: { name: "Git", version: "2.45.1", publisher: "The Git Development Community" },
      hotfixes: "KB5031455",
      ports: null,
    }),
  );
  assertEquals(client.os.id, "windows");
  assertEquals(client.os.name, "Windows 11 Pro");
  assertEquals(client.packages.length, 1);
  assertEquals(client.hotfixes, ["KB5031455"]);
  assertEquals(client.ports, []);
  assertEquals(client.rebootRequired, null);
});

Deno.test("Windows script is fixed, idle priority and encoded without quoting", () => {
  assert(WINDOWS_INVENTORY_SCRIPT.includes("PriorityClass = 'Idle'"));
  assert(!WINDOWS_INVENTORY_SCRIPT.includes('"'));
  const encoded = encodePowerShell("Get-Date");
  // UTF-16LE base64 of "Get-Date".
  assertEquals(encoded, "RwBlAHQALQBEAGEAdABlAA==");
});

Deno.test("text cleanup strips control characters and enforces limits", () => {
  assertEquals(cleanText("  a\u0000b\tc\n ", 10), "abc");
  assertEquals(cleanText("", 10), null);
  assertEquals(cleanText(42, 10), "42");
  assertEquals(cleanText("x".repeat(20), 5), "xxxxx");
  // A version that does not fit is dropped rather than cut.
  assertEquals(parseDpkg(`ii \tpkg\t${"1".repeat(LIMITS.version + 1)}\tall\tpkg`), []);
});

Deno.test("canonical hash is stable for any input order and ignores collectedAt/footprint", async () => {
  const a = canonicalInventory(core());
  const reversed = core();
  reversed.packages = [...reversed.packages].reverse();
  reversed.ports = [...reversed.ports].reverse();
  reversed.packages.push({ ...reversed.packages[0] });
  const b = canonicalInventory(reversed);
  assertEquals(a.core, b.core);
  const hash = await inventoryHash(a.core);
  assertEquals(hash, await inventoryHash(b.core));
  assertMatch(hash, /^[0-9a-f]{64}$/);
  assertEquals(a.core.packages.map((item) => item.name), ["bash", "openssl"]);
  assertEquals(a.core.ports.map((item) => item.port), [22, 53]);

  // Pinned: the API stores this hash as given, so the canonical form must not drift.
  const expected = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(JSON.stringify({
      os: LINUX_OS,
      packageManager: "dpkg",
      packages: [
        { name: "bash", version: "5.2.15-2+b7", arch: "amd64", source: "bash" },
        { name: "openssl", version: "3.0.15-1~deb12u1", arch: "amd64", source: "openssl" },
      ],
      hotfixes: [],
      ports: [
        { protocol: "tcp", address: "0.0.0.0", port: 22, process: "sshd" },
        { protocol: "udp", address: "127.0.0.53", port: 53, process: "systemd-resolve" },
      ],
      rebootRequired: false,
    })),
  );
  assertEquals(
    hash,
    [...new Uint8Array(expected)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
  );

  const first = await buildPayload(core(), "2026-11-07T12:00:00.000Z", {
    durationMs: 1,
    cpuMs: null,
    memoryPeakBytes: null,
  });
  const second = await buildPayload(reversed, "2026-11-08T12:00:00.000Z", {
    durationMs: 999,
    cpuMs: 5,
    memoryPeakBytes: 1,
  });
  assertEquals(first.hash, second.hash);
  assertEquals(first.hash, hash);
  assertEquals(first.truncated, false);
  assert(first.footprint.payloadBytes > 100);
  assertEquals(
    Object.keys(first),
    [
      "hash",
      "collectedAt",
      "os",
      "packageManager",
      "packages",
      "hotfixes",
      "ports",
      "rebootRequired",
      "truncated",
      "footprint",
    ],
  );

  const changed = await inventoryHash(canonicalInventory(core({ rebootRequired: true })).core);
  assert(changed !== hash);
});

Deno.test("lists over the limit keep the first N sorted entries and mark truncated", () => {
  const packages = Array.from({ length: LIMITS.packages + 5 }, (_, index) => ({
    name: `pkg-${String(index).padStart(6, "0")}`,
    version: "1.0",
    arch: "amd64",
    source: null,
  })).reverse();
  const result = canonicalInventory(core({ packages }));
  assertEquals(result.truncated, true);
  assertEquals(result.core.packages.length, LIMITS.packages);
  assertEquals(result.core.packages[0].name, "pkg-000000");
  assertEquals(
    result.core.packages.at(-1)?.name,
    `pkg-${String(LIMITS.packages - 1).padStart(6, "0")}`,
  );
});

Deno.test("payloads over the API body limit are abandoned", async () => {
  const packages = Array.from({ length: 19000 }, (_, index) => ({
    name: `package-${index}-${"n".repeat(180)}`,
    version: "1.0",
    arch: "amd64",
    source: "s".repeat(60),
  }));
  await assertRejects(
    () =>
      buildPayload(core({ packages }), new Date().toISOString(), {
        durationMs: 0,
        cpuMs: null,
        memoryPeakBytes: null,
      }),
    Error,
    "too large",
  );
});

Deno.test("collector commands run in the security slice, else nice/ionice, else plain", () => {
  const all = {
    systemdRun: "/usr/bin/systemd-run",
    slice: true,
    nice: "/usr/bin/nice",
    ionice: "/usr/bin/ionice",
  };
  assertEquals(wrapCommand("/usr/bin/dpkg-query", ["-W"], all), [
    "/usr/bin/systemd-run",
    [
      "--quiet",
      "--collect",
      "--scope",
      "--slice=mnscloud-security.slice",
      "--nice=19",
      "-p",
      "IOWeight=10",
      "--",
      "/usr/bin/ionice",
      "-c3",
      "/usr/bin/dpkg-query",
      "-W",
    ],
  ]);
  assertEquals(wrapCommand("ss", ["-H"], { ...all, slice: false }), [
    "/usr/bin/nice",
    ["-n", "19", "/usr/bin/ionice", "-c3", "ss", "-H"],
  ]);
  assertEquals(wrapCommand("ss", ["-H"], { ...all, systemdRun: null, nice: null }), [
    "/usr/bin/ionice",
    ["-c3", "ss", "-H"],
  ]);
  assertEquals(
    wrapCommand("ss", ["-H"], { systemdRun: null, slice: false, nice: null, ionice: null }),
    ["ss", ["-H"]],
  );
});

Deno.test("slice CPU accounting parser", () => {
  assertEquals(parseCpuStatUsec("usage_usec 410123\nuser_usec 1\nsystem_usec 2\n"), 410123);
  assertEquals(parseCpuStatUsec(null), null);
  assertEquals(parseCpuStatUsec("nothing"), null);
});

Deno.test("HTTP status and cache path helpers", () => {
  assertEquals(httpStatusOf(new Error("/agent/inventory returned HTTP 429: too often")), 429);
  assertEquals(httpStatusOf(new Error("network down")), null);
  assertEquals(
    inventoryCachePath("/var/lib/mnscloud/agent/agent.token"),
    "/var/lib/mnscloud/agent/security-inventory.json",
  );
  assertEquals(
    inventoryCachePath("C:\\ProgramData\\MNSCloud\\Agent\\agent.token"),
    "C:\\ProgramData\\MNSCloud\\Agent\\security-inventory.json",
  );
});

function due(overrides: Partial<DueInput> = {}): DueInput {
  return {
    now: 1_000_000_000,
    enabled: true,
    enabledAt: 1_000_000_000,
    firstDelayMs: 0,
    nextDueAt: null,
    lastAttemptAt: 0,
    attemptStamp: null,
    currentStamp: null,
    ...overrides,
  };
}

Deno.test("scheduler: disabled never collects; the first collection waits its random delay", () => {
  assertEquals(collectionDue(due({ enabled: false })), null);
  assertEquals(collectionDue(due({ firstDelayMs: 5 * 60_000 })), null);
  assertEquals(
    collectionDue(due({ now: 1_000_000_000 + 5 * 60_000, firstDelayMs: 5 * 60_000 })),
    "first",
  );
});

Deno.test("scheduler: 24 h schedule and package database changes", () => {
  const now = 2_000_000_000;
  const base = due({
    now,
    nextDueAt: now + 1000,
    lastAttemptAt: now - FULL_INTERVAL_MS + 1000,
    attemptStamp: "dpkg:1",
    currentStamp: { stamp: "dpkg:1", mtimeMs: now - FULL_INTERVAL_MS },
  });
  assertEquals(collectionDue(base), null);
  assertEquals(collectionDue({ ...base, nextDueAt: now }), "schedule");
  // Changed and settled package database.
  assertEquals(
    collectionDue({ ...base, currentStamp: { stamp: "dpkg:2", mtimeMs: now - PACKAGE_SETTLE_MS } }),
    "packages",
  );
  // Still being written (apt running): wait until it settles.
  assertEquals(
    collectionDue({ ...base, currentStamp: { stamp: "dpkg:2", mtimeMs: now - 1000 } }),
    null,
  );
  // Too close to the last attempt: never a tight loop.
  assertEquals(
    collectionDue({
      ...base,
      lastAttemptAt: now - PACKAGE_MIN_SPACING_MS + 1,
      currentStamp: { stamp: "dpkg:2", mtimeMs: now - PACKAGE_SETTLE_MS },
    }),
    null,
  );
});

function fakePayload(hash: string, collectedAt = "2026-11-07T12:00:00.000Z"): InventoryPayload {
  return {
    hash,
    collectedAt,
    ...core(),
    truncated: false,
    footprint: { durationMs: 1, cpuMs: null, memoryPeakBytes: null, payloadBytes: 10 },
  };
}

function harness(start = 10_000_000_000) {
  const clock = { now: start };
  const logs: string[] = [];
  let collected = 0;
  let fail = false;
  let stamp: { stamp: string; mtimeMs: number } | null = { stamp: "s1", mtimeMs: 0 };
  const inventory = new SecurityInventory({
    collect: () => {
      collected++;
      if (fail) return Promise.reject(new Error("dpkg-query exited with 2."));
      return Promise.resolve(fakePayload(`${collected}`.padStart(64, "a")));
    },
    stamp: () => Promise.resolve(stamp),
    log: (_level, message) => logs.push(message),
    windows: false,
    now: () => clock.now,
    random: () => 0.5,
  });
  return {
    inventory,
    clock,
    logs,
    get collected() {
      return collected;
    },
    setFail(value: boolean) {
      fail = value;
    },
    setStamp(value: { stamp: string; mtimeMs: number } | null) {
      stamp = value;
    },
  };
}

Deno.test("inventory lifecycle: enable, collect, cache, upload on demand, disable deletes the cache", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const path = `${dir}/security-inventory.json`;
    const h = harness();
    await h.inventory.load(path);
    assertEquals(h.inventory.heartbeatField(), { supported: true, hash: null, collectedAt: null });

    // An API without V2 omits the field: disabled, nothing collected.
    await h.inventory.acknowledge(undefined, () => Promise.resolve());
    assertEquals(await h.inventory.tick(), null);

    await h.inventory.acknowledge({ enabled: true, needsFull: false }, () => Promise.resolve());
    assertEquals(await h.inventory.tick(), null, "first collection waits the random delay");
    h.clock.now += FIRST_DELAY_MS / 2;
    assertEquals(await h.inventory.tick(), "first");
    assertEquals(h.collected, 1);
    const field = h.inventory.heartbeatField();
    assertEquals(field.hash, "1".padStart(64, "a"));
    if (Deno.build.os !== "windows") {
      assertEquals((await Deno.stat(path)).mode! & 0o777, 0o600);
    }
    assertEquals(await h.inventory.tick(), null, "not due again right away");

    const sent: InventoryPayload[] = [];
    const send = (payload: InventoryPayload) => {
      sent.push(payload);
      return Promise.resolve();
    };
    await h.inventory.acknowledge({ enabled: true, needsFull: true }, send);
    assertEquals(sent.length, 1);
    assertEquals(sent[0].hash, field.hash);
    // A second request inside the API rate window is not sent.
    await h.inventory.acknowledge({ enabled: true, needsFull: true }, send);
    assertEquals(sent.length, 1);
    h.clock.now += UPLOAD_MIN_SPACING_MS;
    await h.inventory.acknowledge({ enabled: true, needsFull: true }, send);
    assertEquals(sent.length, 2);

    // Restart keeps the hash and does not force a collection.
    const restarted = harness(h.clock.now);
    await restarted.inventory.load(path);
    assertEquals(restarted.inventory.heartbeatField().hash, field.hash);
    await restarted.inventory.acknowledge({ enabled: true, needsFull: false }, send);
    restarted.clock.now += FIRST_DELAY_MS;
    assertEquals(await restarted.inventory.tick(), null);
    assertEquals(restarted.collected, 0);

    // 24 h (+ jitter) later it collects again.
    restarted.clock.now += FULL_INTERVAL_MS + 60 * 60_000;
    assertEquals(await restarted.inventory.tick(), "schedule");

    await restarted.inventory.acknowledge({ enabled: false, needsFull: false }, send);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assertEquals(restarted.inventory.heartbeatField().hash, null);
    await assertRejects(() => Deno.stat(path));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("inventory: package change triggers a collection; failures wait for the schedule", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const h = harness();
    await h.inventory.load(`${dir}/security-inventory.json`);
    await h.inventory.acknowledge({ enabled: true }, () => Promise.resolve());
    h.clock.now += FIRST_DELAY_MS;
    assertEquals(await h.inventory.tick(), "first");

    h.clock.now += PACKAGE_MIN_SPACING_MS;
    h.setStamp({ stamp: "s2", mtimeMs: h.clock.now - PACKAGE_SETTLE_MS });
    h.setFail(true);
    assertEquals(await h.inventory.tick(), "packages");
    assertEquals(h.collected, 2);
    assert(h.logs.some((message) => message.includes("abandoned")));
    // The failed attempt is not retried while nothing changes (no tight loop).
    for (let step = 0; step < 30; step++) {
      h.clock.now += 60_000;
      assertEquals(await h.inventory.tick(), null);
    }
    assertEquals(h.collected, 2);
    // The cached inventory of the last success is kept.
    assertEquals(h.inventory.heartbeatField().hash, "1".padStart(64, "a"));
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("inventory upload: 413 blocks the hash until the next collection; 429/409 are quiet", async () => {
  const dir = await Deno.makeTempDir();
  try {
    const h = harness();
    await h.inventory.load(`${dir}/security-inventory.json`);
    await h.inventory.acknowledge({ enabled: true }, () => Promise.resolve());
    h.clock.now += FIRST_DELAY_MS;
    await h.inventory.tick();

    let attempts = 0;
    const reject = (status: number) => () => {
      attempts++;
      return Promise.reject(new Error(`/agent/inventory returned HTTP ${status}`));
    };
    await h.inventory.acknowledge({ enabled: true, needsFull: true }, reject(429));
    const warnings = h.logs.length;
    h.clock.now += UPLOAD_MIN_SPACING_MS;
    await h.inventory.acknowledge({ enabled: true, needsFull: true }, reject(409));
    assertEquals(h.logs.length, warnings, "429/409 are not logged as failures");

    h.clock.now += UPLOAD_MIN_SPACING_MS;
    await h.inventory.acknowledge({ enabled: true, needsFull: true }, reject(413));
    assertEquals(attempts, 3);
    h.clock.now += UPLOAD_MIN_SPACING_MS;
    await h.inventory.acknowledge({ enabled: true, needsFull: true }, reject(413));
    assertEquals(attempts, 3, "the same hash is not sent again after 413");

    h.clock.now += FULL_INTERVAL_MS + 60 * 60_000;
    assertEquals(await h.inventory.tick(), "schedule");
    h.clock.now += UPLOAD_MIN_SPACING_MS;
    await h.inventory.acknowledge({ enabled: true, needsFull: true }, reject(413));
    assertEquals(attempts, 4, "a new collection may be sent again");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});
