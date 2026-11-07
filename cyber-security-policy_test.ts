import {
  assert,
  assertEquals,
  assertStringIncludes,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  blocklistCommands,
  blocklistDuration,
  CROWDSEC_LIST_REASON,
  CROWDSEC_REPOSITORY_KEY_FINGERPRINTS,
  crowdSecLevelPolicy,
  crowdSecLevelSelection,
  crowdSecRepositorySetupScript,
  crowdSecWhitelistContent,
  hostNetwork,
  managedListDecisions,
  retryCrowdSecCommand,
} from "./cyber-security-policy.ts";

Deno.test("levels have distinct effects", () => {
  assertEquals(crowdSecLevelPolicy("basic"), { osOnly: true, strictScenarios: false });
  assertEquals(crowdSecLevelPolicy("balanced"), { osOnly: false, strictScenarios: false });
  assertEquals(crowdSecLevelPolicy("strict"), { osOnly: false, strictScenarios: true });
  assertEquals(crowdSecLevelPolicy("custom"), { osOnly: false, strictScenarios: false });
  const services = [{ slug: "ssh" }, { slug: "nginx" }, { slug: "asterisk" }];
  const basic = crowdSecLevelSelection("basic", services, ["crowdsecurity/nginx"]);
  assertEquals(basic.services, [{ slug: "ssh" }]);
  assertEquals(basic.collections, ["crowdsecurity/linux", "crowdsecurity/sshd"]);
  const balanced = crowdSecLevelSelection("balanced", services, ["crowdsecurity/nginx"]);
  assertEquals(balanced.services.length, 3);
  assertEquals(balanced.collections, ["crowdsecurity/nginx"]);
});

Deno.test("hostNetwork accepts addresses and CIDRs and refuses anything else", () => {
  assertEquals(hostNetwork("203.0.113.7"), { value: "203.0.113.7", cidr: false });
  assertEquals(hostNetwork("198.51.100.0/24"), { value: "198.51.100.0/24", cidr: true });
  assertEquals(hostNetwork("2001:DB8::/32"), { value: "2001:db8::/32", cidr: true });
  for (const bad of ["300.1.1.1", "10.0.0.0/40", "a.b.c.d", "1.2.3.4 --all", "x\nname: y", 7]) {
    assertEquals(hostNetwork(bad), null, String(bad));
  }
});

Deno.test("whitelist parser lists ips and cidrs, empty lists remove the file", () => {
  assertEquals(crowdSecWhitelistContent([], []), null);
  assertEquals(crowdSecWhitelistContent(["bad value"], []), null);
  const content = crowdSecWhitelistContent(
    ["198.51.100.10", "198.51.100.0/24", "198.51.100.10"],
    ["10.20.0.0/16", "x; rm -rf /"],
  )!;
  assertStringIncludes(content, "name: mnscloud/whitelist");
  assertStringIncludes(content, '  ip:\n    - "198.51.100.10"\n');
  assertStringIncludes(content, '  cidr:\n    - "198.51.100.0/24"\n    - "10.20.0.0/16"\n');
  assert(!content.includes("rm -rf"));
});

Deno.test("managed decisions are only the Agent's own list decisions", () => {
  const alerts = [
    {
      decisions: [
        { id: 10, origin: "cscli", scenario: CROWDSEC_LIST_REASON, value: "203.0.113.50" },
        { id: 11, origin: "crowdsec", scenario: "crowdsecurity/ssh-bf", value: "203.0.113.60" },
        { id: 12, origin: "cscli", scenario: "manual ban", value: "203.0.113.61" },
      ],
    },
    {
      decisions: [{
        id: 13,
        origin: "cscli",
        scenario: CROWDSEC_LIST_REASON,
        value: "198.51.100.0/24",
      }],
    },
  ];
  assertEquals(managedListDecisions(alerts), [
    { id: 10, value: "203.0.113.50" },
    { id: 13, value: "198.51.100.0/24" },
  ]);
});

Deno.test("blocklist convergence adds desired entries and deletes stale managed ones", () => {
  const now = new Date("2026-11-06T12:00:00Z");
  const plan = blocklistCommands(
    [
      { value: "203.0.113.50" },
      { value: "198.51.100.0/24", expiresAt: "2026-11-07T12:00:00" },
      { value: "203.0.113.99", expiresAt: "2026-11-01T00:00:00" },
      { value: "not-an-ip" },
    ],
    [{ id: 10, value: "203.0.113.50" }, { id: 14, value: "192.0.2.1" }],
    now,
  );
  assertEquals(plan.applied, ["203.0.113.50", "198.51.100.0/24"]);
  assertEquals(plan.removed, ["192.0.2.1"]);
  assertEquals(plan.adds, [
    [
      "decisions",
      "add",
      "--ip",
      "203.0.113.50",
      "--duration",
      "8760h",
      "--type",
      "ban",
      "--reason",
      CROWDSEC_LIST_REASON,
    ],
    [
      "decisions",
      "add",
      "--range",
      "198.51.100.0/24",
      "--duration",
      "24h",
      "--type",
      "ban",
      "--reason",
      CROWDSEC_LIST_REASON,
    ],
  ]);
  assertEquals(plan.deletes, [
    ["decisions", "delete", "--id", "14"],
    ["decisions", "delete", "--id", "10"],
  ]);
  assertEquals(blocklistDuration("2026-11-06T12:30:00", now), "1h");
  assertEquals(blocklistDuration(null, now), "8760h");
});

Deno.test("repository setup pins key fingerprints and never pipes a remote script", () => {
  for (const family of ["debian", "rhel"] as const) {
    const script = crowdSecRepositorySetupScript(family);
    assert(!/\|\s*(sh|bash)\b/.test(script), `${family}: remote script piped to a shell`);
    assert(!/install\.crowdsec\.net/.test(script), family);
    for (const fingerprint of CROWDSEC_REPOSITORY_KEY_FINGERPRINTS) {
      assertStringIncludes(script, fingerprint);
    }
    assertStringIncludes(script, "--proto '=https'");
  }
  assertStringIncludes(
    crowdSecRepositorySetupScript("debian"),
    "signed-by=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg",
  );
  const rhel = crowdSecRepositorySetupScript("rhel");
  assertStringIncludes(rhel, "repo_gpgcheck=1");
  assertStringIncludes(rhel, "gpgcheck=1");
  assertStringIncludes(rhel, "gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-crowdsec-repository");
});

Deno.test("cscli calls are retried while the local API restarts after a reload", async () => {
  const waits: number[] = [];
  const codes = [1, 1, 0];
  let calls = 0;
  const ok = await retryCrowdSecCommand(
    () => Promise.resolve({ code: codes[calls++] }),
    [10, 20, 30, 40],
    (ms) => {
      waits.push(ms);
      return Promise.resolve();
    },
  );
  assertEquals(ok.code, 0);
  assertEquals(calls, 3);
  assertEquals(waits, [10, 20]);

  calls = 0;
  const failed = await retryCrowdSecCommand(
    () => Promise.resolve({ code: (calls++, 1) }),
    [1, 1],
    () => Promise.resolve(),
  );
  assertEquals(failed.code, 1);
  assertEquals(calls, 3);
});
