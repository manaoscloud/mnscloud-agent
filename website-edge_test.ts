import {
  assert,
  assertEquals,
  assertRejects,
  assertStringIncludes,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  certbotWildcardArgs,
  needsWildcardRenewal,
  parseHookRequest,
  parseOpensslEndDate,
  publishWebsiteChallenge,
  renderWebsiteEdgeConfig,
  sha256Hex,
  websiteAcmeHookScript,
  websiteBase,
  websiteEdgeConfigFile,
  websiteSiteCommand,
  wildcardCertName,
} from "./website-edge.ts";

const render = (sslEnabled: boolean) =>
  renderWebsiteEdgeConfig({
    base: "Prod.MNSCloud.Website.",
    sslEnabled,
    acmeRoot: "/var/www/certbot",
    apiUpstream: "$api_upstream",
    webappsUpstream: "$webapps_upstream",
    certificateDir: "/etc/letsencrypt/live/wildcard.prod.mnscloud.website/",
    securityHeaders: '    add_header X-Content-Type-Options "nosniff" always;',
  });

Deno.test("website bases are normalized FQDNs; names derive from them", () => {
  assertEquals(websiteBase(" Prod.MNSCloud.Website. "), "prod.mnscloud.website");
  assertEquals(wildcardCertName("dev.mnscloud.website"), "wildcard.dev.mnscloud.website");
  assertEquals(
    websiteEdgeConfigFile("/etc/nginx/mnscloud/website/", "dev.mnscloud.website"),
    "/etc/nginx/mnscloud/website/dev.mnscloud.website.conf",
  );
  for (const bad of ["", "localhost", "*.x.com", "a..b", "x.com;include /etc", "../x.com"]) {
    assertThrows(() => websiteBase(bad));
  }
});

Deno.test("edge config serves *.<base>: HTTP only before the certificate, then redirect + 443 to webapps", () => {
  const http = render(false);
  assertStringIncludes(http, "server_name *.prod.mnscloud.website;");
  assertStringIncludes(http, "location ^~ /.well-known/acme-challenge/");
  assertStringIncludes(http, "proxy_pass $webapps_upstream;");
  assert(!http.includes("listen 443"), "no TLS server without a certificate");
  const https = render(true);
  assertStringIncludes(https, "return 301 https://$host$request_uri;");
  assertStringIncludes(https, "listen 443 ssl;");
  assertStringIncludes(
    https,
    "ssl_certificate /etc/letsencrypt/live/wildcard.prod.mnscloud.website/fullchain.pem;",
  );
  assertStringIncludes(https, "location /api/ {");
  assertStringIncludes(https, "proxy_pass $api_upstream;");
  assertStringIncludes(https, "proxy_set_header Host $host;");
  assertStringIncludes(https, "proxy_set_header X-Forwarded-Proto https;");
  assertEquals(
    https.match(/proxy_pass \$webapps_upstream;/g)?.length,
    1,
    "only 443 serves the sites",
  );
  assertStringIncludes(https, 'add_header X-Content-Type-Options "nosniff" always;');
});

Deno.test("certbot runs DNS-01 with the local hooks and never auto-renews the wildcard", () => {
  const args = certbotWildcardArgs({
    base: "dev.mnscloud.website",
    hook: "/var/lib/x/hook.sh",
    email: "ops@example.com",
  });
  const text = args.join(" ");
  for (
    const part of [
      "certonly --manual --preferred-challenges dns",
      "--cert-name wildcard.dev.mnscloud.website",
      "-d *.dev.mnscloud.website",
      "--no-autorenew",
      "--non-interactive",
      "--email ops@example.com",
    ]
  ) {
    assertStringIncludes(text, part);
  }
  assertEquals(args[args.indexOf("--manual-auth-hook") + 1], "/var/lib/x/hook.sh auth");
  assertEquals(args[args.indexOf("--manual-cleanup-hook") + 1], "/var/lib/x/hook.sh cleanup");
  assert(
    certbotWildcardArgs({ base: "dev.mnscloud.website", hook: "/h" }).includes(
      "--register-unsafely-without-email",
    ),
  );
  const hook = websiteAcmeHookScript();
  assertStringIncludes(hook, '"$dir/req.$id"');
  assertStringIncludes(hook, '"$dir/cleanup.$id"');
  assert(!/token|curl|api\//i.test(hook), "the hook never calls the API");
});

Deno.test("renewal: missing or within 30 days", () => {
  const now = new Date("2026-10-24T00:00:00Z");
  assertEquals(
    parseOpensslEndDate("notAfter=Jan 18 12:00:00 2027 GMT\n")?.toISOString(),
    "2027-01-18T12:00:00.000Z",
  );
  assertEquals(parseOpensslEndDate("garbage"), null);
  assert(needsWildcardRenewal(null, now));
  assert(needsWildcardRenewal(new Date("2026-11-20T00:00:00Z"), now));
  assert(!needsWildcardRenewal(new Date("2026-12-01T00:00:00Z"), now));
});

Deno.test("hook requests must be the wildcard of the base with a valid value", () => {
  const value = "A".repeat(43);
  assertEquals(parseHookRequest(`*.dev.mnscloud.website\n${value}\n`, "dev.mnscloud.website"), {
    name: "_acme-challenge.dev.mnscloud.website",
    value,
  });
  assertThrows(
    () => parseHookRequest(`*.evil.example.com\n${value}\n`, "dev.mnscloud.website"),
    Error,
    "is not",
  );
  assertThrows(
    () => parseHookRequest("*.dev.mnscloud.website\nbad value\n", "dev.mnscloud.website"),
    Error,
    "invalid",
  );
});

Deno.test("a challenge is released for certbot only once published and visible on every nameserver", async () => {
  let clock = 0;
  const states = ["pending", "pending", "published"];
  let visible = 0;
  const id = await publishWebsiteChallenge(
    {
      api: {
        create: () => Promise.resolve({ challengeUUID: "c1", state: "pending" }),
        get: () => Promise.resolve({ state: states.shift() ?? "published" }),
        release: () => Promise.resolve(),
      },
      txtVisible: () => Promise.resolve(++visible >= 2),
      sleep: (ms) => Promise.resolve(void (clock += ms)),
      now: () => clock,
    },
    "_acme-challenge.dev.mnscloud.website",
    "A".repeat(43),
  );
  assertEquals(id, "c1");
  assertEquals(visible, 2);
  await assertRejects(
    () =>
      publishWebsiteChallenge(
        {
          api: {
            create: () => Promise.resolve({ challengeUUID: "c2", state: "failed" }),
            get: () => Promise.resolve({ state: "failed" }),
            release: () => Promise.resolve(),
          },
          txtVisible: () => Promise.resolve(true),
          sleep: () => Promise.resolve(),
          now: () => 0,
        },
        "n",
        "v",
      ),
    Error,
    "failed by the platform DNS worker",
  );
  await assertRejects(
    () =>
      publishWebsiteChallenge(
        {
          api: {
            create: () => Promise.resolve({ challengeUUID: "c3", state: "published" }),
            get: () => Promise.resolve({ state: "published" }),
            release: () => Promise.resolve(),
          },
          txtVisible: () => Promise.resolve(false),
          sleep: (ms) => Promise.resolve(void (clock += ms)),
          now: () => clock,
        },
        "n",
        "v",
        20_000,
      ),
    Error,
    "not visible",
  );
});

Deno.test("site commands are validated before the webapps scripts run", () => {
  const site = "0123456789abcdef0123456789abcdef";
  assertEquals(websiteSiteCommand("remove", { site }), {
    script: "site-remove.sh",
    args: ["--site", site],
  });
  const install = websiteSiteCommand("install", {
    site: site.toUpperCase(),
    version: "v3",
    sha256: "A".repeat(64),
    artifactUrl: "https://example.com/s.tar.gz",
    hosts: ["X.dev.mnscloud.website", "www.shop.test"],
  });
  assertEquals(install.args, [
    "--site",
    site,
    "--version",
    "v3",
    "--sha256",
    "a".repeat(64),
    "--host",
    "x.dev.mnscloud.website",
    "--host",
    "www.shop.test",
  ]);
  assertEquals([install.artifactUrl, install.sha256], [
    "https://example.com/s.tar.gz",
    "a".repeat(64),
  ]);
  const valid = {
    site,
    version: "v1",
    sha256: "a".repeat(64),
    artifactUrl: "https://example.com/s.tar.gz",
    hosts: ["a.example.com"],
  };
  for (
    const [change, message] of [
      [{ site: "xyz" }, "32 hex"],
      [{ version: "../x" }, "version"],
      [{ sha256: "1234" }, "SHA-256"],
      [{ artifactUrl: "http://example.com/s.tar.gz" }, "https"],
      [{ artifactUrl: "https://u:p@example.com/s" }, "https"],
      [{ hosts: [] }, "hosts"],
      [{ hosts: ["evil.test; include /etc/passwd"] }, "hosts"],
    ] as const
  ) {
    assertThrows(() => websiteSiteCommand("install", { ...valid, ...change }), Error, message);
  }
  assertThrows(() => websiteSiteCommand("purge", valid), Error, "Unknown");
});

Deno.test("sha256Hex matches the reference digest", async () => {
  assertEquals(
    await sha256Hex(new TextEncoder().encode("abc")),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});
