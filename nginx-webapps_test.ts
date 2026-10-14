import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import { DEFAULT_NGINX_EDGE_WEBAPPS_PATHS, nginxEdgeWebapps } from "./nginx-webapps.ts";

const legacyIni = {
  enabled: "false",
  upstream: "$webapps_upstream",
  paths: DEFAULT_NGINX_EDGE_WEBAPPS_PATHS,
};

Deno.test("an edge env with the proxy flag is authoritative for ThemeDomain paths", () => {
  const settings = nginxEdgeWebapps(legacyIni, {
    MNSCLOUD_ENABLE_WEBAPPS_PROXY: "true",
    MNSCLOUD_WEBAPPS_UPSTREAM: "http://webapps.internal:8080",
    MNSCLOUD_PHONEWEB_PATH: "/phoneweb/",
    MNSCLOUD_PULSE_PATH: "/pulse/",
  });
  assertEquals(settings.nginxEdgeWebappsEnabled, true);
  assertEquals(settings.nginxEdgeWebappsUpstream, "http://webapps.internal:8080");
  assertEquals(settings.nginxEdgeWebappsPaths, ["/phoneweb/", "/pulse/"]);
  const disabled = nginxEdgeWebapps(legacyIni, { MNSCLOUD_ENABLE_WEBAPPS_PROXY: "false" });
  assertEquals(disabled.nginxEdgeWebappsEnabled, false);
});

Deno.test("hosts without the proxy flag keep the legacy ini and env merge", () => {
  const settings = nginxEdgeWebapps({ ...legacyIni, enabled: "true" }, {
    MNSCLOUD_WEBAPPS_PATHS: "/extra/",
  });
  assertEquals(settings.nginxEdgeWebappsEnabled, true);
  assertEquals(settings.nginxEdgeWebappsPaths, [
    "/phoneweb/",
    "/pulse/",
    "/customer-portal/",
    "/extra/",
  ]);
  assertEquals(nginxEdgeWebapps(legacyIni, {}).nginxEdgeWebappsEnabled, false);
});
