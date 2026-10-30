import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  DEFAULT_NGINX_EDGE_WEBAPPS_PATHS,
  edgeSecurityHeaders,
  nginxEdgeWebapps,
} from "./nginx-webapps.ts";

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
    "/pos/",
    "/extra/",
  ]);
  assertEquals(nginxEdgeWebapps(legacyIni, {}).nginxEdgeWebappsEnabled, false);
});

Deno.test("the POS path is published once even when listed twice", () => {
  const settings = nginxEdgeWebapps(legacyIni, {
    MNSCLOUD_ENABLE_WEBAPPS_PROXY: "true",
    MNSCLOUD_CUSTOMER_PORTAL_PATH: "/customer-portal/",
    MNSCLOUD_POS_PATH: "/pos/",
    MNSCLOUD_WEBAPPS_PATHS: "/pos/",
  });
  assertEquals(settings.nginxEdgeWebappsPaths, ["/customer-portal/", "/pos/"]);
});

Deno.test("edge headers: App and softphone may use the microphone, only the softphone is framable", () => {
  const app = edgeSecurityHeaders("app", "");
  const softphone = edgeSecurityHeaders("softphone", "");
  const webapp = edgeSecurityHeaders("webapp", "");
  assertEquals(app.includes("frame-ancestors 'none'"), true);
  assertEquals(app.includes("microphone=(self)"), true);
  assertEquals(softphone.includes("frame-ancestors 'self'"), true);
  assertEquals(softphone.includes("microphone=(self)"), true);
  assertEquals(webapp.includes("frame-ancestors 'none'"), true);
  assertEquals(webapp.includes("microphone=()"), true);
  // POS web reads barcodes with the camera of its own origin; nothing else gets the camera.
  const scanner = edgeSecurityHeaders("scanner", "");
  assertEquals(scanner.includes("camera=(self)"), true);
  assertEquals(scanner.includes("microphone=()"), true);
  assertEquals(scanner.includes("frame-ancestors 'none'"), true);
  for (const other of [app, softphone, webapp]) assertEquals(other.includes("camera=()"), true);
  // Pulse records the punch position with the geolocation of its own origin; nobody else gets it.
  const timeclock = edgeSecurityHeaders("timeclock", "");
  assertEquals(timeclock.includes("geolocation=(self)"), true);
  assertEquals(timeclock.includes("camera=()"), true);
  assertEquals(timeclock.includes("microphone=()"), true);
  assertEquals(timeclock.includes("frame-ancestors 'none'"), true);
  for (const other of [app, softphone, webapp, scanner]) {
    assertEquals(other.includes("geolocation=()"), true);
  }
  // InfraGIS records the asset position and photographs assets: geolocation and camera.
  const field = edgeSecurityHeaders("field", "");
  assertEquals(field.includes("geolocation=(self)"), true);
  assertEquals(field.includes("camera=(self)"), true);
  assertEquals(field.includes("microphone=()"), true);
  assertEquals(field.includes("frame-ancestors 'none'"), true);
  assertEquals(app.split("\n").length, 4);
  // Tutorial videos: only the App frames youtube-nocookie.com.
  assertEquals(app.includes("frame-src 'self' https://www.youtube-nocookie.com;"), true);
  assertEquals(softphone.includes("frame-src"), false);
  assertEquals(webapp.includes("frame-src"), false);
});

Deno.test("the softphone path comes from MNSCLOUD_PHONEWEB_PATH, defaulting to /phoneweb/", () => {
  const custom = nginxEdgeWebapps(legacyIni, {
    MNSCLOUD_ENABLE_WEBAPPS_PROXY: "true",
    MNSCLOUD_PHONEWEB_PATH: "phone",
  });
  assertEquals(custom.nginxEdgeSoftphonePaths, ["/phone/"]);
  assertEquals(nginxEdgeWebapps(legacyIni, {}).nginxEdgeSoftphonePaths, ["/phoneweb/"]);
  assertEquals(nginxEdgeWebapps(legacyIni, {}).nginxEdgeScannerPaths, ["/pos/"]);
  assertEquals(nginxEdgeWebapps(legacyIni, {}).nginxEdgeTimeclockPaths, ["/pulse/"]);
  assertEquals(nginxEdgeWebapps(legacyIni, {}).nginxEdgeFieldPaths, ["/infragis/"]);
  assertEquals(
    nginxEdgeWebapps(legacyIni, {
      MNSCLOUD_ENABLE_WEBAPPS_PROXY: "true",
      MNSCLOUD_PULSE_PATH: "ponto",
    }).nginxEdgeTimeclockPaths,
    ["/ponto/"],
  );
  assertEquals(
    nginxEdgeWebapps(legacyIni, {
      MNSCLOUD_ENABLE_WEBAPPS_PROXY: "true",
      MNSCLOUD_POS_PATH: "caixa",
    })
      .nginxEdgeScannerPaths,
    ["/caixa/"],
  );
});
