import { assertEquals } from "https://deno.land/std@0.224.0/assert/mod.ts";

import {
  applySofiaUserAgents,
  parseSofiaRegistrationsXml,
  readSofiaRegistrations,
  sofiaProfiles,
} from "./pabx-freeswitch-user-agent.ts";

const xml = `<?xml version="1.0" encoding="ISO-8859-1"?>
<profile>
  <registrations>
    <registration>
        <call-id>abc</call-id>
        <user>1001@pbx.example.com</user>
        <contact>&quot;1001&quot; &lt;sip:1001@198.51.100.10:57310;rinstance=a3f&gt;</contact>
        <agent>Zoiper rv2.10.20.6</agent>
        <status>Registered(UDP)(unknown) exp(2026-11-18 14:30:00) expsecs(120)</status>
        <host>pbx-host</host>
        <network-ip>198.51.100.10</network-ip>
        <network-port>57310</network-port>
        <sip-auth-user>1001</sip-auth-user>
        <sip-auth-realm>PBX.example.com</sip-auth-realm>
    </registration>
    <registration>
        <user>1002@pbx.example.com</user>
        <agent>Yealink SIP-T46U 108.86.0.20 &amp; more</agent>
        <network-ip>203.0.113.7</network-ip>
    </registration>
    <registration>
        <user>1003@pbx.example.com</user>
        <agent></agent>
    </registration>
  </registrations>
</profile>`;

Deno.test("parses the Sofia registration XML and decodes entities", () => {
  assertEquals(parseSofiaRegistrationsXml(xml), [
    {
      username: "1001",
      realm: "pbx.example.com",
      userAgent: "Zoiper rv2.10.20.6",
      networkIP: "198.51.100.10",
    },
    {
      username: "1002",
      realm: "pbx.example.com",
      userAgent: "Yealink SIP-T46U 108.86.0.20 & more",
      networkIP: "203.0.113.7",
    },
  ]);
  assertEquals(parseSofiaRegistrationsXml("+OK no registrations"), []);
});

Deno.test("derives the Sofia profiles from registration URLs", () => {
  assertEquals(
    sofiaProfiles([
      { username: "1", contact: "sofia/internal/sip:1@198.51.100.10" },
      { username: "2", contact: "sofia/external/sip:2@198.51.100.11" },
      { username: "3", contact: "sofia/bad profile/sip:3@x" },
    ]),
    ["external", "internal"],
  );
  assertEquals(sofiaProfiles([{ username: "1", contact: null }]), ["internal"]);
});

Deno.test("fills the missing user agent, preferring the same network IP", () => {
  const sofia = [
    { username: "1001", realm: "pbx.example.com", userAgent: "Desk", networkIP: "10.0.0.1" },
    { username: "1001", realm: "pbx.example.com", userAgent: "Mobile", networkIP: "10.0.0.2" },
    { username: "1002", realm: "other.example.com", userAgent: "Other", networkIP: null },
  ];
  const result = applySofiaUserAgents([
    { username: "1001", domain: "PBX.example.com", networkIP: "10.0.0.2" },
    { username: "1001", domain: "pbx.example.com", networkIP: "10.9.9.9" },
    { username: "1001", domain: "pbx.example.com", userAgent: "Kept" },
    { username: "1002", domain: "pbx.example.com" },
  ], sofia);
  assertEquals(result.map((item) => item.userAgent ?? null), ["Mobile", "Desk", "Kept", null]);
});

Deno.test("reads every profile and skips failures", async () => {
  const calls: string[][] = [];
  const rows = await readSofiaRegistrations(["internal", "external", "bad;rm"], (args) => {
    calls.push(args);
    if (args[1].includes("external")) return Promise.reject(new Error("down"));
    return Promise.resolve({ code: 0, stdout: xml });
  });
  assertEquals(calls, [
    ["-x", "sofia xmlstatus profile internal reg"],
    ["-x", "sofia xmlstatus profile external reg"],
  ]);
  assertEquals(rows.length, 2);
});
