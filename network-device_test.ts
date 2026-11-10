import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "https://deno.land/std@0.224.0/assert/mod.ts";
import {
  aesCfb,
  allowedAddress,
  collectDevice,
  decode,
  decodeV2c,
  detectVendor,
  encodeOid,
  encodeV2c,
  encodeV2cResponse,
  localizeKey,
  NETWORK_DEVICE_CAPABILITY,
  NETWORK_DEVICE_COMMAND,
  NetworkDeviceError,
  OID,
  parseMaterial,
  parseVersion,
  type Transport,
  VENDOR_OIDS,
} from "./network-device.ts";

const hex = (bytes: Uint8Array) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (text: string) => Uint8Array.from(text.match(/../g)!.map((h) => parseInt(h, 16)));

Deno.test("command and capability names are fixed", () => {
  assertEquals(NETWORK_DEVICE_COMMAND, "cyber.security.network-device.collect");
  assertEquals(NETWORK_DEVICE_CAPABILITY, "cyber.security.network-device.v1");
});

Deno.test("SNMPv3 key localization matches RFC 3414 A.3.2 (SHA)", () => {
  const key = localizeKey("sha1", "maplesyrup", unhex("000000000000000000000002"));
  assertEquals(hex(key), "6695febc9288e36282235fc7151f128497b38f3f");
  assertThrows(() => localizeKey("sha1", "short", new Uint8Array(4)), NetworkDeviceError);
});

Deno.test("AES-128 CFB round trip with a partial last block", async () => {
  const key = unhex("000102030405060708090a0b0c0d0e0f");
  const iv = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
  const plain = new TextEncoder().encode("scoped PDU of 37 bytes for the test!!");
  const cipher = await aesCfb(key, iv, plain, false);
  assertEquals(cipher.length, plain.length);
  assert(hex(cipher) !== hex(plain));
  assertEquals(
    new TextDecoder().decode(await aesCfb(key, iv, cipher, true)),
    new TextDecoder().decode(plain),
  );
  // NIST SP 800-38A F.3.13 (CFB128-AES128, first block).
  const nistKey = unhex("2b7e151628aed2a6abf7158809cf4f3c");
  const nistIv = unhex("000102030405060708090a0b0c0d0e0f");
  assertEquals(
    hex(await aesCfb(nistKey, nistIv, unhex("6bc1bee22e409f96e93d7e117393172a"), false)),
    "3b3fd92eb72dad20333449f8e83cfb4a",
  );
});

Deno.test("BER: OIDs with large arcs and long lengths", () => {
  const oid = encodeOid("1.3.6.1.4.1.12356.101.4.1.1.0");
  assertEquals(hex(oid), "060c2b06010401e0446504010100");
  const long = encodeV2c("c".repeat(300), 7, [OID.sysDescr]);
  assertEquals(decode(long).tag, 0x30);
  assertThrows(() => decode(Uint8Array.of(0x30, 0x05, 0x02)), NetworkDeviceError);
});

Deno.test("vendor detection and version normalization", () => {
  assertEquals(detectVendor("1.3.6.1.4.1.14988.1", "RouterOS RB4011iGS+"), "mikrotik_routeros");
  assertEquals(detectVendor("1.3.6.1.4.1.12356.101.1.10004", "FGT60F"), "fortinet_fortios");
  assertEquals(
    detectVendor(
      "1.3.6.1.4.1.9.1.2494",
      "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc5)",
    ),
    "cisco_iosxe",
  );
  assertEquals(
    detectVendor("1.3.6.1.4.1.9.1.2313", "Cisco Adaptive Security Appliance Version 9.16(3)19"),
    "cisco_asa",
  );
  assertEquals(
    detectVendor(
      "1.3.6.1.4.1.9.1.1208",
      "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4",
    ),
    "other",
  );
  assertEquals(
    detectVendor(
      "1.3.6.1.4.1.2636.1.1.1.2.25",
      "Juniper Networks, Inc. mx480 internet router, kernel JUNOS 21.4R3-S1.5",
    ),
    "juniper_junos",
  );
  assertEquals(
    detectVendor("1.3.6.1.4.1.25461.2.3.38", "Palo Alto Networks PA-3200 series firewall"),
    "paloalto_panos",
  );
  assertEquals(
    detectVendor("1.3.6.1.4.1.8741.1", "SonicWALL TZ 370 (SonicOS 7.0.1-5145-R4321)"),
    "sonicwall_sonicos",
  );
  assertEquals(detectVendor(null, "Linux switch 5.10"), "other");

  assertEquals(parseVersion("mikrotik_routeros", "RouterOS RB4011iGS+", "7.12.1"), "7.12.1");
  assertEquals(
    parseVersion("mikrotik_routeros", "RouterOS RB750", "6.49.10 (long-term)"),
    "6.49.10",
  );
  assertEquals(
    parseVersion("fortinet_fortios", "FGT60F", "v7.2.5,build1517,230606 (GA.F)"),
    "7.2.5",
  );
  assertEquals(parseVersion("paloalto_panos", "", "10.2.4-h4"), "10.2.4-h4");
  assertEquals(
    parseVersion(
      "juniper_junos",
      "Juniper Networks, Inc. mx480 internet router, kernel JUNOS 21.4R3-S1.5, Build date",
      null,
    ),
    "21.4r3-s1",
  );
  assertEquals(
    parseVersion(
      "cisco_iosxe",
      "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc5)",
      null,
    ),
    "17.9.4a",
  );
  assertEquals(
    parseVersion("cisco_asa", "Cisco Adaptive Security Appliance Version 9.16(3)19", null),
    "9.16.3.19",
  );
  assertEquals(parseVersion("sonicwall_sonicos", "", "SonicOS 7.0.1-5145-R4321"), "7.0.1-5145");
  assertEquals(parseVersion("other", "anything 1.2.3", "1.2.3"), null);
  assertEquals(parseVersion("fortinet_fortios", "FGT60F", "unknown"), null);
});

Deno.test("material: unicast address and complete credential only", () => {
  const ok = parseMaterial({
    deviceUUID: "D",
    address: "192.168.88.1",
    port: 161,
    snmpVersion: "v3",
    credentials: {
      user: "mns",
      authProtocol: "sha256",
      authPassword: "authpass1",
      privProtocol: "aes",
      privPassword: "privpass1",
    },
  });
  assertEquals(ok.credentials.version, "v3");
  for (
    const address of [
      "127.0.0.1",
      "169.254.1.1",
      "224.0.0.5",
      "0.0.0.0",
      "255.255.255.255",
      "::1",
      "fe80::1",
      "ff02::1",
      "router.local",
      "300.1.1.1",
    ]
  ) {
    assertEquals(allowedAddress(address), false, address);
  }
  assert(allowedAddress("10.0.0.1") && allowedAddress("2001:db8::1"));
  assertThrows(
    () =>
      parseMaterial({ address: "127.0.0.1", snmpVersion: "v2c", credentials: { community: "x" } }),
    NetworkDeviceError,
  );
  assertThrows(
    () => parseMaterial({ address: "10.0.0.1", snmpVersion: "v2c", credentials: {} }),
    NetworkDeviceError,
    "community",
  );
  assertThrows(
    () =>
      parseMaterial({
        address: "10.0.0.1",
        snmpVersion: "v3",
        credentials: { user: "u", authProtocol: "md5", authPassword: "x", privProtocol: "aes" },
      }),
    NetworkDeviceError,
    "incomplete",
  );
  assertThrows(
    () => parseMaterial({ address: "10.0.0.1", snmpVersion: "v1", credentials: {} }),
    NetworkDeviceError,
    "Invalid SNMP version",
  );
  assertThrows(
    () =>
      parseMaterial({
        address: "10.0.0.1",
        port: 0,
        snmpVersion: "v2c",
        credentials: { community: "x" },
      }),
    NetworkDeviceError,
    "port",
  );
});

Deno.test("v2c collection reads the system group and the vendor objects with GET only", async () => {
  const requests: string[][] = [];
  const answers: Record<string, string | null> = {
    [OID.sysDescr]: "FGT60F",
    [OID.sysObjectId]: "1.3.6.1.4.1.12356.101.1.10004",
    [OID.sysUpTime]: "8640000",
    [OID.sysName]: "fw-edge",
    [VENDOR_OIDS.fortinet_fortios!.version!]: "v7.2.5,build1517,230606 (GA.F)",
  };
  const transport: Transport = (address, port, packet) => {
    assertEquals([address, port], ["10.0.0.1", 161]);
    const message = decode(packet);
    const pdu = message.children![2];
    assertEquals(pdu.tag, 0xa0); // GetRequest only
    const requestId = Number(`0x${hex(pdu.children![0].value)}`);
    const oids = pdu.children![3].children!.map((b) => {
      const body = b.children![0].value;
      return decodeOid(body);
    });
    requests.push(oids);
    return Promise.resolve(
      encodeV2cResponse("public", requestId, oids.map((oid) => [oid, answers[oid] ?? null])),
    );
  };
  const result = await collectDevice(
    parseMaterial({
      deviceUUID: "D",
      address: "10.0.0.1",
      snmpVersion: "v2c",
      credentials: { community: "public" },
    }),
    transport,
    () => 0,
  );
  assertEquals(result, {
    networkDevice: 1,
    deviceUUID: "D",
    sysName: "fw-edge",
    sysDescr: "FGT60F",
    sysObjectId: "1.3.6.1.4.1.12356.101.1.10004",
    vendor: "fortinet_fortios",
    model: "FGT60F",
    version: "7.2.5",
    uptimeSeconds: 86400,
    durationMs: 0,
  });
  assertEquals(requests.length, 2);
  assertEquals(requests[1], [VENDOR_OIDS.fortinet_fortios!.version!]);
  // An answer to another request id is refused.
  assertThrows(
    () => decodeV2c(encodeV2cResponse("public", 5, [[OID.sysName, "x"]]), 6),
    NetworkDeviceError,
    "another request",
  );
  await assertRejects(
    () =>
      collectDevice(
        parseMaterial({
          deviceUUID: "D",
          address: "10.0.0.1",
          snmpVersion: "v2c",
          credentials: { community: "public" },
        }),
        () => Promise.reject(new NetworkDeviceError("No SNMP answer")),
      ),
    NetworkDeviceError,
    "No SNMP answer",
  );
});

function decodeOid(bytes: Uint8Array): string {
  const parts = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let v = 0;
  for (const b of bytes.slice(1)) {
    v = v * 128 + (b & 0x7f);
    if (!(b & 0x80)) {
      parts.push(v);
      v = 0;
    }
  }
  return parts.join(".");
}
