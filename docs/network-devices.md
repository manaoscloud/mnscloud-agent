# Network devices (Cyber Security V9)

Job `cyber.security.network-device.collect`, capability `cyber.security.network-device.v1`
(every Agent). Module: `network-device.ts`.

## What the Agent does

- The platform registers a router, firewall or switch with a collector Agent on the same network
  and queues one job per device (daily, or "collect now"). The payload carries only `deviceUUID`.
- The Agent asks `POST /agent/cyber-security/network-devices/<job>/material` for the address,
  UDP port, SNMP version and credential. The API answers only for a job leased by this Agent; the
  credential stays in memory for this job and is never logged or written to disk.
- Read-only: SNMP **GET** of a fixed list of objects, never SET, WALK or BULK:
  - SNMPv2-MIB `sysDescr`, `sysObjectID`, `sysUpTime`, `sysName`;
  - one version (and model) object per vendor: MikroTik `mtxrLicVersion`/`mtxrBoardName`,
    Fortinet `fgSysVersion`, Palo Alto `panSysSwVersion`/`panChassisType`, SonicWall
    `snwlSysFirmwareVersion`/`snwlSysModel`. Cisco IOS XE, Cisco ASA and Juniper Junos report the
    version in `sysDescr`.
- SNMP v2c (community) or v3 (USM): authentication SHA (HMAC-SHA-96) or SHA-256 (HMAC-SHA-256-192,
  RFC 7860), privacy AES-128 (CFB, RFC 3826) or none (authNoPriv). MD5 and DES are not supported.
  Engine discovery and one time-window retry follow RFC 3414; answers are authenticated.
- Address: unicast IPv4/IPv6 only (private allowed; loopback, link-local, multicast and broadcast
  refused). Timeout 3 s, two attempts.

## Result

```json
{"networkDevice":1,"deviceUUID":"...","sysName":"fw-edge","sysDescr":"...","sysObjectId":"1.3.6.1.4.1.12356...",
 "vendor":"fortinet_fortios","model":"FGT60F","version":"7.2.5","uptimeSeconds":86400,"durationMs":120}
```

`vendor` is one of `mikrotik_routeros`, `fortinet_fortios`, `cisco_iosxe`, `cisco_asa`,
`juniper_junos`, `paloalto_panos`, `sonicwall_sonicos` or `other`. `version` is normalized for the
NVD CPE version and update fields (`9.16(3)19` → `9.16.3.19`, `21.4R3-S1.5` → `21.4r3-s1`,
`10.2.4-h4`). A failure (no answer, wrong credential, unknown user) fails the job with
`CYBER_NETWORK_DEVICE_FAILED` and a message the platform shows on the device.

## Tests

`network-device_test.ts` (RFC 3414 key localization, NIST AES-CFB vector, BER, vendor and version
parsing, v2c collection with GET only). The v3 path was exercised against net-snmp 5.9 (SHA/AES,
SHA-256/AES, authNoPriv, wrong password and unknown user reports).
