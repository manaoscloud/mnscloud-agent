# Cyber Security hardening baseline and native antivirus (V8)

Part of the Advanced plan of a server (the same per-server unit as managed patching,
`module.cyber-security.advanced`). The Agent declares `cyber.security.posture.v1` on Linux and
Windows and runs two typed jobs (job type `cyber.security`) that only the platform creates
(`mnscloud-db` → Cyber Security hardening baseline and antivirus):

| Command | When | Payload |
| --- | --- | --- |
| `cyber.security.posture.collect` | Daily (24 h after the last check), or "check now" | `{}` |
| `cyber.security.antivirus.run` | A tenant operator asks for an action | `{ "action": "update" \| "quick_scan" \| "full_scan" \| "install" }` |

Any other action refuses the job (`CYBER_ANTIVIRUS_INVALID_REQUEST`) before the host is touched.
Nothing else from the payload reaches a command line.

## Hardening checks (read-only)

A fixed list of checks based on the CIS Benchmarks (Level 1). The Agent only reads files, kernel
parameters and service states and runs fixed read-only commands; it never changes the host. Each
result carries `code`, `benchmark` (CIS section), `severity` (`high`, `medium`, `low`), `status`
(`pass`, `fail`, `not_applicable`, `error`) and a short `evidence` (the value found; for accounts,
only names, never a password hash).

Linux (21 checks): SSH (`sshd -T`: root login, password login, empty passwords, max auth tries,
X11 forwarding), accounts (only `root` with UID 0, no account without password, `PASS_MAX_DAYS`
≤ 365), permissions of `/etc/shadow` and `/etc/passwd`, kernel parameters (ASLR, SUID core dumps,
`dmesg_restrict`, ICMP redirects, source routing, `send_redirects` and `rp_filter` (not applicable
when IP forwarding is on), SYN cookies), a host firewall (nftables or iptables input rules, ufw,
firewalld), time synchronization and auditd.

Windows (15 checks, one fixed PowerShell script sent as `-EncodedCommand`): firewall profiles,
SMBv1 off, SMB signing required, Remote Desktop with NLA, Guest account off, password length ≥ 14,
complexity, lockout threshold 1-5 (`secedit /export`, locale independent), UAC, LLMNR off, autorun
off, Windows Update service not disabled, TLS 1.0 server off (default off from build 26100), LSA
protection, WDigest off.

OpenSCAP and the SCAP Security Guide are not used: their content and evaluation do not fit the
Essential resource limits of small hosts and do not cover Alpine and Windows; the fixed list keeps
the check light and the same on every host.

## Antivirus

| Host | Engine | State | Actions |
| --- | --- | --- | --- |
| Windows | Microsoft Defender (`Get-MpComputerStatus`) | service, real time, mode (passive when another antivirus is active), engine and signature versions, last quick/full scan; threats from `Get-MpThreatDetection` (last 200) | `update` (`Update-MpSignature`), `quick_scan`/`full_scan` (`Start-MpScan`); `install` is refused |
| Linux | ClamAV (`clamscan --version`, freshclam and clamonacc state) | engine and signature versions, last quick/full scan of the Agent; threats from the Agent's last scans | `update` (`freshclam`, stopping the updater service meanwhile), `quick_scan` (`/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root`, `/var/www`, `/srv`, `/usr/local/bin`), `full_scan` (`/` without `/proc`, `/sys`, `/dev`, `/run`, the ClamAV database, Docker layers, snaps), `install` |

Scans run with `nice -n 19` and `ionice -c 3`, report only infected files (`--infected`) and never
delete or move a file. `clamdscan` is used when clamd runs; otherwise `clamscan` needs about 1.2 GB
free memory and is refused below that. `install` (Debian/Ubuntu `clamav clamav-freshclam`; RHEL
family `dnf install clamav clamav-update`, EPEL needed; Alpine `clamav-scanner freshclam`) needs at
least 2 GB of memory and is offered (`installable = 1`) only then.

The Linux scan state (last scan times and the threats found) is kept in
`security-antivirus.json` next to the Agent token. A threat no longer found by a scan of its path
is resolved by the platform.

## Result

`{ posture: 1, platform, checks?, antivirus, threats, actionResult?, durationMs }`. An antivirus
action omits `checks` (the platform keeps the last ones) and adds `actionResult`
(`action`, `outcome` `success`/`partial`/`failed`, `message`, `infected`). Threat keys are the
SHA-256 of engine, identity and path. Times are ISO-8601 UTC.
