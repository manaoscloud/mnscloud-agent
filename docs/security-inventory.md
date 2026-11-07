# Security inventory (Essential profile)

The Agent keeps a read-only software inventory of its host for the Cyber Security vulnerability
management. It installs nothing and changes nothing on the host. Implementation:
`security-inventory.ts` (tests: `security-inventory_test.ts`).

## Activation

The platform decides per Agent. Every heartbeat sends
`securityInventory: {supported: true, hash, collectedAt}` (hash and time of the cached inventory, or
`null`). The heartbeat answer carries `data.securityInventory: {enabled, needsFull}`:

- `enabled=false`, or an API that omits the field: the Agent does not collect and deletes its local
  cache.
- `enabled=true`: the Agent collects on its own schedule (below).
- `needsFull=true`: the Agent sends the cached inventory to `POST /api/v1/agent/inventory`, detached
  from the heartbeat. At most one upload per 5 minutes; HTTP 409 (disabled) and 429 (too often) are
  quiet and the next heartbeat asks again; HTTP 413 blocks that inventory until the next collection.

## What is collected

| Item            | Linux                                                                                                     | Windows                                                                                                              |
| --------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| OS              | `/etc/os-release` (`ID`, `VERSION_ID`, codename, `PRETTY_NAME`), kernel release, `uname -m`               | Registry `CurrentVersion` (`ProductName`, `DisplayVersion`, `CurrentBuild`, `UBR`, `InstallationType`), architecture |
| Packages        | `dpkg-query` (only `ii`), `rpm -qa` (epoch form `E:V-R`, without `gpg-pubkey`) or `/lib/apk/db/installed` | Uninstall keys (64 and 32 bit, HKLM) without `SystemComponent=1`, without a name or a version                        |
| Hotfixes        | -                                                                                                         | `Get-HotFix` (KB numbers)                                                                                            |
| Listening ports | `ss -H -tulpn` (protocol, local address, port, process name)                                              | `Get-NetTCPConnection -State Listen`, `Get-NetUDPEndpoint` with the owning process name                              |
| Reboot pending  | `/var/run/reboot-required` (dpkg), `needs-restarting -r` (rpm, when installed), else `null`               | CBS `RebootPending`, Windows Update `RebootRequired`                                                                 |

Windows reports `os.id` = `windows` (client) or `windows-server` (`InstallationType` other than
`Client`), `os.versionId` = `CurrentBuild`, `os.kernel` = `10.0.<build>.<UBR>`; client builds from
22000 are named Windows 11 even when `ProductName` still says Windows 10. Programs are sent as
`packages` with `arch` `x64`/`x86` and `source` = publisher; `packageManager` is `windows`.

Never collected: users, accounts, groups, file contents, file listings, environment variables,
command lines, configuration values, credentials or secrets. The collector commands are fixed
argument vectors; their output is parsed, never executed.

## Limits

Packages 20000, hotfixes 2000, ports 2000 (above that the first N of the sorted list are kept and
`truncated=true`); name 255, version 128 (entries that do not fit are dropped, never cut), arch 32,
source 255, process 128 characters; control characters are removed. A payload over 4 MiB is
abandoned.

The hash is the sha256 hex of
`JSON.stringify({os, packageManager, packages, hotfixes, ports,
rebootRequired})` with packages
sorted by (name, version, arch), hotfixes sorted and ports sorted by (protocol, address, port,
process); `collectedAt`, `truncated` and `footprint` are not part of it.

## Schedule

The collector runs in its own Agent lane (checked every minute), never inside the heartbeat.

- First collection after the platform enables the Agent: a random 0-10 minute delay.
- Then every 24 h plus a random 0-60 minute jitter.
- Linux: also when a package database changed (`/var/lib/dpkg/status`, `/var/lib/rpm/rpmdb.sqlite`,
  `/var/lib/rpm/Packages`, `/usr/lib/sysimage/rpm/rpmdb.sqlite`, `/lib/apk/db/installed`), after it
  stayed unchanged for 2 minutes and at least 10 minutes after the previous attempt.
- A failed collection (command error, 120 s per command, 10 minutes overall, output or payload over
  the limit) is logged once and retried only at the next scheduled time or package change.

Cache: `security-inventory.json` (mode 0600) beside `agent.token` in the Agent state directory
(`/var/lib/mnscloud/agent`, `C:\ProgramData\MNSCloud\Agent`), so a restart does not force a new
collection. It is deleted when the platform disables the inventory.

## Resource cap

Linux: `scripts/install-agent.sh` (also run by every update) writes
`/etc/systemd/system/mnscloud-security.slice` with `CPUQuota=5%`, `MemoryMax=128M`, `IOWeight=10`.
Each collector command runs as

```text
systemd-run --quiet --collect --scope --slice=mnscloud-security.slice --nice=19 -p IOWeight=10 -- ionice -c3 <command>
```

when systemd is the init system and the slice file exists; else `nice -n 19 ionice -c3 <command>`
(each wrapper only when installed), else the plain command. If `systemd-run` itself fails, the rest
of that collection uses the `nice`/`ionice` form.

Windows: the collector PowerShell process sets its own priority class to `Idle`.

## Footprint

Each inventory reports `footprint`: `durationMs`, `payloadBytes`, and on Linux with the slice
`cpuMs` (delta of `usage_usec` in the slice `cpu.stat`) and `memoryPeakBytes` (`memory.peak` of the
slice, the peak since the slice started); otherwise `null`. The slice directory comes from
`systemctl show -P ControlGroup mnscloud-security.slice` (normally
`/sys/fs/cgroup/mnscloud.slice/mnscloud-security.slice`; a nested systemd, such as a container, has
a longer prefix). A slice that is not active yet has no cgroup: the collection that starts it counts
from zero. The files are read with `cat` through the collector runner: Deno reads `/sys` only with
`--allow-all`, which the Agent service does not have.

### Measured footprint

Measured in DEV on 2026-11-07 (first collection of each host, Agent 1.0.170). CPU and memory were
`null` on 1.0.170 (the `/sys` read needed `--allow-all`); they come from a disposable Debian 13 host
on 1.0.171, where they are measured by the Agent itself.

| Host                           | OS        | Packages | Duration | CPU    | Memory peak | Payload |
| ------------------------------ | --------- | -------- | -------- | ------ | ----------- | ------- |
| Disposable test host (1.0.171) | Debian 13 | 193      | 2.2 s    | 102 ms | 3.4 MiB     | 16 KB   |
| API server                     | Debian 13 | 376      | 0.6 s    | -      | -           | 32 KB   |
| Database server                | Debian 13 | 400      | 1.4 s    | -      | -           | 35 KB   |
| Freeradius server              | Debian 13 | 388      | 1.6 s    | -      | -           | 34 KB   |
| PABX FreeSWITCH server         | Debian 12 | 577      | 1.6 s    | -      | -           | 52 KB   |
| Media server                   | Debian 12 | 486      | 1.0 s    | -      | -           | 58 KB   |
| Incus host                     | Debian 13 | 684      | 3.1 s    | -      | -           | 59 KB   |

All 20 DEV hosts: 365 to 684 packages, 0.6 to 3.1 s, 31 to 59 KB per full inventory (sent only when
the platform asks for it; the heartbeat carries the 64-character hash). The collector stays inside
`CPUQuota=5%` and `MemoryMax=128M`; the Agent process itself does not grow (the collection runs in
child processes).

## Verify on a host

- The Agent log shows `Security inventory collected.` with the reason, counts and footprint, or
  `Security inventory collection abandoned until the next scheduled time.`
- Linux: `systemctl status mnscloud-security.slice` while a collection runs;
  `ls -l
  /var/lib/mnscloud/agent/security-inventory.json` shows mode `-rw-------`.
- The platform shows the stored inventory through the Cyber Security inventory API.
