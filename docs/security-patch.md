# Cyber Security patch management (V6)

The Agent applies security updates only through one typed job, `cyber.security.patch.apply`
(job type `cyber.security`). The platform creates it from a patch run that a tenant operator
requested from vulnerability findings and approved, inside the server's maintenance window
(`mnscloud-db` → Cyber Security patch management). The Agent declares the capability
`cyber.security.patch.v1` when it can patch: always on Windows, on Linux when it finds apt/dpkg,
dnf/yum/rpm or apk.

## Payload

| Field | Rule |
| --- | --- |
| `runUUID` | Patch run of the platform |
| `scope` | `findings` (Linux packages of the chosen findings) `security_all` (Windows: pending security and critical updates) or `reboot` (reboot campaign, no packages or KBs) |
| `packages` | Up to 200 package names, `^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,127}$` |
| `kbs` | Up to 50 Windows KBs, `^KB\d{4,8}$`; empty = every pending security/critical update |
| `rebootPolicy` | `never`, `if_required` or `always` |
| `timeoutMinutes` | 5-150, default 90 |

Anything else refuses the job (`CYBER_PATCH_INVALID_REQUEST`) before the host is touched. The
package manager comes from the host, never from the payload.

## Actions (fixed list, no shell)

| Host | Steps |
| --- | --- |
| Debian/Ubuntu | `apt-get update`, then `apt-get install --only-upgrade -- <packages>` (noninteractive, keeps local config files, waits up to 300 s for the dpkg lock) |
| RHEL family | `dnf -y --refresh upgrade -- <packages>` (`yum` when there is no dnf) |
| Alpine | `apk update`, `apk upgrade -- <packages>` |
| Windows | Windows Update Agent API (`Microsoft.Update.Session`): search pending software updates, keep the KBs asked (or security/critical ones), download, install. Drivers and feature upgrades are never selected |

Before a Linux update the Agent checks that `/var` and `/` have at least 512 MiB free (`df -Pk`)
and, on dpkg hosts, that the package database is consistent (`dpkg --audit`). Half-configured
packages are first finished with `dpkg --configure -a` (noninteractive, local config files kept);
if they cannot be repaired the job fails without updating anything. When an update step fails or is
killed by the timeout (the whole process group is killed), the same audit and repair run again, so
the host is never left with half-configured packages. The result reports `freeKiB` and
`recovery` (`attempted`, `repaired`).

A package that is not installed is never added. Versions are read before and after
(`dpkg-query`, `rpm -q`, `apk info -v`) and the result lists each updated package.

## Result and verification

The job result (`result.patch = true`) carries `outcome` (`success`, `partial`, `failed`,
`nothing`), `updated` (name, from, to), `unchanged`, the Windows install codes, `rebootRequired`,
`rebootScheduled`, `inventoryRefreshed`, the duration and the last 1,800 characters of output.
Right after the update the Agent collects and uploads the software inventory at once (outside the
24 h schedule and the 5 min upload spacing), so the platform closes the fixed findings from the
new inventory.

## Reboot campaign

Scope `reboot` (capability `cyber.security.patch.reboot.v1`, declared under the same condition as
`cyber.security.patch.v1`) carries empty `packages` and `kbs` and `rebootPolicy: always`. The Agent
runs no update step (Linux or Windows), reports outcome `nothing` and the pending-reboot state, then
reboots with the delayed reboot below even when nothing changed. A failed job never reboots. A
payload with packages or KBs for this scope is refused.

## Reboot

Only after the result is reported, and only when the policy asks: `always` reboots when something
was installed (or the host already needs it), `if_required` only when the host reports a pending
reboot (`/var/run/reboot-required`, `needs-restarting -r`, Windows CBS/WU flags), `never` never.
The reboot is delayed (Linux `shutdown -r +2`, Windows `shutdown /r /t 120`) with the comment
`MNSCloud: reboot after security updates`.

## Resource use

The update steps run at low CPU and IO priority (`nice -n 10`, `ionice -c2 -n7` when present), not
inside `mnscloud-security.slice`: an upgrade needs more memory than the inventory cap, and a memory
kill in the middle of dpkg would leave packages broken.

## Patch lane and lease

A patch job runs in its own lane beside the Agent's job lane (H6), so status, inventory, posture,
simulation and other jobs keep answering during an update. Patches still run one at a time: the
platform queues at most one patch job per server. While the patch lane is busy, the jobs that use
the package manager or restart services are queued behind the patch instead of running on the job
lane: `runtime.update` and `runtime.reconcile` (an Agent restart would kill a running apt/dpkg),
`cyber.security.install`, `cyber.security.profile.apply` and `cyber.security.antivirus.run` (they
install packages and would fail on the dpkg lock). While they wait they report their progress every
5 minutes, so their lease holds. A simulation that arrives during a patch runs nothing and answers
`failed` with "A security patch is running on this server".

The platform leases a patch job for 180 minutes. The Agent reports the current step again every 5
minutes while a step runs, and a progress report only extends the lease (never shortens it), so a
long `apt-get install` is never expired by the platform while it still runs.

## Simulation (campaign preview)

Job `cyber.security.patch.simulate` (capability `cyber.security.patch.simulate.v1`, declared under
the same condition as `cyber.security.patch.v1`; module `security-patch-simulate.ts`) answers what
a patch of the given packages would do, without installing, downloading or refreshing anything.
The campaign preview queues one per eligible server and shows the result before approval.

| Field | Rule |
| --- | --- |
| `simulationUUID` | Simulation of the platform (one per preview) |
| `scope` | `findings` (Linux packages) or `security_all` (Windows: pending security/critical updates) |
| `packages`, `kbs` | Same validation as the patch job |
| `timeoutMinutes` | 1-15, default 10 |

| Host | Single read-only command |
| --- | --- |
| Debian/Ubuntu | `apt-get -s -o Debug::NoLocking=1 -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= install --only-upgrade -- <packages>` (no dpkg lock, no cache file written) |
| RHEL family | `dnf --assumeno -C upgrade -- <packages>` (`yum` without dnf; cache only, answers "no"; exit 1 with "Operation aborted" / "Exiting on user command" is the normal end; the package manager still writes its own log) |
| Alpine | `apk upgrade -s -- <packages>` |
| Windows | Windows Update Agent search only (no download, no install) |

The result (`result.simulate = true`) carries `outcome` (`ok`, `failed`), `upgrade` (name, from,
to), `install` (new dependencies: name, to), `remove` (name, from), Windows `updates` (kb, title),
each list capped at 300, `rebootLikely` (kernel, C library, init or a Windows update that asks for
a reboot), the duration, the last 1,800 characters of output and `error`. The simulation uses the
package lists already on the host (no `apt-get update`), so it shows what the patch would do with
the current metadata; the patch itself refreshes them first.
