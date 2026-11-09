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
| `scope` | `findings` (Linux packages of the chosen findings) or `security_all` (Windows: pending security and critical updates) |
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

A package that is not installed is never added. Versions are read before and after
(`dpkg-query`, `rpm -q`, `apk info -v`) and the result lists each updated package.

## Result and verification

The job result (`result.patch = true`) carries `outcome` (`success`, `partial`, `failed`,
`nothing`), `updated` (name, from, to), `unchanged`, the Windows install codes, `rebootRequired`,
`rebootScheduled`, `inventoryRefreshed`, the duration and the last 1,800 characters of output.
Right after the update the Agent collects and uploads the software inventory at once (outside the
24 h schedule and the 5 min upload spacing), so the platform closes the fixed findings from the
new inventory.

## Reboot

Only after the result is reported, and only when the policy asks: `always` reboots when something
was installed (or the host already needs it), `if_required` only when the host reports a pending
reboot (`/var/run/reboot-required`, `needs-restarting -r`, Windows CBS/WU flags), `never` never.
The reboot is delayed (Linux `shutdown -r +2`, Windows `shutdown /r /t 120`) with the comment
`MNSCloud: reboot after security updates`.

## Resource use

The update runs as the package manager normally does (not inside `mnscloud-security.slice`: an
upgrade needs more than the inventory cap). The platform lease of a patch job is 180 minutes.
