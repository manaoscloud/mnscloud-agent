# macOS Agent (V10a)

The Agent runs on macOS 13 or newer as the launchd daemon `cloud.manaos.mnscloud.agent` (root).
On a Mac it does only the Cyber Security work: heartbeat, software inventory, hardening checks
with the XProtect state, firmware collection of network devices and its own update. Host
metrics, PABX, runtime updates of other products, CrowdSec and managed patching are Linux or
Windows features and stay off.

## Install

```bash
# On the Mac, as an administrator (Command Line Tools first: xcode-select --install)
sudo git clone https://github.com/manaoscloud/mnscloud-agent.git /opt/mnscloud/mnscloud-agent
sudo bash /opt/mnscloud/mnscloud-agent/scripts/install-agent-macos.sh \
  --api-base https://api.publichost.cloud --enrollment-token '<token from MNSCloud>'
```

| Item | Path |
| --- | --- |
| Code | `/opt/mnscloud/agent` (copied from the checkout `/opt/mnscloud/mnscloud-agent`) |
| Deno | `/usr/local/deno/bin/deno` (official installer, at least 2.8.1) |
| Configuration | `/etc/mnscloud/agent/agent.conf` (0600) |
| Identity | `/var/lib/mnscloud/agent` (0700) |
| Logs | `/var/log/mnscloud/agent/agent.log` |
| Daemon | `/Library/LaunchDaemons/cloud.manaos.mnscloud.agent.plist` |

The installer is bash 3.2 compatible (the macOS system shell). `--dry-run` prints the steps,
`--service-file-only` writes only the daemon definition (CI lint). Uninstall with
`sudo bash scripts/uninstall-agent-macos.sh [--remove-repository]`.

## Update

`mnscloud.agent.update` writes the one-shot launchd job `cloud.manaos.mnscloud.agent-update`
(`/var/lib/mnscloud/agent/agent-update.plist`, `AbandonProcessGroup`, `LaunchOnlyOnce`) and loads
it; the job runs `scripts/update-agent-macos.sh --ref vX.Y.Z` (git checkout of the tag, reinstall,
`launchctl kickstart -k`), so the Agent restart does not kill it. Output goes to
`/var/log/mnscloud/agent/update.log`.

## Inventory

`os.family` and `packageManager` are `macos`, `os.id` is `macos`, `os.versionId` the product
version (`sw_vers`), `os.build` the build. Packages: the release itself as `macos`, then every
application of `system_profiler SPApplicationsDataType -json -detailLevel mini` (name, version,
architecture, folder as source). Ports come from `lsof` (listening TCP, bound UDP). A change of
`/Applications`, `SystemVersion.plist` or the install history triggers a new collection. The
platform matches `macos` and `Safari` against the NVD (workers) and dates the end of support.

## Hardening checks

Fixed commands only (no shell): `fdesetup`, `socketfilterfw`, `spctl`, `csrutil`, `defaults read`
of `com.apple.SoftwareUpdate` and `com.apple.loginwindow`, `launchctl print-disabled system`,
`sshd -T` and `softwareupdate --list` (Apple servers; an unreachable answer is an error, not a
failure).

| Code | Severity | Passes when |
| --- | --- | --- |
| `mac.filevault` | high | FileVault is on |
| `mac.firewall` | medium | the application firewall is enabled |
| `mac.firewall_stealth` | low | stealth mode is on |
| `mac.gatekeeper` | high | Gatekeeper assessments are enabled |
| `mac.sip` | high | System Integrity Protection is enabled |
| `mac.update_check` | medium | automatic update checks are on (default on) |
| `mac.security_updates` | high | critical and security data updates install automatically (default on) |
| `mac.auto_install` | medium | macOS updates install automatically |
| `mac.updates_pending` | high | `softwareupdate` lists nothing |
| `mac.ssh_password_auth` | medium | Remote Login is off, or sshd refuses passwords |
| `mac.screen_sharing` | medium | Screen Sharing is off |
| `mac.guest_account` | medium | the guest account is off |
| `mac.auto_login` | high | automatic login is off |

XProtect is reported as engine `xprotect` (signature version and date of its bundle); macOS
updates and runs it, so antivirus actions are refused on a Mac.

## Tests

`macos_test.ts` (parsers, checks, collectors with a fake runner, update job) runs everywhere. The
CI job `macOS Agent` runs on a real Mac: unit tests, bash 3.2 syntax, installer dry run, `plutil`
lint of both property lists and `tests/macos-live-smoke.ts` (real collectors as root, result kept
as the `macos-live` artifact).
