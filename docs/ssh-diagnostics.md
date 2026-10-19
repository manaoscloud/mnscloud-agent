# Restricted SSH diagnostics

The canonical implementation lives in the Agent repository, [diagnostics](../diagnostics/):
`dispatcher.sh`, `collector.py`, `manage.py` and the approved client public key
`diagnostic-client.pub`. [scripts/install-diagnostics.sh](../scripts/install-diagnostics.sh)
converges the account and runs on every Agent install/update. Do not recreate scripts from
chat history.
All commands, usernames and output remain in English.

## Authorization and inventory

Follow [SSH access policy](ssh-access.md). `/root/.ssh/config` is the exclusive
connection inventory. Real addresses, keys and operational reports remain outside Git.
Since diagnostics 3.6 (2026-10-14, user decision) the Agent manages the account: every
Agent install/update (DEV automatically, PROD through the approved promote/rollout) installs
it on hosts without it (approved public key) or updates it in place (keys, UID and GID
preserved). The restricted account still cannot install/update itself and gains no new
privilege; failures never block the Agent and are retried on its next update.

## Commands

| Command | Output and limits |
| --- | --- |
| `help` | Exact allowlist |
| `identity` | Diagnostic UID and groups |
| `memory` | Host memory, 10-second timeout |
| `disk` | Local filesystem usage, 10-second timeout |
| `uptime` | Uptime and load, 10-second timeout |
| `services` | Fixed systemd units (including `asterisk`, `freeswitch`, `kamailio`, `opensips`, `rtpengine-daemon`, `coturn` and the media/TURN/WebRTC heartbeat and sync units) and state properties, no environment/log content |
| `config` | Fixed service env files, explicit safe-value allowlist; other values `SET`/`EMPTY` |
| `config-check` | Missing/empty required settings, invalid endpoints/ports/enums and production debug checks |
| `logs` | Last 15 minutes, at most 40 events per fixed systemd unit; timestamps, severity and fixed error categories only |
| `logs-text` | Masked text: last 120 lines of fixed log files and of the last 60 minutes of each fixed systemd unit journal |
| `journal UNIT [MINUTES] [PRIORITY]` | Masked journal of one fixed systemd unit: last `MINUTES` (1-1440, default 60) at `PRIORITY` or more severe (`err`, `warning`, `notice`, `info`; default `info`), newest 2000 lines, 4 MiB read cap |
| `versions` | Selected package versions (including `freeswitch`, `kamailio`, `opensips`, `rtpengine-daemon` and `coturn`; Asterisk is source-built) and root-controlled checkout VERSION files (including `mnscloud-{asterisk,freeswitch,kamailio-softswitch,opensips-sbc,media,turn,kamailio-webrtc}`) |
| `connectivity` | At most 12 configured endpoints; TCP and verified TLS only, 2-second socket timeout |
| `asterisk-odbc` | Asterisk ODBC pool state from `asterisk -rx "odbc show"`: pool names, active/max connections and `CONNECTED`/`NO_ACTIVE_CONNECTION`; no SQL, credentials or DSN values |

The extended commands accept no arguments, except `journal`. The privileged collector has a
40-second overall deadline. Paths, commands and subprocess arguments are fixed.
Inputs with extra arguments, shell syntax or unknown operations are rejected.

`journal` (diagnostics 3.7, 2026-10-15, user decision) replaces ad hoc `journalctl` for
troubleshooting when the 60-minute/120-line `logs-text` window is not enough (for example the
busy `mnscloud-api` journal). The sudo rule stays exact (`collector.py journal`, no wildcard):
the dispatcher sends the parameters on stdin and the collector validates them before it checks
privilege. `UNIT` must be one of the fixed units of `logs`/`logs-text`; nothing else reaches
`journalctl` (no `--grep`, other units, paths, output formats or follow mode). Each line is
`<UTC timestamp> <syslog priority number> <message>`, masked like `logs-text` and capped at 400
characters. `lines` is `UNAVAILABLE` without a journal and `OUTPUT_TOO_LARGE` past the read cap;
`limitReached` tells that older lines of the window were cut. Filter the result locally.

`config` reads only `/etc/mnscloud/{api,app,nginx,workers,rabbitmq,db}.env`.
It parses text without shell evaluation or environment interpolation. Symlinks,
non-root-owned/group-or-world-writable paths, special files, duplicate keys,
multiline quoted values and files over 64 KiB are rejected. Unsupported files are
reported as `UNREADABLE_OR_UNSAFE`; do not weaken permissions to work around this.

Passwords, tokens, JWT/signing keys, unknown fields and unapproved values are never
returned. Endpoint output strips userinfo, paths, queries and fragments. No secret
hashes/fingerprints are exposed for cross-host comparison. `SET` is not proof that
credentials match or work. This version does not authenticate to databases/brokers,
execute SQL, inspect customer records or test HTTP application routes.

`logs` deliberately discards raw messages. Categories include connection, timeout,
authentication, TLS, memory and generic failure. It does not read Docker container
logs; a oneshot Workers unit in `active/exited` does not prove container health.
Unknown messages appear only as `OTHER_MESSAGE_REDACTED`. This is triage metadata,
not a claim that arbitrary free-text logs can be sanitized perfectly.

`logs-text` exists for installation and runtime troubleshooting where categories are
not enough. It reads only `/var/log/mnscloud-install.log`, `/var/log/asterisk/messages`,
`/var/log/freeswitch/freeswitch.log`, the Kamailio stderr/stdout files
`/var/log/mnscloud/kamailio/kamailio.{err,out}.log`, the coturn file
`/var/log/mnscloud/turn/turnserver.log` and the journal of the fixed units above. Files are
opened without following symlinks and must be regular files with a single hard link, so
a service user cannot point a log name at another file. At most the last 256 KiB and 120
lines per source are returned as `tail`; each line is capped at 400 characters. File sources
also return `highlights`: up to 80 numbered failure lines (errors, `E:` apt messages,
`Last failed command`, tracebacks, OOM/kill markers) with three lines of preceding context,
searched across the whole window so a long post-failure summary cannot hide the cause. Every line is masked
before output: Bearer/Basic credentials, JWTs, URL userinfo, `password`/`secret`/`token`/
`key`-style assignments and flags, private key blocks and long mixed tokens/hashes become
`[REDACTED]`, and terminal control sequences are removed. Masking is best effort: treat
the output as private operational evidence, and do not paste it into public issues. Log
text can still contain customer identifiers such as SIP users, numbers or domains.

Absent services/config files are expected during assembly. Checkout VERSION values
do not prove the exact running artifact. No services are installed, enabled or
restarted by these diagnostics or by their updater.

## Privilege boundary

The account remains `mns-diagnostics`, with its primary group only and no password
provisioned. The home `/var/lib/mns-diagnostics`, shell
`/usr/local/sbin/mns-diagnostics`, and `authorized_keys` remain root-controlled.
Authorization retains `restrict` and the forced dispatcher; no terminal, forwarding,
interactive shell, SCP/SFTP or arbitrary commands are granted.

Version 2 adds `/usr/local/lib/mns-diagnostics/collector.py` and a root-owned 0440
`/etc/sudoers.d/mns-diagnostics` rule. This is a deliberate change from version 1's
no-sudo model: it permits only `/usr/bin/python3 -I` with that fixed collector path
and one of the six exact operations. It never grants generic Python, shell, cat,
editor, systemctl or Docker sudo access. The dispatcher clears the environment;
Python isolated mode ignores user modules/PYTHONPATH; subprocesses use a clean env.
The collector independently validates operation and argument count.
Version 3 adds the masked `logs-text` operation to the same fixed sudo rule and
reports `"diagnostics": "3"` in `versions`; `--update` upgrades version 2 in place.
Version 3.2 adds the Kamailio unit, log files, package and softswitch checkout to the
existing fixed operations, without new commands or sudo changes. Version 3.3 adds the
`opensips` unit and package and the Asterisk, FreeSWITCH and OpenSIPS SBC checkouts the
same way; OpenSIPS logs through the journal of its unit, not a dedicated file.
Version 3.4 adds the Realtime edges the same way: the media relay (`rtpengine-daemon`,
`mnscloud-media-heartbeat`), TURN/STUN (`coturn`, `mnscloud-turn-sync`, `turnserver.log`) and
WebRTC signaling (`mnscloud-webrtc-sync`; its `kamailio` and `nginx` units were already covered),
their packages and the `mnscloud-{media,turn,kamailio-webrtc}` checkouts.
Version 3.6 adds the platform modules the same way: Authentication (`mnscloud-authentication`,
`mnscloud-authentication-config`, `authentication.env`, checkout, `freeradius` package and
`/var/log/freeradius/radius.log` with every bracketed subscriber username replaced by `[USER]`),
OpenVault (`mnscloud-openvault`, `mnscloud-openvault-tls-renew`, `openvault.env`; the KMS key id
stays `SET`), Webapps (`mnscloud-webapps`, `mnscloud-webapps-sync`, checkout), Incus (`incus`
unit and package), `mnscloud-grow-rootfs`, the Agent checkout and
`/var/log/mnscloud-agent-install.log`. No new commands or sudo changes.
Version 3.7 adds the parameterized `journal` operation described above to the fixed sudo rule
and reports `"diagnostics": "3.7"` in `versions`.
Version 3.8 (2026-10-17) reports `db_release_version`, the newest approved DB release prepared by
`database.schema.reconcile` under `/opt/mnscloud/mnscloud-db-releases`, instead of
`db_checkout_version`: `/opt/mnscloud/mnscloud-db` is only the git source of those release
worktrees and its own VERSION goes stale. The applied schema is still `SchemaAppliedRevision`.
Version 3.9 (2026-10-19) adds the Logs node the same way: `mnscloud-logs-storage`,
`mnscloud-logs-ingest` and `mnscloud-logs-config` units, `logs.env` (non-secret keys only; the node
principals file `logs-secrets.env` is never read), the `mnscloud-logs` checkout and the
`clickhouse-server`/`vector` packages. No new commands or sudo changes.

Security depends on root-controlled code and existing host SSH/PAM/sudo policy.
Other administrative identities are unaffected. Review pre-existing broad sudo rules;
this installer does not remove unrelated grants. A compromised root can bypass the
boundary. Reads still consume resources and create ordinary access/audit records.
Concurrent abuse needs host/session-level controls in addition to per-call bounds.

## Install or update

Automatic. `scripts/install-agent.sh` (also used by `update-agent.sh` and the Agent runtime
update job) calls `scripts/install-diagnostics.sh` from the same checkout:

- no `mns-diagnostics` account: `manage.py --install diagnostics/diagnostic-client.pub`;
- account present and installed files differ: `manage.py --update`;
- installed files identical: no change (no backup churn); the 5 newest backups are kept.

Target: Linux with systemd, Python 3, sudo/visudo, runuser, useradd, OpenSSH and the standard
diagnostic utilities. Missing prerequisites skip convergence with a warning in the Agent install
log; the Agent update still succeeds. The tooling does not install packages or change sshd.

Manual convergence on one host (root, from the installed Agent checkout) uses the same path:

```bash
(
  set -euo pipefail
  bash /opt/mnscloud/mnscloud-agent/scripts/install-diagnostics.sh
)
```

The manager validates account ownership, shell, groups and key restrictions;
validates shell/Python/sudoers syntax; takes a root-only timestamped backup; and
replaces files atomically. Local smoke tests check the identity, allowlist, versions
privilege delegation and harmless denied shell command. Service env files and passwords are
untouched.

## Rollback and failures

The updater prints its backup directory under `/var/backups/mns-diagnostics`.
Failures during application restore the previous dispatcher, collector and sudoers
files. A partially created new account is left for explicit administrator review;
never blindly delete accounts or restart installation over conflicting files.

To reverse an applied update, run the same approved `manage.py` as root with
`--rollback /var/backups/mns-diagnostics/EXACT_BACKUP_DIRECTORY`, then repeat tests.
The backup manifest and checksums are verified before restoration. Rollback never
restores revoked keys, changes account identity, restarts services or rolls back
application/database data. Keep the approved manager files or download them again
at the same pinned revision when needed.

## Validate and maintain

1. Register an explicit diagnostic alias in SSH config with `IdentitiesOnly yes`,
   `BatchMode yes` and `StrictHostKeyChecking no`. New host keys are saved automatically;
   changed known keys may also connect without confirmation, subject to OpenSSH's built-in
   restrictions. Keep the normal `known_hosts` files; conflicting entries are not automatically
   replaced and may still produce warnings. This accepts the loss of host-identity protection
   against changed keys, as defined in the SSH access policy. No root fallback is allowed.
2. Through that alias run all thirteen commands (`journal` with a fixed unit). Review missing/unsafe files without
   exposing or changing secrets. Config endpoints are private operational evidence.
3. Send harmless `sh -c id` through the same alias: expect denial and exit 126.
   Connection failure/255 is not proof of enforcement. No destructive denial tests.
4. Record source commit, installed checksums, full alias and test outcomes locally.
   Source publication does not mean a server was updated.
5. For changes, edit the canonical files and this contract together in the Agent
   repository, run `python3 tests/ssh_diagnostics_contract.py`, then review/CI/merge; the
   next Agent release and rollout delivers them.
   Run `bash tests/ssh_diagnostics_integration.sh` with Docker to exercise fresh
   installation, v1 update, sudo denials, key/UID preservation and rollback in a
   disposable Debian container; CI runs this lifecycle test too.
   Explicitly review allowlist additions and sudo privilege changes.

Normal fixes still follow workspace → review/CI/release → authorized Agent rollout.
This account is for investigation and does not bypass that workflow.

## References

- [OpenSSH key restrictions](https://man.openbsd.org/sshd.8): forced commands and
  `restrict` are complementary; server-wide ForceCommand can override key commands.
- [OpenSSH server policy](https://man.openbsd.org/sshd_config).
