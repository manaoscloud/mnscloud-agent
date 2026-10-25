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
| `log-query BASE64URL_JSON` | Filtered historical file/journal pages; see the query contract below |
| `logs-text` | Masked text: last 120 lines of fixed log files and of the last 60 minutes of each fixed systemd unit journal |
| `journal UNIT [MINUTES] [PRIORITY]` | Masked journal of one fixed systemd unit: last `MINUTES` (1-1440, default 60) at `PRIORITY` or more severe (`err`, `warning`, `notice`, `info`; default `info`), newest 2000 lines, 4 MiB read cap |
| `container-logs CONTAINER [MINUTES]` | Masked Docker output (stdout and stderr) of one `mnscloud-*` container: last `MINUTES` (1-1440, default 60), newest 2000 lines ordered by timestamp, 4 MiB read cap; `UNAVAILABLE` when Docker or the container is absent |
| `versions` | Selected package versions (including `freeswitch`, `kamailio`, `opensips`, `rtpengine-daemon` and `coturn`; Asterisk is source-built) and root-controlled checkout VERSION files (including `mnscloud-{asterisk,freeswitch,kamailio-softswitch,opensips-sbc,media,turn,kamailio-webrtc}`) |
| `connectivity` | At most 12 configured endpoints; TCP and verified TLS only, 2-second socket timeout |
| `asterisk-odbc` | Asterisk ODBC pool state from `asterisk -rx "odbc show"`: pool names, active/max connections and `CONNECTED`/`NO_ACTIVE_CONNECTION`; no SQL, credentials or DSN values |
| `artifacts` | What the host serves and runs: App `build.json` + `index.html` SHA-256 under `/var/www/mnscloud-app`, each webapps app under `/opt/mnscloud/webapps/current` (release name, `build.json`, index hash), the `build.json`/`VERSION` of every `/opt/mnscloud/mnscloud-*` runtime checkout the Agent reports, the Agent install and `db_release_version`. Runs unprivileged |
| `health` | Fixed local GET probes: API `/api/v1/health`, App `/build.json` (+ `Cache-Control`), webapps listener `/healthz`, OpenVault `/v1/sys/health`, Logs ClickHouse `/ping` and Vector `/health`; status, latency and listed fields only |
| `agent` | Agent service state and version, last start, latest resource sample and the last 60 job events of 24 h of its journal (listed fields only, errors masked) |
| `host` | Hostname, OS, kernel, architecture, CPUs, boot time, virtualization, NTP sync and timezone. Runs unprivileged |
| `network` | Interfaces and addresses, default routes, listening TCP/UDP ports (no processes or peers) and resolvers. Runs unprivileged |
| `timers` | `mnscloud-*` and certbot timers: next/last run and the result of the activated service. Runs unprivileged |
| `edge` | `nginx -t` of the system and webapps configurations (masked messages), vhost file names and Let's Encrypt certificate expiry; never configuration content |
| `access-summary [MINUTES]` | Edge access log counts by method, normalized path (ids/values replaced) and status for the last `MINUTES` (1-1440, default 15), from the newest 32 MiB; no client addresses, users, queries, referrers or agents |
| `log-usage` | Size of fixed log/data directories, journal disk usage and the 10 largest files under `/var/log` |
| `voip-summary` | Registration, call and session counters of Kamailio, OpenSIPS, Asterisk, FreeSWITCH and rtpengine when installed; numbers only |
| `schema-status` | Database hosts: active `SchemaAppliedRevision` rows and the last 10 `SchemaReconcileJob` stages/status/error codes, through the passwordless local diagnostics database account |

The extended commands accept no arguments, except `journal`, `container-logs`, `log-query` and `access-summary`. The privileged
collector has a 40-second overall deadline. Paths, commands and subprocess arguments are fixed.
Inputs with extra arguments, shell syntax or unknown operations are rejected. Since 4.0 the
dispatcher ignores a leading `mns-diagnostics ` and one trailing ` 2>/dev/null` or ` 2>&1`
(textual normalization only; nothing is evaluated, the rest must match exactly).

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
credentials match or work. Diagnostics never authenticate to brokers, never inspect customer
records and never call application routes other than the fixed local health endpoints of `health`;
the only SQL is the two fixed `schema-status` SELECTs through the column-scoped account above.

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

Version 4.0 (2026-10-19, user decision) adds `artifacts`, `health`, `agent`, `host`, `network`,
`timers`, `edge`, `access-summary`, `log-usage`, `voip-summary` and `schema-status` to the same fixed
sudo rule (one exact entry per operation, no wildcard), so a rollout can be verified on the host
instead of trusting the checkout version. Design rules of these operations:

Version 4.2 (2026-10-25, user decision) adds `container-logs CONTAINER [MINUTES]`: modules that run
in Docker Compose (the workers: `mnscloud-workers.service` only runs `docker compose up -d`) never
write their application output to the journal, so `journal` showed nothing about them. Same model as
`journal`: one exact sudo entry (`collector.py container-logs`, no wildcard), parameters only on stdin,
name validated against `mnscloud-[a-z0-9-]` before `docker logs --timestamps --since Nm --tail 2000`
runs (no follow mode, other options or containers), every line masked like `logs-text`.
Example: `ssh mns-workers-prod1 'container-logs mnscloud-workers 60'`.

Version 4.1 (2026-10-23) adds the DNS node: `pdns`, `pdns-recursor` and `dnsdist` units
(`mnscloud-dns-config` is already covered by the `mnscloud-*` pattern), `dns.env` (non-secret keys
only; the engine API keys file `dns-secrets.env` is never read), the `mnscloud-dns` checkout and the
`pdns-server`/`pdns-recursor`/`dnsdist` packages. No new commands or sudo changes.

- **Least privilege inside the collector.** `artifacts`, `host`, `network` and `timers` drop to the
  `mns-diagnostics` account before reading anything. `health` and `schema-status` read their root-only
  configuration first and drop privileges before any network or database I/O.
- **`health` is loopback/local only.** Targets are fixed paths on `127.0.0.1` or on an address assigned
  to the host itself (checked by binding to it), with ports from the root-owned module env files or
  fixed defaults. GET only, no cookies, tokens or client input, 2-second timeout, 64 KiB body cap, and
  only listed response fields are returned. OpenVault's local self-signed TLS is reported as
  `LOCAL_UNVERIFIED`. Edge/public reachability is verified separately (workspace
  `scripts/ops/verify.sh`).
- **Coverage without releases.** `services`, `logs`, `logs-text` and `journal` cover every installed
  `mnscloud-*` unit (names validated against `mnscloud-[a-z0-9-]`) in addition to the fixed third-party
  units, so a new module timer such as `mnscloud-asterisk-logs` needs no diagnostics change. A contract
  test fails when the Agent reports a runtime product that `artifacts`/`versions` do not read.
- **Passwordless database account.** On database hosts the Agent installer runs
  `diagnostics/db_account.py`, which converges `'mns-diagnostics'@'localhost' IDENTIFIED VIA unix_socket`
  with column-level `SELECT` on `SchemaAppliedRevision` (`SarClusterKey`, `SarDbReleaseTag`,
  `SarAppliedAt`, `SarStatus`, `SarDateDeleted`) and `SchemaReconcileJob` (`SrjStage`, `SrjDbReleaseTag`,
  `SrjStatus`, `SrjStartedAt`, `SrjFinishedAt`, `SrjLastErrorCode`, `SrjDateCreated`, `SrjDateDeleted`).
  Only the OS account of the same name can use it, over the local socket; any other grant found is
  revoked on the next convergence. Messages, payloads and JSON columns stay unreadable.

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
2. Through that alias run every command of `help` (`journal` with a fixed unit). Review missing/unsafe files without
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

## Historical queries (diagnostics 4.3)

`log-query BASE64URL_JSON` reads historical matches instead of the tail. The argument is an unpadded
base64url JSON object, not a shell expression. `{"list":true}` returns registered file sources and
available rotation suffixes, plus journal units. Only those fixed file roots, fixed third-party units
and validated `mnscloud-*` units are readable. This is privileged operational diagnostics, not a
tenant-facing log search API. It does not grant access to every file under `/var/log`.

A query has `source` (a listed file name or `journal:<unit>`), mandatory `since` and `until`
(RFC3339 timestamps with explicit offsets, inclusive), optional `contains` (case-insensitive literal,
maximum 256 characters), `limit` (1–500, default 200), and `cursor`. File queries also accept
`rotation` (a suffix from the catalog, empty for the current file) and `utcOffset` (default `+00:00`)
for timestamps that have no offset in the file. Specify the host's log offset deliberately; it is
not inferred from the client's timezone. No regex, path, command, environment or shell option is
accepted. Redaction happens **before** literal matching to avoid a secret-value search oracle.

Example request (synthetic data):

```json
{"source":"freeswitch","since":"2026-01-02T09:00:00-03:00","until":"2026-01-02T09:30:00-03:00","utcOffset":"-03:00","contains":"NO_ANSWER","limit":200}
```

Encode JSON locally with Python's `base64.urlsafe_b64encode`, remove trailing `=`, then invoke
`scripts/ops/diag.sh <registered-alias> log-query <encoded-request>` from the workspace. Repeat the
**same** query with the returned `nextCursor` until `complete=true`. The cursor is bound to the
filters and source. A page with no matches and a cursor means continue, not “no events”. There is no
maximum number of pages or historical time-window restriction. Query each catalog rotation when
the interval spans files; file pages follow physical order, not a merged chronological sort.

Per request: one query per host (nonblocking lock, `BUSY` on contention), 20-second scan budget,
8 MiB scanned, 1 MiB JSON-escaped message output, 500 matches, and 64 KiB per physical line. The outer
collector deadline remains 40 seconds. Memory is bounded; the collector does not persist log data,
create a search cache or load an entire file. Gzip rotations stream decompression; resuming requires
replaying decompression to the cursor with a deadline. `COMPRESSED_SEEK_BUDGET_EXCEEDED` explicitly
reports when that is too costly; indexed centralized Logs storage is the appropriate solution for
large recurring compressed-history searches. This query does not bypass retention or recover logs
that were deleted.

File timestamps support ISO dates with a space or `T`, optional microseconds and timezone; following
untimestamped lines inherit the preceding timestamp across pages. `unparsedLines` counts lines with
no known timestamp; these cannot be classified into the requested interval. Other date formats need
an explicit parser addition. Lines are masked without the legacy 400-character truncation.
`LINE_TOO_LARGE` reports an unsupported oversized line without returning a partial secret-bearing
fragment. Standalone PEM/base64 continuation lines are suppressed. Masking remains best effort:
customer identifiers can remain, so results must stay in private operational channels.

File cursors bind device/inode/size/mtime and a validated line boundary. Append, rotation or rewrite
returns `SOURCE_CHANGED` rather than pretending the old snapshot is complete; restart against the
now-stable rotated file when needed. Missing, unsafe and unavailable sources have explicit statuses
and `complete=false`. A `status` other than `OK` is never proof of zero matches. Directory-descriptor
walking and `O_NOFOLLOW` reject parent/final symlink races, hard links and non-regular files. Journal
queries use native cursors and kill/reap their fixed `journalctl` child on budget or error.

The exact new sudo operation is `collector.py log-query`, with request data only on stdin. Agent
install/update converges dispatcher, collector and sudo rule together, preserving the account and
key; existing backup/rollback applies. No Agent resident scheduler, API, database or Windows behavior
changes. Validate `python3 tests/ssh_diagnostics_contract.py` and the disposable-container lifecycle
suite before release. Use normal Agent DEV rollout and verification before an authorized PROD rollout.
