# MNSCloud Agent

## Overview

`mnscloud-agent` is the platform's standalone local Agent. It is not named after
PABX, firewall, Docker, or any other specific function; those behaviors are
represented as capabilities and jobs. There is a single runtime. Its effective
limits come from operating system permissions, `agent.conf`, synchronized
capabilities, and API assignments.

## Architecture

1. The installer creates the local `agent.conf`.
2. The installer creates or reuses the local `agent.uuid`.
3. The installer can consume a short-lived MNSCloud enrollment token.
4. The API validates the enrollment, creates or activates the Agent identity,
   and returns the canonical Agent UUID and runtime token directly to the
   installer.
5. The installer writes the service/config, restarts the local Agent service,
   and synchronizes installed capabilities with the API.
6. The Agent sends heartbeat requests to `POST /api/v1/agent/heartbeat`.
7. Heartbeat synchronizes host-declared capabilities.
8. The API returns jobs through `POST /api/v1/agent/jobs/lease` according to
   capabilities and assignments.
9. The Agent runs the job locally and reports success or failure.

## Secure Enrollment

The preferred activation flow is enrollment-based. The MNSCloud API creates a
single-use enrollment token with a short TTL. The app may display an install
command containing that temporary enrollment token, but it never receives the
long-lived Agent runtime token.

The installer consumes the enrollment through:

```text
POST /api/v1/agent/enroll
```

If the enrollment is valid, the API returns the runtime token only to the
server-side installer. When the enrollment was generated from an existing
offline Agent, the API also returns that existing Agent UUID; the installer
writes the canonical UUID to `/var/lib/mnscloud/agent/agent.uuid`, writes the
token to `/var/lib/mnscloud/agent/agent.token`, and starts the service.
Enrollment creation and consumption are recorded as tenant and global activity
logs by the API.

The generated command will look similar to this, but do not copy this example
literally:

```bash
sudo bash scripts/install-agent.sh \
  --api-base https://api.example.com \
  --enrollment-token '<short-lived-enrollment-token>'
```

Operational flow:

1. Generate the enrollment in `Monitoring > Agents` in the MNSCloud App.
2. Copy the generated install command.
3. Run that command on the target server.
4. Confirm the Agent appears online in the App.

Linux install and reinstall are idempotent. After rewriting `agent.conf`,
runtime files, or the systemd unit, `install-agent.sh` must explicitly restart
`mnscloud-agent` and sync capabilities with the API. Runtime installers can
re-run `install-agent.sh` after enabling local capabilities such as WebRTC,
TURN/STUN, Asterisk, or FreeSWITCH; operators must not need a separate manual
restart in the normal install flow.

The MNSCloud App builds `--api-base` from the current browser origin. In
production this should be the same public origin that serves `/api/v1`. In local
development, do not use a `localhost` command on a remote server unless that
server can actually reach that address.

The Agent name shown in the MNSCloud App is the canonical name stored in the
enrollment record. The installer's local label is reported separately as
`installationName` and should not overwrite the App-side Agent name.

Do not register the local UUID manually for new installs. The installer sends
the UUID while consuming the enrollment, and the API links the Agent
automatically. If the enrollment targets an existing Agent record, the API
response wins and the installer replaces the local UUID with that canonical
Agent UUID.

When the installer or updater runs without a new enrollment token, it is not
allowed to trust local files alone. It must validate the existing
`agent.uuid`/`agent.token` pair with:

```text
POST /api/v1/agent/heartbeat
```

If the API rejects the identity, installation or update must fail before
starting the local service. This protects deleted or deactivated Agent
identities from being silently revived by a server that still has old local
state.

## Remote Updates

Remote updates are release-tag based. The control plane must never ask the Agent
to update from an implicit branch. The API queues a `runtime_update` job with a
`product`, capability, and `targetRef` such as `v1.0.6`; the Agent validates the
ref format and runs only the local updater mapped to that declared product.

Remote update support starts at Agent `1.0.6`. Hosts running an older Agent must
be manually updated once before the App can queue remote updates for them. The
Agent self-updates are scheduled outside the currently running process, while
API/App runtime updates are executed synchronously by the host Agent. Final
state is confirmed by the next heartbeat or runtime validation.

The Agent derives `mnscloud.api.update` and `mnscloud.app.update` before each
heartbeat from executable local update scripts under
`/opt/mnscloud/mnscloud-api` and `/opt/mnscloud/mnscloud-app`. When either
capability is active, the heartbeat also reports the installed local runtime
version for that product. The API compares this host inventory against the
published release manifest before exposing an update action in the App. A
release alone is not enough to mark API/App as updateable.

## Local Uninstall

Agent lifecycle scripts are intentionally symmetric:

- `scripts/install-agent.sh`
- `scripts/update-agent.sh`
- `scripts/uninstall-agent.sh`

Windows uses the same lifecycle naming with PowerShell scripts:

- `scripts/install-agent-windows.ps1`
- `scripts/update-agent-windows.ps1`
- `scripts/uninstall-agent-windows.ps1`

The Linux uninstaller removes the local systemd service, runtime files,
configuration, state, and logs:

```text
/etc/systemd/system/mnscloud-agent.service
/opt/mnscloud/agent
/etc/mnscloud/agent
/var/lib/mnscloud/agent
/var/log/mnscloud/agent
```

The repository checkout is preserved by default so an operator can reinstall or
inspect scripts after cleanup. Passing `--remove-repository` also removes
`/opt/mnscloud/mnscloud-agent`.

The Windows uninstaller removes the `MNSCloudAgent` service,
`C:\Program Files\MNSCloud\Agent`, and `C:\ProgramData\MNSCloud\Agent`,
including the local UUID and runtime token.

Local uninstall does not delete the Agent record in the MNSCloud API. Operators
must delete or deactivate that record in the App when the identity should no
longer be used.

## Configuration

Canonical Linux local file:

```text
/etc/mnscloud/agent/agent.conf
```

Canonical Windows local file:

```text
C:\ProgramData\MNSCloud\Agent\agent.conf
```

Linux format:

```ini
[agent]
name = server-01-local-label
hostname = server-01.local
api_base = https://dev1.publichost.cloud
poll_interval_ms = 15000
heartbeat_interval_ms = 60000
cyber_security_sync_interval_ms = 60000

[identity]
agent_uuid_file = /var/lib/mnscloud/agent/agent.uuid
agent_token_file = /var/lib/mnscloud/agent/agent.token

[capabilities]
linux.status = true
linux.package.install = true
linux.service.manage = true
linux.file.manage = true
mnscloud.agent.update = true
mnscloud.api.update = false
mnscloud.app.update = false
security.nftables.manage = true
security.crowdsec.manage = true
security.logs.read = true
voip.asterisk.manage = false
voip.freeswitch.manage = false
realtime.webrtc.manage = false
realtime.turn.manage = false
docker.manage = false
shell.exec = false

[recordings]
roots = /var/lib/freeswitch/recordings,/var/spool/asterisk/monitor
mounts =
delete_after_upload = true

[media_files]
roots = /var/lib/mnscloud/files
mounts =

[nginx_edge]
config_dir = /etc/nginx/mnscloud/theme-domains
acme_root = /var/www/certbot
ssl_live_dir = /etc/letsencrypt/live
ssl_archive_dir = /etc/letsencrypt/archive
ssl_renewal_dir = /etc/letsencrypt/renewal
app_upstream = $app_upstream
api_upstream = $api_upstream
test_command = nginx -t
reload_command = systemctl reload nginx

[certbot]
command = certbot
default_email =

[realtime_webrtc_edge]
sync_command = /opt/mnscloud/kamailio-webrtc/scripts/update-kamailio-webrtc.sh

[commands]
asterisk_cli = asterisk
freeswitch_cli = fs_cli
asterisk_ami_host = 127.0.0.1
asterisk_ami_port = 5038
asterisk_ami_username =
asterisk_ami_secret =
freeswitch_esl_host = 127.0.0.1
freeswitch_esl_port = 8021
freeswitch_esl_password =
timeout_ms = 15000
```

Windows hosts use Windows-specific capabilities:

```ini
[capabilities]
windows.status = true
windows.package.install = true
windows.service.manage = true
windows.file.manage = true
windows.eventlog.read = true
windows.firewall.manage = true
windows.defender.status = true
security.crowdsec.manage = true
security.windows.firewall.manage = true
security.windows.eventlog.read = true
security.windows.defender.manage = false
shell.exec = false
```

Do not use `.env` for the Agent. Identity and state live under
`/var/lib/mnscloud/agent` on Linux and `C:\ProgramData\MNSCloud\Agent` on
Windows.

## Database

Canonical model:

- `MonitoringAgent`: identity, token, hostname, version, status, heartbeat, and
  tenant.
- `MonitoringAgentCapability`: capabilities declared by the Agent, such as
  `linux.status`, `security.crowdsec.manage`, and `voip.asterisk.manage`.
- `MonitoringAgentAssignment`: resources assigned to the Agent, such as
  `voip.pabx.server` or future cyber security resources.

Do not add type, mode, privilege, or resource columns directly to
`MonitoringAgent`. Relationships must stay capability-based and
assignment-based.

## Supported Systems

Supported Linux systems:

- Debian 12/13
- RHEL 9/10
- Rocky Linux 9/10
- AlmaLinux 9/10

Supported Windows systems:

- Windows Server 2019/2022/2025
- Windows 10/11 Pro/Enterprise

Other Linux distributions or Windows editions are experimental. They may work
when the required runtime tools are available, but they are not guaranteed to be
100% compatible.

## API

Canonical endpoints:

- `POST /api/v1/agent/heartbeat`
- `POST /api/v1/agent/jobs/lease`
- `POST /api/v1/agent/jobs/:uuid/progress`
- `POST /api/v1/agent/jobs/:uuid/complete`
- `POST /api/v1/agent/jobs/:uuid/fail`

Canonical headers:

- `Authorization: Bearer <token>`
- `X-MNSCloud-Agent-UUID: <uuid>`

Do not create technology-specific Agent endpoints. PABX, cyber security, and
future functions must use the same lease/progress/complete/fail flow with
`jobType` and typed payloads.

## Language Policy

All public Agent repository content must be written in English: documentation,
installer messages, code comments, examples, commit-facing text, and user-facing
runtime output. Keep Portuguese only in external discussions, not inside this
repository.

## Capabilities

Capabilities are stable, granular names. Examples:

- `linux.status`
- `linux.package.install`
- `linux.service.manage`
- `linux.file.manage`
- `mnscloud.agent.update`
- `mnscloud.api.update`
- `mnscloud.app.update`
- `security.nftables.manage`
- `security.crowdsec.manage`
- `security.logs.read`
- `nginx-edge.manage`
- `certbot.manage`
- `voip.asterisk.manage`
- `voip.freeswitch.manage`
- `docker.manage`
- `shell.exec`
- `windows.status`
- `windows.package.install`
- `windows.service.manage`
- `windows.file.manage`
- `windows.eventlog.read`
- `windows.firewall.manage`
- `windows.defender.status`
- `security.windows.firewall.manage`
- `security.windows.eventlog.read`
- `security.windows.defender.manage`

The Agent declares capabilities in heartbeat requests. The API uses capabilities
together with assignments to decide which jobs may be delivered.

## PABX

For PABX, the assignment remains `voip.pabx.server`, but the capability is
engine-specific:

- Asterisk: `voip.asterisk.manage`
- FreeSWITCH: `voip.freeswitch.manage`

With a compatible assignment and capability, the Agent can:

- sync recording uploads;
- remove local recordings after confirmed upload;
- sync offline media files;
- report live SIP registrations from FreeSWITCH heartbeats for dashboard/runtime
  status;
- run typed local commands allowed by jobs;
- use local AMI/ESL when configured, or local CLI as fallback.

FreeSWITCH registration status is collected with
`fs_cli -x "show registrations as json"` and sent as `pabxRegistrations` in the
standard heartbeat. The API owns matching those rows to tenant PABX extensions
and deciding whether a registration is current; the Agent only reports what the
local runtime exposes.

## Cyber Security

Cyber security uses the same runtime. Jobs such as nftables and CrowdSec
installation/configuration must require explicit capabilities
(`security.nftables.manage`, `security.crowdsec.manage`) and suitable
assignments.

Implemented cyber security jobs:

- `cyber.security.status`: reports nftables, CrowdSec, firewall bouncer, OS,
  kernel, and server network status.
- `cyber.security.install`: installs and enables `nftables`, `crowdsec`, and the
  CrowdSec firewall bouncer on supported Linux systems. Debian uses the nftables
  bouncer package when available; RHEL-compatible systems use the official RPM
  bouncer package. It also installs the default CrowdSec collections
  `crowdsecurity/linux` and `crowdsecurity/sshd`, unless a job payload supplies
  a different `collections` array. The Linux installer configures the CrowdSec
  Local API on `127.0.0.1:7422`, updates local API credentials, and points the
  firewall bouncer to the same loopback endpoint to avoid conflicts with
  application services that already use port `8080`.
- `cyber.security.profile.apply`: installs the selected CrowdSec collections,
  writes MNSCloud-managed log acquisition, validates local policy artifacts with
  `crowdsec -t`, and reloads CrowdSec. The Linux agent translates profile `mode`
  and `level` into local CrowdSec policy files instead of editing Hub content
  directly:
  - `mode=monitor` writes a selected-service profile with no decisions and
    `on_success: break`.
  - `mode=enforce` writes a selected-service ban profile using
    `defaultDecisionDuration`.
  - `level=strict` writes additional MNSCloud scenarios for Asterisk and
    FreeSWITCH slow SIP enumeration/bruteforce detection.
  - `basic`, `balanced`, and unsupported services rely on the official CrowdSec
    Hub collections without extra local scenarios.

The Linux install job is intentionally conservative. It does not flush existing
firewall rules, does not open inbound ports, and configures the CrowdSec
firewall bouncer using a local bouncer API key.

Windows cyber security uses CrowdSec for Windows and the CrowdSec Windows
Firewall remediation component. Windows jobs must require Windows capabilities
such as `windows.package.install`, `windows.service.manage`,
`security.crowdsec.manage`, and `security.windows.firewall.manage`.

Implemented Windows cyber security behavior:

- `cyber.security.status`: reports Windows Firewall, CrowdSec service, CrowdSec
  Windows Firewall bouncer, OS, host IP, alerts, and decisions.
- `cyber.security.install`: installs CrowdSec and the Windows Firewall bouncer
  through Chocolatey, enables Windows Firewall profiles, starts CrowdSec
  services, and installs the `crowdsecurity/windows` collection by default.
- `cyber.security.profile.apply`: installs configured CrowdSec collections and
  restarts CrowdSec services.

The Windows install job requires Chocolatey. If Chocolatey is not installed, the
job must either install it beforehand or set `installChocolatey=true` in the job
payload.

Reference:

- CrowdSec Linux installation:
  <https://docs.crowdsec.net/u/getting_started/installation/linux/>
- CrowdSec Windows installation:
  <https://docs.crowdsec.net/u/getting_started/installation/windows>
- CrowdSec Windows Firewall remediation component:
  <https://docs.crowdsec.net/u/bouncers/windows_firewall/>

Long-running cyber security jobs report progress before and after each major
step so the platform can display the current stage, percentage, and failure
details without requiring direct database access.

## Nginx Edge And Certbot

The Agent can manage public edge Nginx configuration and certificates when it is
installed on the Nginx edge host and declares these capabilities:

- `nginx-edge.manage`
- `certbot.manage`

The edge host keeps certificate private keys local under `/etc/letsencrypt`.
Nginx reads certificates directly from local files; certificates are not copied
through the API or shared with other modules.

Theme domain provisioning uses this Agent path as the primary production model:
the API creates `NginxEdgeAgentJob` and `CertbotAgentJob` records, the edge
agent leases them with outbound API polling, performs the local Nginx/Certbot
operation, and reports completion back to the API.

Implemented Nginx edge commands:

- `nginx.edge.domain.activate`: writes or refreshes the domain Nginx config.
- `nginx.edge.domain.remove`: removes the domain config and local certificate
  files.
- `nginx.edge.domain.inspect`: reports whether config and certificate files
  exist.
- `nginx.edge.config.test`: runs the configured Nginx config test command.
- `nginx.edge.reload`: runs the configured Nginx reload command.

Implemented Certbot commands:

- `certbot.certificate.issue`: creates the HTTP challenge config, issues a
  certificate with webroot validation using the job payload `email`, then
  refreshes the HTTPS config.
- `certbot.certificates.renew`: renews existing certificates and reloads Nginx
  through the configured deploy hook.
- `certbot.certificate.inspect`: reports local certificate paths for a domain.

For HTTP-01 validation, the Nginx edge host must serve
`/.well-known/acme-challenge/` from the configured `acme_root`, normally
`/var/www/certbot`.

## WebRTC Edge Jobs

WebRTC edge provisioning uses a dedicated job contract instead of the generic
Nginx edge domain commands.

- Capability: `realtime.webrtc.manage`
- Job type: `realtime_webrtc_edge`
- Command: `realtime.webrtc.sync`
- Local command: `[realtime_webrtc_edge].sync_command`

The Agent derives API/App update capabilities, realtime runtime capabilities,
and Asterisk/FreeSWITCH management capabilities from the matching local command
being present and executable. This check runs on startup and before each
heartbeat/job polling loop, so a host that installs or removes a runtime
publishes its current capability without relying on stale static config.

The API assigns or auto-discovers the Agent for a `realtime.webrtc.server`,
queues a `RealtimeWebRtcAgentJob`, and the Agent executes only the configured
sync command. The sync command is expected to be the runtime script from
`mnscloud-kamailio-webrtc`, which fetches the edge config from the API, renders
Nginx/Kamailio files, validates both services, and reloads them locally.

WebRTC jobs are not Nginx edge jobs. The generic `nginx-edge.manage` capability
owns App/API/theme-domain HTTP edge work only. SIP/WSS, RTP/SRTP, TURN/STUN,
SFU/video media, rtpengine control, and PABX exposure must use
WebRTC/media-specific capabilities and dedicated realtime modules.

TURN/STUN hosts expose `realtime.turn.manage` when `[turn_edge].sync_command`
points to an executable `mnscloud-turn` runtime script. TURN jobs must stay
typed and API/DB-owned before the Agent executes local runtime sync.
