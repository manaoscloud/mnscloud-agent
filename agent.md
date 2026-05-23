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
3. The operator registers the UUID in MNSCloud.
4. MNSCloud generates the token and the operator writes the local `agent.token`.
5. The Agent sends heartbeat requests to `POST /api/v1/agent/heartbeat`.
6. Heartbeat synchronizes host-declared capabilities.
7. The API returns jobs through `POST /api/v1/agent/jobs/lease` according to
   capabilities and assignments.
8. The Agent runs the job locally and reports success or failure.

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
name = server-01
hostname = server-01.local
api_base = https://dev1.publichost.cloud
version = 0.1.0
poll_interval_ms = 15000
heartbeat_interval_ms = 60000

[identity]
agent_uuid_file = /var/lib/mnscloud/agent/agent.uuid
agent_token_file = /var/lib/mnscloud/agent/agent.token

[capabilities]
linux.status = true
linux.package.install = true
linux.service.manage = true
linux.file.manage = true
security.nftables.manage = true
security.crowdsec.manage = true
security.logs.read = true
voip.asterisk.manage = false
voip.freeswitch.manage = false
webrtc.kamailio.manage = false
docker.manage = false
shell.exec = false

[recordings]
roots = /var/lib/freeswitch/recordings,/var/spool/asterisk/monitor
mounts =
delete_after_upload = true

[media_files]
roots = /var/lib/mnscloud/pabx/media-files
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

[webrtc_edge]
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
  `voip_pabx_server` or future cyber security resources.

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

For PABX, the assignment remains `voip_pabx_server`, but the capability is
engine-specific:

- Asterisk: `voip.asterisk.manage`
- FreeSWITCH: `voip.freeswitch.manage`

With a compatible assignment and capability, the Agent can:

- sync recording uploads;
- remove local recordings after confirmed upload;
- sync offline media files;
- run typed local commands allowed by jobs;
- use local AMI/ESL when configured, or local CLI as fallback.

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
  a different `collections` array.

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

- Capability: `webrtc.kamailio.manage`
- Job type: `webrtc_edge`
- Command: `webrtc.edge.sync`
- Local command: `[webrtc_edge].sync_command`

The API assigns or auto-discovers the Agent for a `voip_webrtc_server`, queues a
`VoipWebRtcAgentJob`, and the Agent executes only the configured sync command.
The sync command is expected to be the runtime script from
`mnscloud-kamailio-webrtc`, which fetches the edge config from the API, renders
Nginx/Kamailio files, validates both services, and reloads them locally.
