# MNSCloud Agent

## Overview

`mnscloud-agent` is the platform's standalone local Agent. It is not named after
PABX, firewall, Docker, or any other specific function; those behaviors are
represented as capabilities and jobs. There is a single runtime. Its effective
limits come from operating system permissions, `agent.conf`, synchronized
capabilities, and API assignments.

## Architecture

1. The installer creates `/etc/mnscloud/agent/agent.conf`.
2. The installer creates or reuses `/var/lib/mnscloud/agent/agent.uuid`.
3. The operator registers the UUID in MNSCloud.
4. MNSCloud generates the token and the operator writes
   `/var/lib/mnscloud/agent/agent.token`.
5. The Agent sends heartbeat requests to `POST /api/v1/agent/heartbeat`.
6. Heartbeat synchronizes host-declared capabilities.
7. The API returns jobs through `POST /api/v1/agent/jobs/lease` according to
   capabilities and assignments.
8. The Agent runs the job locally and reports success or failure.

## Configuration

Canonical local file:

```text
/etc/mnscloud/agent/agent.conf
```

Format:

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
docker.manage = false
shell.exec = false

[recordings]
roots = /var/lib/freeswitch/recordings,/var/spool/asterisk/monitor
mounts =
delete_after_upload = true

[media_files]
roots = /var/lib/mnscloud/pabx/media-files
mounts =

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

Do not use `.env` for the Agent. Identity and state live under
`/var/lib/mnscloud/agent`.

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
- `voip.asterisk.manage`
- `voip.freeswitch.manage`
- `docker.manage`
- `shell.exec`

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
- `cyber.security.install`: installs and enables `nftables`, `crowdsec`, and
  `crowdsec-firewall-bouncer-nftables` on supported Debian-like systems. It also
  installs the default CrowdSec collections `crowdsecurity/linux` and
  `crowdsecurity/sshd`, unless a job payload supplies a different `collections`
  array.

The install job is intentionally conservative. It does not flush existing
firewall rules, does not open inbound ports, and configures the CrowdSec
firewall bouncer for nftables using a local bouncer API key.

Long-running cyber security jobs report progress before and after each major
step so the platform can display the current stage, percentage, and failure
details without requiring direct database access.
