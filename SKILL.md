# Agent Module Skill

Use this contract when changing the `agent/` module.

## Source Of Truth

- Runtime: `main.ts`
- Installer: `scripts/install-agent.sh`
- Update command: `scripts/update-agent.sh`
- Generated systemd unit: `mnscloud-agent.service`
- Windows installer: `scripts/install-agent-windows.ps1`
- Windows update command: `scripts/update-agent-windows.ps1`
- Generated Windows service: `MNSCloudAgent`
- Documentation: `agent.md`
- API runtime: `mnscloud-api/routes/agentRoute.ts`,
  `mnscloud-api/controllers/agentController.ts`,
  `mnscloud-api/services/agentRuntimeService.ts`
- Monitoring model: `MonitoringAgent`, `MonitoringAgentCapability`,
  `MonitoringAgentAssignment`

## Supported Systems

- Linux: Debian 12/13, RHEL 9/10, Rocky Linux 9/10, AlmaLinux 9/10.
- Windows: Windows Server 2019/2022/2025 and Windows 10/11 Pro/Enterprise.
- Other systems are experimental and must be documented as best-effort only.

## Required Naming

- Product: `mnscloud-agent`
- Directory: `mnscloud-agent`
- Service: `mnscloud-agent`
- Local configuration: `agent.conf`

Never create technology-specific names, routes, modes, or installers. This
module contract is always generic.

## Language Policy

All files inside `mnscloud-agent/` must use English only for documentation,
installer messages, code comments, examples, commit-facing text, and runtime
output. Do not add Portuguese text to this repository.

## Model

There is a single Agent runtime. Do not create parallel execution modes in the
product. Specific resources are represented by:

- `capabilities`: example `security.crowdsec.manage`, `voip.asterisk.manage`
- `assignments`: example `voip_pabx_server`, `voip_webrtc_server`
- `jobs`: example `cyber_security`, `recording_upload`, `pabx_command`,
  `webrtc_edge`

Do not add direct resource, mode, or privilege coupling to the Agent's primary
identity.

## Security

- Communication is outbound-only over HTTPS.
- This repository is public by design and consumes the MNSCloud API contract.
- The installer does not define tenant, resource, or function ownership.
- Enrollment generated from an existing Agent must preserve that Agent as the
  canonical identity. The installer may send a local UUID, but it must persist
  the Agent UUID returned by the API response.
- The Agent declares local capabilities; the API decides delivery by capability
  and assignment.
- The Agent token lives at `/var/lib/mnscloud/agent/agent.token`.
- On Windows, the Agent token lives at
  `C:\ProgramData\MNSCloud\Agent\agent.token`.
- Permanent storage credentials stay only in the API.
- Jobs use temporary authorization, preferably signed URLs.
- Local commands must be typed and allowlisted in the runtime.
- Do not commit secrets, customer data, production IPs, tenant-specific values,
  private business rules, static master tokens, or API bypasses.

## Checklist

- Update documentation when changing the Agent contract.
- Run a residue search for obsolete names.
- Check that `mnscloud-agent/` contains no Portuguese text.
- Keep Nginx edge functionality capability-based with `nginx-edge.manage`; do
  not create a separate edge-specific agent runtime.
- Keep Certbot functionality capability-based with `certbot.manage`; private
  keys remain local to the edge host.
- Keep WebRTC edge functionality capability-based with `webrtc.kamailio.manage`;
  the Agent may run only the configured local sync command for
  `webrtc.edge.sync` jobs.
- Keep Linux and Windows capabilities separate. Linux jobs must not assume
  Windows paths/services, and Windows jobs must not assume systemd, nftables,
  `/etc`, `/var`, or POSIX shells.
- Linux Cyber Security must install CrowdSec through the official CrowdSec
  package repository on Debian/RHEL package families, using `apt` for Debian
  12/13 and `dnf`/RPM for RHEL, Rocky Linux, and AlmaLinux 9/10.
- Windows Cyber Security must use CrowdSec for Windows plus the CrowdSec Windows
  Firewall remediation component.
- Validate `scripts/install-agent.sh` with `bash -n`.
- Validate PowerShell installers with PowerShell parser checks when PowerShell
  is available.
- Validate `main.ts` with `deno check`.
- Validate related API services with `deno check` when changing the API
  contract.
- Validate frontend with `npm --prefix mnscloud-app run build` when changing UI.

## Contribution Governance

- External contributions must be submitted through Pull Requests.
- Follow `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md`, and this `SKILL.md`
  before proposing changes.
- Do not add secrets, customer data, private infrastructure details, production
  domains/IPs, or hidden bypass logic.
- MNSCloud may choose to pay, sponsor, contract, or hire contributors when work
  demonstrates strong value, but paid work requires explicit written agreement
  and is never implied by opening a Pull Request.
- Keep security-sensitive decisions, tenant scope, billing, authorization,
  routing ownership, and secret resolution in the MNSCloud API/control plane.
