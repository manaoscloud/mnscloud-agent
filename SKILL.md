# Agent Module Skill

Use this contract when changing the `agent/` module.

## Source Of Truth

- Runtime: `main.ts`
- Installer: `scripts/install-agent.sh`
- Update command: `scripts/update-agent.sh`
- Release manifest: `releases/manifest.json`
- Release helper: `scripts/release-agent.sh`
- Uninstall command: `scripts/uninstall-agent.sh`
- Generated systemd unit: `mnscloud-agent.service`
- Windows installer: `scripts/install-agent-windows.ps1`
- Windows update command: `scripts/update-agent-windows.ps1`
- Windows uninstall command: `scripts/uninstall-agent-windows.ps1`
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

Lifecycle script names must stay symmetric:

- `install-agent`
- `update-agent`
- `uninstall-agent`

Production lifecycle refs must be Git tags. `main` is a development integration
branch and must not be advertised to the application as a production update.

## Language Policy

All files inside `mnscloud-agent/` must use English only for documentation,
installer messages, code comments, examples, commit-facing text, and runtime
output. Do not add Portuguese text to this repository.

## Model

There is a single Agent runtime. Do not create parallel execution modes in the
product. Specific resources are represented by:

- `capabilities`: example `security.crowdsec.manage`, `voip.asterisk.manage`
- `assignments`: example `voip.pabx.server`, `realtime.webrtc.server`
- `jobs`: example `cyber.security`, `recording.upload`, `pabx.command`,
  `realtime.webrtc.edge`, `voip.sbc.runtime`

Do not add direct resource, mode, or privilege coupling to the Agent's primary
identity.

## Security

- Communication is outbound-only over HTTPS.
- This repository is public by design and consumes the MNSCloud API contract.
- The installer does not define tenant, resource, or function ownership.
- Enrollment generated from an existing Agent must preserve that Agent as the
  canonical identity. The installer may send a local UUID, but it must persist
  the Agent UUID returned by the API response.
- Installer/update runs without a new enrollment token must validate the
  existing local `agent.uuid` and `agent.token` against the API before
  installing or starting the service. Deleted or invalid Agent identities must
  fail closed and require local uninstall plus a new generated install command.
- The Agent declares local capabilities; the API decides delivery by capability
  and assignment.
- `pabx.command` is a typed allowlist, never a remote shell. Runtime diagnostics may run only fixed
  local CLI queries derived from API-owned resource identifiers; their output must be bounded and
  redacted before completion.
- Linux install/reinstall must explicitly restart `mnscloud-agent` after
  rewriting runtime files, `agent.conf`, or the systemd unit, then synchronize
  installed capabilities with the API. Do not turn capability refresh into a
  manual operator restart step.
- The Agent token lives at `/var/lib/mnscloud/agent/agent.token`.
- On Windows, the Agent token lives at
  `C:\ProgramData\MNSCloud\Agent\agent.token`.
- Permanent storage credentials stay only in the API.
- Jobs use temporary authorization, preferably signed URLs.
- Local commands must be typed and allowlisted in the runtime.
- Do not commit secrets, customer data, production IPs, tenant-specific values,
  private business rules, static master tokens, or API bypasses.

## Release And Update Contract

- `VERSION` is the installed semantic version without the `v` prefix.
- Git tags use `vX.Y.Z`.
- `releases/manifest.json` is the canonical source for application update
  discovery.
- The application/API should compare heartbeat `version` and `updateChannel`
  against the manifest channel and return the target `ref`.
- `scripts/update-agent.sh --ref vX.Y.Z` is the production update command.
- Omitted `--ref` must fail closed; implicit branch updates are not supported.
- Remote App/API/Agent updates must queue `runtime.update` jobs with an explicit
  `product`, product capability, and `targetRef`; they are supported only by
  Agent `1.0.6` or newer.
- App/API updates are product rollout operations owned by the API/control plane.
  Browser UI must request the runtime product fleet and queue the product
  rollout; it must not infer cluster membership or expose App/API update actions
  as ordinary per-row agent buttons. The rollout may create one or many
  `runtime.update` jobs depending on the eligible online agents reported in
  `MonitoringAgentRuntime`.
- Agents older than `1.0.6` require one manual tagged update before remote
  updates can be offered in the App.
- Operator-visible releases are published by the repository `Auto Release`
  GitHub Actions workflow after validated changes are committed and pushed to
  `main`.
- Do not mark a new release as available until the matching release commit, Git
  tag, and GitHub Release exist on GitHub.
- `scripts/release-agent.sh --version X.Y.Z --channel stable --publish` is the
  canonical release engine used by Actions and is reserved for break-glass
  maintainer use.
- Do not copy release logic into this repository; the release script must use
  the shared `mnscloud-runtime-kit/lib/release.sh` helper.

## Checklist

- Update documentation when changing the Agent contract.
- Run a residue search for obsolete names.
- Check that `mnscloud-agent/` contains no Portuguese text.
- Keep Nginx edge functionality capability-based with `nginx-edge.manage`; do
  not create a separate edge-specific agent runtime.
- Keep Certbot functionality capability-based with `certbot.manage`; private
  keys remain local to the edge host.
- Keep WebRTC edge functionality capability-based with `realtime.webrtc.manage`;
  the Agent may run only the configured local sync command for
  `realtime.webrtc.sync` jobs. The effective capability must be derived from
  `[realtime.webrtc.edge].sync_command` being executable, not from stale static
  state.
- Keep TURN/STUN edge functionality capability-based with
  `realtime.turn.manage`; the Agent may run only typed TURN jobs once the
  API/control plane owns the corresponding contract. The effective capability
  must be derived from `[turn_edge].sync_command` being executable, not from
  stale static state.
- Keep realtime/media responsibilities out of the generic Nginx edge capability.
  SIP/WSS, RTP/SRTP, TURN/STUN, SFU/video media, rtpengine control, and PABX
  exposure require WebRTC/media-specific capabilities and typed jobs.
- Keep Linux and Windows capabilities separate. Linux jobs must not assume
  Windows paths/services, and Windows jobs must not assume systemd, nftables,
  `/etc`, `/var`, or POSIX shells.
- Linux Cyber Security must install CrowdSec through the official CrowdSec
  package repository on Debian/RHEL package families, using `apt` for Debian
  12/13 and `dnf`/RPM for RHEL, Rocky Linux, and AlmaLinux 9/10.
- Windows Cyber Security must use CrowdSec for Windows plus the CrowdSec Windows
  Firewall remediation component.
- Validate `scripts/install-agent.sh` with `bash -n`.
- Validate `scripts/update-agent.sh` with `bash -n`.
- Validate `scripts/release-agent.sh` with `bash -n`.
- Validate `scripts/uninstall-agent.sh` with `bash -n`.
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
