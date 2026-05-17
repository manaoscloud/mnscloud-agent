# Agent Module Skill

Use this contract when changing the `agent/` module.

## Source Of Truth

- Runtime: `agent/main.ts`
- Installer: `agent/scripts/install-agent.sh`
- Update command: `agent/scripts/update-agent.sh`
- Generated systemd unit: `mnscloud-agent.service`
- Documentation: `agent/agent.md`
- API runtime: `api/routes/agentRoute.ts`, `api/controllers/agentController.ts`, `api/services/agentRuntimeService.ts`
- Monitoring model: `MonitoringAgent`, `MonitoringAgentCapability`, `MonitoringAgentAssignment`

## Required Naming

- Product: `mnscloud-agent`
- Directory: `agent`
- Service: `mnscloud-agent`
- Local configuration: `agent.conf`

Never create technology-specific names, routes, modes, or installers. This module contract is always generic.

## Language Policy

All files inside `agent/` must use English only for documentation, installer messages, code comments, examples, commit-facing text, and runtime output. Do not add Portuguese text to this repository.

## Model

There is a single Agent runtime. Do not create parallel execution modes in the product. Specific resources are represented by:

- `capabilities`: example `security.crowdsec.manage`, `voip.asterisk.manage`
- `assignments`: example `voip_pabx_server`
- `jobs`: example `cyber_security`, `recording_upload`, `pabx_command`

Do not add direct resource, mode, or privilege coupling to the Agent's primary identity.

## Security

- Communication is outbound-only over HTTPS.
- This repository is public by design and consumes the MNSCloud API contract.
- The installer does not define tenant, resource, or function ownership.
- The Agent declares local capabilities; the API decides delivery by capability and assignment.
- The Agent token lives at `/var/lib/mnscloud/agent/agent.token`.
- Permanent storage credentials stay only in the API.
- Jobs use temporary authorization, preferably signed URLs.
- Local commands must be typed and allowlisted in the runtime.
- Do not commit secrets, customer data, production IPs, tenant-specific values, private business
  rules, static master tokens, or API bypasses.

## Checklist

- Update documentation when changing the Agent contract.
- Run a residue search for obsolete names.
- Check that `agent/` contains no Portuguese text.
- Validate `agent/scripts/install-agent.sh` with `bash -n`.
- Validate `agent/main.ts` with `deno check`.
- Validate related API services with `deno check` when changing the API contract.
- Validate frontend with `npm --prefix app run build` when changing UI.

## Contribution Governance

- External contributions must be submitted through Pull Requests.
- Follow `CONTRIBUTING.md`, `SECURITY.md`, `AGENTS.md`, and this `SKILL.md` before proposing changes.
- Do not add secrets, customer data, private infrastructure details, production domains/IPs, or hidden bypass logic.
- MNSCloud may choose to pay, sponsor, contract, or hire contributors when work demonstrates strong value, but paid work requires explicit written agreement and is never implied by opening a Pull Request.
- Keep security-sensitive decisions, tenant scope, billing, authorization, routing ownership, and secret resolution in the MNSCloud API/control plane.
