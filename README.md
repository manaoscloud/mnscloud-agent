# mnscloud-agent

Standalone native MNSCloud Agent.

The Agent runs as a native service and communicates with the MNSCloud API
through outbound HTTPS. Linux hosts use `systemd`; Windows hosts use a Windows
Service. There is a single runtime: the Agent only runs work allowed by local
capabilities declared in `agent.conf`, API assignments, and typed jobs.

## Contract

- Product/runtime: `mnscloud-agent`
- Project directory: `agent/`
- Linux installer: `scripts/install-agent.sh`
- Windows installer: `scripts/install-agent-windows.ps1`
- Linux service: `mnscloud-agent.service`
- Windows service: `MNSCloudAgent`
- Linux configuration: `/etc/mnscloud/agent/agent.conf`
- Windows configuration: `C:\ProgramData\MNSCloud\Agent\agent.conf`
- Linux state: `/var/lib/mnscloud/agent`
- Windows state: `C:\ProgramData\MNSCloud\Agent`

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

## Repository Access

Install GitHub CLI if needed:
[cli/cli installation](https://github.com/cli/cli#installation).

Authenticate GitHub CLI:

```bash
gh auth login
```

Clone the private repository:

```bash
sudo install -d -m 0755 /opt/mnscloud
cd /opt/mnscloud
gh repo clone manaoscloud/mnscloud-agent
cd /opt/mnscloud/mnscloud-agent
```

## Linux Installation

```bash
sudo bash scripts/install-agent.sh
```

The installer prepares Deno, creates or reuses
`/var/lib/mnscloud/agent/agent.uuid`, writes `agent.conf`, installs the systemd
unit, and starts `mnscloud-agent`.

After installation, register the UUID in MNSCloud and generate an Agent token.
The token is stored in `/var/lib/mnscloud/agent/agent.token`; restart the
service after writing it.

## Windows Installation

Run from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\scripts\install-agent-windows.ps1 -ApiBase "https://api.example.com" -Name "windows-server-01"
```

The Windows installer prepares Deno, creates or reuses
`C:\ProgramData\MNSCloud\Agent\agent.uuid`, writes `agent.conf`, installs the
`MNSCloudAgent` Windows Service, and starts it.

After installation, register the UUID in MNSCloud and generate an Agent token.
The token is stored in `C:\ProgramData\MNSCloud\Agent\agent.token`; restart the
service after writing it:

```powershell
Restart-Service MNSCloudAgent
```

Long-running jobs report progress back to the platform, including stage,
percentage, and error details. Operators should use the MNSCloud UI job details
view as the primary troubleshooting surface instead of querying the database.

## Updating

Use the explicit update command when this repository has a newer Agent version:

```bash
cd /opt/mnscloud/mnscloud-agent
sudo bash scripts/update-agent.sh
```

Windows update:

```powershell
.\scripts\update-agent-windows.ps1
```

The update command syncs the repository, reinstalls service files, preserves the
existing Agent UUID/token, reuses the current API base URL and Agent name from
`/etc/mnscloud/agent/agent.conf`, then restarts `mnscloud-agent.service`.

Manual equivalent:

```bash
cd /opt/mnscloud/mnscloud-agent
gh repo sync
sudo bash scripts/install-agent.sh
sudo systemctl restart mnscloud-agent.service
sudo systemctl status mnscloud-agent.service --no-pager
```

The installer does not automatically pull code on every run. Updates are
explicit so production servers do not execute new public code unless the
operator intentionally requests it.

## Security

- Communication is always outbound to the API.
- There is one Agent runtime; limits are enforced through OS permissions,
  capabilities, assignments, and jobs.
- Capabilities are declared by the host and synchronized on heartbeat.
- Nginx edge and Certbot can be enabled on the public edge host through
  `nginx-edge.manage` and `certbot.manage` capabilities.
- Windows cyber security uses Windows-specific capabilities and jobs. It does
  not receive Linux-only nftables/systemd jobs.
- Permanent storage credentials stay only in the API.
- Jobs use temporary authorization, such as signed URLs.
- Local files can only be read or written inside configured roots.
- Local recordings may be removed only after upload is confirmed.

See [agent.md](./agent.md) for the full design and [SKILL.md](./SKILL.md) for
the technical evolution contract.
