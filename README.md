# mnscloud-agent

Standalone native MNSCloud Agent.

The Agent runs as a native `systemd` service on a Linux server and communicates
with the MNSCloud API through outbound HTTPS. There is a single runtime: the
Agent only runs work allowed by local capabilities declared in `agent.conf`, API
assignments, and typed jobs.

## Contract

- Product/runtime: `mnscloud-agent`
- Project directory: `agent/`
- Installer: `agent/scripts/install-agent.sh`
- Service: `mnscloud-agent.service`
- Local configuration: `/etc/mnscloud/agent/agent.conf`
- Local state: `/var/lib/mnscloud/agent`
- Local logs: `/var/log/mnscloud/agent`

## Repository Access

Install GitHub CLI if needed, authenticate, and clone the private repository. If
`gh` is not installed yet, follow the official installation guide:
[cli/cli installation](https://github.com/cli/cli#installation).

```bash
gh auth login
gh auth status

sudo install -d -m 0755 /opt/mnscloud
cd /opt/mnscloud
gh repo clone manaoscloud/mnscloud-agent
cd /opt/mnscloud/mnscloud-agent
```

## Installation

```bash
sudo bash scripts/install-agent.sh
```

The installer prepares Deno, creates or reuses
`/var/lib/mnscloud/agent/agent.uuid`, writes `agent.conf`, installs the systemd
unit, and starts `mnscloud-agent`.

After installation, register the UUID in MNSCloud and generate an Agent token.
The token is stored in `/var/lib/mnscloud/agent/agent.token`; restart the
service after writing it.

Long-running jobs report progress back to the platform, including stage,
percentage, and error details. Operators should use the MNSCloud UI job details
view as the primary troubleshooting surface instead of querying the database.

## Updating

Use the explicit update command when this repository has a newer Agent version:

```bash
cd /opt/mnscloud/mnscloud-agent
sudo bash scripts/update-agent.sh
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
- Permanent storage credentials stay only in the API.
- Jobs use temporary authorization, such as signed URLs.
- Local files can only be read or written inside configured roots.
- Local recordings may be removed only after upload is confirmed.

See [agent.md](./agent.md) for the full design and [SKILL.md](./SKILL.md) for
the technical evolution contract.
