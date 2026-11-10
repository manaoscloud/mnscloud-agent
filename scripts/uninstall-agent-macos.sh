#!/bin/bash
# Removes the macOS Agent (launchd daemon, code, configuration, identity and logs).
# Bash 3.2 compatible.
set -euo pipefail

LOG_PREFIX="[uninstall-agent-macos]"
SERVICE_LABEL="cloud.manaos.mnscloud.agent"
UPDATE_LABEL="cloud.manaos.mnscloud.agent-update"
DRY_RUN=false
REMOVE_REPOSITORY=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --remove-repository) REMOVE_REPOSITORY=true; shift ;;
    --help|-h) echo "Usage: sudo bash scripts/uninstall-agent-macos.sh [--dry-run] [--remove-repository]"; exit 0 ;;
    *) echo "${LOG_PREFIX} unsupported option: $1" >&2; exit 2 ;;
  esac
done

run() {
  local command="$1"
  if $DRY_RUN; then echo "${LOG_PREFIX} DRY-RUN ${command}"; else /bin/bash -c "$command"; fi
}

$DRY_RUN || [[ "$(id -u)" -eq 0 ]] || { echo "${LOG_PREFIX} ERROR run as root" >&2; exit 1; }
run "launchctl bootout system/${SERVICE_LABEL} 2>/dev/null || true"
run "launchctl bootout system/${UPDATE_LABEL} 2>/dev/null || true"
run "rm -f /Library/LaunchDaemons/${SERVICE_LABEL}.plist"
run "rm -rf /opt/mnscloud/agent /etc/mnscloud/agent /var/lib/mnscloud/agent /var/log/mnscloud/agent"
if $REMOVE_REPOSITORY; then
  run "rm -rf /opt/mnscloud/mnscloud-agent"
fi
echo "${LOG_PREFIX} OK MNSCloud Agent removed from this Mac."
