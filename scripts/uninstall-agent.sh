#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[uninstall-agent]"
DRY_RUN=false
REMOVE_REPOSITORY=false
LOG_FILE="${LOG_FILE:-/var/log/mnscloud-agent-uninstall.log}"

usage() {
  cat <<'TXT'
Usage:
  scripts/uninstall-agent.sh [--dry-run] [--remove-repository]

Uninstalls the native MNSCloud Agent systemd service and removes local runtime,
configuration, state, and log files from this host.

Options:
  --dry-run             Show what would be removed without changing the host.
  --remove-repository   Also remove /opt/mnscloud/mnscloud-agent after cleanup.
TXT
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --remove-repository)
      REMOVE_REPOSITORY=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "${LOG_PREFIX} unsupported option: $1" >&2
      usage
      exit 2
      ;;
  esac
done

log() {
  local level="$1"; shift
  local message="$*"
  echo "${LOG_PREFIX} ${level} ${message}"
  printf "[%s] %s %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >> "$LOG_FILE" || true
}

info() { log INFO "$*"; }
ok() { log OK "$*"; }
fail() { log ERROR "$*"; exit 1; }

run() {
  if $DRY_RUN; then
    log DRY-RUN "$*"
    return 0
  fi
  info "RUN: $*"
  bash -c "$*"
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "Run as root, for example: sudo bash $0"
}

remove_path() {
  local path="$1"
  if [[ -e "$path" || -L "$path" ]]; then
    run "rm -rf '${path}'"
  else
    ok "Path already absent: ${path}"
  fi
}

main() {
  local service_name="mnscloud-agent"
  local service_file="/etc/systemd/system/${service_name}.service"
  local install_dir="/opt/mnscloud/agent"
  local config_dir="/etc/mnscloud/agent"
  local data_dir="/var/lib/mnscloud/agent"
  local logs_dir="/var/log/mnscloud/agent"
  local repository_dir="/opt/mnscloud/mnscloud-agent"

  require_root

  info "Stopping ${service_name}.service if present."
  if command -v systemctl >/dev/null 2>&1; then
    run "systemctl disable --now '${service_name}.service' >/dev/null 2>&1 || true"
  fi

  remove_path "$service_file"

  if command -v systemctl >/dev/null 2>&1; then
    run "systemctl daemon-reload"
    run "systemctl reset-failed '${service_name}.service' >/dev/null 2>&1 || true"
  fi

  remove_path "$install_dir"
  remove_path "$config_dir"
  remove_path "$data_dir"
  remove_path "$logs_dir"

  if $REMOVE_REPOSITORY; then
    remove_path "$repository_dir"
  else
    info "Repository checkout preserved: ${repository_dir}"
  fi

  ok "mnscloud-agent local uninstall completed."
  info "Delete or deactivate the Agent record in MNSCloud before reusing the host identity."
}

main "$@"
