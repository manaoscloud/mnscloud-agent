#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[install-agent]"
DRY_RUN=false
DEFAULT_API_BASE="${MNSCLOUD_API_BASE:-https://dev1.publichost.cloud}"
AGENT_USER="root"
AGENT_GROUP="root"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${LOG_FILE:-/var/log/mnscloud-agent-install.log}"

usage() {
  cat <<'TXT'
Usage:
  agent/scripts/install-agent.sh [--dry-run] [--api-base URL] [--name NAME]

Installs the single native MNSCloud Agent as a systemd service.
TXT
}

API_BASE=""
AGENT_NAME=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)
      DRY_RUN=true
      shift
      ;;
    --api-base)
      API_BASE="${2:-}"
      shift 2
      ;;
    --name)
      AGENT_NAME="${2:-}"
      shift 2
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
warn() { log WARN "$*"; }
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

write_file() {
  local path="$1" content="$2"
  if $DRY_RUN; then
    log DRY-RUN "write ${path}"
    return 0
  fi
  info "WRITE: ${path}"
  printf "%s\n" "$content" > "$path"
}

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "Run as root, for example: sudo bash $0"
}

detect_os() {
  [[ -r /etc/os-release ]] || fail "Could not read /etc/os-release"
  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${VERSION_ID:-}" in
    debian:12|debian:13) echo "debian" ;;
    rocky:8*|rocky:9*) echo "rocky" ;;
    *) fail "Unsupported operating system. Supported: Debian 12/13 and Rocky 8/9." ;;
  esac
}

install_packages() {
  local os="$1"
  case "$os" in
    debian)
      run "apt-get update -y"
      run "apt-get install -y --no-install-recommends ca-certificates curl unzip"
      ;;
    rocky)
      run "dnf -y makecache"
      run "dnf -y install ca-certificates curl unzip"
      ;;
  esac
}

ensure_deno() {
  if command -v deno >/dev/null 2>&1; then
    ok "Deno is available: $(deno --version | head -n1)"
    return 0
  fi
  install_packages "$(detect_os)"
  run "install -m 0755 -d /usr/local/deno /usr/local/bin"
  run "CI=1 DENO_INSTALL=/usr/local/deno sh -c 'curl -fsSL https://deno.land/install.sh | sh -s -- --no-modify-path'"
  run "ln -sf /usr/local/deno/bin/deno /usr/local/bin/deno"
}

normalize_url() {
  printf "%s" "$1" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g; s#/*$##'
}

prompt_value() {
  local prompt="$1" default_value="${2:-}" value=""
  if [[ -t 0 && -z "${default_value}" ]]; then
    read -r -p "${prompt}: " value
  elif [[ -t 0 ]]; then
    read -r -p "${prompt} [${default_value}]: " value
  fi
  printf "%s" "${value:-$default_value}"
}

new_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  elif [[ -r /proc/sys/kernel/random/uuid ]]; then
    cat /proc/sys/kernel/random/uuid
  else
    deno eval "console.log(crypto.randomUUID())"
  fi
}

detect_capability() {
  local binary="$1"
  command -v "$binary" >/dev/null 2>&1 && printf "true" || printf "false"
}

write_agent_config() {
  local config_file="$1" agent_name="$2" hostname="$3" api_base="$4"
  write_file "$config_file" "# MNSCloud Agent configuration
# Managed by agent/scripts/install-agent.sh

[agent]
name = ${agent_name}
hostname = ${hostname}
api_base = ${api_base}
version = 1.0.0
poll_interval_ms = 15000
heartbeat_interval_ms = 60000

[identity]
agent_uuid_file = /var/lib/mnscloud/agent/agent.uuid
agent_token_file = /var/lib/mnscloud/agent/agent.token

[recordings]
roots = /var/lib/freeswitch/recordings,/var/spool/asterisk/monitor
mounts =
delete_after_upload = true

[media_files]
roots = /var/lib/mnscloud/pabx/media-files
mounts =

[capabilities]
linux.status = true
linux.package.install = true
linux.service.manage = true
linux.file.manage = true
security.nftables.manage = true
security.crowdsec.manage = true
security.logs.read = true
voip.asterisk.manage = $(detect_capability asterisk)
voip.freeswitch.manage = $(detect_capability fs_cli)
docker.manage = $(detect_capability docker)
shell.exec = false

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
"
}

write_service_file() {
  local service_file="$1" agent_dir="$2" config_file="$3"
  write_file "$service_file" "[Unit]
Description=MNSCloud Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${AGENT_USER}
Group=${AGENT_GROUP}
WorkingDirectory=${agent_dir}
ExecStart=$(command -v deno) task start --config ${agent_dir}/deno.jsonc
Environment=MNSCLOUD_AGENT_CONFIG=${config_file}
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=20
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
"
}

main() {
  local api_base agent_uuid agent_name hostname
  local install_dir="/opt/mnscloud/agent"
  local config_dir="/etc/mnscloud/agent"
  local data_dir="/var/lib/mnscloud/agent"
  local logs_dir="/var/log/mnscloud/agent"
  local config_file="${config_dir}/agent.conf"
  local service_file="/etc/systemd/system/mnscloud-agent.service"

  require_root
  ensure_deno

  api_base="$(normalize_url "${API_BASE:-$(prompt_value "MNSCloud API base URL" "$DEFAULT_API_BASE")}")"
  hostname="$(hostname -f 2>/dev/null || hostname)"
  agent_name="${AGENT_NAME:-$(prompt_value "Agent name" "$hostname")}"

  info "Preparing native mnscloud-agent..."
  run "mkdir -p '${install_dir}' '${config_dir}' '${data_dir}' '${logs_dir}' /var/lib/mnscloud/pabx/media-files"
  run "cp '${AGENT_SOURCE_DIR}/main.ts' '${install_dir}/main.ts'"
  run "cp '${AGENT_SOURCE_DIR}/deno.jsonc' '${install_dir}/deno.jsonc'"

  if [[ -f "${data_dir}/agent.uuid" ]]; then
    agent_uuid="$(tr -d '[:space:]' < "${data_dir}/agent.uuid")"
  else
    agent_uuid="$(new_uuid)"
    write_file "${data_dir}/agent.uuid" "${agent_uuid}"
  fi

  write_agent_config "$config_file" "$agent_name" "$hostname" "$api_base"
  write_service_file "$service_file" "$install_dir" "$config_file"

  run "chmod 0755 '${install_dir}' '${config_dir}'"
  run "chmod 0700 '${data_dir}' '${logs_dir}'"
  run "chmod 0600 '${config_file}'"
  run "chmod 0644 '${service_file}'"
  run "systemctl daemon-reload"
  run "systemctl enable --now mnscloud-agent"

  ok "mnscloud-agent installed as native systemd service."
  info "Agent UUID: ${agent_uuid}"
  info "Register this UUID in MNSCloud, then paste the generated token into ${data_dir}/agent.token."
}

main "$@"
