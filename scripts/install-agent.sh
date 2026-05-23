#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[install-agent]"
DRY_RUN=false
DEFAULT_API_BASE="${MNSCLOUD_API_BASE:-https://api.publichost.cloud}"
AGENT_USER="root"
AGENT_GROUP="root"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_FILE="${LOG_FILE:-/var/log/mnscloud-agent-install.log}"

usage() {
  cat <<'TXT'
Usage:
  agent/scripts/install-agent.sh [--dry-run] [--api-base URL] [--install-label LABEL] [--enrollment-token TOKEN]

Installs the single native MNSCloud Agent as a systemd service.
TXT
}

API_BASE=""
INSTALL_LABEL=""
ENROLLMENT_TOKEN="${MNSCLOUD_AGENT_ENROLLMENT_TOKEN:-}"
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
    --install-label)
      INSTALL_LABEL="${2:-}"
      shift 2
      ;;
    --enrollment-token)
      ENROLLMENT_TOKEN="${2:-}"
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
  local major="${VERSION_ID%%.*}"
  case "${ID:-}:${major}" in
    debian:12|debian:13) echo "debian" ;;
    rhel:9|rhel:10|rocky:9|rocky:10|almalinux:9|almalinux:10) echo "rhel" ;;
    *)
      warn "Unsupported or experimental Linux distribution: ${PRETTY_NAME:-${ID:-unknown} ${VERSION_ID:-}}. Supported: Debian 12/13, RHEL 9/10, Rocky Linux 9/10, AlmaLinux 9/10."
      echo "experimental"
      ;;
  esac
}

ensure_local_hostname() {
  local short_hostname fqdn
  short_hostname="$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
  fqdn="$(hostname -f 2>/dev/null || true)"
  [[ -n "$short_hostname" ]] || return 0

  if grep -Eq "^[[:space:]]*[0-9a-fA-F:.]+[[:space:]].*(^|[[:space:]])${short_hostname}([[:space:]]|$)" /etc/hosts 2>/dev/null; then
    ok "Local hostname already present in /etc/hosts: ${short_hostname}"
    return 0
  fi

  if $DRY_RUN; then
    log DRY-RUN "append local hostname to /etc/hosts: ${short_hostname}"
    return 0
  fi

  info "Adding local hostname to /etc/hosts: ${short_hostname}"
  if [[ -n "$fqdn" && "$fqdn" != "$short_hostname" ]]; then
    printf "127.0.1.1\t%s %s\n" "$fqdn" "$short_hostname" >> /etc/hosts
  else
    printf "127.0.1.1\t%s\n" "$short_hostname" >> /etc/hosts
  fi
}

install_packages() {
  local os="$1"
  case "$os" in
    debian)
      run "apt-get update -y"
      run "apt-get install -y --no-install-recommends ca-certificates curl unzip"
      ;;
    rhel)
      run "dnf -y makecache"
      run "dnf -y install ca-certificates curl unzip"
      ;;
    experimental)
      if command -v apt-get >/dev/null 2>&1; then
        run "apt-get update -y"
        run "apt-get install -y --no-install-recommends ca-certificates curl unzip"
      elif command -v dnf >/dev/null 2>&1; then
        run "dnf -y makecache"
        run "dnf -y install ca-certificates curl unzip"
      else
        fail "Unsupported experimental Linux distribution: apt-get or dnf is required."
      fi
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

read_config_value() {
  local config_file="$1" section="$2" key="$3"
  [[ -r "$config_file" ]] || return 0
  awk -v section="$section" -v key="$key" '
    $0 ~ "^\\[" section "\\]$" { in_section = 1; next }
    $0 ~ "^\\[" { in_section = 0 }
    in_section && $1 == key {
      sub("^[^=]*= *", "")
      sub(" *$", "")
      print
      exit
    }
  ' "$config_file"
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

detect_executable_file() {
  local path="$1"
  [[ -x "$path" ]] && printf "true" || printf "false"
}

write_agent_config() {
  local config_file="$1" install_label="$2" hostname="$3" api_base="$4"
  write_file "$config_file" "# MNSCloud Agent configuration
# Managed by agent/scripts/install-agent.sh

[agent]
name = ${install_label}
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

[nginx_edge]
config_dir = /etc/nginx/mnscloud/theme-domains
acme_root = /var/www/certbot
ssl_live_dir = /etc/letsencrypt/live
ssl_archive_dir = /etc/letsencrypt/archive
ssl_renewal_dir = /etc/letsencrypt/renewal
app_upstream = \$app_upstream
api_upstream = \$api_upstream
test_command = nginx -t
reload_command = systemctl reload nginx

[certbot]
command = certbot
default_email =

[webrtc_edge]
sync_command = /opt/mnscloud/kamailio-webrtc/scripts/update-kamailio-webrtc.sh

[capabilities]
linux.status = true
linux.package.install = true
linux.service.manage = true
linux.file.manage = true
nginx-edge.manage = $(detect_capability nginx)
certbot.manage = $(detect_capability certbot)
security.nftables.manage = true
security.crowdsec.manage = true
security.logs.read = true
voip.asterisk.manage = $(detect_capability asterisk)
voip.freeswitch.manage = $(detect_capability fs_cli)
webrtc.kamailio.manage = $(detect_executable_file /opt/mnscloud/kamailio-webrtc/scripts/update-kamailio-webrtc.sh)
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

activate_enrollment() {
  local api_base="$1" agent_uuid="$2" install_label="$3" hostname="$4" token_file="$5"
  [[ -n "${ENROLLMENT_TOKEN}" ]] || return 0
  if $DRY_RUN; then
    log DRY-RUN "consume agent enrollment token at ${api_base}/api/v1/agent/enroll"
    return 0
  fi

  local payload_file response_file agent_token
  payload_file="$(mktemp)"
  response_file="$(mktemp)"
  TOKEN="${ENROLLMENT_TOKEN}" AGENT_UUID="${agent_uuid}" INSTALL_LABEL="${install_label}" AGENT_HOSTNAME="${hostname}" \
    deno run --allow-env=TOKEN,AGENT_UUID,INSTALL_LABEL,AGENT_HOSTNAME - <<'DENO' > "${payload_file}"
      const payload = {
        enrollmentToken: Deno.env.get("TOKEN"),
        agentUUID: Deno.env.get("AGENT_UUID"),
        installationName: Deno.env.get("INSTALL_LABEL"),
        hostname: Deno.env.get("AGENT_HOSTNAME"),
      };
      console.log(JSON.stringify(payload));
DENO

  info "Consuming MNSCloud Agent enrollment token."
  local http_code
  http_code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    -X POST "${api_base}/api/v1/agent/enroll" \
    -H "Content-Type: application/json" \
    --data-binary "@${payload_file}")"
  rm -f "${payload_file}"
  if [[ "${http_code}" != "201" && "${http_code}" != "200" ]]; then
    warn "Agent enrollment failed with HTTP ${http_code}: $(tr '\n' ' ' < "${response_file}" | head -c 300)"
    rm -f "${response_file}"
    fail "Could not activate the Agent enrollment token."
  fi

  agent_token="$(deno run --allow-read="${response_file}" - "${response_file}" <<'DENO'
    const payload = JSON.parse(await Deno.readTextFile(Deno.args[0]));
    console.log(payload?.data?.agentToken ?? "");
DENO
)"
  rm -f "${response_file}"
  [[ -n "${agent_token}" ]] || fail "Enrollment response did not include an Agent runtime token."

  write_file "${token_file}" "${agent_token}"
  run "chmod 0600 '${token_file}'"
  ok "Agent enrollment consumed and local token saved."
}

main() {
  local api_base agent_uuid install_label hostname existing_api_base existing_install_label
  local install_dir="/opt/mnscloud/agent"
  local config_dir="/etc/mnscloud/agent"
  local data_dir="/var/lib/mnscloud/agent"
  local logs_dir="/var/log/mnscloud/agent"
  local config_file="${config_dir}/agent.conf"
  local service_file="/etc/systemd/system/mnscloud-agent.service"

  require_root
  ensure_local_hostname
  ensure_deno

  hostname="$(hostname -f 2>/dev/null || hostname)"
  existing_api_base="$(read_config_value "$config_file" "agent" "api_base")"
  existing_install_label="$(read_config_value "$config_file" "agent" "name")"
  api_base="$(normalize_url "${API_BASE:-$(prompt_value "MNSCloud API base URL" "${existing_api_base:-$DEFAULT_API_BASE}")}")"
  install_label="${INSTALL_LABEL:-$(prompt_value "Local install label" "${existing_install_label:-$hostname}")}"

  info "Preparing native mnscloud-agent..."
  run "mkdir -p '${install_dir}' '${config_dir}' '${data_dir}' '${logs_dir}' /var/lib/mnscloud/pabx/media-files /etc/nginx/mnscloud/theme-domains /var/www/certbot"
  run "cp '${AGENT_SOURCE_DIR}/main.ts' '${install_dir}/main.ts'"
  run "cp '${AGENT_SOURCE_DIR}/deno.jsonc' '${install_dir}/deno.jsonc'"

  if [[ -f "${data_dir}/agent.uuid" ]]; then
    agent_uuid="$(tr -d '[:space:]' < "${data_dir}/agent.uuid")"
  else
    agent_uuid="$(new_uuid)"
    write_file "${data_dir}/agent.uuid" "${agent_uuid}"
  fi

  write_agent_config "$config_file" "$install_label" "$hostname" "$api_base"
  write_service_file "$service_file" "$install_dir" "$config_file"
  activate_enrollment "$api_base" "$agent_uuid" "$install_label" "$hostname" "${data_dir}/agent.token"

  run "chmod 0755 '${install_dir}' '${config_dir}'"
  run "chmod 0700 '${data_dir}' '${logs_dir}'"
  run "chmod 0600 '${config_file}'"
  run "chmod 0644 '${service_file}'"
  run "systemctl daemon-reload"
  run "systemctl enable --now mnscloud-agent"

  ok "mnscloud-agent installed as native systemd service."
  info "Agent UUID: ${agent_uuid}"
  info "Agent enrolled and runtime token stored at ${data_dir}/agent.token."
}

main "$@"
