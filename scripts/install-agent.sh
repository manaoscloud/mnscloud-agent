#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[install-agent]"
DRY_RUN=false
DEFAULT_API_BASE="${MNSCLOUD_API_BASE:-https://api.publichost.cloud}"
AGENT_USER="root"
AGENT_GROUP="root"
AGENT_RUNTIME_KIT_DIR="${AGENT_RUNTIME_KIT_DIR:-/opt/mnscloud/runtime-kit}"
AGENT_RUNTIME_KIT_REPO_URL="${AGENT_RUNTIME_KIT_REPO_URL:-https://github.com/manaoscloud/mnscloud-runtime-kit.git}"
AGENT_RUNTIME_KIT_REF="${AGENT_RUNTIME_KIT_REF:-}"
AGENT_RUNTIME_KIT_CHANNEL="${AGENT_RUNTIME_KIT_CHANNEL:-stable}"

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

ensure_runtime_kit_git() {
  if command -v git >/dev/null 2>&1; then
    return 0
  fi

  install_packages "$(detect_os)"
  if command -v apt-get >/dev/null 2>&1; then
    run "apt-get install -y --no-install-recommends git"
  elif command -v dnf >/dev/null 2>&1; then
    run "dnf -y install git"
  fi

  command -v git >/dev/null 2>&1 || fail "git is required to install mnscloud-runtime-kit"
}

load_runtime_kit() {
  if $DRY_RUN; then
    log DRY-RUN "load mnscloud-runtime-kit from ${AGENT_RUNTIME_KIT_REPO_URL}"
    return 0
  fi

  ensure_runtime_kit_git
  if [[ -d "${AGENT_RUNTIME_KIT_DIR}/.git" ]]; then
    info "Updating runtime kit in ${AGENT_RUNTIME_KIT_DIR}"
    git -C "$AGENT_RUNTIME_KIT_DIR" fetch --all --tags --prune
  else
    info "Installing runtime kit in ${AGENT_RUNTIME_KIT_DIR}"
    install -d -m 0755 "$(dirname "$AGENT_RUNTIME_KIT_DIR")"
    git clone "$AGENT_RUNTIME_KIT_REPO_URL" "$AGENT_RUNTIME_KIT_DIR"
  fi

  if [[ -z "$AGENT_RUNTIME_KIT_REF" ]]; then
    AGENT_RUNTIME_KIT_REF="$(resolve_runtime_kit_ref "$AGENT_RUNTIME_KIT_DIR" "$AGENT_RUNTIME_KIT_CHANNEL")"
    info "Resolved runtime kit ${AGENT_RUNTIME_KIT_CHANNEL} channel to ${AGENT_RUNTIME_KIT_REF}"
  fi

  git -C "$AGENT_RUNTIME_KIT_DIR" -c advice.detachedHead=false checkout "$AGENT_RUNTIME_KIT_REF"
  git -C "$AGENT_RUNTIME_KIT_DIR" pull --ff-only origin "$AGENT_RUNTIME_KIT_REF" 2>/dev/null || true
  [[ -r "${AGENT_RUNTIME_KIT_DIR}/lib/packages.sh" ]] || fail "runtime kit packages library not found"

  export MNSCLOUD_RUNTIME_KIT_LOG_PREFIX="mnscloud-agent/runtime-kit"
  # shellcheck disable=SC1091
  source "${AGENT_RUNTIME_KIT_DIR}/lib/packages.sh"
}

resolve_runtime_kit_ref() {
  local kit_dir="$1"
  local channel="$2"
  local manifest ref

  manifest="$(git -C "$kit_dir" show "origin/main:releases/manifest.json" 2>/dev/null)" ||
    fail "cannot read runtime kit release manifest from origin/main"
  ref="$(printf '%s\n' "$manifest" | awk -v channel="$channel" '
    $0 ~ "\"" channel "\"" { in_channel = 1; next }
    in_channel && /"ref"[[:space:]]*:/ {
      gsub(/.*"ref"[[:space:]]*:[[:space:]]*"/, "")
      gsub(/".*/, "")
      print
      exit
    }
    in_channel && /^[[:space:]]*}/ { in_channel = 0 }
  ')"
  [[ "$ref" =~ ^v[0-9]+[.][0-9]+[.][0-9]+([-+][0-9A-Za-z.-]+)?$ ]] ||
    fail "invalid runtime kit ref for channel ${channel}: ${ref:-empty}"
  printf '%s\n' "$ref"
}

ensure_deno() {
  if $DRY_RUN; then
    log DRY-RUN "install Deno ${MNSCLOUD_DENO_VERSION:-2.8.1} via mnscloud-runtime-kit"
    return 0
  fi

  load_runtime_kit
  export MNSCLOUD_DENO_VERSION="${MNSCLOUD_DENO_VERSION:-2.8.1}"
  mrtk_ensure_deno
  ok "Deno is available: $(deno --version | head -n1)"
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

agent_version() {
  if [[ -f "${AGENT_SOURCE_DIR}/VERSION" ]]; then
    tr -d '[:space:]' < "${AGENT_SOURCE_DIR}/VERSION"
  else
    printf "1.0.0"
  fi
}

agent_build_ref() {
  git -C "${AGENT_SOURCE_DIR}" rev-parse --short=12 'HEAD^{commit}' 2>/dev/null || printf "unknown"
}

write_agent_build_metadata() {
  local install_dir="$1"
  local version="$2"
  local build_ref="$3"
  local build_date
  build_date="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  write_file "${install_dir}/VERSION" "${version}
"
  write_file "${install_dir}/build.json" "{
  \"version\": \"${version}\",
  \"buildRef\": \"${build_ref}\",
  \"buildDate\": \"${build_date}\",
  \"updateChannel\": \"stable\",
  \"sourceRepo\": \"manaoscloud/mnscloud-agent\"
}
"
}

write_agent_config() {
  local config_file="$1" install_label="$2" hostname="$3" api_base="$4"
  write_file "$config_file" "# MNSCloud Agent configuration
# Managed by agent/scripts/install-agent.sh

[agent]
name = ${install_label}
hostname = ${hostname}
api_base = ${api_base}
update_repo_dir = ${AGENT_SOURCE_DIR}
poll_interval_ms = 15000
heartbeat_interval_ms = 60000
cyber_security_sync_interval_ms = 60000

[identity]
agent_uuid_file = /var/lib/mnscloud/agent/agent.uuid
agent_token_file = /var/lib/mnscloud/agent/agent.token

[recordings]
roots = /var/lib/freeswitch/recordings,/var/spool/asterisk/monitor
mounts =
delete_after_upload = true

[media_files]
roots = /var/lib/mnscloud/files
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

[realtime_webrtc_edge]
sync_command = /opt/mnscloud/kamailio-webrtc/scripts/update-kamailio-webrtc.sh

[turn_edge]
sync_command = /opt/mnscloud/turn/scripts/update-turn.sh

[realtime_media_edge]
sync_command = /opt/mnscloud/media/scripts/update-media.sh

[capabilities]
linux.status = true
linux.package.install = true
linux.service.manage = true
linux.file.manage = true
mnscloud.agent.update = true
mnscloud.api.update = $(detect_executable_file /opt/mnscloud/mnscloud-api/scripts/update-api.sh)
mnscloud.app.update = $(detect_executable_file /opt/mnscloud/mnscloud-app/scripts/update-nginx-runtime.sh)
nginx-edge.manage = $(detect_capability nginx)
certbot.manage = $(detect_capability certbot)
security.nftables.manage = true
security.crowdsec.manage = true
security.logs.read = true
voip.asterisk.manage = $(detect_capability asterisk)
voip.freeswitch.manage = $(detect_capability fs_cli)
realtime.webrtc.manage = $(detect_executable_file /opt/mnscloud/kamailio-webrtc/scripts/update-kamailio-webrtc.sh)
realtime.turn.manage = $(detect_executable_file /opt/mnscloud/turn/scripts/update-turn.sh)
realtime.media.manage = $(detect_executable_file /opt/mnscloud/media/scripts/update-media.sh)
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
  local api_base="$1" agent_uuid="$2" install_label="$3" hostname="$4" token_file="$5" uuid_file="$6"
  [[ -n "${ENROLLMENT_TOKEN}" ]] || return 0
  if $DRY_RUN; then
    log DRY-RUN "consume agent enrollment token at ${api_base}/api/v1/agent/enroll"
    return 0
  fi

  local payload_file response_file agent_token activated_agent_uuid
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
  activated_agent_uuid="$(deno run --allow-read="${response_file}" - "${response_file}" <<'DENO'
    const payload = JSON.parse(await Deno.readTextFile(Deno.args[0]));
    console.log(payload?.data?.agentUUID ?? "");
DENO
)"
  rm -f "${response_file}"
  [[ -n "${agent_token}" ]] || fail "Enrollment response did not include an Agent runtime token."

  if [[ -n "${activated_agent_uuid}" ]]; then
    write_file "${uuid_file}" "${activated_agent_uuid}"
    run "chmod 0600 '${uuid_file}'"
  fi

  write_file "${token_file}" "${agent_token}"
  run "chmod 0600 '${token_file}'"
  ok "Agent enrollment consumed and local token saved."
}

validate_existing_identity() {
  local api_base="$1" uuid_file="$2" token_file="$3" hostname="$4"
  [[ -z "${ENROLLMENT_TOKEN}" ]] || return 0

  if $DRY_RUN; then
    log DRY-RUN "validate existing Agent identity at ${api_base}/api/v1/agent/heartbeat"
    return 0
  fi

  if [[ ! -s "${uuid_file}" || ! -s "${token_file}" ]]; then
    fail "Existing Agent UUID/token not found. Generate a new install command from MNSCloud and pass --enrollment-token."
  fi

  local agent_uuid agent_token response_file http_code version build_ref
  agent_uuid="$(tr -d '[:space:]' < "${uuid_file}")"
  agent_token="$(tr -d '[:space:]' < "${token_file}")"
  version="$(agent_version)"
  build_ref="$(agent_build_ref)"
  response_file="$(mktemp)"
  info "Validating existing Agent identity with MNSCloud API."
  http_code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
    -X POST "${api_base}/api/v1/agent/heartbeat" \
    -H "Content-Type: application/json" \
    -H "X-MNSCloud-Agent-UUID: ${agent_uuid}" \
    -H "Authorization: Bearer ${agent_token}" \
    --data-binary "{\"hostname\":\"${hostname}\",\"version\":\"${version}\",\"buildRef\":\"${build_ref}\",\"updateChannel\":\"stable\",\"installerValidation\":true}")"

  if [[ "${http_code}" != "200" ]]; then
    warn "Agent identity validation failed with HTTP ${http_code}: $(tr '\n' ' ' < "${response_file}" | head -c 300)"
    rm -f "${response_file}"
    fail "Existing Agent identity is not valid in MNSCloud. Run scripts/uninstall-agent.sh and generate a new install command."
  fi

  rm -f "${response_file}"
  ok "Existing Agent identity validated by MNSCloud API."
}

capabilities_json_from_config() {
  local config_file="$1"
  deno run --allow-read="${config_file}" - "${config_file}" <<'DENO'
const configPath = Deno.args[0];
const text = await Deno.readTextFile(configPath);
let section = "";
const capabilities = [];
for (const rawLine of text.split(/\r?\n/)) {
  const line = rawLine.trim();
  if (!line || line.startsWith("#") || line.startsWith(";")) continue;
  const sectionMatch = line.match(/^\[([a-zA-Z0-9_.-]+)\]$/);
  if (sectionMatch) {
    section = sectionMatch[1];
    continue;
  }
  if (section !== "capabilities") continue;
  const separator = line.indexOf("=");
  if (separator < 0) continue;
  const key = line.slice(0, separator).trim();
  const value = line.slice(separator + 1).trim().toLowerCase();
  if (key && ["1", "true", "yes", "y", "on"].includes(value)) {
    capabilities.push(key);
  }
}
console.log(JSON.stringify(capabilities.length ? capabilities : ["linux.status"]));
DENO
}

sync_installed_capabilities() {
  local api_base="$1" uuid_file="$2" token_file="$3" config_file="$4" hostname="$5"
  $DRY_RUN && { log DRY-RUN "sync installed Agent capabilities at ${api_base}/api/v1/agent/heartbeat"; return 0; }

  [[ -s "${uuid_file}" && -s "${token_file}" ]] || fail "Agent UUID/token not found after install."

  local agent_uuid agent_token capabilities_json payload_file response_file http_code attempt max_attempts
  agent_uuid="$(tr -d '[:space:]' < "${uuid_file}")"
  agent_token="$(tr -d '[:space:]' < "${token_file}")"
  capabilities_json="$(capabilities_json_from_config "${config_file}")"
  payload_file="$(mktemp)"
  response_file="$(mktemp)"
  max_attempts="${MNSCLOUD_AGENT_SYNC_ATTEMPTS:-6}"

  HOSTNAME_VALUE="${hostname}" CAPABILITIES_JSON="${capabilities_json}" AGENT_VERSION="$(agent_version)" AGENT_BUILD_REF="$(agent_build_ref)" deno run \
    --allow-env=HOSTNAME_VALUE,CAPABILITIES_JSON,AGENT_VERSION,AGENT_BUILD_REF - <<'DENO' > "${payload_file}"
const capabilities = JSON.parse(Deno.env.get("CAPABILITIES_JSON") ?? "[]");
console.log(JSON.stringify({
  hostname: Deno.env.get("HOSTNAME_VALUE") ?? "",
  version: Deno.env.get("AGENT_VERSION") ?? "1.0.0",
  buildRef: Deno.env.get("AGENT_BUILD_REF") ?? "",
  updateChannel: "stable",
  installerValidation: true,
  capabilities,
}));
DENO

  info "Syncing installed Agent capabilities with MNSCloud API."
  for ((attempt = 1; attempt <= max_attempts; attempt++)); do
    : > "${response_file}"
    http_code="$(curl -sS -o "${response_file}" -w "%{http_code}" \
      -X POST "${api_base}/api/v1/agent/heartbeat" \
      -H "Content-Type: application/json" \
      -H "X-MNSCloud-Agent-UUID: ${agent_uuid}" \
      -H "Authorization: Bearer ${agent_token}" \
      --data-binary "@${payload_file}")"

    if [[ "${http_code}" == "200" ]]; then
      rm -f "${payload_file}" "${response_file}"
      ok "Installed Agent capabilities synced with MNSCloud API."
      return 0
    fi

    warn "Agent capability sync attempt ${attempt}/${max_attempts} failed with HTTP ${http_code}: $(tr '\n' ' ' < "${response_file}" | head -c 300)"
    if (( attempt < max_attempts )); then
      sleep 10
    fi
  done

  rm -f "${payload_file}" "${response_file}"
  fail "Could not sync installed Agent capabilities with MNSCloud."
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
  validate_existing_identity "$api_base" "${data_dir}/agent.uuid" "${data_dir}/agent.token" "$hostname"

  info "Preparing native mnscloud-agent..."
  run "mkdir -p '${install_dir}' '${config_dir}' '${data_dir}' '${logs_dir}' /var/lib/mnscloud/files /etc/nginx/mnscloud/theme-domains /var/www/certbot"
  run "cp '${AGENT_SOURCE_DIR}/main.ts' '${install_dir}/main.ts'"
  run "cp '${AGENT_SOURCE_DIR}/deno.jsonc' '${install_dir}/deno.jsonc'"
  write_agent_build_metadata "$install_dir" "$(agent_version)" "$(agent_build_ref)"

  if [[ -f "${data_dir}/agent.uuid" ]]; then
    agent_uuid="$(tr -d '[:space:]' < "${data_dir}/agent.uuid")"
  else
    agent_uuid="$(new_uuid)"
    write_file "${data_dir}/agent.uuid" "${agent_uuid}"
  fi

  write_agent_config "$config_file" "$install_label" "$hostname" "$api_base"
  write_service_file "$service_file" "$install_dir" "$config_file"
  activate_enrollment "$api_base" "$agent_uuid" "$install_label" "$hostname" "${data_dir}/agent.token" "${data_dir}/agent.uuid"
  if [[ -f "${data_dir}/agent.uuid" ]]; then
    agent_uuid="$(tr -d '[:space:]' < "${data_dir}/agent.uuid")"
  fi

  run "chmod 0755 '${install_dir}' '${config_dir}'"
  run "chmod 0700 '${data_dir}' '${logs_dir}'"
  run "chmod 0600 '${config_file}'"
  run "chmod 0644 '${service_file}'"
  run "systemctl daemon-reload"
  run "systemctl enable --now mnscloud-agent"
  run "systemctl restart mnscloud-agent"
  sync_installed_capabilities "$api_base" "${data_dir}/agent.uuid" "${data_dir}/agent.token" "$config_file" "$hostname"

  ok "mnscloud-agent installed as native systemd service."
  info "Agent UUID: ${agent_uuid}"
  if [[ -n "${ENROLLMENT_TOKEN}" ]]; then
    info "Agent enrolled and runtime token stored at ${data_dir}/agent.token."
  else
    info "Existing Agent identity validated with runtime token at ${data_dir}/agent.token."
  fi
}

main "$@"
