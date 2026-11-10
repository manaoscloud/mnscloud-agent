#!/bin/bash
# MNSCloud Agent for macOS (V10a): LaunchDaemon cloud.manaos.mnscloud.agent, run as root.
# Bash 3.2 compatible (the macOS system shell). Paths follow the Linux Agent:
#   /opt/mnscloud/agent (code), /etc/mnscloud/agent/agent.conf (0600), /var/lib/mnscloud/agent
#   (identity, 0700), /var/log/mnscloud/agent (logs). Deno lives in /usr/local/deno.
set -euo pipefail

LOG_PREFIX="[install-agent-macos]"
DRY_RUN=false
SKIP_LATEST=false
SERVICE_FILE_ONLY=false
DEFAULT_API_BASE="${MNSCLOUD_API_BASE:-https://api.publichost.cloud}"
DENO_VERSION="${MNSCLOUD_DENO_VERSION:-2.8.1}"
DENO_DIR_PREFIX="/usr/local/deno"
DENO_BIN="${DENO_DIR_PREFIX}/bin/deno"
SERVICE_LABEL="cloud.manaos.mnscloud.agent"
SERVICE_FILE="${MNSCLOUD_MACOS_SERVICE_FILE:-/Library/LaunchDaemons/${SERVICE_LABEL}.plist}"
INSTALL_CHANNEL="stable"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ORIGINAL_ARGS=("$@")

usage() {
  cat <<'TXT'
Usage:
  sudo bash scripts/install-agent-macos.sh [--dry-run] [--api-base URL] [--install-label LABEL] [--enrollment-token TOKEN] [--skip-latest]

Installs the MNSCloud Agent on macOS 13 or newer as a launchd daemon.
TXT
}

API_BASE=""
INSTALL_LABEL=""
ENROLLMENT_TOKEN="${MNSCLOUD_AGENT_ENROLLMENT_TOKEN:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --api-base) API_BASE="${2:-}"; shift 2 ;;
    --install-label) INSTALL_LABEL="${2:-}"; shift 2 ;;
    --enrollment-token) ENROLLMENT_TOKEN="${2:-}"; shift 2 ;;
    --skip-latest) SKIP_LATEST=true; shift ;;
    # Writes only the launchd daemon definition (MNSCLOUD_MACOS_SERVICE_FILE) and exits: CI lint.
    --service-file-only) SERVICE_FILE_ONLY=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "${LOG_PREFIX} unsupported option: $1" >&2; usage; exit 2 ;;
  esac
done

log() { echo "${LOG_PREFIX} $1 ${*:2}"; }
info() { log INFO "$*"; }
warn() { log WARN "$*"; }
ok() { log OK "$*"; }
fail() { log ERROR "$*"; exit 1; }

run() {
  if $DRY_RUN; then
    log DRY-RUN "$1"
  else
    /bin/bash -c "$1"
  fi
}

write_file() {
  local path="$1" content="$2"
  if $DRY_RUN; then
    log DRY-RUN "write ${path}"
    return 0
  fi
  printf '%s' "$content" > "$path"
}

require_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || fail "This installer is for macOS; use scripts/install-agent.sh on Linux."
  local major
  major="$(sw_vers -productVersion | cut -d. -f1)"
  [[ "$major" -ge 13 ]] || fail "macOS 13 or newer is required (found $(sw_vers -productVersion))."
}

require_root() {
  $DRY_RUN && return 0
  [[ "$(id -u)" -eq 0 ]] || fail "Run as root, for example: sudo bash $0"
}

require_tools() {
  command -v curl >/dev/null 2>&1 || fail "curl is required."
  command -v unzip >/dev/null 2>&1 || fail "unzip is required."
  # /usr/bin/git is a stub until the Command Line Tools are installed.
  xcode-select -p >/dev/null 2>&1 || fail "Install the Command Line Tools first: xcode-select --install"
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
    in_section && $1 == key { sub("^[^=]*= *", ""); sub(" *$", ""); print; exit }
  ' "$config_file"
}

agent_version() {
  if [[ -f "${AGENT_SOURCE_DIR}/VERSION" ]]; then tr -d '[:space:]' < "${AGENT_SOURCE_DIR}/VERSION"; else printf "1.0.0"; fi
}

agent_build_ref() {
  git -C "${AGENT_SOURCE_DIR}" rev-parse --short=12 'HEAD^{commit}' 2>/dev/null || printf "unknown"
}

current_git_ref() {
  git -C "${AGENT_SOURCE_DIR}" describe --tags --exact-match HEAD 2>/dev/null || agent_build_ref
}

bootstrap_latest_agent_release() {
  $DRY_RUN && return 0
  $SKIP_LATEST && return 0
  [[ -d "${AGENT_SOURCE_DIR}/.git" ]] || return 0
  local base url payload version ref
  base="$(normalize_url "${API_BASE:-$DEFAULT_API_BASE}")"
  [[ "$base" == */api/v1 ]] || base="${base}/api/v1"
  url="${base}/runtime/releases/latest?product=mnscloud-agent&channel=${INSTALL_CHANNEL}"
  payload="$(curl -fsS --connect-timeout 10 --max-time 20 "$url" 2>/dev/null)" || {
    warn "Could not resolve the latest Agent release; continuing with $(agent_version)."
    return 0
  }
  version="$(printf '%s\n' "$payload" | sed -n 's/.*"version":"\([^"]*\)".*/\1/p' | head -n1)"
  ref="$(printf '%s\n' "$payload" | sed -n 's/.*"ref":"\([^"]*\)".*/\1/p' | head -n1)"
  [[ "$version" =~ ^[0-9]+[.][0-9]+[.][0-9]+$ && "$ref" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]] || return 0
  if [[ "$(agent_version)" == "$version" && "$(current_git_ref)" == "$ref" ]]; then
    ok "Installer already on the latest release ${version}."
    return 0
  fi
  info "Latest Agent release is ${version} (${ref}); switching the installer first."
  # Bash 3.2 treats an empty array as unbound under set -u.
  exec /bin/bash "${AGENT_SOURCE_DIR}/scripts/update-agent-macos.sh" --ref "$ref" ${ORIGINAL_ARGS[@]+"${ORIGINAL_ARGS[@]}"} --skip-latest
}

deno_version_ok() {
  local installed
  [[ -x "$DENO_BIN" ]] || return 1
  installed="$("$DENO_BIN" --version | awk 'NR == 1 { print $2 }')"
  [[ "$(printf '%s\n' "$DENO_VERSION" "$installed" | sort -t. -k1,1n -k2,2n -k3,3n | head -1)" == "$DENO_VERSION" ]]
}

ensure_deno() {
  if deno_version_ok; then
    ok "Deno $("$DENO_BIN" --version | awk 'NR == 1 { print $2 }') is available."
    return 0
  fi
  if $DRY_RUN; then
    log DRY-RUN "install Deno ${DENO_VERSION} into ${DENO_DIR_PREFIX}"
    return 0
  fi
  info "Installing Deno ${DENO_VERSION} with the official deno.land installer."
  curl -fsSL https://deno.land/install.sh | CI=1 DENO_INSTALL="$DENO_DIR_PREFIX" sh -s -- --no-modify-path "v${DENO_VERSION}" >/dev/null
  deno_version_ok || fail "Deno ${DENO_VERSION} could not be installed."
  ok "Deno installed: $("$DENO_BIN" --version | head -n1)"
}

write_agent_config() {
  local config_file="$1" install_label="$2" hostname="$3" api_base="$4"
  write_file "$config_file" "# MNSCloud Agent configuration (macOS)
# Managed by scripts/install-agent-macos.sh

[agent]
name = ${install_label}
hostname = ${hostname}
api_base = ${api_base}
update_repo_dir = ${AGENT_SOURCE_DIR}
request_timeout_ms = 30000
poll_interval_ms = 15000
heartbeat_interval_ms = 60000
host_metrics_enabled = false
cyber_security_sync_interval_ms = 60000

[identity]
agent_uuid_file = /var/lib/mnscloud/agent/agent.uuid
agent_token_file = /var/lib/mnscloud/agent/agent.token

[capabilities]
macos.status = true
mnscloud.agent.update = true
"
}

write_service_file() {
  local install_dir="$1" config_file="$2"
  write_file "$SERVICE_FILE" "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
  <key>Label</key><string>${SERVICE_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${DENO_BIN}</string>
    <string>run</string>
    <string>--config</string>
    <string>${install_dir}/deno.jsonc</string>
    <string>--allow-read</string>
    <string>--allow-write</string>
    <string>--allow-net</string>
    <string>--allow-run</string>
    <string>--allow-env</string>
    <string>${install_dir}/main.ts</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>MNSCLOUD_AGENT_CONFIG</key><string>${config_file}</string>
    <key>PATH</key><string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
    <key>DENO_DIR</key><string>/var/lib/mnscloud/agent/deno</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>/var/log/mnscloud/agent/agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/mnscloud/agent/agent.log</string>
</dict>
</plist>
"
}

enrollment_payload() {
  TOKEN="${ENROLLMENT_TOKEN}" AGENT_UUID="$1" INSTALL_LABEL="$2" AGENT_HOSTNAME="$3" \
    "$DENO_BIN" eval --quiet 'console.log(JSON.stringify({ enrollmentToken: Deno.env.get("TOKEN"), agentUUID: Deno.env.get("AGENT_UUID"), installationName: Deno.env.get("INSTALL_LABEL"), hostname: Deno.env.get("AGENT_HOSTNAME") }))'
}

json_field() {
  "$DENO_BIN" eval --quiet "const p = JSON.parse(await Deno.readTextFile('$1')); console.log(p?.data?.$2 ?? '')"
}

activate_enrollment() {
  local api_base="$1" agent_uuid="$2" install_label="$3" hostname="$4" token_file="$5" uuid_file="$6"
  [[ -n "${ENROLLMENT_TOKEN}" ]] || return 0
  if $DRY_RUN; then
    log DRY-RUN "consume the enrollment token at ${api_base}/api/v1/agent/enroll"
    return 0
  fi
  local payload_file response_file http_code agent_token activated_uuid
  payload_file="$(mktemp)"
  response_file="$(mktemp)"
  chmod 0600 "$payload_file" "$response_file"
  enrollment_payload "$agent_uuid" "$install_label" "$hostname" > "$payload_file"
  info "Consuming the MNSCloud Agent enrollment token."
  http_code="$(curl -sS -o "$response_file" -w "%{http_code}" -X POST "${api_base}/api/v1/agent/enroll" \
    -H "Content-Type: application/json" --data-binary "@${payload_file}")"
  rm -f "$payload_file"
  if [[ "$http_code" != "201" && "$http_code" != "200" ]]; then
    warn "Agent enrollment failed with HTTP ${http_code}."
    rm -f "$response_file"
    fail "Could not activate the Agent enrollment token."
  fi
  agent_token="$(json_field "$response_file" agentToken)"
  activated_uuid="$(json_field "$response_file" agentUUID)"
  rm -f "$response_file"
  [[ -n "$agent_token" ]] || fail "The enrollment answer has no Agent token."
  if [[ -n "$activated_uuid" ]]; then
    write_file "$uuid_file" "$activated_uuid"
    chmod 0600 "$uuid_file"
  fi
  write_file "$token_file" "$agent_token"
  chmod 0600 "$token_file"
  ok "Agent enrollment consumed and the local token saved."
}

heartbeat() {
  local api_base="$1" uuid_file="$2" token_file="$3" hostname="$4" capabilities="$5"
  local agent_uuid agent_token payload response_file http_code
  agent_uuid="$(tr -d '[:space:]' < "$uuid_file")"
  agent_token="$(tr -d '[:space:]' < "$token_file")"
  payload="{\"hostname\":\"${hostname}\",\"version\":\"$(agent_version)\",\"buildRef\":\"$(agent_build_ref)\",\"updateChannel\":\"stable\",\"installerValidation\":true${capabilities}}"
  response_file="$(mktemp)"
  http_code="$(curl -sS -o "$response_file" -w "%{http_code}" -X POST "${api_base}/api/v1/agent/heartbeat" \
    -H "Content-Type: application/json" -H "X-MNSCloud-Agent-UUID: ${agent_uuid}" \
    -H "Authorization: Bearer ${agent_token}" --data-binary "$payload")"
  rm -f "$response_file"
  [[ "$http_code" == "200" ]]
}

validate_existing_identity() {
  local api_base="$1" uuid_file="$2" token_file="$3" hostname="$4"
  [[ -z "${ENROLLMENT_TOKEN}" ]] || return 0
  $DRY_RUN && { log DRY-RUN "validate the existing Agent identity"; return 0; }
  [[ -s "$uuid_file" && -s "$token_file" ]] ||
    fail "No Agent identity on this Mac. Generate an install command in MNSCloud and pass --enrollment-token."
  heartbeat "$api_base" "$uuid_file" "$token_file" "$hostname" "" ||
    fail "The Agent identity of this Mac is not valid. Run scripts/uninstall-agent-macos.sh and enroll again."
  ok "Existing Agent identity validated."
}

sync_installed_capabilities() {
  local api_base="$1" uuid_file="$2" token_file="$3" hostname="$4" attempt
  $DRY_RUN && { log DRY-RUN "sync the installed capabilities"; return 0; }
  for attempt in 1 2 3 4 5 6; do
    if heartbeat "$api_base" "$uuid_file" "$token_file" "$hostname" ',"capabilities":["macos.status","mnscloud.agent.update"]'; then
      ok "Installed Agent capabilities synced."
      return 0
    fi
    warn "Capability sync attempt ${attempt}/6 failed."
    sleep 10
  done
  fail "Could not sync the installed Agent capabilities."
}

main() {
  if $SERVICE_FILE_ONLY; then
    write_service_file "/opt/mnscloud/agent" "/etc/mnscloud/agent/agent.conf"
    exit 0
  fi
  local install_dir="/opt/mnscloud/agent"
  local config_dir="/etc/mnscloud/agent"
  local data_dir="/var/lib/mnscloud/agent"
  local logs_dir="/var/log/mnscloud/agent"
  local config_file="${config_dir}/agent.conf"
  local hostname api_base install_label agent_uuid

  require_macos
  require_root
  require_tools
  hostname="$(scutil --get LocalHostName 2>/dev/null || hostname)"
  api_base="$(normalize_url "${API_BASE:-$(read_config_value "$config_file" agent api_base)}")"
  api_base="${api_base:-$DEFAULT_API_BASE}"
  install_label="${INSTALL_LABEL:-$(read_config_value "$config_file" agent name)}"
  install_label="${install_label:-$hostname}"
  bootstrap_latest_agent_release
  ensure_deno
  validate_existing_identity "$api_base" "${data_dir}/agent.uuid" "${data_dir}/agent.token" "$hostname"

  info "Preparing the MNSCloud Agent for macOS..."
  run "mkdir -p '${install_dir}' '${config_dir}' '${data_dir}' '${logs_dir}'"
  run "cp '${AGENT_SOURCE_DIR}/main.ts' '${install_dir}/main.ts'"
  run "cp '${AGENT_SOURCE_DIR}/host-resources.ts' '${install_dir}/host-resources.ts'"
  run "cp '${AGENT_SOURCE_DIR}/bounded-io.ts' '${install_dir}/bounded-io.ts'"
  run "cp '${AGENT_SOURCE_DIR}/scheduler.ts' '${install_dir}/scheduler.ts'"
  run "cp '${AGENT_SOURCE_DIR}/schema-release.ts' '${install_dir}/schema-release.ts'"
  run "cp '${AGENT_SOURCE_DIR}/openvault-status.ts' '${install_dir}/openvault-status.ts'"
  run "cp '${AGENT_SOURCE_DIR}/webapps-status.ts' '${install_dir}/webapps-status.ts'"
  run "cp '${AGENT_SOURCE_DIR}/webapps-update.ts' '${install_dir}/webapps-update.ts'"
  run "cp '${AGENT_SOURCE_DIR}/nginx-webapps.ts' '${install_dir}/nginx-webapps.ts'"
  run "cp '${AGENT_SOURCE_DIR}/database-maintenance.ts' '${install_dir}/database-maintenance.ts'"
  run "cp '${AGENT_SOURCE_DIR}/runtime-reconcile.ts' '${install_dir}/runtime-reconcile.ts'"
  run "cp '${AGENT_SOURCE_DIR}/database-principal.ts' '${install_dir}/database-principal.ts'"
  run "cp '${AGENT_SOURCE_DIR}/pabx-state.ts' '${install_dir}/pabx-state.ts'"
  run "cp '${AGENT_SOURCE_DIR}/voip-load.ts' '${install_dir}/voip-load.ts'"
  run "cp '${AGENT_SOURCE_DIR}/voip-rate.ts' '${install_dir}/voip-rate.ts'"
  run "cp '${AGENT_SOURCE_DIR}/pabx-registration-insight.ts' '${install_dir}/pabx-registration-insight.ts'"
  run "cp '${AGENT_SOURCE_DIR}/pabx-presence.ts' '${install_dir}/pabx-presence.ts'"
  run "cp '${AGENT_SOURCE_DIR}/pabx-events.ts' '${install_dir}/pabx-events.ts'"
  run "cp '${AGENT_SOURCE_DIR}/logs-refresh.ts' '${install_dir}/logs-refresh.ts'"
  run "cp '${AGENT_SOURCE_DIR}/dns-probe.ts' '${install_dir}/dns-probe.ts'"
  run "cp '${AGENT_SOURCE_DIR}/dns-monitor.ts' '${install_dir}/dns-monitor.ts'"
  run "cp '${AGENT_SOURCE_DIR}/job-report.ts' '${install_dir}/job-report.ts'"
  run "cp '${AGENT_SOURCE_DIR}/website-edge.ts' '${install_dir}/website-edge.ts'"
  run "cp '${AGENT_SOURCE_DIR}/cyber-security-policy.ts' '${install_dir}/cyber-security-policy.ts'"
  run "cp '${AGENT_SOURCE_DIR}/security-inventory.ts' '${install_dir}/security-inventory.ts'"
  run "cp '${AGENT_SOURCE_DIR}/security-patch.ts' '${install_dir}/security-patch.ts'"
  run "cp '${AGENT_SOURCE_DIR}/security-posture.ts' '${install_dir}/security-posture.ts'"
  run "cp '${AGENT_SOURCE_DIR}/network-device.ts' '${install_dir}/network-device.ts'"
  run "cp '${AGENT_SOURCE_DIR}/macos-agent.ts' '${install_dir}/macos-agent.ts'"
  run "cp '${AGENT_SOURCE_DIR}/deno.jsonc' '${install_dir}/deno.jsonc'"
  write_file "${install_dir}/VERSION" "$(agent_version)
"
  if [[ -f "${data_dir}/agent.uuid" ]]; then
    agent_uuid="$(tr -d '[:space:]' < "${data_dir}/agent.uuid")"
  else
    agent_uuid="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    write_file "${data_dir}/agent.uuid" "$agent_uuid"
  fi
  write_agent_config "$config_file" "$install_label" "$hostname" "$api_base"
  write_service_file "$install_dir" "$config_file"
  activate_enrollment "$api_base" "$agent_uuid" "$install_label" "$hostname" "${data_dir}/agent.token" "${data_dir}/agent.uuid"
  run "chmod 0755 '${install_dir}' '${config_dir}'"
  run "chmod 0700 '${data_dir}' '${logs_dir}'"
  run "chmod 0600 '${config_file}'"
  run "chown root:wheel '${SERVICE_FILE}' && chmod 0644 '${SERVICE_FILE}'"
  # Reload the daemon with the new definition (bootout fails harmlessly on the first install).
  run "launchctl bootout system/${SERVICE_LABEL} 2>/dev/null || true"
  run "launchctl enable system/${SERVICE_LABEL}"
  run "launchctl bootstrap system '${SERVICE_FILE}'"
  run "launchctl kickstart -k system/${SERVICE_LABEL}"
  sync_installed_capabilities "$api_base" "${data_dir}/agent.uuid" "${data_dir}/agent.token" "$hostname"
  ok "MNSCloud Agent installed as the launchd daemon ${SERVICE_LABEL}."
  info "Agent UUID: $(tr -d '[:space:]' < "${data_dir}/agent.uuid" 2>/dev/null || printf '%s' "$agent_uuid")"
}

main "$@"
