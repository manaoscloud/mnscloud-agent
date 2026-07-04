#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[validate-agent]"
CONFIG_FILE="${MNSCLOUD_AGENT_CONFIG:-/etc/mnscloud/agent/agent.conf}"
UUID_FILE="/var/lib/mnscloud/agent/agent.uuid"
TOKEN_FILE="/var/lib/mnscloud/agent/agent.token"
RUNTIME_MAIN="/opt/mnscloud/agent/main.ts"
SERVICE_NAME="mnscloud-agent"
REQUIRE_ACTIVE=false
REQUIRE_ENROLLED=false
VALIDATE_API=false
API_BASE=""
REQUIRED_JOBS=()
REQUIRED_CAPABILITIES=()

usage() {
  cat <<'TXT'
Usage:
  sudo bash scripts/validate-agent.sh [options]

Options:
  --require-active                 Require mnscloud-agent.service to be active.
  --require-enrolled               Require local Agent UUID and runtime token files.
  --require-job JOB_TYPE           Require installed Agent runtime support for a job type.
  --require-capability CAPABILITY  Require capability to be declared/enabled or derivable locally.
  --api-base URL                   API/control-plane base URL for identity validation.
  --validate-api                   Validate current Agent UUID/token with POST /api/v1/agent/heartbeat.
  --help                           Show this help.

Examples:
  sudo bash scripts/validate-agent.sh --require-active --require-enrolled --require-job voip.sbc.runtime
  sudo bash scripts/validate-agent.sh --require-active --require-enrolled --require-job realtime.webrtc.edge
TXT
}

log() {
  local level="$1"
  shift
  printf '%s %s %s\n' "$LOG_PREFIX" "$level" "$*"
}

info() { log INFO "$*"; }
ok() { log OK "$*"; }
fail() { log ERROR "$*"; exit 1; }

trim_file() {
  local path="$1"
  tr -d '[:space:]' < "$path"
}

config_value() {
  local section="$1" key="$2" fallback="${3:-}"
  [[ -r "$CONFIG_FILE" ]] || {
    printf '%s\n' "$fallback"
    return 0
  }
  awk -F= -v section="$section" -v key="$key" -v fallback="$fallback" '
    BEGIN { current = ""; found = 0 }
    /^[[:space:]]*\[[^]]+\][[:space:]]*$/ {
      current = $0
      gsub(/^[[:space:]]*\[/, "", current)
      gsub(/\][[:space:]]*$/, "", current)
      next
    }
    current == section {
      raw = $1
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", raw)
      if (raw == key) {
        value = $0
        sub(/^[^=]*=/, "", value)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
        print value
        found = 1
        exit
      }
    }
    END { if (!found) print fallback }
  ' "$CONFIG_FILE"
}

truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|y|Y|on|ON) return 0 ;;
    *) return 1 ;;
  esac
}

command_path_from_capability() {
  case "$1" in
    realtime.webrtc.manage) config_value "realtime.webrtc.edge" "sync_command" "/opt/mnscloud/kamailio-webrtc/scripts/update-kamailio-webrtc.sh" ;;
    voip.sbc.manage) config_value "voip.sbc.runtime" "sync_command" "/opt/mnscloud/mnscloud-opensips-sbc/scripts/sync-and-reload-opensips-sbc.sh" ;;
    realtime.turn.manage) config_value "turn_edge" "sync_command" "/opt/mnscloud/turn/scripts/update-turn.sh" ;;
    realtime.media.manage) config_value "realtime_media_edge" "sync_command" "/opt/mnscloud/media/scripts/update-media.sh" ;;
    mnscloud.api.update) printf '%s\n' "/opt/mnscloud/mnscloud-api/scripts/update-api.sh" ;;
    mnscloud.app.update) printf '%s\n' "/opt/mnscloud/mnscloud-app/scripts/update-nginx-runtime.sh" ;;
    *) return 1 ;;
  esac
}

validate_active() {
  command -v systemctl >/dev/null 2>&1 ||
    fail "systemctl is required to validate ${SERVICE_NAME}."
  systemctl is-active --quiet "$SERVICE_NAME" ||
    fail "${SERVICE_NAME} must be installed, enrolled, and active before installing this runtime."
  ok "${SERVICE_NAME} is active."
}

validate_enrolled() {
  [[ -s "$CONFIG_FILE" ]] || fail "Agent config not found at ${CONFIG_FILE}."
  UUID_FILE="$(config_value "identity" "agent_uuid_file" "$UUID_FILE")"
  TOKEN_FILE="$(config_value "identity" "agent_token_file" "$TOKEN_FILE")"
  [[ -s "$UUID_FILE" ]] || fail "Agent UUID not found at ${UUID_FILE}. Enroll the Agent first."
  [[ -s "$TOKEN_FILE" ]] || fail "Agent runtime token not found at ${TOKEN_FILE}. Enroll the Agent first."
  ok "Agent local identity is present."
}

validate_job_support() {
  local job="$1"
  [[ -s "$RUNTIME_MAIN" ]] || fail "Agent runtime not found at ${RUNTIME_MAIN}. Update/reinstall the Agent first."
  grep -Fq "\"${job}\"" "$RUNTIME_MAIN" ||
    grep -Fq "'${job}'" "$RUNTIME_MAIN" ||
    fail "Installed Agent runtime does not support job type ${job}. Update/reinstall the Agent first."
  ok "Agent runtime supports job type ${job}."
}

validate_capability() {
  local capability="$1" command_path value
  value="$(config_value "capabilities" "$capability" "")"
  if truthy "$value"; then
    ok "Agent capability ${capability} is enabled in config."
    return 0
  fi
  if command_path="$(command_path_from_capability "$capability")"; then
    [[ -x "$command_path" ]] ||
      fail "Agent capability ${capability} requires executable local command: ${command_path}"
    ok "Agent capability ${capability} is derivable from executable local command."
    return 0
  fi
  fail "Agent capability ${capability} is not enabled in ${CONFIG_FILE}."
}

validate_api_identity() {
  local agent_uuid agent_token response_file http_code payload version build_ref
  command -v curl >/dev/null 2>&1 || fail "curl is required for --validate-api."
  [[ -n "$API_BASE" ]] || API_BASE="$(config_value "agent" "api_base" "")"
  API_BASE="${API_BASE%/}"
  [[ -n "$API_BASE" ]] || fail "API base is required for --validate-api."
  UUID_FILE="$(config_value "identity" "agent_uuid_file" "$UUID_FILE")"
  TOKEN_FILE="$(config_value "identity" "agent_token_file" "$TOKEN_FILE")"
  agent_uuid="$(trim_file "$UUID_FILE")"
  agent_token="$(trim_file "$TOKEN_FILE")"
  version="unknown"
  build_ref="unknown"
  [[ -r /opt/mnscloud/agent/VERSION ]] && version="$(trim_file /opt/mnscloud/agent/VERSION)"
  [[ -r /opt/mnscloud/agent/build.json ]] && build_ref="$(sed -n 's/.*"buildRef"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' /opt/mnscloud/agent/build.json | head -n1)"
  payload="{\"hostname\":\"$(hostname -f 2>/dev/null || hostname)\",\"version\":\"${version}\",\"buildRef\":\"${build_ref}\",\"capabilities\":[\"linux.status\"]}"
  response_file="$(mktemp)"
  http_code="$(curl -sS -o "$response_file" -w "%{http_code}" \
    -X POST "${API_BASE}/api/v1/agent/heartbeat" \
    -H "Content-Type: application/json" \
    -H "X-MNSCloud-Agent-UUID: ${agent_uuid}" \
    -H "Authorization: Bearer ${agent_token}" \
    --data "$payload")" || {
      rm -f "$response_file"
      fail "Could not reach Agent heartbeat endpoint at ${API_BASE}/api/v1/agent/heartbeat."
    }
  if [[ "$http_code" != "200" ]]; then
    fail "Agent identity validation failed with HTTP ${http_code}: $(tr '\n' ' ' < "$response_file" | head -c 300)"
  fi
  rm -f "$response_file"
  ok "Agent identity validated by MNSCloud API."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-active) REQUIRE_ACTIVE=true; shift ;;
    --require-enrolled) REQUIRE_ENROLLED=true; shift ;;
    --require-job) REQUIRED_JOBS+=("${2:-}"); shift 2 ;;
    --require-capability) REQUIRED_CAPABILITIES+=("${2:-}"); shift 2 ;;
    --api-base) API_BASE="${2:-}"; shift 2 ;;
    --validate-api) VALIDATE_API=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) fail "Unsupported option: $1" ;;
  esac
done

for job in "${REQUIRED_JOBS[@]}"; do
  [[ -n "$job" ]] || fail "--require-job requires a value."
done
for capability in "${REQUIRED_CAPABILITIES[@]}"; do
  [[ -n "$capability" ]] || fail "--require-capability requires a value."
done

$REQUIRE_ACTIVE && validate_active
$REQUIRE_ENROLLED && validate_enrolled
for job in "${REQUIRED_JOBS[@]}"; do validate_job_support "$job"; done
for capability in "${REQUIRED_CAPABILITIES[@]}"; do validate_capability "$capability"; done
$VALIDATE_API && validate_api_identity

ok "Agent validation completed."
