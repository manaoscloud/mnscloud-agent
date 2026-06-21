#!/usr/bin/env bash
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="/etc/mnscloud/agent/agent.conf"
CHANNEL="stable"
API_BASE="${MNSCLOUD_RELEASE_API_BASE_URL:-${MNSCLOUD_API_BASE_URL:-${API_BASE_URL:-}}}"
PRINT_COMMAND=0

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/update-latest-agent.sh [--api-base https://dev.publichost.cloud] [--channel stable] [--config /etc/mnscloud/agent/agent.conf] [--print-command]

This helper resolves the latest approved mnscloud-agent release from the MNSCloud API registry,
then calls update-agent.sh with the required release ref.

If --api-base is omitted, the helper reads [agent] api_base from the existing agent.conf.
Use --print-command to inspect the resolved update command without applying it.
For other environments, replace only the --api-base value with that environment's public edge base
URL.
EOF
}

read_agent_api_base() {
  local config_file="$1"
  [[ -f "$config_file" ]] || return 0
  awk '
    BEGIN { section = "" }
    /^[[:space:]]*\[/ {
      section = $0
      gsub(/^[[:space:]]*\[|\][[:space:]]*$/, "", section)
      next
    }
    section == "agent" && /^[[:space:]]*api_base[[:space:]]*=/ {
      sub(/^[^=]*=[[:space:]]*/, "", $0)
      gsub(/[[:space:]]+$/, "", $0)
      print $0
      exit
    }
  ' "$config_file"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-base) API_BASE="${2:-}"; shift 2 ;;
    --channel) CHANNEL="${2:-}"; shift 2 ;;
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    --print-command) PRINT_COMMAND=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf '[mnscloud-agent] ERROR: unknown argument: %s\n' "$1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "$API_BASE" ]]; then
  API_BASE="$(read_agent_api_base "$CONFIG_FILE")"
fi

if [[ -z "$API_BASE" ]]; then
  printf '[mnscloud-agent] ERROR: --api-base is required when agent.conf does not provide api_base.\n' >&2
  usage >&2
  exit 1
fi

API_BASE="${API_BASE%/}"
if [[ "$API_BASE" != */api/v1 ]]; then
  API_BASE="${API_BASE}/api/v1"
fi

export MNSCLOUD_AGENT_RELEASE_URL="${API_BASE}/runtime/releases/latest?product=mnscloud-agent&channel=${CHANNEL}"

eval "$(
python3 <<'PY'
import json
import os
import sys
import urllib.error
import urllib.request

url = os.environ["MNSCLOUD_AGENT_RELEASE_URL"]
try:
    with urllib.request.urlopen(url, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
except urllib.error.HTTPError as exc:
    body = exc.read().decode("utf-8", errors="replace")
    print(f"[mnscloud-agent] ERROR: release lookup failed HTTP {exc.code}: {body}", file=sys.stderr)
    sys.exit(1)
except Exception as exc:
    print(f"[mnscloud-agent] ERROR: release lookup failed: {exc}", file=sys.stderr)
    sys.exit(1)

data = payload.get("data")
if not isinstance(data, dict):
    print("[mnscloud-agent] ERROR: release lookup response did not include data", file=sys.stderr)
    sys.exit(1)
if not data.get("ref"):
    print("[mnscloud-agent] ERROR: release is missing required field: ref", file=sys.stderr)
    sys.exit(1)

for source, target in {
    "version": "VERSION",
    "ref": "REF",
    "buildRef": "BUILD_REF",
}.items():
    value = "" if data.get(source) is None else str(data.get(source))
    print(f"RELEASE_{target}={value!r}")
PY
)"

printf '[mnscloud-agent] latest release: %s (%s, build %s)\n' \
  "${RELEASE_VERSION:-unknown}" "$RELEASE_REF" "${RELEASE_BUILD_REF:-unknown}"

if [[ "$PRINT_COMMAND" == "1" ]]; then
  cat <<EOF
cd $REPO_ROOT
sudo bash scripts/update-agent.sh --ref '$RELEASE_REF'
sudo systemctl status mnscloud-agent --no-pager -l
EOF
  exit 0
fi

bash "$REPO_ROOT/scripts/update-agent.sh" --ref "$RELEASE_REF"
systemctl status mnscloud-agent --no-pager -l
