#!/bin/bash
# Updates the macOS Agent to a release tag (run by the one-shot launchd job of the Agent update,
# or by an operator). Bash 3.2 compatible.
set -euo pipefail

LOG_PREFIX="[update-agent-macos]"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SERVICE_LABEL="cloud.manaos.mnscloud.agent"
TARGET_REF=""
INSTALL_ARGS=()

log() { echo "${LOG_PREFIX} $1 ${*:2}"; }
fail() { log ERROR "$*"; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ref) TARGET_REF="${2:-}"; [[ -n "$TARGET_REF" ]] || fail "--ref requires a value"; shift 2 ;;
    --help|-h) echo "Usage: sudo bash scripts/update-agent-macos.sh --ref vX.Y.Z [install options]"; exit 0 ;;
    *) INSTALL_ARGS+=("$1"); shift ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || fail "Run as root, for example: sudo bash $0 --ref vX.Y.Z"
[[ "$TARGET_REF" =~ ^v[0-9]+[.][0-9]+[.][0-9]+$ ]] || fail "--ref must be a release tag (vX.Y.Z)."
[[ -d "${REPO_DIR}/.git" ]] || fail "Repository metadata not found; cannot check out ${TARGET_REF}."

cd "$REPO_DIR"
log INFO "Fetching Git tags and checking out ${TARGET_REF}."
git fetch --all --tags --prune
git -c advice.detachedHead=false checkout "$TARGET_REF"
log INFO "Reinstalling the Agent from ${REPO_DIR}."
/bin/bash "${REPO_DIR}/scripts/install-agent-macos.sh" --skip-latest ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"}
launchctl kickstart -k "system/${SERVICE_LABEL}"
log OK "MNSCloud Agent update to ${TARGET_REF} completed."
