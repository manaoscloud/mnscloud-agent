#!/usr/bin/env bash
set -euo pipefail

LOG_PREFIX="[update-agent]"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_REF=""

usage() {
  cat <<'EOF'
Usage: sudo bash scripts/update-agent.sh --ref vX.Y.Z [install-agent options]

The updater requires an explicit Git tag/ref before reinstalling the agent.
Use the ref returned by the MNSCloud API from the release manifest.
EOF
}

log() {
  local level="$1"; shift
  echo "${LOG_PREFIX} ${level} $*"
}

info() { log INFO "$*"; }
ok() { log OK "$*"; }
fail() { log ERROR "$*"; exit 1; }

require_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || fail "Run as root, for example: sudo bash $0"
}

parse_update_args() {
  INSTALL_ARGS=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --ref)
        TARGET_REF="${2:-}"
        [[ -n "$TARGET_REF" ]] || fail "--ref requires a value"
        shift 2
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        INSTALL_ARGS+=("$1")
        shift
        ;;
    esac
  done
}

sync_repository() {
  [[ -n "$TARGET_REF" ]] || fail "--ref is required. Production Agent updates must use a release tag/ref."

  if [[ ! -d "${REPO_DIR}/.git" ]]; then
    fail "Repository metadata not found; cannot check out ${TARGET_REF}."
  fi

  cd "$REPO_DIR"

  info "Fetching Git tags and checking out ${TARGET_REF}."
  git fetch --all --tags --prune
  git -c advice.detachedHead=false checkout "$TARGET_REF"
}

main() {
  require_root
  parse_update_args "$@"
  sync_repository
  info "Reinstalling agent from ${REPO_DIR}."
  bash "${REPO_DIR}/scripts/install-agent.sh" "${INSTALL_ARGS[@]}"
  info "Restarting mnscloud-agent.service."
  systemctl restart mnscloud-agent.service
  systemctl status mnscloud-agent.service --no-pager
  ok "mnscloud-agent update completed."
}

main "$@"
