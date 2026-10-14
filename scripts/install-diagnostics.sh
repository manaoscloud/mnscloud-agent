#!/usr/bin/env bash
# Converge the restricted SSH diagnostics account (mns-diagnostics) from this Agent checkout.
# Called by install-agent.sh on every Agent install/update, so new and existing Linux hosts get
# the same allowlist without manual steps. Fresh hosts receive the approved public key in
# diagnostics/diagnostic-client.pub; existing accounts keep their keys, UID and GID.
# Never fatal for the Agent: failures are logged and retried on the next Agent update.
set -uo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../diagnostics" && pwd)"
SHELL_PATH=/usr/local/sbin/mns-diagnostics
COLLECTOR_PATH=/usr/local/lib/mns-diagnostics/collector.py
BACKUPS=/var/backups/mns-diagnostics
KEEP_BACKUPS=5

log() { printf '[mns-diagnostics] %s\n' "$*"; }

converge() {
  [[ "$(uname -s)" == Linux ]] || { log 'Skipped: Linux only.'; return 0; }
  [[ "$EUID" -eq 0 ]] || { log 'Skipped: root required.'; return 1; }
  if id mns-diagnostics >/dev/null 2>&1; then
    if cmp -s "$SOURCE_DIR/dispatcher.sh" "$SHELL_PATH" && cmp -s "$SOURCE_DIR/collector.py" "$COLLECTOR_PATH"; then
      log 'Current; no change.'
      return 0
    fi
    python3 -I "$SOURCE_DIR/manage.py" --update || return 1
  else
    python3 -I "$SOURCE_DIR/manage.py" --install "$SOURCE_DIR/diagnostic-client.pub" || return 1
  fi
  # Keep the most recent backups only; each is a root-only directory created by manage.py.
  if [[ -d "$BACKUPS" && ! -L "$BACKUPS" ]]; then
    find "$BACKUPS" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -rn |
      tail -n +"$((KEEP_BACKUPS + 1))" | cut -d' ' -f2- | while IFS= read -r old; do rm -rf -- "$old"; done
  fi
  log 'Converged.'
}

if ! converge; then
  log 'WARNING: diagnostics convergence failed; the Agent continues and retries on its next update.'
fi
exit 0
