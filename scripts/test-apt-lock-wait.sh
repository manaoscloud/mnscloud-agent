#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Exercise the real installer run()/lock helpers with stubbed lslocks, apt-get and sleep;
# never install packages or touch an Agent identity during this regression test.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
eval "$(sed -n '/^MNSCLOUD_APT_LOCK_TIMEOUT=/p; /^MNSCLOUD_APT_LOCK_PATTERN=/p; /^apt_locks_held() {$/,/^}$/p; /^apt_prepare_for_lock() {$/,/^}$/p; /^run() {$/,/^}$/p' scripts/install-agent.sh)"
MESSAGES="$WORK/messages"
log() { printf '%s %s\n' "$1" "${*:2}" >>"$MESSAGES"; }
info() { log INFO "$*"; }
warn() { log WARN "$*"; }
DRY_RUN=false
cat >"$WORK/lslocks" <<STUB
#!/usr/bin/env bash
n=\$(cat "$WORK/polls" 2>/dev/null || echo 0); echo \$((n + 1)) >"$WORK/polls"
if (( n < \${HELD_POLLS:-0} )); then echo /var/lib/apt/lists/lock; fi
STUB
cat >"$WORK/apt-get" <<STUB
#!/usr/bin/env bash
echo "apt-get \$* | \$(cat "\$APT_CONFIG")" >>"$WORK/apt-calls"
STUB
printf '#!/usr/bin/env bash\nexit 0\n' >"$WORK/sleep"
chmod +x "$WORK/lslocks" "$WORK/apt-get" "$WORK/sleep"
export PATH="$WORK:$PATH" TMPDIR="$WORK"
sleep() { command "$WORK/sleep" "$@"; }

check() (
  export HELD_POLLS="$1"
  MNSCLOUD_APT_LOCK_TIMEOUT="$2"
  unset APT_CONFIG
  rm -f "$WORK/polls" "$WORK/apt-calls" "$MESSAGES"
  run "echo not-apt-marker >/dev/null"
  run "apt-get update -y"
  polls="$(cat "$WORK/polls")"
  [[ "$polls" == "$3" ]] || { printf 'Expected %s lock polls, got %s\n' "$3" "$polls" >&2; exit 1; }
  grep -q "apt-get update -y | DPkg::Lock::Timeout \"$2\";" "$WORK/apt-calls" ||
    { echo 'apt-get did not run with the lock timeout config' >&2; exit 1; }
  grep -q "$4" "$MESSAGES" || { printf 'Missing message: %s\n' "$4" >&2; exit 1; }
)
check 3 600 4 'Waiting for another apt/dpkg process'
check 0 600 1 'RUN: apt-get update -y'
check 1000 10 3 'still held after 10s'
