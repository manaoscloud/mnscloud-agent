#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Exercise the real installer function with mocked package operations; never install
# packages or touch an Agent identity during this regression test.
eval "$(sed -n '/^ensure_deno() {$/,/^}$/p' scripts/install-agent.sh)"
ok() { :; }
log() { :; }
DRY_RUN=false
load_runtime_kit() { :; }
deno() { printf 'deno %s (stable)\n' "$TEST_INSTALLED"; }
mrtk_ensure_deno() { TEST_SELECTED="$MNSCLOUD_DENO_VERSION"; }
check() (
  TEST_INSTALLED="$1"
  TEST_SELECTED=preserved
  unset MNSCLOUD_DENO_VERSION
  [[ -z "$2" ]] || export MNSCLOUD_DENO_VERSION="$2"
  ensure_deno
  [[ "$TEST_SELECTED" == "$3" ]] || {
    printf 'Expected %s, got %s for installed=%s override=%s\n' "$3" "$TEST_SELECTED" "$1" "$2" >&2
    exit 1
  }
)
check 2.8.1 '' preserved
check 2.9.6 '' preserved
check 2.10.0 '' preserved
check 2.7.0 '' 2.8.1
check invalid '' 2.8.1
check 2.9.6 2.8.1 2.8.1
check 2.8.1 2.9.6 2.9.6
echo 'Shared Deno runtime selection passed'
