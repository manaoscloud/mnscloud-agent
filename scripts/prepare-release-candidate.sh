#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: prepare-release-candidate.sh --output <directory> --source-sha <git-sha> [--version <x.y.z>]
EOF
}

output=''
source_sha=''
version=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="${2:-}"; shift 2 ;;
    --source-sha) source_sha="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 64 ;;
  esac
done

[[ -n "$output" && -n "$source_sha" ]] || { usage >&2; exit 64; }
[[ "$source_sha" =~ ^[0-9a-f]{40}$ ]] || { echo 'source SHA must be a full lowercase SHA-1.' >&2; exit 64; }

cd "$ROOT_DIR"
if [[ -z "$version" ]]; then
  version="$(python3 - <<'PY'
import re
import subprocess

def parse(value):
    match = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)', value)
    return tuple(map(int, match.groups())) if match else None

versions = [parse(open('VERSION', encoding='utf-8').read().strip())]
for tag in subprocess.check_output(['git', 'tag', '--list', 'v[0-9]*'], text=True).splitlines():
    parsed = parse(tag[1:])
    if parsed:
        versions.append(parsed)
major, minor, patch = max(item for item in versions if item is not None)
print(f'{major}.{minor}.{patch + 1}')
PY
)"
fi

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid release version: $version" >&2; exit 64; }
mkdir -p "$output"
VERSION="$version" SOURCE_SHA="$source_sha" python3 - <<'PY' > "$output/release-candidate.json"
import datetime
import json
import os

print(json.dumps({
    'product': 'mnscloud-agent',
    'version': os.environ['VERSION'],
    'sourceSha': os.environ['SOURCE_SHA'],
    'createdAt': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
}, indent=2))
PY
printf '[mnscloud-agent] release candidate prepared: v%s (%s)\n' "$version" "$source_sha"
