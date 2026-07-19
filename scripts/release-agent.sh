#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PRODUCT='mnscloud-agent'
REPOSITORY='manaoscloud/mnscloud-agent'

usage() {
  cat <<'EOF'
Usage: release-agent.sh --verify-release-candidate <directory>
       release-agent.sh --promote-release-candidate <directory>
EOF
}

mode=''
candidate_dir=''
case "${1:-}" in
  --verify-release-candidate|--promote-release-candidate)
    mode="$1"
    candidate_dir="${2:-}"
    ;;
  *) usage >&2; exit 64 ;;
esac
[[ -n "$candidate_dir" && -f "$candidate_dir/release-candidate.json" ]] || {
  echo 'Release candidate metadata is required.' >&2
  exit 64
}

cd "$ROOT_DIR"
readarray -t candidate < <(python3 - "$candidate_dir/release-candidate.json" "$PRODUCT" <<'PY'
import json
import re
import sys

candidate = json.load(open(sys.argv[1], encoding='utf-8'))
if candidate.get('product') != sys.argv[2]:
    raise SystemExit('Release candidate product does not match this repository.')
version = candidate.get('version', '')
source = candidate.get('sourceSha', '')
if not re.fullmatch(r'\d+\.\d+\.\d+', version):
    raise SystemExit('Release candidate version is invalid.')
if not re.fullmatch(r'[0-9a-f]{40}', source):
    raise SystemExit('Release candidate source SHA is invalid.')
print(version)
print(source)
PY
)
version="${candidate[0]}"
source_sha="${candidate[1]}"
current_sha="$(git rev-parse HEAD)"
[[ "$current_sha" == "$source_sha" ]] || {
  echo "Candidate source SHA does not match checked out revision: $source_sha != $current_sha" >&2
  exit 65
}

if [[ "$mode" == '--verify-release-candidate' ]]; then
  printf '[%s] release candidate verified: v%s (%s)\n' "$PRODUCT" "$version" "$source_sha"
  exit 0
fi

tag="v${version}"
release_branch="release/${PRODUCT}-v${version}"
if git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1; then
  git fetch --quiet origin "refs/tags/${tag}:refs/tags/${tag}"
  tag_manifest="$(git show "${tag}:releases/manifest.json")"
  TAG_MANIFEST="$tag_manifest" VERSION="$version" SOURCE_SHA="$source_sha" python3 - <<'PY'
import json
import os

stable = json.loads(os.environ['TAG_MANIFEST']).get('channels', {}).get('stable', {})
if stable.get('version') != os.environ['VERSION'] or stable.get('sourceSha') != os.environ['SOURCE_SHA']:
    raise SystemExit('Existing release tag does not match this candidate.')
PY
  printf '[%s] release tag %s already promotes this candidate.\n' "$PRODUCT" "$tag"
else
  git switch --detach "$source_sha"
  RELEASE_VERSION="$version" SOURCE_SHA="$source_sha" python3 - <<'PY'
import datetime
import json
import os

with open('releases/manifest.json', encoding='utf-8') as handle:
    manifest = json.load(handle)
stable = manifest.setdefault('channels', {}).setdefault('stable', {})
stable.update({
    'version': os.environ['RELEASE_VERSION'],
    'ref': f"v{os.environ['RELEASE_VERSION']}",
    'releasedAt': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'),
    'minimumVersion': stable.get('minimumVersion', '1.0.0'),
    'autoUpdate': stable.get('autoUpdate', False),
    'sourceSha': os.environ['SOURCE_SHA'],
})
with open('VERSION', 'w', encoding='utf-8') as handle:
    handle.write(f"{os.environ['RELEASE_VERSION']}\n")
with open('releases/manifest.json', 'w', encoding='utf-8') as handle:
    json.dump(manifest, handle, indent=2)
    handle.write('\n')
PY
  git switch -C "$release_branch"
  git add VERSION releases/manifest.json
  git commit -m "Release ${PRODUCT} ${tag}"
  git tag -a "$tag" -m "Release ${PRODUCT} ${tag}"
  git push origin "HEAD:refs/heads/${release_branch}"
  git push origin "refs/tags/${tag}"
fi

if [[ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]]; then
  if ! gh release view "$tag" >/dev/null 2>&1; then
    gh release create "$tag" --title "${PRODUCT} ${tag}" --generate-notes
  fi
fi
printf '[%s] release promoted: %s\n' "$PRODUCT" "$tag"
