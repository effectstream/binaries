#!/usr/bin/env bash

set -euo pipefail

repo="effectstream/binaries"
release="0.3.120"
expected_asset_count=""

usage() {
  cat <<'EOF'
Usage: scripts/check-release-drift.sh [options]

Read-only Phase 0 sanity check for the permanent development release.

  --repo OWNER/REPO
  --release TAG
  --expected-asset-count COUNT
EOF
}

while (($#)); do
  case "$1" in
    --repo)
      repo=${2:?missing value for --repo}
      shift 2
      ;;
    --release)
      release=${2:?missing value for --release}
      shift 2
      ;;
    --expected-asset-count)
      expected_asset_count=${2:?missing value for --expected-asset-count}
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ $repo =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || {
  echo "invalid repository identity" >&2
  exit 2
}
[[ $release =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "invalid release tag" >&2
  exit 2
}
[[ -z $expected_asset_count || $expected_asset_count =~ ^[0-9]+$ ]] || {
  echo "invalid expected asset count" >&2
  exit 2
}

snapshot=$(mktemp)
trap 'rm -f "$snapshot"' EXIT
chmod 600 "$snapshot"

# GET only: no subcommand in this script mutates repository or release state.
gh api "repos/$repo/releases/tags/$release" >"$snapshot"

jq -e \
  --arg repo "$repo" \
  --arg tag "$release" \
  --argjson release_id 270761136 '
    .tag_name == $tag and
    .draft == false and
    .prerelease == false and
    .immutable == false and
    .id == $release_id and
    (.url | contains("/repos/" + $repo + "/releases/"))
  ' "$snapshot" >/dev/null

actual_count=$(jq '.assets | length' "$snapshot")
if [[ -n $expected_asset_count && $actual_count -ne $expected_asset_count ]]; then
  echo "release asset count drift: expected $expected_asset_count, observed $actual_count" >&2
  exit 1
fi

jq -e '
  (.assets | length) == ([.assets[].name] | unique | length) and
  all(.assets[];
    .state == "uploaded" and
    (.size | type == "number" and . >= 0) and
    (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
    (.url | type == "string") and
    (.browser_download_url | type == "string")
  )
' "$snapshot" >/dev/null

printf 'PASS repo=%s release=%s release_id=%s assets=%s mode=read-only\n' \
  "$repo" "$release" "$(jq -r '.id' "$snapshot")" "$actual_count"
