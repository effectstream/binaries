#!/usr/bin/env bash
set -euo pipefail

repo="effectstream/binaries"
release="0.3.120"
baseline="metadata/baselines/0.3.120-initial.json"
independent_downloads=true

usage() {
  cat <<'EOF'
Usage: scripts/check-release-drift.sh [options]

Read-only full FR-039 drift check. It verifies repository/release/body/pagination and
all asset identity fields. Independent re-download hashing is on by default.

  --repo OWNER/REPO
  --release TAG
  --baseline FILE
  --skip-independent-downloads-for-test  Unit fixtures only; forbidden in CI/live checks
EOF
}

while (($#)); do
  case "$1" in
    --repo) repo=${2:?missing value}; shift 2 ;;
    --release) release=${2:?missing value}; shift 2 ;;
    --baseline) baseline=${2:?missing value}; shift 2 ;;
    --expected-asset-count)
      [[ ${2:?missing value} == 66 ]] || { echo 'only the exact baseline count 66 is accepted' >&2; exit 2; }
      shift 2
      ;;
    --skip-independent-downloads-for-test) independent_downloads=false; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ $repo == effectstream/binaries && $release == 0.3.120 ]] || {
  echo 'only the canonical effectstream/binaries@0.3.120 authority is accepted' >&2
  exit 2
}
[[ -f $baseline ]] || { echo "baseline not found: $baseline" >&2; exit 2; }

args=(drift --baseline "$baseline")
if [[ $independent_downloads == true ]]; then
  args+=(--independent-downloads)
elif [[ ${GITHUB_ACTIONS:-false} == true ]]; then
  echo 'CI/live drift checks may not skip independent downloads' >&2
  exit 2
fi

exec python3 "$(dirname "$0")/warehouse_lib.py" "${args[@]}"
