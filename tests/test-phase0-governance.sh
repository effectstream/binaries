#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
checker="$repo_root/scripts/check-drift-heartbeat.sh"
workflow="$repo_root/.github/workflows/release-drift.yml"
fixture_dir=$(mktemp -d)
trap 'rm -rf "$fixture_dir"' EXIT

write_fixture() {
  local path=$1
  local state=$2
  local created_at=$3
  local status=$4
  local conclusion=$5
  jq -n \
    --arg state "$state" \
    --arg created_at "$created_at" \
    --arg status "$status" \
    --arg conclusion "$conclusion" '
      {
        workflow: {id: 100, state: $state},
        run: {
          id: 200,
          created_at: $created_at,
          status: $status,
          conclusion: $conclusion,
          html_url: "https://github.com/effectstream/binaries/actions/runs/200"
        }
      }
    ' >"$path"
}

expect_failure() {
  local label=$1
  shift
  if "$@" >"$fixture_dir/$label.stdout" 2>"$fixture_dir/$label.stderr"; then
    echo "expected failure: $label" >&2
    exit 1
  fi
}

write_fixture "$fixture_dir/success.json" active 2026-08-28T01:00:00Z completed success
write_fixture "$fixture_dir/disabled.json" disabled_manually 2026-08-28T01:00:00Z completed success
write_fixture "$fixture_dir/stale.json" active 2026-08-25T01:00:00Z completed success
write_fixture "$fixture_dir/failed.json" active 2026-08-28T01:00:00Z completed failure

"$checker" --fixture "$fixture_dir/success.json" --now 2026-08-28T02:00:00Z --max-age-hours 36 >/dev/null
expect_failure disabled "$checker" --fixture "$fixture_dir/disabled.json" --now 2026-08-28T02:00:00Z --max-age-hours 36
expect_failure stale "$checker" --fixture "$fixture_dir/stale.json" --now 2026-08-28T02:00:00Z --max-age-hours 36
expect_failure failed "$checker" --fixture "$fixture_dir/failed.json" --now 2026-08-28T02:00:00Z --max-age-hours 36

grep -F 'contents: read' "$workflow" >/dev/null
if grep -Eq 'contents:[[:space:]]*write|id-token:[[:space:]]*write|pull_request_target|release (create|upload|edit|delete)|gh release (create|upload|edit|delete)' "$workflow"; then
  echo "workflow contains a forbidden write/OIDC trigger or release command" >&2
  exit 1
fi
grep -F 'persist-credentials: false' "$workflow" >/dev/null

echo 'PASS phase0-governance-fixtures=4 workflow-permissions=read-only'

