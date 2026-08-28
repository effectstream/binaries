#!/usr/bin/env bash

set -euo pipefail

repo="effectstream/binaries"
workflow="release-drift.yml"
max_age_hours=36
fixture=""
now=""

usage() {
  cat <<'EOF'
Usage: scripts/check-drift-heartbeat.sh [options]

  --repo OWNER/REPO
  --workflow FILE_OR_ID
  --max-age-hours HOURS
  --fixture FILE          Read a non-secret test fixture instead of GitHub
  --now ISO8601           Override current time for deterministic fixture tests
EOF
}

while (($#)); do
  case "$1" in
    --repo)
      repo=${2:?missing value for --repo}
      shift 2
      ;;
    --workflow)
      workflow=${2:?missing value for --workflow}
      shift 2
      ;;
    --max-age-hours)
      max_age_hours=${2:?missing value for --max-age-hours}
      shift 2
      ;;
    --fixture)
      fixture=${2:?missing value for --fixture}
      shift 2
      ;;
    --now)
      now=${2:?missing value for --now}
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
[[ $workflow =~ ^[A-Za-z0-9._/-]+$ ]] || {
  echo "invalid workflow identity" >&2
  exit 2
}
[[ $max_age_hours =~ ^[0-9]+$ && $max_age_hours -gt 0 ]] || {
  echo "max age must be a positive integer" >&2
  exit 2
}

payload=$(mktemp)
workflow_json=$(mktemp)
runs_json=$(mktemp)
trap 'rm -f "$payload" "$workflow_json" "$runs_json"' EXIT
chmod 600 "$payload" "$workflow_json" "$runs_json"

if [[ -n $fixture ]]; then
  cp -- "$fixture" "$payload"
else
  # GET only: this checker never enables, dispatches, or otherwise mutates a workflow.
  gh api "repos/$repo/actions/workflows/$workflow" >"$workflow_json"
  workflow_id=$(jq -er '.id' "$workflow_json")
  gh api "repos/$repo/actions/workflows/$workflow_id/runs?per_page=1" >"$runs_json"
  jq -n \
    --slurpfile workflow "$workflow_json" \
    --slurpfile runs "$runs_json" '
      {
        workflow: $workflow[0],
        run: ($runs[0].workflow_runs[0] // null)
      }
    ' >"$payload"
fi

state=$(jq -er '.workflow.state' "$payload")
if [[ $state != active ]]; then
  echo "workflow heartbeat alert: state=$state (expected active)" >&2
  exit 1
fi

if ! jq -e '.run != null' "$payload" >/dev/null; then
  echo "workflow heartbeat alert: no run exists" >&2
  exit 1
fi

status=$(jq -er '.run.status' "$payload")
conclusion=$(jq -er '.run.conclusion' "$payload")
if [[ $status != completed || $conclusion != success ]]; then
  echo "workflow heartbeat alert: status=$status conclusion=$conclusion" >&2
  exit 1
fi

created_at=$(jq -er '.run.created_at' "$payload")
now=${now:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}
created_epoch=$(date -u -d "$created_at" +%s)
now_epoch=$(date -u -d "$now" +%s)
age_seconds=$((now_epoch - created_epoch))
max_age_seconds=$((max_age_hours * 3600))

if ((age_seconds < 0)); then
  echo "workflow heartbeat alert: latest run timestamp is in the future" >&2
  exit 1
fi
if ((age_seconds > max_age_seconds)); then
  echo "workflow heartbeat alert: latest successful run is older than ${max_age_hours}h" >&2
  exit 1
fi

printf 'PASS workflow=%s state=active run_id=%s conclusion=success age_seconds=%s url=%s\n' \
  "$workflow" \
  "$(jq -er '.run.id' "$payload")" \
  "$age_seconds" \
  "$(jq -er '.run.html_url' "$payload")"

