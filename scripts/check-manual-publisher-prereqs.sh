#!/usr/bin/env bash

set -euo pipefail
export GH_HOST=github.com

repo=""
account=""
release=""
reviewed_head=""
authority_ref=""
output=""

usage() {
  cat <<'EOF'
Usage: scripts/check-manual-publisher-prereqs.sh --repo OWNER/REPO --account LOGIN --release TAG --reviewed-head FULL_SHA --authority-ref REFERENCE --output RECORD.json

Read-only prerequisite probe. It never uploads, edits a release, or prints auth material.
EOF
}

while (($#)); do
  case "$1" in
    --repo)
      repo=${2:?missing value for --repo}
      shift 2
      ;;
    --account)
      account=${2:?missing value for --account}
      shift 2
      ;;
    --release)
      release=${2:?missing value for --release}
      shift 2
      ;;
    --reviewed-head)
      reviewed_head=${2:?missing value for --reviewed-head}
      shift 2
      ;;
    --authority-ref)
      authority_ref=${2:?missing value for --authority-ref}
      shift 2
      ;;
    --output)
      output=${2:?missing value for --output}
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
  echo "invalid or missing --repo" >&2
  exit 2
}
[[ $account =~ ^[A-Za-z0-9-]+$ ]] || {
  echo "invalid or missing --account" >&2
  exit 2
}
[[ $release =~ ^[A-Za-z0-9._-]+$ ]] || {
  echo "invalid or missing --release" >&2
  exit 2
}
[[ $reviewed_head =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid or missing --reviewed-head" >&2
  exit 2
}
[[ $authority_ref =~ ^[A-Za-z0-9][A-Za-z0-9._:/#@-]{2,255}$ ]] || {
  echo "invalid or missing --authority-ref" >&2
  exit 2
}
[[ -n $output && -d $(dirname "$output") && ! -e $output ]] || {
  echo "invalid, existing, or missing --output" >&2
  exit 2
}
python3 - "$output" <<'PY' || {
from pathlib import Path
import sys
path = Path(sys.argv[1])
parent = path.parent
if not path.is_absolute() or parent.is_symlink() or (parent.stat().st_mode & 0o077):
    raise SystemExit(1)
PY
  echo "--output must be absolute and its existing parent must be private (0700)" >&2
  exit 2
}

top_level=$(git rev-parse --show-toplevel 2>/dev/null) || {
  echo "publisher prerequisite failed: not a git checkout" >&2
  exit 1
}
[[ $(pwd -P) == $(cd "$top_level" && pwd -P) ]] || {
  echo "publisher prerequisite failed: run from checkout root" >&2
  exit 1
}

if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "publisher prerequisite failed: worktree is dirty" >&2
  exit 1
fi
git diff --check >/dev/null
actual_head=$(git rev-parse HEAD)
[[ $actual_head == "$reviewed_head" ]] || {
  echo "publisher prerequisite failed: checkout HEAD is not the explicitly reviewed commit" >&2
  exit 1
}

origin=$(git remote get-url origin 2>/dev/null) || {
  echo "publisher prerequisite failed: origin is missing" >&2
  exit 1
}
case "$origin" in
  "git@github.com:$repo.git"|"https://github.com/$repo.git"|"https://github.com/$repo"|"ssh://git@github.com/$repo.git")
    ;;
  *)
    echo "publisher prerequisite failed: origin does not match the intended repository" >&2
    exit 1
    ;;
esac

# Suppress gh's auth report because it contains credential metadata that does not belong in logs.
gh auth status --hostname github.com >/dev/null 2>&1 || {
  echo "publisher prerequisite failed: GitHub authentication is unavailable" >&2
  exit 1
}
active_account=$(gh api --hostname github.com user --jq '.login')
[[ $active_account == "$account" ]] || {
  echo "publisher prerequisite failed: active GitHub account is not the explicitly authorized account" >&2
  exit 1
}

repo_json=$(mktemp)
release_json=$(mktemp)
trap 'rm -f "$repo_json" "$release_json"' EXIT
chmod 600 "$repo_json" "$release_json"
gh api --hostname github.com "repos/$repo" >"$repo_json"
gh api --hostname github.com "repos/$repo/releases/tags/$release" >"$release_json"

jq -e --arg repo "$repo" '
  .full_name == $repo and
  .id == 1117580582 and
  .node_id == "R_kgDOQpztJg" and
  (.permissions.admin == true or .permissions.maintain == true or .permissions.push == true)
' "$repo_json" >/dev/null || {
  echo "publisher prerequisite failed: repository identity or effective write permission mismatch" >&2
  exit 1
}
jq -e --arg release "$release" '
  .tag_name == $release and
  .id == 270761136 and
  .node_id == "RE_kwDOQpztJs4QI3yw" and
  .draft == false and
  .prerelease == false and
  .immutable == false
' "$release_json" >/dev/null || {
  echo "publisher prerequisite failed: release identity mismatch" >&2
  exit 1
}

script_sha256=$(python3 - "$0" <<'PY'
import hashlib
from pathlib import Path
import sys
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)
gh_version=$(gh --version | head -n 1)
captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
record_tmp=$(mktemp "$(dirname "$output")/.publisher-prerequisite.XXXXXX")
chmod 600 "$record_tmp"
jq -S -c -n \
  --arg capturedAt "$captured_at" \
  --arg authorityRef "$authority_ref" \
  --arg account "$active_account" \
  --arg origin "$origin" \
  --arg head "$actual_head" \
  --arg scriptSha256 "$script_sha256" \
  --arg ghVersion "$gh_version" \
  --argjson repositoryId "$(jq '.id' "$repo_json")" \
  --arg repositoryNodeId "$(jq -r '.node_id' "$repo_json")" \
  --argjson releaseId "$(jq '.id' "$release_json")" \
  --arg releaseNodeId "$(jq -r '.node_id' "$release_json")" \
  '{
    schemaVersion:"publisher-prerequisite-v1", capturedAt:$capturedAt,
    authorityRef:$authorityRef, githubHost:"github.com", account:$account,
    repository:{fullName:"effectstream/binaries",id:$repositoryId,nodeId:$repositoryNodeId},
    release:{tag:"0.3.120",id:$releaseId,nodeId:$releaseNodeId,draft:false,prerelease:false,immutable:false},
    checkout:{origin:$origin,head:$head,clean:true},
    tool:{name:"check-manual-publisher-prereqs.sh",scriptSha256:$scriptSha256,ghVersion:$ghVersion},
    effectiveWrite:true,result:"pass"
  }' >"$record_tmp"
if ! ln "$record_tmp" "$output"; then
  unlink "$record_tmp"
  echo "publisher prerequisite failed: output appeared during capture; refusing to replace it" >&2
  exit 1
fi
unlink "$record_tmp"

printf 'PASS account=%s repository=%s repository_id=%s repository_node_id=%s release=%s release_id=%s release_node_id=%s head=%s authority_ref=%s worktree=clean mode=read-only\n' \
  "$active_account" \
  "$repo" \
  "$(jq -r '.id' "$repo_json")" \
  "$(jq -r '.node_id' "$repo_json")" \
  "$release" \
  "$(jq -r '.id' "$release_json")" \
  "$(jq -r '.node_id' "$release_json")" \
  "$actual_head" \
  "$authority_ref"
printf 'RECORD path=%s sha256=%s\n' "$output" "$(python3 - "$output" <<'PY'
import hashlib
from pathlib import Path
import sys
print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)"

echo 'WARNING: best-effort single-operator coordination and snapshot rechecks cannot eliminate concurrent-publisher TOCTOU.'
