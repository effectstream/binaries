# Effectstream development binaries

[![Release drift](https://github.com/effectstream/binaries/actions/workflows/release-drift.yml/badge.svg)](https://github.com/effectstream/binaries/actions/workflows/release-drift.yml)

> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.** Release `0.3.120` is mutable; verify every downloaded SHA-256 against committed metadata before installation or execution.

This repository is the metadata and operator surface for the permanent development-artifact warehouse at [`0.3.120`](https://github.com/effectstream/binaries/releases/tag/0.3.120). Artifact bytes remain GitHub Release assets and are appended manually from a maintainer's local authenticated session. GitHub Actions is deliberately read-only and must never upload, edit, replace, or delete release assets.

## Phase 0 governance baseline

The daily `Release drift` workflow performs a read-only release/API sanity check and exposes its result through the badge above. The repository owner `acedward` treats a failed workflow run as the initial notification, opens the retained job summary/report, and records an acknowledgement before any remediation. The heartbeat check is mandatory at least weekly and before every upload or demo:

```sh
scripts/check-drift-heartbeat.sh \
  --repo effectstream/binaries \
  --workflow release-drift.yml \
  --max-age-hours 36
```

If the workflow is disabled, stale, or unsuccessful, recover it explicitly and require a fresh successful run before relying on the badge:

```sh
gh workflow enable release-drift.yml --repo effectstream/binaries
gh workflow run release-drift.yml --repo effectstream/binaries
gh run watch --repo effectstream/binaries --exit-status
scripts/check-drift-heartbeat.sh --repo effectstream/binaries --workflow release-drift.yml --max-age-hours 36
```

GitHub may disable scheduled workflows in inactive public repositories. A green badge is not evidence of freshness without the heartbeat check. Daily monitoring only reports; it never changes release or catalog state.

## Manual publisher boundary

Destination publication is a local, manual, append-only operation. Before a future upload tool is permitted to write, it must enforce all of the following:

1. Work from a clean, reviewed `effectstream/binaries` commit whose `origin` resolves exactly to this repository.
2. Run `gh auth status` without exporting or printing credentials, confirm the active account explicitly, and verify its effective permission on the exact repository and numeric release identity.
3. Treat every candidate name and byte as inert data. Never execute, source, interpolate, or trust candidate text as a path, command, workflow annotation, or log control sequence.
4. Capture a canonical complete live snapshot, bind its hash and the reviewed candidate/proposal to a receipt, and require typed confirmation.
5. Recheck the snapshot immediately before the first create-only upload. Never use `--clobber`; journal and fsync every response; re-download and hash every uploaded asset.
6. Coordinate one operator on a best-effort basis. Coordination and snapshot rechecks reduce but cannot eliminate a concurrent-publisher TOCTOU race. The first duplicate or unexpected state stops all remaining writes; reconciliation proceeds only for exact same-candidate bytes after a new full snapshot.
7. Keep stable metadata and the index unchanged until the complete release is read back and verified.

The Phase 0 prerequisite probe is read-only:

```sh
scripts/check-manual-publisher-prereqs.sh \
  --repo effectstream/binaries \
  --account acedward \
  --release 0.3.120
```

The complete artifact naming, metadata, receipt, upload, recovery, proof-data, and macOS-signing guide is added by the reviewed warehouse implementation phase before any asset upload.
