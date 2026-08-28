> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.** Release `0.3.120` is mutable; verify every downloaded SHA-256 against committed metadata before installation or execution.

# Effectstream development binary warehouse

[![Release drift](https://github.com/effectstream/binaries/actions/workflows/release-drift.yml/badge.svg)](https://github.com/effectstream/binaries/actions/workflows/release-drift.yml)

This repository is the metadata and operator surface for the permanent development-artifact warehouse at [`effectstream/binaries@0.3.120`](https://github.com/effectstream/binaries/releases/tag/0.3.120). Binary and public proof-data bytes live only as GitHub Release assets. They are appended manually from a maintainer's local authenticated session. Destination GitHub Actions has read-only `contents` permission and must never upload, alter, replace, or delete a release asset.

Release `0.3.120` is intentionally mutable as a location. A URL is not an identity. The committed SHA-256 is the identity and must be checked before installation or execution.

## 1. Permanent append-only rules

- The only canonical destination is repository `effectstream/binaries` (numeric ID `1117580582`, node ID `R_kgDOQpztJg`) and release `0.3.120` (numeric ID `270761136`, node ID `RE_kwDOQpztJs4QI3yw`). There is no successor release and no `legacyLocations` fallback.
- Never overwrite, delete, replace, rename, or use `--clobber` on an existing asset. Corrected bytes, changed source, a new proof-data generation, or later Developer-ID signing require a new family-conforming version/name and catalog row.
- Publication state is `planned → uploading → verified → published`, plus `revoked`. Stable resolution returns only `published`. Per-asset upload progress exists only in a local mode-`0600` journal.
- Every catalog row and resolver result is `distributionTier=development-only` and `releaseMutability=mutable-warehouse`.

A reviewed `planned` catalog row exposes only the candidate basename, `state=candidate`, exact byte count, and SHA-256; destination URLs and asset IDs do not exist yet and must not be invented. The upload remains journal-only while in flight. After complete independent read-back, a reviewed `uploading → verified` change fills the observed destination identity, and a final reviewed `verified → published` change updates the stable index. CI compares each catalog change with the reviewed PR base and rejects skipped or reversed transitions; running the validator locally uses the merge-base with `origin/main`, so fetch the current base first or pass `--previous-catalog` explicitly. Only the one-time first-catalog PR whose reviewed base contains no catalog reconstructs its exact prior 66 rows from the immutable independent-download baseline.

The schemas, exact backfill, stable index, family contracts, proof-data contract, and initial proposal are:

- [`metadata/schema/artifact-catalog-v1.schema.json`](metadata/schema/artifact-catalog-v1.schema.json)
- [`metadata/releases/0.3.120.json`](metadata/releases/0.3.120.json)
- [`metadata/index.json`](metadata/index.json)
- [`metadata/contracts/families-v1.json`](metadata/contracts/families-v1.json)
- [`metadata/contracts/proof-data-q8b-v1.json`](metadata/contracts/proof-data-q8b-v1.json)
- [`metadata/proposals/initial-31-v1.json`](metadata/proposals/initial-31-v1.json)

## 2. Binary names, selectors, layouts, and coverage

Canonical operating-system tokens are `linux|macos`; canonical architectures are `amd64|arm64`. Resolver inputs also accept `darwin|osx → macos`, `x86_64|x64 → amd64`, and `aarch64 → arm64`. Aliases never appear in canonical names.

| Family | Exact outer name | Archive/install contract |
|---|---|---|
| Avail | `avail-node-{os}-{arch}-v{version}.tar.gz` | Existing exceptions are cataloged; new executable installs `0755` |
| Celestia app | `celestia-appd-{os}-{arch}-v{version}.tar.gz` | `LICENSE`, `README.md`, `celestia-appd`; executable `0755` |
| Celestia node | `celestia-node-{os}-{arch}-v{version}.tar.gz` | `LICENSE`, `README.md`, `celestia`; executable `0755` |
| Indexer | `indexer-standalone-{os}-{arch}-v{version}.zip` | exactly one root executable named `indexer-standalone-{os}-{arch}-v{version}` (the archive basename without `.zip`), stored/installed `0755` |
| Midnight node | `midnight-node-{os}-{arch}-{version}.zip` | root versioned executable plus `res/` |
| Midnight node toolkit | `midnight-node-toolkit-{os}-{arch}-{version}.zip` | exactly one root `midnight-node-toolkit`, stored/installed `0755` |
| Proof-server executable | `midnight-proof-server-{os}-{arch}-{version}.zip` | one root versioned executable; new publication is deferred |
| Legacy proof-server executable | `midnight-proof-server-{os}-{arch}-ledger-{version}.zip` | `variant=ledger`; new publication is deferred |

For each new binary family/version set, `linux/amd64` and native `macos/arm64` are required, `linux/arm64` is desired, and `macos/amd64` is optional unless separately required. Existing exact published rows count toward completeness. A native target may not be satisfied by architecture fallback or a Linux-host Apple-SDK cross-build.

The selected toolkit set is exactly:

- `midnight-node-toolkit-linux-amd64-2.0.0-rc.4.zip`
- `midnight-node-toolkit-linux-arm64-2.0.0-rc.4.zip`
- `midnight-node-toolkit-macos-arm64-2.0.0-rc.4.zip`

Linux toolkits are deterministic repacks of exact upstream assets; macOS arm64 is a native locked source build. A new family cannot be forced through a generic template: obtain owner approval, then add its outer name, inner layout, install mapping, schema rule, resolver rule, and positive/negative golden fixtures before building or uploading.

## 3. Choose the artifact operation

Use exactly one operation and record it:

| Operation | Use when | Required identity evidence |
|---|---|---|
| `build` | source must be compiled | full source SHA/tag, locked dependency set, compiler/toolchain/image digest, flags/features, native runner label/OS/arch, reproducibility and license/runtime closure |
| `identity-mirror` | upstream bytes and name are retained | upstream repository/release/object and asset ID/node ID/name/URL/size/SHA-256; output digest must equal input |
| `rename-only` | upstream bytes are retained under an approved warehouse name | all identity-mirror fields, explicit old/new name mapping, output digest equal to input |
| `repackage` | approved upstream members are placed in the family archive contract | typed `deterministic-repackage-v1` record: exact input asset ID/node/name/URL/size/digest; each input member path/size/digest mapped to one exact output path/size/digest/mode/fixed timestamp; fixed archive algorithm/compression/order/path policy; outer size/digest; distinct-runner two-run digests plus independent read-back; source manifest, checksums, provenance, member lineage, license/runtime closure, and software SBOM |
| `assemble-data` | public noarch objects form a structured deterministic archive | every source URL/path/size/hash/destination/mode, lineage/license evidence, deterministic member-manifest digest |

Do not use `identity-mirror` if bytes change. Do not use `repackage` to hide an unknown source. A repackage record is invalid if any mapped byte, path, mode, timestamp, input identity, output identity, or either independent run differs. Known/new software rows must also match the machine-readable family coverage tier and exact archive/install layout. No payload moves forward until redistribution/license evidence and software runtime closure (or proof-data public lineage) are reviewed.

## 4. Required metadata and evidence

Every row records:

- schema and semantic ID; `artifactKind=software|proof-data`; family/version/variant or exact proof selector;
- target tier and `linux|macos` plus `amd64|arm64`, or exactly `platform=noarch` for proof data;
- immutable source/build/upstream identities, operation, locked inputs, license and redistribution evidence;
- GitHub asset numeric/node ID, exact name, API/download URL, state, size, API digest, independent SHA-256, timestamps, and content type;
- compressed/raw and expanded/member contract, stored mode, install path/mode, safety limits and legacy anomalies;
- dependencies/runtime closure, or exact proof-server source/image compatibility;
- SRS generation/K/official alias/cache alias, or Ledger-static semver/cache namespace/member-manifest revision;
- forge source manifest/checksums/provenance/attestation and software SBOM, or proof-data member/lineage manifest (never fabricate a software SBOM for data);
- publication state, `development-only`, `mutable-warehouse`, and applicable macOS signing/notarization evidence.

Candidate evidence remains in the immutable forge release and is referenced by warehouse metadata. Only typed payloads append to `0.3.120`; forge evidence assets are not destination payloads. The initial invariant is ten binary payloads plus twenty raw SRS objects and one Ledger-static archive: `payloadCount=31`.

## 5. Prepare and validate a proposal

Start from a clean branch and edit metadata only. Do not download candidate bytes into the Git checkout.

```sh
python3 -m pip install -r requirements-ci.txt
scripts/validate-catalog
scripts/resolve --family indexer-standalone --version 4.4.0-rc.1 --os darwin --arch aarch64
```

For a new publication, commit the exact proposal and hidden planned catalog rows on the reviewed branch first. A future family, K, or static revision is valid only when that same review extends the corresponding machine-readable contract and binds the proposal to the new contract digests. CI exercises the real proposal/planned-catalog/preflight boundary; changing only a README example, outer filename, or claimed hash cannot authorize arbitrary bytes.

The resolver returns exactly one published `0.3.120` URL and SHA-256. It never guesses across OS, architecture, version, variant, K, SRS generation, or Ledger-static revision. Download to a new temporary directory, hash before extraction, then use a bounded family-aware extractor.

`Compact` and `compactc` proposals fail validation. Compact 0.34 is downloaded directly from the official LFDT-Minokawa `compactc-v0.34.0` release by pinned upstream asset identity/digest. It must never be built, mirrored, repackaged, uploaded, or cataloged here.

## 6. Manual prerequisite and transaction sequence

The following sequence is mandatory and ordered. Candidate bytes are inert: never execute, source, extract during privileged verification, expand into a command, use as a path other than an exact safe basename, interpret workflow syntax, or print untrusted bytes to logs. Never enable shell tracing around authentication or upload commands. Do not put tokens, Apple credentials, wallets, environment files, databases, private caches, or secrets in Git, staging, Actions artifacts, receipts, journals, logs, or release assets.

1. Obtain explicit live-upload authority naming the repo/release/candidate. Record a non-secret authority reference. Fetch the reviewed warehouse PR, confirm the exact full commit SHA, clean worktree, and exact `origin`.
2. Confirm GitHub host/account/effective write permission and exact repo/release numeric+node identities. Authentication reports are suppressed to avoid credential metadata.
3. Independently verify the allowlisted immutable forge repository/workflow/ref/full SHA, candidate release/tag/ID/node ID/immutable state, canonical envelope, source manifest, checksums, staging asset-list digest, raw attestation bundle, and every inert asset size/digest. The preflight command itself freshly queries `github.com`, downloads the staging artifact and every candidate-release asset, compares those bytes with the local candidate, and reruns the raw protocol/attestation verifier; it never trusts an operator-supplied verification record. The warehouse consumes the exact audited promotion implementation pinned by [`protocol/forge-promotion-envelope-v1.json`](protocol/forge-promotion-envelope-v1.json) and separately requires the candidate issuer to contain or descend from the independently audited component-policy remediation pinned by [`protocol/forge-component-policy-v1.json`](protocol/forge-component-policy-v1.json). The exact remediated component/build schemas and validator blobs must also match that second pin. The warehouse does not redefine forge canonicalization, and a pre-remediation, unrelated, dirty, or regressed issuer is rejected.
4. Capture the complete FR-039 snapshot through all pages. It binds repository/release/body identities plus every legacy asset ID/node ID/name/state/size/API and independent download digest/API URL/download URL/content type/timestamps. A partial name-only inventory is invalid.
5. Run complete-set zero-write preflight. It reports every absent, identical no-op, and conflicting candidate name. Any conflict creates no release write, journal, catalog state, or stable index change.
6. Bind explicit authority, exact proposal, canonical candidate/envelope/list, complete snapshot hash, and intended warning-body digest into a mode-`0600` receipt. Type the exact receipt-hash confirmation.
7. Re-download/recheck the complete live snapshot immediately before the first write. This reduces but cannot eliminate concurrent-publisher TOCTOU.
8. Upload only absent safe basenames through the create-only GitHub API. There is no delete/edit/`--clobber` path. Fsync a sanitized mode-`0600` journal after every API response.
9. On the first duplicate, unexpected response, or drift: stop all remaining writes; capture a fresh complete snapshot and journal; reconcile only if every observed candidate byte belongs to the same receipt. A foreign digest or any legacy-asset change hard-stops.
10. Independently re-download the complete release (legacy plus additions), validate every identity/hash, and reconstruct proof data. Transition through `verified`; merge stable `published` catalog/index last; then run drift check.

Commands (values are deliberately explicit; no credential value is an argument):

```sh
REVIEWED_HEAD=0123456789abcdef0123456789abcdef01234567
AUTHORITY_REF=owner-approval-reference
FORGE_CHECKOUT=/absolute/read-only/path/to/midnight-binary-forge
FORGE_COMPONENT_CHECKOUT=/absolute/read-only/path/to/candidate-issuer/midnight-binary-forge
CANDIDATE_DIR=/absolute/private/mode-0700/candidate
RECEIPT_DIR=/absolute/private/mode-0700/receipts

scripts/check-manual-publisher-prereqs.sh \
  --repo effectstream/binaries --account acedward --release 0.3.120 \
  --reviewed-head "$REVIEWED_HEAD" --authority-ref "$AUTHORITY_REF" \
  --output "$RECEIPT_DIR/prerequisite.json"

scripts/snapshot-0.3.120 --output "$RECEIPT_DIR/preflight-snapshot.json" \
  --independent-downloads

scripts/preflight-upload \
  --candidate-dir "$CANDIDATE_DIR/payloads" \
  --candidate-manifest "$CANDIDATE_DIR/candidate-assets.json" \
  --proposal metadata/proposals/initial-31-v1.json \
  --planned-catalog "$CANDIDATE_DIR/planned-catalog.json" \
  --snapshot "$RECEIPT_DIR/preflight-snapshot.json" \
  --candidate-envelope "$CANDIDATE_DIR/promotion-envelope-initial-31-v1.json" \
  --authority "$AUTHORITY_REF" \
  --prerequisite-record "$RECEIPT_DIR/prerequisite.json" \
  --candidate-bundle "$CANDIDATE_DIR/attestation-initial-31-v1.sigstore.json" \
  --forge-checkout "$FORGE_CHECKOUT" \
  --forge-component-checkout "$FORGE_COMPONENT_CHECKOUT" \
  --intended-release-body metadata/templates/release-body.md \
  --receipt "$RECEIPT_DIR/receipt.json" \
  --report "$RECEIPT_DIR/conflicts.json"

# Read the exact receipt digest printed by preflight. Do not script acceptance.
scripts/upload-0.3.120 \
  --receipt "$RECEIPT_DIR/receipt.json" \
  --candidate-dir "$CANDIDATE_DIR/payloads" \
  --candidate-manifest "$CANDIDATE_DIR/candidate-assets.json" \
  --journal "$RECEIPT_DIR/journal.json" \
  --confirm 'UPLOAD effectstream/binaries 0.3.120 <exact-full-receipt-sha256>' \
  --forge-component-checkout "$FORGE_COMPONENT_CHECKOUT" \
  --execute

scripts/verify-release --receipt "$RECEIPT_DIR/receipt.json" \
  --output-snapshot "$RECEIPT_DIR/final-snapshot.json"
scripts/check-drift
```

Preflight issues no receipt until the live release body is the exact committed warning-body template. If the current body is still the reviewed old value, stop before preflight, apply only the exact `metadata/templates/release-body.md` body under separate confirmed authority, read the release back into a new full snapshot, and run the fresh prerequisite/preflight sequence into new files. An arbitrary pre-existing body, the old body, or any other release drift cannot be folded into a receipt or carried into asset creation.

The prerequisite and freshly generated candidate-verification records are canonical, mode-`0600`, and digest-bound into the receipt. Preflight and upload repeat the live checkout/account/repository/release/component-policy checks so a record captured in an earlier state cannot authorize a later state. The candidate-envelope, planned-catalog, and intended-body digests are always computed from the exact verified files; no operator-supplied digest can substitute them. Keep receipt/journal directories outside Git at `0700`; receipt/journal files are new-only, atomically written and fsynced at `0600`. Retain a sanitized final receipt/journal as audit evidence, never authentication output or response headers that may reveal credential metadata.

The typed transaction records are defined by [`publisher-prerequisite-v1`](metadata/schema/publisher-prerequisite-v1.schema.json), [`promotion-live-evidence-v1`](metadata/schema/promotion-live-evidence-v1.schema.json), [`candidate-verification-v1`](metadata/schema/candidate-verification-v1.schema.json), [`promotion-receipt-v1`](metadata/schema/promotion-receipt-v1.schema.json), and [`promotion-journal-v1`](metadata/schema/promotion-journal-v1.schema.json). Duplicate JSON keys, unknown fields, missing live identities, stale prerequisite records, digest rebinding, or a broken journal event chain fail closed.

## 7. Executable examples and clean-room fixture

CI executes the resolver example above and [`tests/test_clean_room.py`](tests/test_clean_room.py) using only README-linked contracts, schemas, proposals, metadata, templates, and scripts. The clean-room fixtures materialize deterministic family-conforming ZIP bytes, bind their real outer/member sizes and SHA-256 values into a planned row, and execute the production preflight payload/archive inspector and receipt boundary; the hosted two-pin fixture does the same before its exact verifier record crosses receipt validation. They also execute the stable resolver, validate the bound prerequisite/component-policy records, exercise future-K rejection and same-semver Ledger-static correction resolution, and prove an unreviewed family-contract edit remains fail-closed until its parser/schema/install/test changes land together. Their direct negatives cover Compact/count drift and mixed or ambiguous selectors. The companion manual-transaction fixtures exercise the live prerequisite and component-policy gates and reject stale or cross-state prerequisite evidence, pre-remediation/unrelated/regressed component issuers, foreign release drift, and unsafe continuation. README changes that disagree with these executable surfaces fail CI.

## 8. Conflict, interruption, revocation, and drift

- Identical existing name+size+digest is a no-op. A same name with different bytes is a hard conflict; never replace it.
- After interruption, run `scripts/reconcile-upload` with the receipt and a fresh full snapshot. If and only if it reports the exact same-receipt candidate additions plus absent names and zero foreign/repository/release/body/pagination/legacy drift, rerun the prerequisite probe into a new private record and repeat the same `scripts/upload-0.3.120` command with `--resume --resume-prerequisite-record /absolute/private/new-prerequisite.json`. The authenticated existing mode-`0600` journal, nonce, event hash chain, and exact receipt hash preserve lineage. A fresh transaction uses a new snapshot, prerequisite/candidate records, receipt, and journal. Foreign bytes or changed legacy fields hard-stop.
- A revoked artifact remains in the release/catalog as evidence, changes to `revoked`, disappears from stable resolution, and gets a reviewed incident advisory. A corrected new version/name is appended only after that PR.
- Consumer digest rejection is immediate. The daily read-only workflow provides best-effort detection within 24 hours plus GitHub delay. GitHub may disable schedules after 60 inactive days, so `acedward` runs the heartbeat at least weekly and before every upload or demo. Schedule-stop detection is bounded only by that check.

```sh
scripts/check-drift-heartbeat.sh --repo effectstream/binaries \
  --workflow release-drift.yml --max-age-hours 36
```

A green badge is not fresh evidence. Disabled, missing, failed, or older-than-36-hour state alerts. Recovery is explicit and read-only until inspection:

```sh
gh workflow enable release-drift.yml --repo effectstream/binaries
previous_run_id=$(gh run list --repo effectstream/binaries --workflow release-drift.yml \
  --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // ""')
dispatch_started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
gh workflow run release-drift.yml --repo effectstream/binaries
run_id=$(gh run list --repo effectstream/binaries --workflow release-drift.yml \
  --event workflow_dispatch --created ">=$dispatch_started" --limit 1 \
  --json databaseId --jq '.[0].databaseId')
test -n "$run_id"
test "$run_id" != "$previous_run_id"
gh run watch "$run_id" --repo effectstream/binaries --exit-status
scripts/check-drift-heartbeat.sh --repo effectstream/binaries \
  --workflow release-drift.yml --max-age-hours 36
```

The captured `run_id` must be the newly dispatched run; never substitute an older green run. If listing races dispatch, query again before watching. Record that ID in the incident acknowledgement.

On failure, `acedward` inspects the retained job report, records run ID/time and acknowledgement, then either records a false-alarm/fresh-success result or opens the reviewed manual `revoked` incident PR/advisory. The workflow only reports and never auto-revokes or auto-blesses bytes.

`metadata/baselines/0.3.120-current.json` is a rotatable pointer to the reviewed current live release snapshot, not a permanent initial-state oracle. Whenever an authorized body or asset append is independently verified, add a new immutable full snapshot under `metadata/baselines/`, record its raw-file SHA-256 in the pointer, and update both at the first post-write reviewed catalog state; later `verified`/`published` states retain that exact snapshot unless another authorized release change occurred. Never rewrite, rename, or delete an old snapshot. CI binds every pointed live asset to a non-planned catalog destination identity and rejects a pointer that blesses uncataloged bytes. A subsequent preflight must equal the pointed repository/release/legacy asset identities and may perform only its separately intended body transition; stale initial, pre-existing foreign, or unreviewed live drift is rejected.

## 9. macOS distribution signing

Initial macOS candidates without Developer ID are user-facing `UNSIGNED_DEVELOPMENT_ONLY`, even when the Apple linker added an ad-hoc signature. Machine metadata separately records `codeSignatureKind=none|linker-adhoc|developer-id`, CDHash, authorities, Team ID, hardened-runtime state, and strict verification.

Distribution-signing states are:

- `UNSIGNED_DEVELOPMENT_ONLY` — no Developer ID; Gatekeeper warnings are expected;
- `DEVELOPER_ID_SIGNED_NOT_NOTARIZED`;
- `DEVELOPER_ID_SIGNED_NOTARIZED_ONLINE_TICKET` — standalone CLI/ZIP, `stapling=not-applicable`, ticket checked online.

Applying Developer ID changes Mach-O bytes/CDHash. Packaging after signing changes the ZIP digest. Never sign or repackage an existing released asset in place: choose a distinct family-conforming version/name and append a new row. Owner-only temporary steps are in [`MACOS.md`](MACOS.md). That file remains until owner-confirmed completion; after deletion these permanent states, naming rules, and durable evidence remain here and in the catalog/audit.

## 10. Compact 0.34 direct-upstream policy

**Do not publish Compact.** Resolve stable `compactc-v0.34.0` directly from official LFDT-Minokawa by the pinned source commit, release asset ID, size, and SHA-256 for the exact host. Compiler 0.34 adoption is a coordinated runtime-0.19/Ledger-9 migration. This schema, validator, candidate, catalog, and release must contain zero Compact payloads.

## 11. Public proof-data guide

The selected architecture-neutral set is exactly twenty raw assets `bls_midnight_2p0` through `bls_midnight_2p19` plus `midnight-ledger-static-noarch-9.0.0.zip`: 21 payloads published once, never per OS, architecture, or proof-server release. These are public SRS/built-in Ledger inputs, not project-specific AA proving keys, wallets, private caches, or software binaries.

K1–K19 use `srsGeneration=midnight-trusted-setup@3ea610263b228af24840f7b00661ee22360db6d8`; official names `midnight-srs-2p{k}` map explicitly to cache names `bls_midnight_2p{k}`. K0 has no ceremony catalog row and truthfully uses provider compatibility provenance `midnight-ledger-provider-compat@7a89f45d29792be7e09ca5eb246f1e69f0b2a179/sha256:59b30b…`. All raw files install `0644` under their literal cache names.

The Ledger archive restores only twelve `zswap/9/*` and `dust/9/*` files at `0644`. Its identity is `ledgerStaticSemver=9.0.0`, `cacheNamespace=9`, and full `memberManifestSha256`; it is not versioned by proof-server RC. Exact rc.5 source plus the two pinned OCI digests accept static-9. Exact source `cd652d7…`/static-10 and its architecture-specific images reject static-9 while reusing the unchanged SRS.

Append-only correction rules:

- Changed bytes for an existing K use `midnight-srs-noarch-2p{k}-{generation}.bin`, where generation is `ts-<full-commit>`, `provider-<full-commit>-sha256-<full-digest>`, or `sha256-<full-digest>`. Multiple same-K rows require the explicit full generation and install to the mapped literal alias; never guess latest.
- A normal static semver bump uses `midnight-ledger-static-noarch-{semver}.zip`. Changed bytes under unchanged semver use `midnight-ledger-static-noarch-{semver}-manifest-sha256-{full-member-manifest-digest}.zip` with `ledgerStaticRevision=manifest-sha256:<full-digest>`. Multiple same-semver rows require the full member manifest.
- A changed same-semver Ledger archive never inherits rc.5 compatibility merely because its namespace is `9`: its typed correction record must bind the exact new member manifest, source commit, both tested image digests, pass result, and reviewed evidence digest/reference. Static-10 source/images remain a hard negative.
- Byte-identical proof data adds exact compatibility metadata without another upload.

Bootstrap/adoption rules: derive every generated BZKIR's K through the proof-server `/k` endpoint. Download only selected published rows, verify outer/raw and every member, compute the combined SRS+Ledger content-manifest SHA, take an exclusive lock, stage/fsync/verify on the same persistent filesystem, rename to immutable `generations/<combined-sha256>`, and atomically replace `current` while both readers are stopped. Resolve the pointer once and mount the same fixed generation path read-only into both services as `MIDNIGHT_PP`. Never mutate a generation in place. Retain the previous complete generation on failure; with readers quiesced, quarantine/repair a corrupt same-digest generation and garbage-collect only non-current/unreferenced generations.

Do not point `MIDNIGHT_PARAM_SOURCE` at the flat GitHub Release: nested Ledger paths cannot resolve there. The documented fallback remains `https://srs.midnight.network/`. An opt-in fallback uses a separate disposable writable copy and never mutates the persistent verified generation. Offline tests block that origin, cold-start/restart both rc.5 variants, exercise K18/K19 and Compact ZKIR-v2/v3, corrupt every member class, and prove exact rc.7/static-10 rejection.

K20+, a new Ledger namespace, any same-K generation, or a custom/project key needs owner approval, a new reviewed manifest, K query, size/storage/license/compatibility review, tests, and receipt. K24/K25 each exceed GitHub's under-2-GiB per-asset limit and cannot be single release assets. No allowlist grows silently.
