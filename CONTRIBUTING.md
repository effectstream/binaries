# Contributing development artifacts

This document defines artifact contribution, naming, metadata, evidence, and validation requirements. See [publishing operations](docs/PUBLISHING.md), [public proof-data policy](docs/PROOF_DATA.md), and [macOS signing policy](docs/MACOS_SIGNING.md) for the corresponding specialist procedures.

## Permanent append-only rules

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

## Binary names, selectors, layouts, and coverage

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

## Choose the artifact operation

Use exactly one operation and record it:

| Operation | Use when | Required identity evidence |
|---|---|---|
| `build` | source must be compiled | full source SHA/tag, locked dependency set, compiler/toolchain/image digest, flags/features, native runner label/OS/arch, reproducibility and license/runtime closure |
| `identity-mirror` | upstream bytes and name are retained | upstream repository/release/object and asset ID/node ID/name/URL/size/SHA-256; output digest must equal input |
| `rename-only` | upstream bytes are retained under an approved warehouse name | all identity-mirror fields, explicit old/new name mapping, output digest equal to input |
| `repackage` | approved upstream members are placed in the family archive contract | typed `deterministic-repackage-v1` record: exact input asset ID/node/name/URL/size/digest; each input member path/size/digest mapped to one exact output path/size/digest/mode/fixed timestamp; fixed archive algorithm/compression/order/path policy; outer size/digest; distinct-runner two-run digests plus independent read-back; source manifest, checksums, provenance, member lineage, license/runtime closure, and software SBOM |
| `assemble-data` | public noarch objects form a structured deterministic archive | every source URL/path/size/hash/destination/mode, lineage/license evidence, deterministic member-manifest digest |

Do not use `identity-mirror` if bytes change. Do not use `repackage` to hide an unknown source. A repackage record is invalid if any mapped byte, path, mode, timestamp, input identity, output identity, or either independent run differs. Known/new software rows must also match the machine-readable family coverage tier and exact archive/install layout. No payload moves forward until redistribution/license evidence and software runtime closure (or proof-data public lineage) are reviewed.

## Required metadata and evidence

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

## Prepare and validate a proposal

Start from a clean branch and edit metadata only. Do not download candidate bytes into the Git checkout.

```sh
python3 -m pip install -r requirements-ci.txt
scripts/validate-catalog
scripts/resolve --family indexer-standalone --version 4.4.0-rc.1 --os darwin --arch aarch64
```

For a new publication, commit the exact proposal and hidden planned catalog rows on the reviewed branch first. A future family, K, or static revision is valid only when that same review extends the corresponding machine-readable contract and binds the proposal to the new contract digests. CI exercises the real proposal/planned-catalog/preflight boundary; changing only a README example, outer filename, or claimed hash cannot authorize arbitrary bytes.

The resolver returns exactly one published `0.3.120` URL and SHA-256. It never guesses across OS, architecture, version, variant, K, SRS generation, or Ledger-static revision. Download to a new temporary directory, hash before extraction, then use a bounded family-aware extractor.

`Compact` and `compactc` proposals fail validation. Compact 0.34 is downloaded directly from the official LFDT-Minokawa `compactc-v0.34.0` release by pinned upstream asset identity/digest. It must never be built, mirrored, repackaged, uploaded, or cataloged here.

## Executable examples and clean-room fixture

CI executes the resolver example above and [`tests/test_clean_room.py`](tests/test_clean_room.py) using only documentation-linked contracts, schemas, proposals, metadata, templates, and scripts. The clean-room fixtures materialize deterministic family-conforming ZIP bytes, bind their real outer/member sizes and SHA-256 values into a planned row, and execute the production preflight payload/archive inspector and receipt boundary; the hosted two-pin fixture does the same before its exact verifier record crosses receipt validation. They also execute the stable resolver, validate the bound prerequisite/component-policy records, exercise future-K rejection and same-semver Ledger-static correction resolution, and prove an unreviewed family-contract edit remains fail-closed until its parser/schema/install/test changes land together. Their direct negatives cover Compact/count drift and mixed or ambiguous selectors. The companion manual-transaction fixtures exercise the live prerequisite and component-policy gates and reject stale or cross-state prerequisite evidence, pre-remediation/unrelated/regressed component issuers, foreign release drift, and unsafe continuation. Documentation changes that disagree with these executable surfaces fail CI.

## Compact 0.34 direct-upstream policy

**Do not publish Compact.** Resolve stable `compactc-v0.34.0` directly from official LFDT-Minokawa by the pinned source commit, release asset ID, size, and SHA-256 for the exact host. Compiler 0.34 adoption is a coordinated runtime-0.19/Ledger-9 migration. This schema, validator, candidate, catalog, and release must contain zero Compact payloads.
