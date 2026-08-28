# Public proof-data guide

The selected architecture-neutral set is exactly twenty raw assets `bls_midnight_2p0` through `bls_midnight_2p19` plus `midnight-ledger-static-noarch-9.0.0.zip`: 21 payloads published once, never per OS, architecture, or proof-server release. These are public SRS/built-in Ledger inputs, not project-specific AA proving keys, wallets, private caches, or software binaries.

K1–K19 use `srsGeneration=midnight-trusted-setup@3ea610263b228af24840f7b00661ee22360db6d8`; official names `midnight-srs-2p{k}` map explicitly to cache names `bls_midnight_2p{k}`. K0 has no ceremony catalog row and truthfully uses provider compatibility provenance `midnight-ledger-provider-compat@7a89f45d29792be7e09ca5eb246f1e69f0b2a179/sha256:59b30b…`. All raw files install `0644` under their literal cache names.

The Ledger archive restores only twelve `zswap/9/*` and `dust/9/*` files at `0644`. Its semantic identity is the canonical, file-only, path-sorted `ledger-static-member-manifest-v1` projection (`path`, `bytes`, `sha256`, `mode`) and full `memberManifestSha256`; deterministic ZIP directory/type/order evidence is retained separately as the ZIP-layout manifest and never changes the semantic digest algorithm. Its version identity is `ledgerStaticSemver=9.0.0` plus `cacheNamespace=9`, not a proof-server RC. Exact rc.5 source plus the two pinned OCI digests accept static-9. Exact source `cd652d7…`/static-10 and its architecture-specific images reject static-9 while reusing the unchanged SRS.

Append-only correction rules:

- Changed bytes for an existing K use `midnight-srs-noarch-2p{k}-{generation}.bin`, where generation is `ts-<full-commit>`, `provider-<full-commit>-sha256-<full-digest>`, or `sha256-<full-digest>`. Multiple same-K rows require the explicit full generation and install to the mapped literal alias; never guess latest.
- A normal static semver bump uses `midnight-ledger-static-noarch-{semver}.zip`. Changed bytes under unchanged semver use `midnight-ledger-static-noarch-{semver}-manifest-sha256-{full-member-manifest-digest}.zip` with `ledgerStaticRevision=manifest-sha256:<full-digest>`. Multiple same-semver rows require the full member manifest.
- A changed same-semver Ledger archive never inherits rc.5 compatibility merely because its namespace is `9`: its typed correction record must bind the exact new member manifest, source commit, both tested image digests, pass result, and reviewed evidence digest/reference. Static-10 source/images remain a hard negative.
- Byte-identical proof data adds exact compatibility metadata without another upload.

Bootstrap/adoption rules: derive every generated BZKIR's K through the proof-server `/k` endpoint. Download only selected published rows, verify outer/raw and every member, compute the combined SRS+Ledger content-manifest SHA, take an exclusive lock, stage/fsync/verify on the same persistent filesystem, rename to immutable `generations/<combined-sha256>`, and atomically replace `current` while both readers are stopped. Resolve the pointer once and mount the same fixed generation path read-only into both services as `MIDNIGHT_PP`. Never mutate a generation in place. Retain the previous complete generation on failure; with readers quiesced, quarantine/repair a corrupt same-digest generation and garbage-collect only non-current/unreferenced generations.

Do not point `MIDNIGHT_PARAM_SOURCE` at the flat GitHub Release: nested Ledger paths cannot resolve there. The documented fallback remains `https://srs.midnight.network/`. An opt-in fallback uses a separate disposable writable copy and never mutates the persistent verified generation. Offline tests block that origin, cold-start/restart both rc.5 variants, exercise K18/K19 and Compact ZKIR-v2/v3, corrupt every member class, and prove exact rc.7/static-10 rejection.

K20+, a new Ledger namespace, any same-K generation, or a custom/project key needs owner approval, a new reviewed manifest, K query, size/storage/license/compatibility review, tests, and receipt. K24/K25 each exceed GitHub's under-2-GiB per-asset limit and cannot be single release assets. No allowlist grows silently.

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for artifact metadata and evidence requirements.
