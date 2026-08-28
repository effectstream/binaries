# Publishing, recovery, and drift operations

Run all commands from the repository root. Artifact requirements and proposal preparation are defined in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Manual prerequisite and transaction sequence

The following sequence is mandatory and ordered. Candidate bytes are inert: never execute, source, extract during privileged verification, expand into a command, use as a path other than an exact safe basename, interpret workflow syntax, or print untrusted bytes to logs. Never enable shell tracing around authentication or upload commands. Do not put tokens, Apple credentials, wallets, environment files, databases, private caches, or secrets in Git, staging, Actions artifacts, receipts, journals, logs, or release assets.

1. Obtain explicit live-upload authority naming the repo/release/candidate. Record a non-secret authority reference. Fetch the reviewed warehouse PR, confirm the exact full commit SHA, clean worktree, and exact `origin`.
2. Confirm GitHub host/account/effective write permission and exact repo/release numeric+node identities. Authentication reports are suppressed to avoid credential metadata.
3. Independently verify the allowlisted immutable forge repository/workflow/ref/full SHA, candidate release/tag/ID/node ID/immutable state, canonical envelope, source manifest, checksums, staging asset-list digest, raw attestation bundle, and every inert asset size/digest. The preflight command itself freshly queries `github.com`, downloads the staging artifact and every candidate-release asset, compares those bytes with the local candidate, and reruns the raw protocol/attestation verifier; it never trusts an operator-supplied verification record. The warehouse consumes the exact audited promotion implementation pinned by [`protocol/forge-promotion-envelope-v1.json`](../protocol/forge-promotion-envelope-v1.json) and separately requires the live candidate issuer to descend from both the independently audited component-policy remediation and the Phase-6 policy revision pinned by [`protocol/forge-component-policy-v1.json`](../protocol/forge-component-policy-v1.json). The exact current component/build schemas and validator blobs must match that second pin. Its older audited fixture blobs remain in an explicit `testFixture` lane used only with the noncryptographic test marker; they cannot authorize a live candidate. The warehouse does not redefine forge canonicalization, and a pre-revision, unrelated, dirty, or regressed live issuer is rejected.
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

The typed transaction records are defined by [`publisher-prerequisite-v1`](../metadata/schema/publisher-prerequisite-v1.schema.json), [`promotion-live-evidence-v1`](../metadata/schema/promotion-live-evidence-v1.schema.json), [`candidate-verification-v1`](../metadata/schema/candidate-verification-v1.schema.json), [`promotion-receipt-v1`](../metadata/schema/promotion-receipt-v1.schema.json), and [`promotion-journal-v1`](../metadata/schema/promotion-journal-v1.schema.json). Duplicate JSON keys, unknown fields, missing live identities, stale prerequisite records, digest rebinding, or a broken journal event chain fail closed.

## Conflict, interruption, revocation, and drift

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
