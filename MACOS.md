# Temporary owner handoff: Developer ID and notarization

Permanent signing states and append-only publication policy are documented in [`docs/MACOS_SIGNING.md`](docs/MACOS_SIGNING.md). This temporary owner handoff remains until the signed-artifact workflow is completed and confirmed.

> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.** Initial macOS release assets have no Developer ID and may be blocked by Gatekeeper. Never modify or replace an existing `0.3.120` asset.

This temporary file is for the owner performing the later signing step on a trusted macOS host. It contains no credential, identity, password, profile value, private key, or candidate-specific secret. Keep all working files outside Git in a mode-`0700` directory. Do not enable shell tracing and do not paste Keychain or notarization output containing private metadata into public logs.

Official references:

- [Inside Code Signing: Hashes](https://developer.apple.com/documentation/technotes/tn3126-inside-code-signing-hashes)
- [Create Developer ID certificates](https://developer.apple.com/help/account/certificates/create-developer-id-certificates)
- [Create distribution-signed code](https://developer.apple.com/documentation/xcode/creating-distribution-signed-code-for-the-mac/)
- [Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)

## 1. Freeze and inspect the initial bytes

Choose one binary and verify its downloaded ZIP SHA-256 against the published catalog before extraction. Record the released asset ID/name/size/SHA-256, source SHA, architecture, and initial ZIP digest. Extract into a fresh directory and identify the one intended Mach-O; reject links, traversal, extra executables, AppleDouble, or unexpected members.

```sh
codesign --display --verbose=4 -- "$BINARY" 2>before-codesign-display.txt || true
codesign --verify --strict --verbose=4 -- "$BINARY" 2>before-codesign-verify.txt || true
lipo -archs "$BINARY"
otool -L "$BINARY"
vtool -show-build "$BINARY"
shasum -a 256 "$BINARY" >before-binary.sha256
```

Classify `codeSignatureKind` truthfully:

- `none`: `codesign` reports no signature;
- `linker-adhoc`: a signature exists with no Developer ID authority/Team ID (common on Apple Silicon);
- `developer-id`: a valid Developer ID Application authority and Team ID exist.

Record the before-state CDHash, every authority line, Team ID (or null), hardened-runtime state, and strict-verification result. `none` or `linker-adhoc` remains user-facing `UNSIGNED_DEVELOPMENT_ONLY`.

## 2. Select the identity and stable code identifier

List identities locally and choose a valid `Developer ID Application` identity whose Team ID is owned by the operator. Never copy the certificate private key or identity output into Git.

```sh
security find-identity -v -p codesigning
```

Choose and record a stable reverse-DNS code identifier for this binary family. Pick a **distinct family-conforming follow-up version/name before signing**. Developer ID changes Mach-O bytes/CDHash and the later ZIP digest, so the released no-Developer-ID name is permanently reserved and must not be reused.

## 3. Sign inside-out, without `--deep`

If an archive ever contains nested signable code, sign the deepest verified item first and work outward. These initial contracts are raw CLI binaries, so sign the one binary. Do not use `--deep`.

```sh
codesign --force --timestamp --options runtime \
  --identifier "$CODE_IDENTIFIER" \
  --sign "$DEVELOPER_IDENTITY" \
  -- "$BINARY"
```

Then capture strict post-sign evidence:

```sh
codesign --display --verbose=4 -- "$BINARY" 2>after-codesign-display.txt
codesign --verify --strict --verbose=4 -- "$BINARY" 2>after-codesign-verify.txt
shasum -a 256 "$BINARY" >after-binary.sha256
```

Require Developer ID authority, expected Team ID/identifier, hardened runtime, timestamp, new CDHash, and strict verification success. Prove the before/after Mach-O digests differ.

## 4. Package after signing

Create the exact deterministic family archive only after signing. Re-run the complete archive/name/member/mode/architecture/linkage/version/smoke checks and write a new SHA-256. Never alter the accepted ZIP afterward.

The new ZIP name/version and catalog row must be distinct. The old row and bytes remain unchanged. `--clobber`, delete, replace, and in-place signing are forbidden.

## 5. Store notarization credentials in Keychain

Create a Keychain profile interactively. Do not put Apple ID passwords, app-specific passwords, issuer IDs, keys, certificates, or profile secrets in shell history, environment files, scripts, Git, Actions, archives, receipts, or logs.

```sh
xcrun notarytool store-credentials "$NOTARY_PROFILE"
```

The command prompts locally. Record only the non-secret profile label in private operator notes.

## 6. Submit once, wait, and retain the log

Submit the final byte-identical ZIP and wait:

```sh
xcrun notarytool submit "$FINAL_ZIP" \
  --keychain-profile "$NOTARY_PROFILE" --wait \
  --output-format json >notary-submit.json
```

Require `Accepted`, record submission ID and timestamps, then fetch and inspect the log locally:

```sh
xcrun notarytool log "$SUBMISSION_ID" \
  --keychain-profile "$NOTARY_PROFILE" >notary-log.json
```

Redact/check evidence before publication. Never re-ZIP after acceptance; doing so creates unsubmitted bytes.

## 7. Online-ticket and Gatekeeper verification

Raw CLI binaries and ZIP archives cannot be stapled. Record `stapling=not-applicable`; notarization is delivered through Apple's online ticket lookup. Verify the exact binary/ZIP using supported online checks and Gatekeeper:

```sh
codesign --check-notarization --verbose=4 -- "$BINARY"
spctl --assess --type execute --verbose=4 -- "$BINARY"
shasum -a 256 "$FINAL_ZIP"
```

On a separate clean Apple-Silicon Mac, download the ZIP through a browser so quarantine metadata is present, verify its catalog SHA-256, extract normally, and run `codesign --verify --strict`, `spctl`, architecture/linkage/version/help, and the exact family smoke probe. Do not strip quarantine to make the test pass.

## 8. Evidence and append-only publication

The reviewed row/evidence must include:

- old asset ID/name/Mach-O/ZIP digests and before `codeSignatureKind`;
- new distinct version/name, source/build identity, exact binary/ZIP SHA-256;
- stable identifier, authorities, Team ID, CDHash, timestamp, hardened runtime and strict verification;
- distribution state `DEVELOPER_ID_SIGNED_NOT_NOTARIZED` or `DEVELOPER_ID_SIGNED_NOTARIZED_ONLINE_TICKET`;
- notarization submission ID/status/times, sanitized log digest/reference, `stapling=not-applicable`, online-ticket result, Gatekeeper result, and clean quarantined-download smoke;
- proof that the old release asset was not changed and the new asset passed normal preflight/read-back/drift gates.

Only after owner confirmation, new-name P7/P8 publication, durable catalog/audit evidence, and verification may a follow-up PR delete this temporary file. The permanent README signing states, append-only rule, and evidence requirements remain.
