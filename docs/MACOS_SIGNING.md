# macOS distribution signing

Initial macOS candidates without Developer ID are user-facing `UNSIGNED_DEVELOPMENT_ONLY`, even when the Apple linker added an ad-hoc signature. Machine metadata separately records `codeSignatureKind=none|linker-adhoc|developer-id`, CDHash, authorities, Team ID, hardened-runtime state, and strict verification.

Distribution-signing states are:

- `UNSIGNED_DEVELOPMENT_ONLY` — no Developer ID; Gatekeeper warnings are expected;
- `DEVELOPER_ID_SIGNED_NOT_NOTARIZED`;
- `DEVELOPER_ID_SIGNED_NOTARIZED_ONLINE_TICKET` — standalone CLI/ZIP, `stapling=not-applicable`, ticket checked online.

Applying Developer ID changes Mach-O bytes/CDHash. Packaging after signing changes the ZIP digest. Never sign or repackage an existing released asset in place: choose a distinct family-conforming version/name and append a new row. Owner-only temporary steps are in [`MACOS.md`](../MACOS.md). That file remains until owner-confirmed completion; after deletion these permanent states, naming rules, and durable evidence remain here and in the catalog/audit.

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for append-only contribution and metadata requirements.
