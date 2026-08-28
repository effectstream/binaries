from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from promotion_tool import make_receipt, validate_initial_proposal, validate_receipt_bindings  # noqa: E402
from warehouse_lib import WarehouseError, canonical_bytes, load_json, resolve_catalog, sha256_file, validate_catalog  # noqa: E402
from tests.test_proof_contract import proof_entry  # noqa: E402


class CleanRoomReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_warning_is_first_and_all_eleven_contracts_are_documented(self) -> None:
        self.assertTrue(self.readme.startswith("> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.**"))
        required = [
            "Permanent append-only rules", "Binary names, selectors, layouts, and coverage",
            "Choose the artifact operation", "Required metadata and evidence",
            "Prepare and validate a proposal", "Manual prerequisite and transaction sequence",
            "Executable examples and clean-room fixture", "Conflict, interruption, revocation, and drift",
            "macOS distribution signing", "Compact 0.34 direct-upstream policy", "Public proof-data guide",
            "explicit live-upload authority", "effective write permission", "numeric ID", "node ID",
            "inert", "mode-`0600` journal", "TOCTOU", "stable `published` catalog/index last",
            "atomic", "MIDNIGHT_PP", "K24/K25", "static-10",
        ]
        for text in required:
            self.assertIn(text, self.readme)

    def test_readme_linked_files_exist_and_example_executes(self) -> None:
        links = re.findall(r"\[[^]]+\]\(([^)]+)\)", self.readme)
        local = [link for link in links if not link.startswith(("https://", "http://", "#"))]
        for link in local:
            self.assertTrue((ROOT / link).exists(), link)
        result = subprocess.run(
            [str(ROOT / "scripts/resolve"), "--family", "indexer-standalone", "--version", "4.4.0-rc.1", "--os", "darwin", "--arch", "aarch64"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["assetName"], "indexer-standalone-macos-arm64-v4.4.0-rc.1.zip")
        self.assertRegex(payload["sha256"], r"^[0-9a-f]{64}$")

    def test_future_addition_controls_are_unambiguous(self) -> None:
        contracts = json.loads((ROOT / "metadata/contracts/families-v1.json").read_text())
        proof = json.loads((ROOT / "metadata/contracts/proof-data-q8b-v1.json").read_text())
        self.assertEqual(contracts["proofData"]["srs"]["multipleGenerationSelection"], "explicit-full-generation-required")
        self.assertEqual(contracts["proofData"]["ledgerStatic"]["multipleRevisionSelection"], "full-memberManifestSha256-required")
        self.assertEqual(proof["futureScope"]["k20Plus"], "owner-reviewed-manifest-required")
        self.assertEqual(proof["futureScope"]["customOrProjectKeys"], "forbidden")
        self.assertTrue(proof["githubReleaseIsNotMidnightParamSource"])
        pin = json.loads((ROOT / "protocol/forge-promotion-envelope-v1.json").read_text())
        self.assertEqual(pin["commitSha"], "2052e6e3d47495b8404876092d34e7bcbd560690")
        self.assertEqual(pin["canonicalization"], "forge-canonical-json-v1")
        self.assertEqual(len(pin["files"]), 7)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) for row in pin["files"]))

    def test_readme_exact_proposal_and_receipt_boundary_executes(self) -> None:
        proposal = load_json(ROOT / "metadata/proposals/initial-31-v1.json")
        names = sorted(proposal["binaryPayloads"] + proposal["proofPayloads"])
        candidate = [
            {"name": name, "size": len(name.encode("utf-8")), "sha256": hashlib.sha256(name.encode("utf-8")).hexdigest()}
            for name in names
        ]
        manifest = {"schemaVersion": "candidate-assets-v1", "assets": candidate}
        binary_names = set(proposal["binaryPayloads"])
        issuer = "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe"
        envelope = {
            "schemaVersion": "promotion-envelope-v1", "claimsDigest": "sha256:" + "d" * 64,
            "claims": {
                "issuer": {"commitSha": issuer}, "payloadCount": 31,
                "destination": {"repository": "effectstream/binaries", "tag": "0.3.120", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"},
                "contentAssets": [
                    {**row, "role": "payload", "artifactKind": "software" if row["name"] in binary_names else "proof-data", "componentId": "clean-room", "mediaType": "application/octet-stream"}
                    for row in candidate
                ],
            },
        }
        envelope_bytes = canonical_bytes(envelope)
        validate_initial_proposal(proposal, candidate, envelope)
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        prerequisite = {
            "schemaVersion": "publisher-prerequisite-v1", "capturedAt": now,
            "authorityRef": "owner-approval-clean-room", "githubHost": "github.com", "account": "acedward",
            "repository": {"fullName": "effectstream/binaries", "id": 1117580582, "nodeId": "R_kgDOQpztJg"},
            "release": {"tag": "0.3.120", "id": 270761136, "nodeId": "RE_kwDOQpztJs4QI3yw", "draft": False, "prerelease": False, "immutable": False},
            "checkout": {"origin": "git@github.com:effectstream/binaries.git", "head": "a" * 40, "clean": True},
            "tool": {"name": "check-manual-publisher-prereqs.sh", "scriptSha256": sha256_file(ROOT / "scripts/check-manual-publisher-prereqs.sh"), "ghVersion": "gh version clean-room"},
            "effectiveWrite": True, "result": "pass",
        }
        verification = {
            "schemaVersion": "candidate-verification-v1", "verifiedAt": now, "result": "pass", "testOnly": False,
            "protocolCommit": "2052e6e3d47495b8404876092d34e7bcbd560690",
            "protocolManifestSha256": sha256_file(ROOT / "protocol/forge-promotion-envelope-v1.json"),
            "forge": {"origin": "git@github.com:acedward/midnight-binary-forge.git", "head": "2052e6e3d47495b8404876092d34e7bcbd560690", "clean": True},
            "componentPolicy": {"origin": "git@github.com:acedward/midnight-binary-forge.git", "issuerCommit": issuer, "minimumCommit": issuer, "manifestSha256": sha256_file(ROOT / "protocol/forge-component-policy-v1.json"), "clean": True, "minimumAncestorVerified": True, "exactPinnedBlobs": True},
            "candidate": {"repository": "acedward/midnight-binary-forge", "tag": "clean-room", "releaseId": 1, "releaseNodeId": "RE_clean_room", "claimsDigest": "d" * 64},
            "envelopeSha256": hashlib.sha256(envelope_bytes).hexdigest(), "bundleSha256": "b" * 64,
            "liveEvidenceSha256": "c" * 64, "contentIdentitySha256": None,
        }
        receipt = make_receipt(
            snapshot=load_json(ROOT / "metadata/baselines/0.3.120-initial.json"),
            candidate=candidate, candidate_manifest=manifest, proposal=proposal,
            envelope_bytes=envelope_bytes, authority="owner-approval-clean-room",
            intended_body_bytes=(ROOT / "metadata/templates/release-body.md").read_bytes(),
            publisher_prerequisite=prerequisite, candidate_verification=verification,
        )
        validate_receipt_bindings(receipt, manifest)
        self.assertEqual(receipt["preflight"]["absentCount"], 31)
        self.assertEqual(receipt["preflight"]["conflictCount"], 0)

        for mutate in [
            lambda value: value.update({"payloadCount": 30}),
            lambda value: value["binaryPayloads"].__setitem__(0, "compactc-linux-amd64-v0.34.0.tar.gz"),
        ]:
            invalid = copy.deepcopy(proposal)
            mutate(invalid)
            with self.assertRaises(WarehouseError):
                validate_initial_proposal(invalid, candidate, envelope)

    def test_readme_extension_future_k_and_static_revision_gates_execute(self) -> None:
        catalog = load_json(ROOT / "metadata/releases/0.3.120.json")
        family_contract = load_json(ROOT / "metadata/contracts/families-v1.json")
        extended_contract = copy.deepcopy(family_contract)
        extended_contract["softwareFamilies"].append({
            "family": "future-tool", "nameTemplate": "future-tool-{os}-{arch}-v{version}.zip",
            "archive": "zip", "members": ["future-tool"], "installMode": "0755",
        })
        self.assertEqual(len(extended_contract["softwareFamilies"]), len(family_contract["softwareFamilies"]) + 1)
        unreviewed = copy.deepcopy(catalog)
        row = unreviewed["entries"][0]
        row["family"] = "future-tool"
        row["semanticId"] = f"future-tool/{row['version']}/{row['os']}/{row['arch']}"
        with self.assertRaises(WarehouseError):
            validate_catalog(unreviewed, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")

        future_k = proof_entry(k=19)
        future_k["proofData"].update({"k": 20, "officialAlias": "midnight-srs-2p20", "cacheAlias": "bls_midnight_2p20", "installedPath": "bls_midnight_2p20"})
        future_k["semanticId"] = "srs/20/midnight-trusted-setup-3ea610263b228af24840f7b00661ee22360db6d8"
        future_k["asset"].update({"name": "bls_midnight_2p20", "downloadUrl": "https://github.com/effectstream/binaries/releases/download/0.3.120/bls_midnight_2p20"})
        future_k["archive"]["members"][0]["path"] = "bls_midnight_2p20"
        future_catalog = copy.deepcopy(catalog)
        future_catalog["entries"].append(future_k)
        with self.assertRaisesRegex(WarehouseError, "outside the exact reviewed"):
            validate_catalog(future_catalog)

        first = proof_entry(semver="9.0.0", correction_seed="a")
        second = proof_entry(semver="9.0.0", correction_seed="b")
        second["asset"].update({"id": 1001, "nodeId": "RA_clean_room_2", "apiUrl": "https://api.github.com/repos/effectstream/binaries/releases/assets/1001"})
        revisions = copy.deepcopy(catalog)
        revisions["entries"].extend([first, second])
        validate_catalog(revisions, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")
        with self.assertRaisesRegex(WarehouseError, "Ledger-static"):
            resolve_catalog(revisions, family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation=None, ledger_static="9.0.0", member_manifest=None)
        selected = resolve_catalog(revisions, family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation=None, ledger_static="9.0.0", member_manifest=second["proofData"]["memberManifestSha256"])
        self.assertEqual(selected["assetName"], second["asset"]["name"])

        with self.assertRaises(WarehouseError):
            resolve_catalog(catalog, family="indexer-standalone", version="4.4.0-rc.1", os_name="linux", arch="amd64", variant=None, k=1, srs_generation=None, ledger_static=None, member_manifest=None)

    def test_macos_handoff_has_no_secret_or_example_credential(self) -> None:
        text = (ROOT / "MACOS.md").read_text(encoding="utf-8")
        for pattern in [r"ghp_[A-Za-z0-9]", r"github_pat_", r"BEGIN PRIVATE KEY", r"AC_PASSWORD=", r"APPLE_ID=.*@"]:
            self.assertIsNone(re.search(pattern, text), pattern)
        for required in ["--options runtime", "--timestamp", "without `--deep`", "notarytool", "--wait", "stapling=not-applicable", "online ticket", "quarantine", "distinct family-conforming"]:
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
