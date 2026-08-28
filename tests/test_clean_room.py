from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from promotion_tool import main as promotion_main, make_receipt, validate_candidate_payloads, validate_initial_proposal, validate_receipt_bindings  # noqa: E402
from warehouse_lib import (  # noqa: E402
    WarehouseError,
    canonical_bytes,
    canonical_sha256,
    inspect_archive,
    load_json,
    load_release_baseline,
    resolve_catalog,
    sha256_file,
    stable_index,
    validate_catalog,
    validate_repository_state,
    write_canonical,
)
from tests.test_proof_contract import proof_entry  # noqa: E402


def current_catalog() -> dict:
    return load_json(ROOT / "metadata/releases/0.3.120.json")


class CleanRoomReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.index = load_json(ROOT / "metadata/index.json")

    def future_proposal(self, candidates: list[dict], *, binary_names: list[str], proof_names: list[str], family_contract: dict | None = None, proof_contract: dict | None = None) -> dict:
        family_contract = family_contract or load_json(ROOT / "metadata/contracts/families-v1.json")
        proof_contract = proof_contract or load_json(ROOT / "metadata/contracts/proof-data-q8b-v1.json")
        return {
            "schemaVersion": "warehouse-proposal-v1", "proposalId": "clean-room-reviewed-v1",
            "destination": {"repository": "effectstream/binaries", "releaseTag": "0.3.120", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"},
            "publicationState": "planned", "payloadCount": len(candidates),
            "evidenceRequired": ["source-manifest", "checksums", "license", "provenance", "attestation", "software-sbom-or-proof-member-lineage"],
            "binaryPayloads": binary_names, "proofPayloads": proof_names, "compactPayloadCount": 0,
            "contractExtension": {
                "reviewedId": "clean-room-reviewed-v1",
                "familyContractsSha256": canonical_sha256(family_contract),
                "proofContractsSha256": canonical_sha256(proof_contract),
            },
            "warning": "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE. Release `0.3.120` is mutable; verify every downloaded SHA-256 against committed metadata before installation or execution.",
        }

    def planned_indexer(self, candidate: dict, *, family: str = "indexer-standalone", version: str = "9.9.9", archive: dict | None = None) -> tuple[dict, dict]:
        catalog = current_catalog()
        contracts = load_json(ROOT / "metadata/contracts/families-v1.json")
        contract = next(row for row in contracts["softwareFamilies"] if row["family"] == family)
        name = contract["nameTemplate"].format(os="linux", arch="amd64", version=version)
        self.assertEqual(candidate["name"], name)
        members = [value.format(os="linux", arch="amd64", version=version) for value in contract["members"]]
        executable = members[-1]
        entry = {
            "semanticId": f"{family}/{version}/linux/amd64", "artifactKind": "software",
            "family": family, "version": version, "variant": None,
            "platform": "linux/amd64", "os": "linux", "arch": "amd64", "coverageTier": "required",
            "publicationState": "planned", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse",
            "asset": {**candidate, "state": "candidate"},
            "archive": archive or {"format": contract["archive"], "memberCount": len(members), "expandedSize": len(members), "members": [
                {"path": path, "type": "file", "size": 1, "sha256": hashlib.sha256(path.encode()).hexdigest(),
                 "storedMode": "0755" if path == executable else "0644", "installMode": "0755" if path == executable else "0644"}
                for path in members
            ], "legacyAnomalies": []},
            "install": {"path": executable, "mode": "0755"},
            "source": {"method": "build", "repository": "owner/source", "commitSha": "a" * 40,
                       "license": "Apache-2.0", "redistributionEvidence": "LICENSE@a",
                       "lockedDependenciesSha256": "b" * 64, "toolchain": "rust@sha256:" + "c" * 64,
                       "flags": [], "native": True},
            "evidence": {"sourceManifest": "source.json", "checksums": "SHA256SUMS", "provenance": "provenance.json", "sbom": "sbom.json", "memberLineage": None},
            "legacyProvenance": "known",
        }
        catalog["entries"].append(entry)
        catalog["entries"].sort(key=lambda row: row["semanticId"])
        return catalog, entry

    def envelope(self, candidates: list[dict], binary_names: list[str]) -> dict:
        return {
            "schemaVersion": "promotion-envelope-v1", "claimsDigest": "sha256:" + "b" * 64,
            "claims": {
                "issuer": {"repository": "acedward/midnight-binary-forge", "commitSha": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe", "workflowSha": "e" * 40},
                "candidateDraft": {"repository": "acedward/midnight-binary-forge", "tag": "clean-room", "releaseId": 1, "releaseNodeId": "RE_clean_room"},
                "staging": {"runId": 7, "runAttempt": 1, "artifactId": 8, "archiveSha256": "c" * 64},
                "transport": {"envelopeName": "promotion-envelope.json", "attestationBundleName": "attestation.sigstore.json"},
                "payloadCount": len(candidates),
                "destination": {"repository": "effectstream/binaries", "tag": "0.3.120", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"},
                "contentAssets": [
                    {**row, "role": "payload", "artifactKind": "software" if row["name"] in binary_names else "proof-data", "componentId": "clean-room", "mediaType": "application/octet-stream"}
                    for row in candidates
                ],
            },
        }

    def receipt_from_exact_two_pin_record(self, verification: dict) -> dict:
        """Drive the checked-in at/after-remediation verifier record through the receipt gate."""
        envelope_bytes = (ROOT / "tests/fixtures/integration-envelope-ddd.json").read_bytes()
        envelope = load_json(ROOT / "tests/fixtures/integration-envelope-ddd.json")
        candidate = [
            {key: row[key] for key in ("name", "size", "sha256")}
            for row in envelope["claims"]["contentAssets"] if row["role"] == "payload"
        ]
        manifest = {"schemaVersion": "candidate-assets-v1", "assets": candidate}
        proposal = self.future_proposal(candidate, binary_names=[candidate[0]["name"]], proof_names=[])
        with tempfile.TemporaryDirectory() as temporary:
            candidate_dir = Path(temporary)
            archive_path = candidate_dir / candidate[0]["name"]
            member_name = candidate[0]["name"].removesuffix(".zip")
            member = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = 0o100755 << 16
            member.compress_type = zipfile.ZIP_STORED
            with zipfile.ZipFile(archive_path, "w") as archive_file:
                archive_file.writestr(member, b"integration-indexer-fixture\n")
            self.assertEqual(
                {"size": archive_path.stat().st_size, "sha256": sha256_file(archive_path)},
                {"size": candidate[0]["size"], "sha256": candidate[0]["sha256"]},
            )
            planned_catalog, _ = self.planned_indexer(
                candidate[0], archive=inspect_archive(archive_path, candidate[0]["name"]),
            )
            validate_candidate_payloads(candidate_dir, planned_catalog)
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        prerequisite = {
            "schemaVersion": "publisher-prerequisite-v1", "capturedAt": now,
            "authorityRef": "owner-approval-two-pin-fixture", "githubHost": "github.com", "account": "acedward",
            "repository": {"fullName": "effectstream/binaries", "id": 1117580582, "nodeId": "R_kgDOQpztJg"},
            "release": {"tag": "0.3.120", "id": 270761136, "nodeId": "RE_kwDOQpztJs4QI3yw", "draft": False, "prerelease": False, "immutable": False},
            "checkout": {"origin": "git@github.com:effectstream/binaries.git", "head": "a" * 40, "clean": True},
            "tool": {"name": "check-manual-publisher-prereqs.sh", "scriptSha256": sha256_file(ROOT / "scripts/check-manual-publisher-prereqs.sh"), "ghVersion": "gh version hosted-two-pin-fixture"},
            "effectiveWrite": True, "result": "pass",
        }
        snapshot = load_release_baseline(ROOT / "metadata/baselines/0.3.120-current.json")
        snapshot["release"]["bodySha256"] = hashlib.sha256((ROOT / "metadata/templates/release-body.md").read_bytes()).hexdigest()
        receipt = make_receipt(
            snapshot=snapshot, candidate=candidate, candidate_manifest=manifest,
            proposal=proposal, planned_catalog=planned_catalog,
            envelope_bytes=envelope_bytes, authority=prerequisite["authorityRef"],
            intended_body_bytes=(ROOT / "metadata/templates/release-body.md").read_bytes(),
            publisher_prerequisite=prerequisite, candidate_verification=verification,
        )
        validate_receipt_bindings(receipt, manifest, allow_test_verification=True)
        return receipt

    def test_readme_is_warning_first_and_focused(self) -> None:
        first_line = (
            "> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.** Release `0.3.120` is mutable; "
            "verify every downloaded SHA-256 against committed metadata before installation or execution."
        )
        self.assertEqual(self.readme.splitlines()[0], first_line)
        self.assertEqual(self.readme.count("<!-- BEGIN GENERATED CURRENT FILE CATALOG -->"), 1)
        self.assertEqual(self.readme.count("<!-- END GENERATED CURRENT FILE CATALOG -->"), 1)
        self.assertIn("## Current files", self.readme)
        self.assertIn("## Documentation", self.readme)
        for operator_heading in [
            "Permanent append-only rules", "Binary names, selectors, layouts, and coverage",
            "Choose the artifact operation", "Required metadata and evidence",
            "Prepare and validate a proposal", "Manual prerequisite and transaction sequence",
            "Executable examples and clean-room fixture", "Conflict, interruption, revocation, and drift",
            "macOS distribution signing", "Compact 0.34 direct-upstream policy", "Public proof-data guide",
        ]:
            self.assertNotIn(operator_heading, self.readme)

    def test_generated_readme_catalog_exactly_matches_stable_index(self) -> None:
        result = subprocess.run(
            [str(ROOT / "scripts/render-readme-catalog"), "--check"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        rows = re.findall(
            r"^\| (software|proof-data) \| \[([^]]+)\]\((https://[^)]+)\) \| `([0-9a-f]{64})` \|$",
            self.readme,
            flags=re.MULTILINE,
        )
        actual = [(kind, name, url, sha256) for kind, name, url, sha256 in rows]
        expected = [
            (entry["artifactKind"], entry["assetName"], entry["url"], entry["sha256"])
            for entry in self.index["entries"]
        ]
        self.assertEqual(len(actual), 97)
        self.assertEqual(len(set(actual)), 97)
        self.assertEqual(sum(kind == "software" for kind, *_ in actual), 76)
        self.assertEqual(sum(kind == "proof-data" for kind, *_ in actual), 21)
        self.assertCountEqual(actual, expected)
        for _kind, name, _url, sha256 in actual:
            row = next(line for line in self.readme.splitlines() if f"[{name}]" in line)
            self.assertEqual(row.count(f"[{name}]"), 1)
            self.assertEqual(row.count(sha256), 1)

    def test_document_split_retains_all_operator_contracts(self) -> None:
        contracts = {
            ROOT / "CONTRIBUTING.md": [
                "Permanent append-only rules", "Binary names, selectors, layouts, and coverage",
                "Choose the artifact operation", "Required metadata and evidence",
                "Prepare and validate a proposal", "Executable examples and clean-room fixture",
                "Compact 0.34 direct-upstream policy", "numeric ID", "node ID",
            ],
            ROOT / "docs/PUBLISHING.md": [
                "Manual prerequisite and transaction sequence",
                "Conflict, interruption, revocation, and drift", "explicit live-upload authority",
                "effective write permission", "inert", "mode-`0600` journal", "TOCTOU",
                "stable `published` catalog/index last", "--planned-catalog", "--candidate-bundle",
                "--resume-prerequisite-record", "0.3.120-current.json", "run_id", "--created",
                'gh run watch "$run_id"',
            ],
            ROOT / "docs/PROOF_DATA.md": [
                "Public proof-data guide", "atomically replace", "MIDNIGHT_PP", "K24/K25", "static-10",
            ],
            ROOT / "docs/MACOS_SIGNING.md": [
                "macOS distribution signing", "UNSIGNED_DEVELOPMENT_ONLY",
                "DEVELOPER_ID_SIGNED_NOTARIZED_ONLINE_TICKET", "distinct family-conforming",
            ],
        }
        for path, required in contracts.items():
            text = path.read_text(encoding="utf-8")
            for phrase in required:
                self.assertIn(phrase, text, f"{phrase!r} missing from {path.relative_to(ROOT)}")

    def test_all_documentation_relative_links_resolve(self) -> None:
        markdown_files = [
            ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "MACOS.md",
            ROOT / "docs/PUBLISHING.md", ROOT / "docs/PROOF_DATA.md", ROOT / "docs/MACOS_SIGNING.md",
        ]
        for source in markdown_files:
            text = source.read_text(encoding="utf-8")
            for link in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
                if link.startswith(("https://", "http://", "mailto:", "#")):
                    continue
                target = link.split("#", 1)[0]
                self.assertTrue((source.parent / target).exists(), f"{source.relative_to(ROOT)} -> {link}")

    def test_documented_resolver_example_executes(self) -> None:
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
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        transaction_root = Path(temporary.name)
        os.chmod(transaction_root, 0o700)
        candidate_dir = transaction_root / "candidate"
        candidate_dir.mkdir(mode=0o700)
        name = "indexer-standalone-linux-amd64-v9.9.9.zip"
        archive_path = candidate_dir / name
        member_name = name.removesuffix(".zip")
        member_bytes = b"clean-room-indexer-fixture\n"
        member = zipfile.ZipInfo(member_name, date_time=(1980, 1, 1, 0, 0, 0))
        member.create_system = 3
        member.external_attr = 0o100755 << 16
        member.compress_type = zipfile.ZIP_STORED
        with zipfile.ZipFile(archive_path, "w") as archive_file:
            archive_file.writestr(member, member_bytes)
        candidate = [{"name": name, "size": archive_path.stat().st_size, "sha256": sha256_file(archive_path)}]
        manifest = {"schemaVersion": "candidate-assets-v1", "assets": candidate}
        proposal = self.future_proposal(candidate, binary_names=[name], proof_names=[])
        planned_catalog, _ = self.planned_indexer(candidate[0], archive=inspect_archive(archive_path, name))
        issuer = "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe"
        envelope = self.envelope(candidate, [name])
        envelope_bytes = canonical_bytes(envelope)
        validate_initial_proposal(proposal, candidate, envelope, planned_catalog)
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
        live_assets = [
            candidate[0],
            {"name": "promotion-envelope.json", "size": len(envelope_bytes), "sha256": hashlib.sha256(envelope_bytes).hexdigest()},
            {"name": "attestation.sigstore.json", "size": 1, "sha256": "b" * 64},
        ]
        live_assets.sort(key=lambda row: row["name"])
        live = {
            "schemaVersion": "promotion-live-evidence-v1", "capturedAt": now,
            "repository": {"fullName": "acedward/midnight-binary-forge", "id": 1349127482, "nodeId": "R_kgDOUGoNOg"},
            "protectedRef": {"ref": "refs/heads/main", "commitSha": issuer, "protected": True},
            "workflowFile": {"path": ".github/workflows/candidate.yml", "commitSha": issuer, "blobSha": "e" * 40},
            "run": {"id": 7, "attempt": 1, "repository": "acedward/midnight-binary-forge", "workflowPath": ".github/workflows/candidate.yml", "event": "workflow_dispatch", "headSha": issuer, "headRef": "main", "status": "completed", "conclusion": "success"},
            "stagingArtifact": {"id": 8, "runId": 7, "runAttempt": 1, "name": "clean-room-staging", "archiveSha256": "c" * 64, "expired": False, "expiresAt": "2030-01-01T00:00:00Z"},
            "release": {"id": 1, "nodeId": "RE_clean_room", "repository": "acedward/midnight-binary-forge", "tag": "clean-room", "targetCommitish": issuer, "url": "https://github.com/acedward/midnight-binary-forge/releases/tag/clean-room", "draft": False, "prerelease": True, "immutable": True},
            "releaseAssets": live_assets,
        }
        verification = {
            "schemaVersion": "candidate-verification-v1", "verifiedAt": now, "result": "pass", "testOnly": False,
            "protocolCommit": "2052e6e3d47495b8404876092d34e7bcbd560690",
            "protocolManifestSha256": sha256_file(ROOT / "protocol/forge-promotion-envelope-v1.json"),
            "forge": {"origin": "git@github.com:acedward/midnight-binary-forge.git", "head": "2052e6e3d47495b8404876092d34e7bcbd560690", "clean": True},
            "componentPolicy": {"origin": "git@github.com:acedward/midnight-binary-forge.git", "issuerCommit": issuer, "minimumCommit": issuer, "manifestSha256": sha256_file(ROOT / "protocol/forge-component-policy-v1.json"), "clean": True, "minimumAncestorVerified": True, "exactPinnedBlobs": True},
            "candidate": {"repository": "acedward/midnight-binary-forge", "tag": "clean-room", "releaseId": 1, "releaseNodeId": "RE_clean_room", "claimsDigest": "b" * 64},
            "envelopeSha256": hashlib.sha256(envelope_bytes).hexdigest(), "bundleSha256": "b" * 64,
            "liveEvidenceSha256": canonical_sha256(live),
            "liveEvidence": live, "contentIdentitySha256": canonical_sha256(candidate),
        }
        snapshot = load_release_baseline(ROOT / "metadata/baselines/0.3.120-current.json")
        snapshot["release"]["bodySha256"] = hashlib.sha256((ROOT / "metadata/templates/release-body.md").read_bytes()).hexdigest()
        paths = {
            "manifest": transaction_root / "candidate.json",
            "proposal": transaction_root / "proposal.json",
            "planned": transaction_root / "planned.json",
            "snapshot": transaction_root / "snapshot.json",
            "envelope": transaction_root / "promotion-envelope.json",
            "bundle": transaction_root / "attestation.sigstore.json",
            "prerequisite": transaction_root / "prerequisite.json",
            "body": transaction_root / "release-body.md",
        }
        for key, value in [
            ("manifest", manifest), ("proposal", proposal), ("planned", planned_catalog),
            ("snapshot", snapshot), ("prerequisite", prerequisite),
        ]:
            write_canonical(paths[key], value, mode=0o600 if key == "prerequisite" else 0o644)
        paths["envelope"].write_bytes(envelope_bytes)
        paths["bundle"].write_bytes(b"clean-room-test-bundle")
        paths["body"].write_bytes((ROOT / "metadata/templates/release-body.md").read_bytes())
        receipt_path = transaction_root / "receipt.json"
        argv = [
            "promotion_tool.py", "preflight", "--candidate-dir", str(candidate_dir),
            "--candidate-manifest", str(paths["manifest"]), "--proposal", str(paths["proposal"]),
            "--planned-catalog", str(paths["planned"]), "--snapshot", str(paths["snapshot"]),
            "--candidate-envelope", str(paths["envelope"]), "--authority", "owner-approval-clean-room",
            "--prerequisite-record", str(paths["prerequisite"]), "--candidate-bundle", str(paths["bundle"]),
            "--forge-checkout", str(transaction_root / "protocol"),
            "--forge-component-checkout", str(transaction_root / "component"),
            "--intended-release-body", str(paths["body"]), "--receipt", str(receipt_path),
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch("promotion_tool.validate_prerequisite_record"),
            mock.patch("promotion_tool.fresh_verify_candidate", return_value=verification) as verifier,
            mock.patch("promotion_tool.validate_component_policy_checkout"),
        ):
            self.assertEqual(promotion_main(), 0)
            verifier.assert_called_once()
        receipt = load_json(receipt_path)
        validate_receipt_bindings(receipt, manifest, allow_test_verification=True)
        self.assertEqual(receipt["candidateVerification"]["componentPolicy"]["issuerCommit"], issuer)
        self.assertEqual(receipt["preflight"]["absentCount"], 1)
        self.assertEqual(receipt["preflight"]["conflictCount"], 0)

        for mutate in [
            lambda value: value.update({"payloadCount": 30}),
            lambda value: value["binaryPayloads"].__setitem__(0, "compactc-linux-amd64-v0.34.0.tar.gz"),
        ]:
            invalid = copy.deepcopy(proposal)
            mutate(invalid)
            with self.assertRaises(WarehouseError):
                validate_initial_proposal(invalid, candidate, envelope, planned_catalog)

        # The checked-in current pointer is deterministic and still resolves to the
        # immutable 66-asset baseline until the reviewed publication rotates it.
        pointer = load_json(ROOT / "metadata/baselines/0.3.120-current.json")
        target = ROOT / "metadata/baselines" / pointer["snapshotPath"]
        self.assertEqual(pointer["snapshotSha256"], sha256_file(target))

        # Execute the documented state choreography without exposing the planned row
        # through the stable index and without skipping a transition.
        base = current_catalog()
        base_index_count = len(stable_index(base)["entries"])
        validate_repository_state(planned_catalog, stable_index(planned_catalog), base)
        uploading = copy.deepcopy(planned_catalog)
        row = next(item for item in uploading["entries"] if item["publicationState"] == "planned")
        row["publicationState"] = "uploading"
        row["asset"] = {
            "id": 1001, "nodeId": "RA_clean_room", **candidate[0], "state": "uploaded",
            "apiDigest": "sha256:" + candidate[0]["sha256"],
            "apiUrl": "https://api.github.com/repos/effectstream/binaries/releases/assets/1001",
            "downloadUrl": f"https://github.com/effectstream/binaries/releases/download/0.3.120/{name}",
            "contentType": "application/zip", "createdAt": now, "updatedAt": now,
        }
        with self.assertRaisesRegex(WarehouseError, "current baseline assets"):
            validate_repository_state(uploading, stable_index(uploading), planned_catalog)
        uploaded_snapshot = copy.deepcopy(snapshot)
        uploaded_snapshot["assets"].append(copy.deepcopy(row["asset"]))
        uploaded_snapshot["assets"].sort(key=lambda item: item["name"])
        uploaded_snapshot["pagination"]["totalCount"] += 1
        uploaded_snapshot["pagination"]["pages"][0]["count"] += 1
        validate_repository_state(uploading, stable_index(uploading), planned_catalog, uploaded_snapshot)
        verified = copy.deepcopy(uploading)
        next(item for item in verified["entries"] if item["semanticId"] == row["semanticId"])["publicationState"] = "verified"
        validate_repository_state(verified, stable_index(verified), uploading, uploaded_snapshot)
        published = copy.deepcopy(verified)
        next(item for item in published["entries"] if item["semanticId"] == row["semanticId"])["publicationState"] = "published"
        validate_repository_state(published, stable_index(published), verified, uploaded_snapshot)
        self.assertEqual(len(stable_index(planned_catalog)["entries"]), base_index_count)
        self.assertEqual(len(stable_index(published)["entries"]), base_index_count + 1)

    def test_readme_extension_future_k_and_static_revision_gates_execute(self) -> None:
        catalog = current_catalog()
        family_contract = load_json(ROOT / "metadata/contracts/families-v1.json")
        extended_contract = copy.deepcopy(family_contract)
        extended_contract["softwareFamilies"].append({
            "family": "future-tool", "nameTemplate": "future-tool-{os}-{arch}-v{version}.zip",
            "archive": "zip", "members": ["future-tool"], "installMode": "0755",
        })
        self.assertEqual(len(extended_contract["softwareFamilies"]), len(family_contract["softwareFamilies"]) + 1)
        source_candidate = {"name": "indexer-standalone-linux-amd64-v10.0.0.zip", "size": 7, "sha256": "a" * 64}
        unreviewed, row = self.planned_indexer(source_candidate, version="10.0.0")
        future_name = "future-tool-linux-amd64-v10.0.0.zip"
        row["family"] = "future-tool"
        row["semanticId"] = "future-tool/10.0.0/linux/amd64"
        row["asset"]["name"] = future_name
        row["archive"] = {"format": "zip", "memberCount": 1, "expandedSize": 1, "members": [{
            "path": "future-tool", "type": "file", "size": 1,
            "sha256": hashlib.sha256(b"future-tool").hexdigest(), "storedMode": "0755", "installMode": "0755",
        }], "legacyAnomalies": []}
        row["install"] = {"path": "future-tool", "mode": "0755"}
        with self.assertRaises(WarehouseError):
            validate_catalog(unreviewed, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")
        validate_catalog(
            unreviewed, ROOT / "metadata/schema/artifact-catalog-v1.schema.json",
            family_contracts_override=extended_contract,
        )
        future_candidate = [{"name": future_name, "size": 7, "sha256": "a" * 64}]
        future_proposal = self.future_proposal(
            future_candidate, binary_names=[future_name], proof_names=[], family_contract=extended_contract,
        )
        validate_initial_proposal(
            future_proposal, future_candidate, self.envelope(future_candidate, [future_name]), unreviewed,
            family_contracts=extended_contract,
        )

        proof_contract = load_json(ROOT / "metadata/contracts/proof-data-q8b-v1.json")
        extended_proof = copy.deepcopy(proof_contract)
        k20_digest = "d" * 64
        extended_proof["srs"]["objects"].append({
            "k": 20, "assetName": "bls_midnight_2p20", "installedPath": "bls_midnight_2p20",
            "officialAlias": "midnight-srs-2p20", "bytes": 7, "sha256": k20_digest,
            "srsGeneration": "midnight-trusted-setup@3ea610263b228af24840f7b00661ee22360db6d8",
        })
        extended_proof["payloadCount"] = 22
        future_k = proof_entry(k=19)
        future_k["publicationState"] = "planned"
        future_k["proofData"].update({"k": 20, "officialAlias": "midnight-srs-2p20", "cacheAlias": "bls_midnight_2p20", "installedPath": "bls_midnight_2p20"})
        future_k["semanticId"] = "srs/20/midnight-trusted-setup-3ea610263b228af24840f7b00661ee22360db6d8"
        future_k["asset"] = {"name": "bls_midnight_2p20", "state": "candidate", "size": 7, "sha256": k20_digest}
        future_k["archive"].update({"expandedSize": 7})
        future_k["archive"]["members"][0].update({"path": "bls_midnight_2p20", "size": 7, "sha256": k20_digest})
        future_catalog = copy.deepcopy(catalog)
        future_catalog["entries"].append(future_k)
        with self.assertRaisesRegex(WarehouseError, "outside the exact reviewed"):
            validate_catalog(future_catalog)
        validate_catalog(
            future_catalog, ROOT / "metadata/schema/artifact-catalog-v1.schema.json",
            proof_contract_override=extended_proof,
        )
        k20_candidate = [{"name": "bls_midnight_2p20", "size": 7, "sha256": k20_digest}]
        k20_proposal = self.future_proposal(
            k20_candidate, binary_names=[], proof_names=["bls_midnight_2p20"], proof_contract=extended_proof,
        )
        validate_initial_proposal(
            k20_proposal, k20_candidate, self.envelope(k20_candidate, []), future_catalog,
            proof_contract=extended_proof,
        )

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
