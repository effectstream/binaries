from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from promotion_tool import (  # noqa: E402
    append_journal,
    canonical_pagination_proof,
    candidate_rows,
    complete_conflict_report,
    fresh_verify_candidate,
    live_upload,
    make_receipt,
    parse_release_asset_link_header,
    reconcile,
    main as promotion_main,
    validate_initial_proposal,
    validate_component_policy_checkout,
    validate_journal,
    validate_preflight_snapshot_transition,
    validate_prerequisite_record,
    validate_receipt_bindings,
    verify_envelope_candidate_binding,
)
from warehouse_lib import WarehouseError, canonical_bytes, canonical_sha256, compare_snapshots, inspect_archive, load_json, sha256_file, snapshot_identity, write_canonical  # noqa: E402


class PromotionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = load_json(ROOT / "metadata/baselines/0.3.120-initial.json")
        body = (ROOT / "metadata/templates/release-body.md").read_bytes()
        cls.snapshot["release"]["bodySha256"] = hashlib.sha256(body).hexdigest()
        cls.proposal = load_json(ROOT / "metadata/proposals/initial-31-v1.json")

    def fixture_proposal(self, candidate: list[dict]) -> dict:
        return {
            "schemaVersion": "warehouse-proposal-v1", "proposalId": "fixture-reviewed-v1",
            "destination": {"repository": "effectstream/binaries", "releaseTag": "0.3.120", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"},
            "publicationState": "planned", "payloadCount": len(candidate),
            "evidenceRequired": ["source-manifest", "checksums", "license", "provenance", "attestation", "software-sbom-or-proof-member-lineage"],
            "binaryPayloads": [row["name"] for row in candidate], "proofPayloads": [],
            "compactPayloadCount": 0,
            "contractExtension": {
                "reviewedId": "fixture-reviewed-v1",
                "familyContractsSha256": canonical_sha256(load_json(ROOT / "metadata/contracts/families-v1.json")),
                "proofContractsSha256": canonical_sha256(load_json(ROOT / "metadata/contracts/proof-data-q8b-v1.json")),
            },
            "warning": "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE. Release `0.3.120` is mutable; verify every downloaded SHA-256 against committed metadata before installation or execution.",
        }

    def envelope(self, candidate: list[dict], proposal: dict) -> dict:
        binaries = set(proposal["binaryPayloads"])
        return {
            "schemaVersion": "promotion-envelope-v1",
            "claimsDigest": "sha256:" + "d" * 64,
            "claims": {
                "payloadCount": len(candidate),
                "issuer": {"repository": "acedward/midnight-binary-forge", "commitSha": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe", "workflowSha": "e" * 40},
                "candidateDraft": {"repository": "acedward/midnight-binary-forge", "tag": "fixture", "releaseId": 1, "releaseNodeId": "RE_fixture"},
                "staging": {"runId": 7, "runAttempt": 1, "artifactId": 8, "archiveSha256": "c" * 64},
                "transport": {"envelopeName": "promotion-envelope.json", "attestationBundleName": "attestation.sigstore.json"},
                "destination": {"repository": "effectstream/binaries", "tag": "0.3.120", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"},
                "contentAssets": [
                    {**row, "role": "payload", "artifactKind": "software" if row["name"] in binaries else "proof-data", "componentId": "fixture", "mediaType": "application/octet-stream"}
                    for row in candidate
                ],
            },
        }

    def evidence(self, envelope_bytes: bytes, authority: str = "owner-approval-1") -> tuple[dict, dict]:
        now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        head = "a" * 40
        envelope = json.loads(envelope_bytes)
        claims = envelope["claims"]
        issuer = claims["issuer"]["commitSha"]
        live_assets = [
            {"name": row["name"], "size": row["size"], "sha256": row["sha256"]}
            for row in claims["contentAssets"]
        ] + [
            {"name": claims["transport"]["envelopeName"], "size": len(envelope_bytes), "sha256": hashlib.sha256(envelope_bytes).hexdigest()},
            {"name": claims["transport"]["attestationBundleName"], "size": 1, "sha256": "b" * 64},
        ]
        live_assets.sort(key=lambda row: row["name"])
        live = {
            "schemaVersion": "promotion-live-evidence-v1", "capturedAt": now,
            "repository": {"fullName": "acedward/midnight-binary-forge", "id": 1349127482, "nodeId": "R_kgDOUGoNOg"},
            "protectedRef": {"ref": "refs/heads/main", "commitSha": issuer, "protected": True},
            "workflowFile": {"path": ".github/workflows/candidate.yml", "commitSha": issuer, "blobSha": claims["issuer"]["workflowSha"]},
            "run": {"id": 7, "attempt": 1, "repository": "acedward/midnight-binary-forge", "workflowPath": ".github/workflows/candidate.yml", "event": "workflow_dispatch", "headSha": issuer, "headRef": "main", "status": "completed", "conclusion": "success"},
            "stagingArtifact": {"id": 8, "runId": 7, "runAttempt": 1, "name": "fixture-staging", "archiveSha256": "c" * 64, "expired": False, "expiresAt": "2030-01-01T00:00:00Z"},
            "release": {"id": 1, "nodeId": "RE_fixture", "repository": "acedward/midnight-binary-forge", "tag": "fixture", "targetCommitish": issuer, "url": "https://github.com/acedward/midnight-binary-forge/releases/tag/fixture", "draft": False, "prerelease": True, "immutable": True},
            "releaseAssets": live_assets,
        }
        prerequisite = {
            "schemaVersion": "publisher-prerequisite-v1", "capturedAt": now,
            "authorityRef": authority, "githubHost": "github.com", "account": "acedward",
            "repository": {"fullName": "effectstream/binaries", "id": 1117580582, "nodeId": "R_kgDOQpztJg"},
            "release": {"tag": "0.3.120", "id": 270761136, "nodeId": "RE_kwDOQpztJs4QI3yw", "draft": False, "prerelease": False, "immutable": False},
            "checkout": {"origin": "git@github.com:effectstream/binaries.git", "head": head, "clean": True},
            "tool": {"name": "check-manual-publisher-prereqs.sh", "scriptSha256": sha256_file(ROOT / "scripts/check-manual-publisher-prereqs.sh"), "ghVersion": "gh version fixture"},
            "effectiveWrite": True, "result": "pass",
        }
        verification = {
            "schemaVersion": "candidate-verification-v1", "verifiedAt": now, "result": "pass", "testOnly": False,
            "protocolCommit": "2052e6e3d47495b8404876092d34e7bcbd560690",
            "protocolManifestSha256": sha256_file(ROOT / "protocol/forge-promotion-envelope-v1.json"),
            "forge": {"origin": "git@github.com:acedward/midnight-binary-forge.git", "head": "2052e6e3d47495b8404876092d34e7bcbd560690", "clean": True},
            "componentPolicy": {
                "origin": "git@github.com:acedward/midnight-binary-forge.git", "issuerCommit": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe",
                "minimumCommit": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe", "manifestSha256": sha256_file(ROOT / "protocol/forge-component-policy-v1.json"),
                "clean": True, "minimumAncestorVerified": True, "exactPinnedBlobs": True,
            },
            "candidate": {"repository": "acedward/midnight-binary-forge", "tag": "fixture", "releaseId": 1, "releaseNodeId": "RE_fixture", "claimsDigest": "d" * 64},
            "envelopeSha256": hashlib.sha256(envelope_bytes).hexdigest(), "bundleSha256": "b" * 64,
            "liveEvidenceSha256": canonical_sha256(live),
            "liveEvidence": live, "contentIdentitySha256": canonical_sha256([
                {"name": row["name"], "size": row["size"], "sha256": row["sha256"]}
                for row in sorted(claims["contentAssets"], key=lambda item: item["name"])
            ]),
        }
        return prerequisite, verification

    def planned_catalog(self, candidate: list[dict]) -> dict:
        catalog = load_json(ROOT / "metadata/releases/0.3.120.json")
        for row in candidate:
            match = re.fullmatch(r"indexer-standalone-linux-amd64-v(.+)[.]zip", row["name"])
            self.assertIsNotNone(match, row["name"])
            version = match.group(1)
            inner = row["name"].removesuffix(".zip")
            catalog["entries"].append({
                "semanticId": f"indexer-standalone/{version}/linux/amd64",
                "artifactKind": "software", "family": "indexer-standalone", "version": version,
                "variant": None, "platform": "linux/amd64", "os": "linux", "arch": "amd64",
                "coverageTier": "required", "publicationState": "planned",
                "distributionTier": "development-only", "releaseMutability": "mutable-warehouse",
                "asset": {**row, "state": "candidate"},
                "archive": {"format": "zip", "memberCount": 1, "expandedSize": 1, "members": [{
                    "path": inner, "type": "file", "size": 1, "sha256": hashlib.sha256(inner.encode()).hexdigest(),
                    "storedMode": "0755", "installMode": "0755",
                }], "legacyAnomalies": []},
                "install": {"path": inner, "mode": "0755"},
                "source": {"method": "build", "repository": "owner/source", "commitSha": "a" * 40,
                           "license": "Apache-2.0", "redistributionEvidence": "LICENSE@a",
                           "lockedDependenciesSha256": "b" * 64, "toolchain": "rust@sha256:" + "c" * 64,
                           "flags": [], "native": True},
                "evidence": {"sourceManifest": "source.json", "checksums": "SHA256SUMS", "provenance": "provenance.json", "sbom": "sbom.json", "memberLineage": None},
                "legacyProvenance": "known",
            })
        catalog["entries"].sort(key=lambda row: row["semanticId"])
        return catalog

    def receipt_for(self, candidate: list[dict], manifest: dict, proposal: dict) -> dict:
        envelope_bytes = canonical_bytes(self.envelope(candidate, proposal))
        prerequisite, verification = self.evidence(envelope_bytes)
        return make_receipt(
            snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest,
            proposal=proposal, planned_catalog=self.planned_catalog(candidate), envelope_bytes=envelope_bytes, authority="owner-approval-1",
            intended_body_bytes=(ROOT / "metadata/templates/release-body.md").read_bytes(),
            publisher_prerequisite=prerequisite, candidate_verification=verification,
        )

    def make_candidate(self, directory: Path, names: list[str] = ["indexer-standalone-linux-amd64-v9.9.1.zip"]) -> tuple[Path, dict]:
        rows = []
        for index, name in enumerate(sorted(names)):
            payload = f"fixture-{index}".encode()
            (directory / name).write_bytes(payload)
            import hashlib
            rows.append({"name": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        return directory, {"schemaVersion": "candidate-assets-v1", "assets": rows}

    def write_indexer_zip(self, directory: Path, *, version: str = "9.9.1") -> tuple[Path, dict, dict]:
        name = f"indexer-standalone-linux-amd64-v{version}.zip"
        inner = name.removesuffix(".zip")
        path = directory / name
        info = zipfile.ZipInfo(inner, date_time=(1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = (stat.S_IFREG | 0o755) << 16
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            archive.writestr(info, b"clean-room-indexer")
        candidate = [{"name": name, "size": path.stat().st_size, "sha256": sha256_file(path)}]
        manifest = {"schemaVersion": "candidate-assets-v1", "assets": candidate}
        planned = self.planned_catalog(candidate)
        planned_row = next(row for row in planned["entries"] if row["publicationState"] == "planned")
        planned_row["archive"] = inspect_archive(path, name)
        return path, manifest, planned

    def test_actual_preflight_archive_contract_and_strict_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            path, manifest, planned = self.write_indexer_zip(candidate_dir)
            candidate = manifest["assets"]
            proposal = self.fixture_proposal(candidate)
            envelope_bytes = canonical_bytes(self.envelope(candidate, proposal))
            prerequisite, verification = self.evidence(envelope_bytes)
            snapshot = copy.deepcopy(self.snapshot)
            files = {
                "manifest": root / "candidate.json", "proposal": root / "proposal.json",
                "planned": root / "planned.json", "snapshot": root / "snapshot.json",
                "envelope": root / "envelope.json", "bundle": root / "bundle.json",
                "prerequisite": root / "prerequisite.json", "body": root / "body.md",
            }
            for key, value in [
                ("manifest", manifest), ("proposal", proposal), ("planned", planned),
                ("snapshot", snapshot), ("prerequisite", prerequisite),
            ]:
                write_canonical(files[key], value, mode=0o600 if key == "prerequisite" else 0o644)
            files["envelope"].write_bytes(envelope_bytes)
            files["bundle"].write_bytes(b"fixture-bundle")
            files["body"].write_bytes((ROOT / "metadata/templates/release-body.md").read_bytes())
            receipt = root / "receipt.json"
            argv = [
                "promotion_tool.py", "preflight", "--candidate-dir", str(candidate_dir),
                "--candidate-manifest", str(files["manifest"]), "--proposal", str(files["proposal"]),
                "--planned-catalog", str(files["planned"]), "--snapshot", str(files["snapshot"]),
                "--candidate-envelope", str(files["envelope"]), "--authority", "owner-approval-1",
                "--prerequisite-record", str(files["prerequisite"]), "--candidate-bundle", str(files["bundle"]),
                "--forge-checkout", str(root / "protocol"), "--forge-component-checkout", str(root / "component"),
                "--intended-release-body", str(files["body"]), "--receipt", str(receipt),
            ]
            with mock.patch.object(sys, "argv", argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.fresh_verify_candidate", return_value=verification) as verifier, mock.patch("promotion_tool.validate_component_policy_checkout"):
                self.assertEqual(promotion_main(), 0)
                verifier.assert_called_once()
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            validate_receipt_bindings(load_json(receipt), manifest)
            original_receipt = receipt.read_bytes()
            with mock.patch.object(sys, "argv", argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.fresh_verify_candidate", return_value=verification), mock.patch("promotion_tool.validate_component_policy_checkout"):
                self.assertEqual(promotion_main(), 1)
            self.assertEqual(receipt.read_bytes(), original_receipt)

            # A matching basename/size/digest claim for arbitrary one-byte content
            # cannot substitute for the exact reviewed archive/member contract.
            bad_dir = root / "bad"
            bad_dir.mkdir()
            bad_path = bad_dir / path.name
            bad_path.write_bytes(b"x")
            bad_candidate = [{"name": path.name, "size": 1, "sha256": hashlib.sha256(b"x").hexdigest()}]
            bad_manifest = {"schemaVersion": "candidate-assets-v1", "assets": bad_candidate}
            bad_planned = self.planned_catalog(bad_candidate)
            bad_proposal = self.fixture_proposal(bad_candidate)
            bad_envelope = canonical_bytes(self.envelope(bad_candidate, bad_proposal))
            write_canonical(files["manifest"], bad_manifest)
            write_canonical(files["planned"], bad_planned)
            write_canonical(files["proposal"], bad_proposal)
            files["envelope"].write_bytes(bad_envelope)
            bad_argv = argv.copy()
            bad_argv[bad_argv.index(str(candidate_dir))] = str(bad_dir)
            bad_argv[bad_argv.index(str(receipt))] = str(root / "bad-receipt.json")
            with mock.patch.object(sys, "argv", bad_argv), mock.patch("promotion_tool.fresh_verify_candidate") as verifier:
                self.assertEqual(promotion_main(), 1)
                verifier.assert_not_called()

            # Duplicate-key JSON is rejected at the first consume boundary, before
            # any live verification or destination interaction.
            files["manifest"].write_text('{"schemaVersion":"candidate-assets-v1","schemaVersion":"candidate-assets-v1","assets":[]}\n')
            duplicate_argv = argv.copy()
            duplicate_argv[duplicate_argv.index(str(receipt))] = str(root / "duplicate-receipt.json")
            with mock.patch.object(sys, "argv", duplicate_argv), mock.patch("promotion_tool.fresh_verify_candidate") as verifier:
                self.assertEqual(promotion_main(), 1)
                verifier.assert_not_called()

            # Reject a forged huge central-directory count before ZipFile allocates
            # its member table.
            bounded = bytearray(path.read_bytes())
            eocd = bounded.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd, 0)
            struct.pack_into("<HH", bounded, eocd + 8, 0xFFFF, 0xFFFF)
            bomb = root / "bounded.zip"
            bomb.write_bytes(bounded)
            with self.assertRaisesRegex(WarehouseError, "ZIP64|member"):
                inspect_archive(bomb, "bounded.zip")

            tar_candidate = root / "bounded.tar.gz"
            tar_candidate.write_bytes(b"not-expanded-by-the-test")
            fake_archive = mock.MagicMock()
            fake_archive.__enter__.return_value = []
            with mock.patch("warehouse_lib.tarfile.open", return_value=fake_archive) as opener:
                with self.assertRaisesRegex(WarehouseError, "empty tar"):
                    inspect_archive(tar_candidate, tar_candidate.name)
            opener.assert_called_once_with(tar_candidate, mode="r|gz")

    def test_zero_write_preflight_absent_identical_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate_dir, manifest = self.make_candidate(Path(temporary))
            candidate = candidate_rows(candidate_dir, manifest)
            report = complete_conflict_report(self.snapshot, candidate)
            self.assertEqual((report["absentCount"], report["identicalCount"], report["conflictCount"]), (1, 0, 0))
            receipt = make_receipt(
                snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest,
                proposal=self.fixture_proposal(candidate), envelope_bytes=canonical_bytes(self.envelope(candidate, self.fixture_proposal(candidate))),
                planned_catalog=self.planned_catalog(candidate),
                authority="owner-approval-1", intended_body_bytes=(ROOT / "metadata/templates/release-body.md").read_bytes(),
                publisher_prerequisite=self.evidence(canonical_bytes(self.envelope(candidate, self.fixture_proposal(candidate))))[0],
                candidate_verification=self.evidence(canonical_bytes(self.envelope(candidate, self.fixture_proposal(candidate))))[1],
            )
            self.assertEqual(receipt["state"], "planned")
            self.assertEqual(receipt["preflight"]["absentCount"], 1)

            existing = copy.deepcopy(self.snapshot)
            matching = copy.deepcopy(candidate[0])
            matching.update({"id": 1000, "nodeId": "RA_fixture", "state": "uploaded", "apiDigest": "sha256:" + matching["sha256"], "apiUrl": "https://api.github.test/1000", "downloadUrl": "https://github.test/fixture", "contentType": "application/zip", "createdAt": "2026-08-28T00:00:00Z", "updatedAt": "2026-08-28T00:00:00Z"})
            existing["assets"].append(matching)
            report = complete_conflict_report(existing, candidate)
            self.assertEqual(report["identicalCount"], 1)
            existing["assets"][-1]["sha256"] = "f" * 64
            report = complete_conflict_report(existing, candidate)
            self.assertEqual(report["conflictCount"], 1)
            with self.assertRaisesRegex(WarehouseError, "conflicts"):
                make_receipt(snapshot=existing, candidate=candidate, candidate_manifest=manifest, proposal=self.fixture_proposal(candidate), planned_catalog=self.planned_catalog(candidate), envelope_bytes=b"{}", authority="owner", intended_body_bytes=b"body", publisher_prerequisite={}, candidate_verification={})
            with self.assertRaisesRegex(WarehouseError, "bound to proposal"):
                make_receipt(snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest, proposal=self.proposal, planned_catalog=self.planned_catalog(candidate), envelope_bytes=b"{}", authority="owner", intended_body_bytes=b"body", publisher_prerequisite={}, candidate_verification={})

    def test_inert_boundary_rejects_extra_symlink_and_control_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            candidate_dir, manifest = self.make_candidate(directory)
            (directory / "extra").write_bytes(b"x")
            with self.assertRaises(WarehouseError):
                candidate_rows(candidate_dir, manifest)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "link.zip").symlink_to("missing")
            manifest = {"schemaVersion": "candidate-assets-v1", "assets": [{"name": "link.zip", "size": 0, "sha256": "0" * 64}]}
            with self.assertRaises(WarehouseError):
                candidate_rows(directory, manifest)

    def test_exact_envelope_candidate_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate_dir, manifest = self.make_candidate(Path(temporary))
            candidate = candidate_rows(candidate_dir, manifest)
            envelope = {
                "schemaVersion": "promotion-envelope-v1",
                "claims": {
                    "payloadCount": 1,
                    "contentAssets": [{**candidate[0], "role": "payload", "artifactKind": "software", "componentId": "fixture", "mediaType": "application/zip"}],
                },
            }
            verify_envelope_candidate_binding(envelope, candidate)
            envelope["claims"]["contentAssets"][0]["sha256"] = "f" * 64
            with self.assertRaisesRegex(WarehouseError, "envelope"):
                verify_envelope_candidate_binding(envelope, candidate)

    def test_stale_snapshot_and_reconcile(self) -> None:
        intended_body_sha256 = hashlib.sha256((ROOT / "metadata/templates/release-body.md").read_bytes()).hexdigest()
        validate_preflight_snapshot_transition(self.snapshot, intended_body_sha256)
        old_body = copy.deepcopy(self.snapshot)
        old_body["release"]["bodySha256"] = load_json(ROOT / "metadata/baselines/0.3.120-initial.json")["release"]["bodySha256"]
        with self.assertRaisesRegex(WarehouseError, "exact intended warning body"):
            validate_preflight_snapshot_transition(old_body, intended_body_sha256)

        stale = copy.deepcopy(self.snapshot)
        stale["assets"][0]["updatedAt"] = "2026-08-28T00:00:00Z"
        with self.assertRaisesRegex(WarehouseError, "drift"):
            compare_snapshots(self.snapshot, stale)

        with tempfile.TemporaryDirectory() as temporary:
            candidate_dir, manifest = self.make_candidate(Path(temporary), [
                "indexer-standalone-linux-amd64-v9.9.1.zip",
                "indexer-standalone-linux-amd64-v9.9.2.zip",
            ])
            candidate = candidate_rows(candidate_dir, manifest)
            receipt = self.receipt_for(candidate, manifest, self.fixture_proposal(candidate))
            partial = self.uploaded_snapshot(candidate[:1])
            report = reconcile(receipt, partial)
            self.assertTrue(report["safeToResume"])
            self.assertEqual(len(report["exactCandidate"]), 1)
            self.assertEqual(len(report["absentCandidate"]), 1)
            partial["assets"][-1]["sha256"] = "f" * 64
            self.assertFalse(reconcile(receipt, partial)["safeToResume"])

            tampered_receipt = copy.deepcopy(receipt)
            tampered_receipt["snapshot"]["pagination"]["pages"][0]["link"] = "https://evil.invalid/arbitrary"
            self.assertFalse(reconcile(tampered_receipt, self.uploaded_snapshot(candidate[:1]))["safeToResume"])
            duplicate_node_receipt = copy.deepcopy(receipt)
            duplicate_node_receipt["snapshot"]["assets"][1]["nodeId"] = duplicate_node_receipt["snapshot"]["assets"][0]["nodeId"]
            self.assertFalse(reconcile(duplicate_node_receipt, self.uploaded_snapshot(candidate[:1]))["safeToResume"])

            for mutate in [
                lambda value: value["repository"].update({"id": 1}),
                lambda value: value["release"].update({"id": 1}),
                lambda value: value["release"].update({"nodeId": "RE_recreated"}),
                lambda value: value["release"].update({"bodySha256": "f" * 64}),
                lambda value: value["release"].update({"unexpected": True}),
                lambda value: value["pagination"].update({"complete": False}),
                lambda value: value["pagination"].update({"totalCount": 0}),
                lambda value: value["pagination"].update({"pages": []}),
                lambda value: value["pagination"]["pages"][0].update({"link": "https://evil.invalid/arbitrary"}),
                lambda value: value["assets"][-1].update({"nodeId": value["assets"][0]["nodeId"]}),
            ]:
                invalid = self.uploaded_snapshot(candidate[:1])
                mutate(invalid)
                self.assertFalse(reconcile(receipt, invalid)["safeToResume"])

    def test_pagination_link_parser_binds_exact_release_and_relations(self) -> None:
        first = (
            '<https://api.github.com/repositories/1117580582/releases/270761136/assets?per_page=100&page=2>; rel="next", '
            '<https://api.github.com/repositories/1117580582/releases/270761136/assets?per_page=100&page=3>; rel="last"'
        )
        final = (
            '<https://api.github.com/repos/effectstream/binaries/releases/270761136/assets?per_page=100&page=1>; rel="first", '
            '<https://api.github.com/repos/effectstream/binaries/releases/270761136/assets?per_page=100&page=2>; rel="prev"'
        )
        self.assertEqual(parse_release_asset_link_header(first), {"next": 2, "last": 3})
        self.assertEqual(parse_release_asset_link_header(final), {"first": 1, "prev": 2})
        self.assertIsNone(parse_release_asset_link_header(None))
        for invalid in [
            "https://evil.invalid/arbitrary",
            '<https://evil.invalid/repos/effectstream/binaries/releases/270761136/assets?per_page=100&page=2>; rel="next"',
            '<https://api.github.com/repos/effectstream/binaries/releases/1/assets?per_page=100&page=2>; rel="next"',
            '<https://api.github.com/repos/effectstream/binaries/releases/270761136/assets?per_page=99&page=2>; rel="next"',
            '<https://api.github.com/repos/effectstream/binaries/releases/270761136/assets?per_page=100&page=2&extra=1>; rel="next"',
        ]:
            with self.assertRaises(WarehouseError):
                parse_release_asset_link_header(invalid)

        exact_page = copy.deepcopy(self.snapshot)
        for index in range(len(exact_page["assets"]), 100):
            exact_page["assets"].append({"name": f"fixture-{index}", "id": 10000 + index, "nodeId": f"RA_fixture_{index}"})
        exact_page["pagination"].update({"totalCount": 100, "pages": [{
            "page": 1,
            "request": "https://api.github.com/repos/effectstream/binaries/releases/270761136/assets?per_page=100&page=1",
            "count": 100, "link": None, "etag": "fixture",
        }]})
        self.assertTrue(canonical_pagination_proof(exact_page))

    def test_durable_journal_is_0600_and_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "journal.json"
            journal = {"schemaVersion": "promotion-journal-v1", "events": []}
            append_journal(path, journal, {"event": "fixture", "name": "safe.zip", "sha256": "a" * 64})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            text = path.read_text()
            for forbidden in ["Authorization", "Bearer", "gho_", "github_pat_"]:
                self.assertNotIn(forbidden, text)

    def upload_fixture(self, root: Path) -> tuple[Path, Path, Path, dict, list[dict], str]:
        candidate_dir = root / "candidate"
        candidate_dir.mkdir()
        names = [
            "indexer-standalone-linux-amd64-v9.9.1.zip",
            "indexer-standalone-linux-amd64-v9.9.2.zip",
            "indexer-standalone-linux-amd64-v9.9.3.zip",
        ]
        _, manifest = self.make_candidate(candidate_dir, names)
        candidate = candidate_rows(candidate_dir, manifest)
        receipt = self.receipt_for(candidate, manifest, self.fixture_proposal(candidate))
        manifest_path = root / "candidate.json"
        receipt_path = root / "receipt.json"
        journal_path = root / "journal.json"
        write_canonical(manifest_path, manifest)
        write_canonical(receipt_path, receipt, mode=0o600)
        confirmation = f"{receipt['requiredConfirmationPrefix']} {canonical_sha256(receipt)}"
        return candidate_dir, manifest_path, receipt_path, receipt, candidate, confirmation

    def uploaded_snapshot(self, candidates: list[dict]) -> dict:
        result = copy.deepcopy(self.snapshot)
        for index, candidate in enumerate(candidates, start=1001):
            result["assets"].append({
                **candidate, "id": index, "nodeId": f"RA_uploaded_{index}", "state": "uploaded",
                "apiDigest": "sha256:" + candidate["sha256"],
                "apiUrl": f"https://api.github.com/repos/effectstream/binaries/releases/assets/{index}",
                "downloadUrl": "https://github.com/effectstream/binaries/releases/download/0.3.120/" + candidate["name"],
                "contentType": "application/zip" if candidate["name"].endswith(".zip") else "application/octet-stream",
                "createdAt": "2026-08-28T00:00:00Z", "updatedAt": "2026-08-28T00:00:00Z",
            })
        result["assets"].sort(key=lambda row: row["name"])
        result["pagination"]["totalCount"] = len(result["assets"])
        result["pagination"]["pages"][0]["count"] = len(result["assets"])
        if candidates:
            result["release"]["updatedAt"] = "2026-08-28T00:00:00Z"
        return result

    def test_mocked_create_readback_interruption_stale_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_dir, manifest_path, receipt_path, receipt, candidates, confirmation = self.upload_fixture(root)
            journal = root / "journal.json"
            argv = ["promotion_tool.py", "upload", "--receipt", str(receipt_path), "--candidate-dir", str(candidate_dir), "--candidate-manifest", str(manifest_path), "--journal", str(journal), "--confirm", confirmation, "--execute", "--forge-component-checkout", str(root / "component")]
            response = {"transport": "gh-release-upload", "result": "create-command-accepted"}
            with mock.patch.object(sys, "argv", argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.validate_component_policy_checkout"), mock.patch("promotion_tool.snapshot_release", side_effect=[self.snapshot, self.uploaded_snapshot(candidates)]), mock.patch("promotion_tool.live_upload", return_value=response) as uploader:
                self.assertEqual(promotion_main(), 0)
                self.assertEqual(uploader.call_count, 3)
            saved = load_json(journal)
            self.assertEqual(saved["state"], "verified")
            self.assertEqual(journal.stat().st_mode & 0o777, 0o600)

            stale = copy.deepcopy(self.snapshot)
            stale["release"]["updatedAt"] = "2026-08-28T00:00:00Z"
            stale_journal = root / "stale-journal.json"
            stale_argv = argv.copy()
            stale_argv[stale_argv.index(str(journal))] = str(stale_journal)
            with mock.patch.object(sys, "argv", stale_argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.validate_component_policy_checkout"), mock.patch("promotion_tool.snapshot_release", return_value=stale), mock.patch("promotion_tool.live_upload") as uploader:
                self.assertEqual(promotion_main(), 1)
                uploader.assert_not_called()
                self.assertFalse(stale_journal.exists())

            interrupted_journal = root / "interrupted-journal.json"
            interrupted_argv = argv.copy()
            interrupted_argv[interrupted_argv.index(str(journal))] = str(interrupted_journal)
            with mock.patch.object(sys, "argv", interrupted_argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.validate_component_policy_checkout"), mock.patch("promotion_tool.snapshot_release", side_effect=[self.snapshot, self.snapshot]), mock.patch("promotion_tool.live_upload", side_effect=WarehouseError("duplicate")):
                self.assertEqual(promotion_main(), 1)
            interrupted = load_json(interrupted_journal)
            self.assertEqual(interrupted["state"], "aborted")
            self.assertIn("transaction-aborted", [event["kind"] for event in interrupted["events"]])

            wrong_argv = argv.copy()
            wrong_argv[wrong_argv.index(confirmation)] = "UPLOAD effectstream/binaries 0.3.120 wrong"
            with mock.patch.object(sys, "argv", wrong_argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.validate_component_policy_checkout"), mock.patch("promotion_tool.snapshot_release") as snapshotter:
                self.assertEqual(promotion_main(), 1)
                snapshotter.assert_not_called()

    def test_receipt_bindings_reject_tamper_before_live_calls(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_dir, manifest_path, receipt_path, receipt, candidates, confirmation = self.upload_fixture(root)
            for field in [
                "candidateEnvelopeSha256", "candidateAssetListSha256", "proposalSha256",
                "intendedReleaseBodySha256", "snapshotSha256", "snapshotIdentitySha256",
                "publisherPrerequisiteSha256", "candidateVerificationSha256", "plannedCatalogSha256",
            ]:
                tampered = copy.deepcopy(receipt)
                tampered[field] = "0" * 64
                write_canonical(receipt_path, tampered, mode=0o600)
                argv = [
                    "promotion_tool.py", "upload", "--receipt", str(receipt_path),
                    "--candidate-dir", str(candidate_dir), "--candidate-manifest", str(manifest_path),
                    "--journal", str(root / f"{field}.journal"),
                    "--confirm", f"{tampered['requiredConfirmationPrefix']} {canonical_sha256(tampered)}", "--execute",
                    "--forge-component-checkout", str(root / "component"),
                ]
                with mock.patch.object(sys, "argv", argv), mock.patch("promotion_tool.snapshot_release") as snapshotter:
                    self.assertEqual(promotion_main(), 1, field)
                    snapshotter.assert_not_called()
            write_canonical(receipt_path, receipt, mode=0o600)

            stale = copy.deepcopy(receipt)
            stale["publisherPrerequisite"]["capturedAt"] = "2020-01-01T00:00:00Z"
            stale["publisherPrerequisiteSha256"] = canonical_sha256(stale["publisherPrerequisite"])
            with self.assertRaisesRegex(WarehouseError, "stale"):
                validate_receipt_bindings(stale, stale["candidateAssetManifest"])

            pre_pin = copy.deepcopy(receipt)
            pre_pin["candidateVerification"]["componentPolicy"]["minimumAncestorVerified"] = False
            pre_pin["candidateVerificationSha256"] = canonical_sha256(pre_pin["candidateVerification"])
            with self.assertRaises(WarehouseError):
                validate_receipt_bindings(pre_pin, pre_pin["candidateAssetManifest"])

            issuer_mismatch = copy.deepcopy(receipt)
            issuer_mismatch["candidateVerification"]["componentPolicy"]["issuerCommit"] = "f" * 40
            issuer_mismatch["candidateVerificationSha256"] = canonical_sha256(issuer_mismatch["candidateVerification"])
            with self.assertRaisesRegex(WarehouseError, "issuer differs"):
                validate_receipt_bindings(issuer_mismatch, issuer_mismatch["candidateAssetManifest"])

            for mutate in [
                lambda value: value["candidateVerification"]["liveEvidence"]["run"].update({"headSha": "f" * 40}),
                lambda value: value["candidateVerification"]["liveEvidence"]["release"].update({"id": 2}),
                lambda value: value["candidateVerification"]["liveEvidence"]["stagingArtifact"].update({"archiveSha256": "f" * 64}),
                lambda value: value["candidateVerification"]["liveEvidence"]["releaseAssets"][0].update({"sha256": "f" * 64}),
            ]:
                invalid_live = copy.deepcopy(receipt)
                mutate(invalid_live)
                invalid_live["candidateVerification"]["liveEvidenceSha256"] = canonical_sha256(invalid_live["candidateVerification"]["liveEvidence"])
                invalid_live["candidateVerificationSha256"] = canonical_sha256(invalid_live["candidateVerification"])
                with self.assertRaises(WarehouseError):
                    validate_receipt_bindings(invalid_live, invalid_live["candidateAssetManifest"])

            for mutate in [
                lambda value: value["snapshot"]["assets"][0].update({"updatedAt": "2030-01-01T00:00:00Z"}),
                lambda value: value["snapshot"]["release"].update({"bodySha256": "f" * 64}),
            ]:
                drifted = copy.deepcopy(receipt)
                mutate(drifted)
                drifted["snapshotSha256"] = canonical_sha256(drifted["snapshot"])
                drifted["snapshotIdentitySha256"] = canonical_sha256(snapshot_identity(drifted["snapshot"]))
                with self.assertRaises(WarehouseError):
                    validate_receipt_bindings(drifted, drifted["candidateAssetManifest"])

    def test_prerequisite_live_recheck_rejects_cross_state_checkout(self) -> None:
        prerequisite, _ = self.evidence(canonical_bytes(self.envelope([], self.fixture_proposal([]))))
        with mock.patch(
            "promotion_tool.subprocess.check_output",
            side_effect=["b" * 40 + "\n", prerequisite["checkout"]["origin"] + "\n", ""],
        ), mock.patch("promotion_tool.subprocess.run") as runner:
            with self.assertRaisesRegex(WarehouseError, "checkout state changed"):
                validate_prerequisite_record(prerequisite, live_recheck=True)
            runner.assert_not_called()

    def test_component_policy_pin_rejects_pre_pin_unrelated_and_regressed_checkouts(self) -> None:
        pin = load_json(ROOT / "protocol/forge-component-policy-v1.json")
        _, verification = self.evidence(canonical_bytes(self.envelope([], self.fixture_proposal([]))))
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary) / "component"
            (checkout / ".git").mkdir(parents=True)
            for item in pin["files"]:
                destination = checkout / item["path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("fixture\n", encoding="utf-8")

            expected_digests = {str((checkout / item["path"]).resolve()): item["sha256"] for item in pin["files"]}

            def pinned_digest(path: Path) -> str:
                return expected_digests[str(path.resolve())]

            def check_output_for(head: str):
                def result(command: list[str], **_: object) -> str:
                    if command[-2:] == ["rev-parse", "HEAD"]:
                        return head + "\n"
                    if command[-3:] == ["remote", "get-url", "origin"]:
                        return verification["componentPolicy"]["origin"] + "\n"
                    if command[-3:] == ["status", "--porcelain=v1", "--untracked-files=all"]:
                        return ""
                    raise AssertionError(command)
                return result

            with mock.patch("promotion_tool.subprocess.check_output", side_effect=check_output_for(pin["minimumCommitSha"])), mock.patch("promotion_tool.subprocess.run", return_value=mock.Mock(returncode=0)), mock.patch("promotion_tool.sha256_file", side_effect=pinned_digest):
                validate_component_policy_checkout(verification, checkout)

            for invalid_head in ["9dccfb27758209f1efe7a04cf4c2982f41081427", "f" * 40]:
                invalid = copy.deepcopy(verification)
                invalid["componentPolicy"]["issuerCommit"] = invalid_head
                with mock.patch("promotion_tool.subprocess.check_output", side_effect=check_output_for(invalid_head)), mock.patch("promotion_tool.subprocess.run", return_value=mock.Mock(returncode=1)), mock.patch("promotion_tool.sha256_file", side_effect=pinned_digest):
                    with self.assertRaisesRegex(WarehouseError, "does not descend"):
                        validate_component_policy_checkout(invalid, checkout)

            with mock.patch("promotion_tool.subprocess.check_output", side_effect=check_output_for(pin["minimumCommitSha"])), mock.patch("promotion_tool.subprocess.run", return_value=mock.Mock(returncode=0)), mock.patch("promotion_tool.sha256_file", return_value="0" * 64):
                with self.assertRaisesRegex(WarehouseError, "blob mismatch"):
                    validate_component_policy_checkout(verification, checkout)

    def test_fresh_candidate_verification_host_pins_and_reruns_raw_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            payload_name = "indexer-standalone-linux-amd64-v9.9.9.zip"
            payload_bytes = b"payload-9"
            (candidate_dir / payload_name).write_bytes(payload_bytes)
            bundle_bytes = b"attestation-bundle"
            bundle = root / "bundle.json"
            bundle.write_bytes(bundle_bytes)
            envelope = {
                "schemaVersion": "promotion-envelope-v1", "claimsDigest": "sha256:" + "d" * 64,
                "claims": {
                    "issuer": {"repository": "acedward/midnight-binary-forge", "commitSha": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe", "workflowSha": "e" * 40},
                    "candidateDraft": {"repository": "acedward/midnight-binary-forge", "tag": "forge-fixture", "releaseId": 9, "releaseNodeId": "RE_forge_fixture"},
                    "staging": {"runId": 7, "runAttempt": 1, "artifactId": 8, "archiveSha256": hashlib.sha256(b"staging").hexdigest()},
                    "transport": {"envelopeName": "promotion-envelope.json", "attestationBundleName": "attestation.sigstore.json"},
                    "contentAssets": [{"name": payload_name, "size": len(payload_bytes), "sha256": hashlib.sha256(payload_bytes).hexdigest(), "role": "payload"}],
                },
            }
            envelope_path = root / "promotion-envelope.json"
            envelope_bytes = canonical_bytes(envelope)
            envelope_path.write_bytes(envelope_bytes)
            release_assets = [
                {"id": 91, "name": "promotion-envelope.json", "size": len(envelope_bytes)},
                {"id": 92, "name": "attestation.sigstore.json", "size": len(bundle_bytes)},
                {"id": 93, "name": payload_name, "size": len(payload_bytes)},
            ]
            api = {
                "repos/acedward/midnight-binary-forge": {"full_name": "acedward/midnight-binary-forge", "id": 1349127482, "node_id": "R_kgDOUGoNOg"},
                "repos/acedward/midnight-binary-forge/branches/main": {"protected": True, "commit": {"sha": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe"}},
                "repos/acedward/midnight-binary-forge/contents/.github/workflows/candidate.yml?ref=ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe": {"sha": "e" * 40},
                "repos/acedward/midnight-binary-forge/actions/runs/7": {"id": 7, "run_attempt": 1, "path": ".github/workflows/candidate.yml", "event": "workflow_dispatch", "head_sha": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe", "head_branch": "main", "status": "completed", "conclusion": "success"},
                "repos/acedward/midnight-binary-forge/actions/artifacts/8": {"id": 8, "name": "candidate-staging", "expired": False, "expires_at": "2026-09-01T00:00:00Z", "workflow_run": {"id": 7}},
                "repos/acedward/midnight-binary-forge/releases/9": {"id": 9, "node_id": "RE_forge_fixture", "immutable": True, "tag_name": "forge-fixture", "target_commitish": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe", "html_url": "https://github.com/acedward/midnight-binary-forge/releases/tag/forge-fixture", "draft": False, "prerelease": True},
            }

            def download(endpoint: str, output: Path) -> str:
                if endpoint.endswith("/artifacts/8/zip"):
                    content = b"staging"
                else:
                    asset_id = int(endpoint.rsplit("/", 1)[1])
                    content = {91: envelope_bytes, 92: bundle_bytes, 93: payload_bytes}[asset_id]
                output.write_bytes(content)
                return hashlib.sha256(content).hexdigest()

            pagination = canonical_bytes([release_assets])

            def raw_verifier(command: list[str], **_: object) -> mock.Mock:
                self.assertIn("verify-candidate", command[0])
                live_path = Path(command[command.index("--live-evidence") + 1])
                output = Path(command[command.index("--output") + 1])
                live = load_json(live_path)
                record = {
                    "schemaVersion": "candidate-verification-v1", "verifiedAt": "2026-08-28T00:00:00Z", "result": "pass", "testOnly": False,
                    "protocolCommit": "2052e6e3d47495b8404876092d34e7bcbd560690",
                    "protocolManifestSha256": sha256_file(ROOT / "protocol/forge-promotion-envelope-v1.json"),
                    "forge": {"origin": "git@github.com:acedward/midnight-binary-forge.git", "head": "2052e6e3d47495b8404876092d34e7bcbd560690", "clean": True},
                    "componentPolicy": {"origin": "git@github.com:acedward/midnight-binary-forge.git", "issuerCommit": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe", "minimumCommit": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe", "manifestSha256": sha256_file(ROOT / "protocol/forge-component-policy-v1.json"), "clean": True, "minimumAncestorVerified": True, "exactPinnedBlobs": True},
                    "candidate": {"repository": "acedward/midnight-binary-forge", "tag": "forge-fixture", "releaseId": 9, "releaseNodeId": "RE_forge_fixture", "claimsDigest": "d" * 64},
                    "envelopeSha256": hashlib.sha256(envelope_bytes).hexdigest(), "bundleSha256": hashlib.sha256(bundle_bytes).hexdigest(),
                    "liveEvidenceSha256": canonical_sha256(live), "liveEvidence": live,
                    "contentIdentitySha256": canonical_sha256([{"name": payload_name, "size": len(payload_bytes), "sha256": hashlib.sha256(payload_bytes).hexdigest()}]),
                }
                write_canonical(output, record, mode=0o600)
                return mock.Mock(returncode=0)

            with mock.patch.dict(os.environ, {"GH_HOST": "evil.invalid"}), mock.patch("promotion_tool.pinned_gh_json", side_effect=lambda endpoint: api[endpoint]) as api_reader, mock.patch("promotion_tool.pinned_gh_download", side_effect=download), mock.patch("promotion_tool.subprocess.check_output", return_value=pagination) as pager, mock.patch("promotion_tool.subprocess.run", side_effect=raw_verifier) as verifier:
                record = fresh_verify_candidate(
                    forge_checkout=root / "protocol", component_checkout=root / "component",
                    envelope_path=envelope_path, bundle_path=bundle, candidate_dir=candidate_dir,
                )
            self.assertEqual(record["result"], "pass")
            self.assertEqual(api_reader.call_count, 6)
            page_command = pager.call_args.args[0]
            self.assertEqual(page_command[:4], ["gh", "api", "--hostname", "github.com"])
            self.assertEqual(pager.call_args.kwargs["env"]["GH_HOST"], "github.com")
            verifier.assert_called_once()

            (candidate_dir / payload_name).write_bytes(b"changed!!")
            with mock.patch("promotion_tool.pinned_gh_json", side_effect=lambda endpoint: api[endpoint]), mock.patch("promotion_tool.pinned_gh_download", side_effect=download), mock.patch("promotion_tool.subprocess.check_output", return_value=pagination), mock.patch("promotion_tool.subprocess.run") as verifier:
                with self.assertRaisesRegex(WarehouseError, "local candidate differs"):
                    fresh_verify_candidate(
                        forge_checkout=root / "protocol", component_checkout=root / "component",
                        envelope_path=envelope_path, bundle_path=bundle, candidate_dir=candidate_dir,
                    )
                verifier.assert_not_called()

    def test_initial_proposal_roles_and_compact_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, manifest = self.make_candidate(directory)
            candidate = candidate_rows(directory, manifest)
            proposal = self.fixture_proposal(candidate)
            envelope = self.envelope(candidate, proposal)
            planned = self.planned_catalog(candidate)
            validate_initial_proposal(proposal, candidate, envelope, planned)
            def wrong_binary_role(proposal: dict, env: dict) -> None:
                row = next(item for item in env["claims"]["contentAssets"] if item["name"] in proposal["binaryPayloads"])
                row["artifactKind"] = "proof-data"

            for mutate in [
                lambda proposal, env: proposal["binaryPayloads"].__setitem__(0, "compactc-linux-amd64-v0.34.0.tar.gz"),
                lambda proposal, env: proposal.update({"payloadCount": 2}),
                wrong_binary_role,
                lambda proposal, env: proposal["contractExtension"].update({"familyContractsSha256": "0" * 64}),
            ]:
                invalid_proposal = copy.deepcopy(proposal)
                invalid_envelope = copy.deepcopy(envelope)
                mutate(invalid_proposal, invalid_envelope)
                with self.assertRaises(WarehouseError):
                    validate_initial_proposal(invalid_proposal, candidate, invalid_envelope, planned)

    def test_create_only_transport_has_no_clobber_and_redacts_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "safe.zip"
            path.write_bytes(b"safe")
            expected = {"name": "safe.zip", "size": 4, "sha256": hashlib.sha256(b"safe").hexdigest()}
            success = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            with mock.patch("promotion_tool.subprocess.run", return_value=success) as runner:
                response = live_upload(path, expected)
            command = runner.call_args.args[0]
            self.assertEqual(command[:4], ["gh", "release", "upload", "0.3.120"])
            self.assertNotIn("--clobber", command)
            self.assertEqual(command[-2:], ["--repo", "github.com/effectstream/binaries"])
            self.assertEqual(runner.call_args.kwargs["env"]["GH_HOST"], "github.com")
            self.assertNotEqual(Path(command[4]), path)
            self.assertEqual(response["result"], "create-command-accepted")

            failure = mock.Mock(returncode=1, stdout=b"", stderr=b"HTTP 422 Authorization: Bearer secret")
            with mock.patch("promotion_tool.subprocess.run", return_value=failure):
                with self.assertRaises(WarehouseError) as raised:
                    live_upload(path, expected)
            self.assertNotIn("secret", str(raised.exception))
            self.assertNotIn("Authorization", str(raised.exception))

            changed = {**expected, "sha256": "0" * 64}
            with mock.patch("promotion_tool.subprocess.run") as runner:
                with self.assertRaisesRegex(WarehouseError, "changed"):
                    live_upload(path, changed)
                runner.assert_not_called()

    def test_bound_resume_continues_exact_candidate_and_preserves_lineage(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_dir, manifest_path, receipt_path, receipt, candidates, confirmation = self.upload_fixture(root)
            journal = root / "resume.journal"
            argv = [
                "promotion_tool.py", "upload", "--receipt", str(receipt_path),
                "--candidate-dir", str(candidate_dir), "--candidate-manifest", str(manifest_path),
                "--journal", str(journal), "--confirm", confirmation, "--execute",
                "--forge-component-checkout", str(root / "component"),
            ]
            partial = self.uploaded_snapshot(candidates[:1])
            side_effect = [{"result": "created"}, WarehouseError("interrupted")]
            with mock.patch.object(sys, "argv", argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.validate_component_policy_checkout"), mock.patch("promotion_tool.snapshot_release", side_effect=[self.snapshot, partial]), mock.patch("promotion_tool.live_upload", side_effect=side_effect):
                self.assertEqual(promotion_main(), 1)
            aborted = load_json(journal)
            receipt_hash = aborted["receiptSha256"]
            self.assertEqual(aborted["state"], "aborted")
            tampered_journal = copy.deepcopy(aborted)
            tampered_journal["journalNonce"] = "0" * 64
            with self.assertRaisesRegex(WarehouseError, "authentication"):
                validate_journal(tampered_journal, receipt)
            tampered_event = copy.deepcopy(aborted)
            tampered_event["events"][0]["details"]["tampered"] = True
            with self.assertRaisesRegex(WarehouseError, "digest"):
                validate_journal(tampered_event, receipt)

            resume_prerequisite = root / "resume-prerequisite.json"
            write_canonical(resume_prerequisite, receipt["publisherPrerequisite"], mode=0o600)
            resume_argv = argv + ["--resume", "--resume-prerequisite-record", str(resume_prerequisite)]
            partial_twice = self.uploaded_snapshot(candidates[:2])
            with mock.patch.object(sys, "argv", resume_argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.validate_component_policy_checkout"), mock.patch("promotion_tool.snapshot_release", side_effect=[partial, partial_twice]), mock.patch("promotion_tool.live_upload", side_effect=[{"result": "created"}, WarehouseError("interrupted-again")]) as uploader:
                self.assertEqual(promotion_main(), 1)
                self.assertEqual(uploader.call_count, 2)
            repeated = load_json(journal)
            self.assertEqual(repeated["state"], "aborted")
            self.assertEqual(repeated["receiptSha256"], receipt_hash)

            final = self.uploaded_snapshot(candidates)
            with mock.patch.object(sys, "argv", resume_argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.validate_component_policy_checkout"), mock.patch("promotion_tool.snapshot_release", side_effect=[partial_twice, final]), mock.patch("promotion_tool.live_upload", return_value={"result": "created"}) as uploader:
                self.assertEqual(promotion_main(), 0)
                self.assertEqual(uploader.call_count, 1)
            completed = load_json(journal)
            self.assertEqual(completed["state"], "verified")
            self.assertEqual(completed["receiptSha256"], receipt_hash)
            self.assertEqual([event["kind"] for event in completed["events"]].count("bound-resume-full-resnapshot-pass"), 2)

            foreign = copy.deepcopy(partial)
            foreign["assets"][-1]["sha256"] = "f" * 64
            blocked_journal = root / "blocked.journal"
            write_canonical(blocked_journal, aborted, mode=0o600)
            blocked_argv = resume_argv.copy()
            blocked_argv[blocked_argv.index(str(journal))] = str(blocked_journal)
            with mock.patch.object(sys, "argv", blocked_argv), mock.patch("promotion_tool.validate_prerequisite_record"), mock.patch("promotion_tool.validate_component_policy_checkout"), mock.patch("promotion_tool.snapshot_release", return_value=foreign), mock.patch("promotion_tool.live_upload") as uploader:
                self.assertEqual(promotion_main(), 1)
                uploader.assert_not_called()


if __name__ == "__main__":
    unittest.main()
