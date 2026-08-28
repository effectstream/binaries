from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from promotion_tool import (  # noqa: E402
    append_journal,
    candidate_rows,
    complete_conflict_report,
    make_receipt,
    reconcile,
    main as promotion_main,
    verify_envelope_candidate_binding,
)
from warehouse_lib import WarehouseError, canonical_sha256, compare_snapshots, load_json, write_canonical  # noqa: E402


class PromotionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.snapshot = load_json(ROOT / "metadata/baselines/0.3.120-initial.json")
        cls.proposal = load_json(ROOT / "metadata/proposals/initial-31-v1.json")

    def fixture_proposal(self, candidate: list[dict]) -> dict:
        return {
            "schemaVersion": "warehouse-proposal-v1", "proposalId": "fixture",
            "destination": {"repository": "effectstream/binaries", "releaseTag": "0.3.120", "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"},
            "publicationState": "planned", "payloadCount": len(candidate),
            "evidenceRequired": ["fixture"],
            "binaryPayloads": [row["name"] for row in candidate], "proofPayloads": [],
            "compactPayloadCount": 0,
            "warning": "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE. Release `0.3.120` is mutable; verify every downloaded SHA-256 against committed metadata before installation or execution.",
        }

    def make_candidate(self, directory: Path, names: list[str] = ["fixture-new-linux-amd64-v1.0.0.zip"]) -> tuple[Path, dict]:
        rows = []
        for index, name in enumerate(sorted(names)):
            payload = f"fixture-{index}".encode()
            (directory / name).write_bytes(payload)
            import hashlib
            rows.append({"name": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        return directory, {"schemaVersion": "candidate-assets-v1", "assets": rows}

    def test_zero_write_preflight_absent_identical_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            candidate_dir, manifest = self.make_candidate(Path(temporary))
            candidate = candidate_rows(candidate_dir, manifest)
            report = complete_conflict_report(self.snapshot, candidate)
            self.assertEqual((report["absentCount"], report["identicalCount"], report["conflictCount"]), (1, 0, 0))
            receipt = make_receipt(
                snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest,
                proposal=self.fixture_proposal(candidate), envelope_sha256="a" * 64,
                authority="owner-approval-1", intended_body_sha256="b" * 64,
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
                make_receipt(snapshot=existing, candidate=candidate, candidate_manifest=manifest, proposal=self.fixture_proposal(candidate), envelope_sha256="a" * 64, authority="owner", intended_body_sha256="b" * 64)
            with self.assertRaisesRegex(WarehouseError, "bound to proposal"):
                make_receipt(snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest, proposal=self.proposal, envelope_sha256="a" * 64, authority="owner", intended_body_sha256="b" * 64)

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
        stale = copy.deepcopy(self.snapshot)
        stale["assets"][0]["updatedAt"] = "2026-08-28T00:00:00Z"
        with self.assertRaisesRegex(WarehouseError, "drift"):
            compare_snapshots(self.snapshot, stale)

        with tempfile.TemporaryDirectory() as temporary:
            candidate_dir, manifest = self.make_candidate(Path(temporary), ["fixture-a.zip", "fixture-b.zip"])
            candidate = candidate_rows(candidate_dir, manifest)
            receipt = make_receipt(snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest, proposal=self.fixture_proposal(candidate), envelope_sha256="a" * 64, authority="owner", intended_body_sha256="b" * 64)
            partial = copy.deepcopy(self.snapshot)
            row = {**candidate[0], "id": 1000, "nodeId": "RA_x", "state": "uploaded", "apiDigest": "sha256:" + candidate[0]["sha256"], "apiUrl": "api", "downloadUrl": "download", "contentType": "application/zip", "createdAt": "2026-08-28T00:00:00Z", "updatedAt": "2026-08-28T00:00:00Z"}
            partial["assets"].append(row)
            report = reconcile(receipt, partial)
            self.assertTrue(report["safeToResume"])
            self.assertEqual(len(report["exactCandidate"]), 1)
            self.assertEqual(len(report["absentCandidate"]), 1)
            partial["assets"][-1]["sha256"] = "f" * 64
            self.assertFalse(reconcile(receipt, partial)["safeToResume"])

    def test_durable_journal_is_0600_and_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "journal.json"
            journal = {"schemaVersion": "promotion-journal-v1", "events": []}
            append_journal(path, journal, {"event": "fixture", "name": "safe.zip", "sha256": "a" * 64})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            text = path.read_text()
            for forbidden in ["Authorization", "Bearer", "gho_", "github_pat_"]:
                self.assertNotIn(forbidden, text)

    def upload_fixture(self, root: Path) -> tuple[Path, Path, Path, dict, dict, str]:
        candidate_dir = root / "candidate"
        candidate_dir.mkdir()
        _, manifest = self.make_candidate(candidate_dir)
        candidate = candidate_rows(candidate_dir, manifest)
        receipt = make_receipt(snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest, proposal=self.fixture_proposal(candidate), envelope_sha256="a" * 64, authority="owner", intended_body_sha256="b" * 64)
        manifest_path = root / "candidate.json"
        receipt_path = root / "receipt.json"
        journal_path = root / "journal.json"
        write_canonical(manifest_path, manifest)
        write_canonical(receipt_path, receipt, mode=0o600)
        confirmation = f"{receipt['requiredConfirmationPrefix']} {canonical_sha256(receipt)}"
        return candidate_dir, manifest_path, receipt_path, receipt, candidate[0], confirmation

    def uploaded_snapshot(self, candidate: dict) -> dict:
        result = copy.deepcopy(self.snapshot)
        result["assets"].append({
            **candidate, "id": 1001, "nodeId": "RA_uploaded", "state": "uploaded",
            "apiDigest": "sha256:" + candidate["sha256"],
            "apiUrl": "https://api.github.com/repos/effectstream/binaries/releases/assets/1001",
            "downloadUrl": "https://github.com/effectstream/binaries/releases/download/0.3.120/" + candidate["name"],
            "contentType": "application/zip", "createdAt": "2026-08-28T00:00:00Z", "updatedAt": "2026-08-28T00:00:00Z",
        })
        return result

    def test_mocked_create_readback_interruption_stale_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate_dir, manifest_path, receipt_path, receipt, candidate, confirmation = self.upload_fixture(root)
            journal = root / "journal.json"
            argv = ["promotion_tool.py", "upload", "--receipt", str(receipt_path), "--candidate-dir", str(candidate_dir), "--candidate-manifest", str(manifest_path), "--journal", str(journal), "--confirm", confirmation, "--execute"]
            response = {"id": 1001, "node_id": "RA_uploaded", "name": candidate["name"], "state": "uploaded", "size": candidate["size"], "digest": "sha256:" + candidate["sha256"], "url": "api", "browser_download_url": "download", "created_at": "now", "updated_at": "now"}
            with mock.patch.object(sys, "argv", argv), mock.patch("promotion_tool.snapshot_release", side_effect=[self.snapshot, self.uploaded_snapshot(candidate)]), mock.patch("promotion_tool.live_upload", return_value=response) as uploader:
                self.assertEqual(promotion_main(), 0)
                uploader.assert_called_once()
            saved = load_json(journal)
            self.assertEqual(saved["state"], "verified")
            self.assertEqual(journal.stat().st_mode & 0o777, 0o600)

            stale = copy.deepcopy(self.snapshot)
            stale["release"]["updatedAt"] = "2026-08-28T00:00:00Z"
            stale_journal = root / "stale-journal.json"
            stale_argv = argv.copy()
            stale_argv[stale_argv.index(str(journal))] = str(stale_journal)
            with mock.patch.object(sys, "argv", stale_argv), mock.patch("promotion_tool.snapshot_release", return_value=stale), mock.patch("promotion_tool.live_upload") as uploader:
                self.assertEqual(promotion_main(), 1)
                uploader.assert_not_called()
                self.assertFalse(stale_journal.exists())

            interrupted_journal = root / "interrupted-journal.json"
            interrupted_argv = argv.copy()
            interrupted_argv[interrupted_argv.index(str(journal))] = str(interrupted_journal)
            with mock.patch.object(sys, "argv", interrupted_argv), mock.patch("promotion_tool.snapshot_release", side_effect=[self.snapshot, self.snapshot]), mock.patch("promotion_tool.live_upload", side_effect=WarehouseError("duplicate")):
                self.assertEqual(promotion_main(), 1)
            interrupted = load_json(interrupted_journal)
            self.assertEqual(interrupted["state"], "aborted")
            self.assertIn("transaction-aborted", [event["event"] for event in interrupted["events"]])

            wrong_argv = argv.copy()
            wrong_argv[wrong_argv.index(confirmation)] = "UPLOAD effectstream/binaries 0.3.120 wrong"
            with mock.patch.object(sys, "argv", wrong_argv), mock.patch("promotion_tool.snapshot_release") as snapshotter:
                self.assertEqual(promotion_main(), 1)
                snapshotter.assert_not_called()


if __name__ == "__main__":
    unittest.main()
