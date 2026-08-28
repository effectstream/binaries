from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
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
    live_upload,
    make_receipt,
    reconcile,
    main as promotion_main,
    validate_initial_proposal,
    validate_component_policy_checkout,
    validate_prerequisite_record,
    validate_receipt_bindings,
    verify_envelope_candidate_binding,
)
from warehouse_lib import WarehouseError, canonical_bytes, canonical_sha256, compare_snapshots, load_json, sha256_file, write_canonical  # noqa: E402


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

    def envelope(self, candidate: list[dict], proposal: dict) -> dict:
        binaries = set(proposal["binaryPayloads"])
        return {
            "schemaVersion": "promotion-envelope-v1",
            "claimsDigest": "sha256:" + "d" * 64,
            "claims": {
                "payloadCount": len(candidate),
                "issuer": {"commitSha": "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe"},
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
            "liveEvidenceSha256": "c" * 64, "contentIdentitySha256": None,
        }
        return prerequisite, verification

    def receipt_for(self, candidate: list[dict], manifest: dict, proposal: dict) -> dict:
        envelope_bytes = canonical_bytes(self.envelope(candidate, proposal))
        prerequisite, verification = self.evidence(envelope_bytes)
        return make_receipt(
            snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest,
            proposal=proposal, envelope_bytes=envelope_bytes, authority="owner-approval-1",
            intended_body_bytes=(ROOT / "metadata/templates/release-body.md").read_bytes(),
            publisher_prerequisite=prerequisite, candidate_verification=verification,
        )

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
                proposal=self.fixture_proposal(candidate), envelope_bytes=canonical_bytes(self.envelope(candidate, self.fixture_proposal(candidate))),
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
                make_receipt(snapshot=existing, candidate=candidate, candidate_manifest=manifest, proposal=self.fixture_proposal(candidate), envelope_bytes=b"{}", authority="owner", intended_body_bytes=b"body", publisher_prerequisite={}, candidate_verification={})
            with self.assertRaisesRegex(WarehouseError, "bound to proposal"):
                make_receipt(snapshot=self.snapshot, candidate=candidate, candidate_manifest=manifest, proposal=self.proposal, envelope_bytes=b"{}", authority="owner", intended_body_bytes=b"body", publisher_prerequisite={}, candidate_verification={})

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
            receipt = self.receipt_for(candidate, manifest, self.fixture_proposal(candidate))
            partial = self.uploaded_snapshot(candidate[:1])
            report = reconcile(receipt, partial)
            self.assertTrue(report["safeToResume"])
            self.assertEqual(len(report["exactCandidate"]), 1)
            self.assertEqual(len(report["absentCandidate"]), 1)
            partial["assets"][-1]["sha256"] = "f" * 64
            self.assertFalse(reconcile(receipt, partial)["safeToResume"])

            for mutate in [
                lambda value: value["repository"].update({"id": 1}),
                lambda value: value["release"].update({"id": 1}),
                lambda value: value["release"].update({"nodeId": "RE_recreated"}),
                lambda value: value["release"].update({"bodySha256": "f" * 64}),
                lambda value: value["release"].update({"unexpected": True}),
                lambda value: value["pagination"].update({"complete": False}),
                lambda value: value["pagination"].update({"totalCount": 0}),
                lambda value: value["pagination"].update({"pages": []}),
            ]:
                invalid = self.uploaded_snapshot(candidate[:1])
                mutate(invalid)
                self.assertFalse(reconcile(receipt, invalid)["safeToResume"])

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
        names = self.proposal["binaryPayloads"] + self.proposal["proofPayloads"]
        _, manifest = self.make_candidate(candidate_dir, names)
        candidate = candidate_rows(candidate_dir, manifest)
        receipt = self.receipt_for(candidate, manifest, self.proposal)
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
                self.assertEqual(uploader.call_count, 31)
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
            self.assertIn("transaction-aborted", [event["event"] for event in interrupted["events"]])

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
                "publisherPrerequisiteSha256", "candidateVerificationSha256",
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

    def test_initial_proposal_roles_and_compact_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, manifest = self.make_candidate(directory, self.proposal["binaryPayloads"] + self.proposal["proofPayloads"])
            candidate = candidate_rows(directory, manifest)
            envelope = self.envelope(candidate, self.proposal)
            validate_initial_proposal(self.proposal, candidate, envelope)
            def wrong_binary_role(proposal: dict, env: dict) -> None:
                row = next(item for item in env["claims"]["contentAssets"] if item["name"] in proposal["binaryPayloads"])
                row["artifactKind"] = "proof-data"

            for mutate in [
                lambda proposal, env: proposal["binaryPayloads"].__setitem__(0, "compactc-linux-amd64-v0.34.0.tar.gz"),
                lambda proposal, env: proposal.update({"payloadCount": 30}),
                wrong_binary_role,
                lambda proposal, env: proposal["proofPayloads"].__setitem__(0, "bls_midnight_2p0-linux-amd64"),
            ]:
                invalid_proposal = copy.deepcopy(self.proposal)
                invalid_envelope = copy.deepcopy(envelope)
                mutate(invalid_proposal, invalid_envelope)
                with self.assertRaises(WarehouseError):
                    validate_initial_proposal(invalid_proposal, candidate, invalid_envelope)

    def test_create_only_transport_has_no_clobber_and_redacts_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "safe.zip"
            path.write_bytes(b"safe")
            success = mock.Mock(returncode=0, stdout=b"", stderr=b"")
            with mock.patch("promotion_tool.subprocess.run", return_value=success) as runner:
                response = live_upload(path, "safe.zip")
            command = runner.call_args.args[0]
            self.assertEqual(command[:4], ["gh", "release", "upload", "0.3.120"])
            self.assertNotIn("--clobber", command)
            self.assertEqual(command[-2:], ["--repo", "effectstream/binaries"])
            self.assertEqual(response["result"], "create-command-accepted")

            failure = mock.Mock(returncode=1, stdout=b"", stderr=b"HTTP 422 Authorization: Bearer secret")
            with mock.patch("promotion_tool.subprocess.run", return_value=failure):
                with self.assertRaises(WarehouseError) as raised:
                    live_upload(path, "safe.zip")
            self.assertNotIn("secret", str(raised.exception))
            self.assertNotIn("Authorization", str(raised.exception))

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

            resume_argv = argv + ["--resume"]
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
                self.assertEqual(uploader.call_count, 29)
            completed = load_json(journal)
            self.assertEqual(completed["state"], "verified")
            self.assertEqual(completed["receiptSha256"], receipt_hash)
            self.assertEqual([event["event"] for event in completed["events"]].count("bound-resume-full-resnapshot-pass"), 2)

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
