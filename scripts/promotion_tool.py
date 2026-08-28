#!/usr/bin/env python3
"""Manual, append-only warehouse promotion transaction tooling."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from warehouse_lib import (
    RELEASE_ID,
    RELEASE_TAG,
    REPOSITORY,
    WarehouseError,
    canonical_bytes,
    canonical_sha256,
    compare_snapshots,
    load_json,
    rfc3339_now,
    safe_asset_name,
    sha256_file,
    snapshot_identity,
    snapshot_release,
    write_canonical,
)


RECEIPT_SCHEMA = "promotion-receipt-v1"
JOURNAL_SCHEMA = "promotion-journal-v1"


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise WarehouseError(message)


def candidate_rows(candidate_dir: Path, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    expect(manifest.get("schemaVersion") == "candidate-assets-v1", "wrong candidate asset-list schema")
    expected = manifest.get("assets")
    expect(isinstance(expected, list) and expected, "candidate asset list is empty")
    expected_names = [row["name"] for row in expected]
    expect(expected_names == sorted(expected_names), "candidate assets must be sorted")
    expect(len(expected_names) == len(set(expected_names)), "duplicate candidate name")
    observed_names = sorted(path.name for path in candidate_dir.iterdir())
    expect(observed_names == expected_names, "candidate directory is not the exact inert asset list")
    rows = []
    for row in expected:
        name = safe_asset_name(row["name"])
        path = candidate_dir / name
        expect(path.is_file() and not path.is_symlink(), f"candidate is not a regular file: {name}")
        observed = {"name": name, "size": path.stat().st_size, "sha256": sha256_file(path)}
        expect(observed == row, f"candidate byte identity mismatch: {name}")
        rows.append(observed)
    return rows


def complete_conflict_report(snapshot: dict[str, Any], candidate: list[dict[str, Any]]) -> dict[str, Any]:
    by_name = {row["name"]: row for row in snapshot["assets"]}
    rows = []
    for item in candidate:
        current = by_name.get(item["name"])
        if current is None:
            disposition = "absent"
            current_digest = None
        elif current["sha256"] == item["sha256"] and current["size"] == item["size"]:
            disposition = "identical-noop"
            current_digest = current["sha256"]
        else:
            disposition = "conflict"
            current_digest = current["sha256"]
        rows.append(
            {
                "name": item["name"],
                "candidateSha256": item["sha256"],
                "currentSha256": current_digest,
                "disposition": disposition,
            }
        )
    return {
        "schemaVersion": "complete-conflict-report-v1",
        "candidateCount": len(candidate),
        "absentCount": sum(row["disposition"] == "absent" for row in rows),
        "identicalCount": sum(row["disposition"] == "identical-noop" for row in rows),
        "conflictCount": sum(row["disposition"] == "conflict" for row in rows),
        "rows": rows,
    }


def verify_envelope_candidate_binding(envelope: dict[str, Any], candidate: list[dict[str, Any]]) -> None:
    expect(envelope.get("schemaVersion") == "promotion-envelope-v1", "wrong promotion envelope schema")
    claims = envelope.get("claims", {})
    payloads = [
        {"name": row["name"], "size": row["size"], "sha256": row["sha256"]}
        for row in claims.get("contentAssets", []) if row.get("role") == "payload"
    ]
    expect(payloads == candidate, "candidate payload bytes/list differ from promotion envelope claims")
    expect(claims.get("payloadCount") == len(candidate), "promotion envelope payloadCount mismatch")
    destination = claims.get("destination")
    if destination is not None:
        expect(destination == {"repository": REPOSITORY, "tag": RELEASE_TAG, "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"}, "promotion envelope destination mismatch")


def make_receipt(
    *,
    snapshot: dict[str, Any],
    candidate: list[dict[str, Any]],
    candidate_manifest: dict[str, Any],
    proposal: dict[str, Any],
    envelope_sha256: str,
    authority: str,
    intended_body_sha256: str,
) -> dict[str, Any]:
    expect(re.fullmatch(r"[0-9a-f]{64}", envelope_sha256) is not None, "invalid envelope digest")
    expect(re.fullmatch(r"[0-9a-f]{64}", intended_body_sha256) is not None, "invalid intended body digest")
    expect(proposal.get("schemaVersion") == "warehouse-proposal-v1", "wrong proposal schema")
    expect(proposal.get("publicationState") == "planned", "preflight proposal must remain hidden planned state")
    destination = proposal.get("destination", {})
    expect(destination == {"repository": REPOSITORY, "releaseTag": RELEASE_TAG, "distributionTier": "development-only", "releaseMutability": "mutable-warehouse"}, "proposal destination authority mismatch")
    proposed_names = sorted(proposal.get("binaryPayloads", []) + proposal.get("proofPayloads", []))
    candidate_names = [row["name"] for row in candidate]
    expect(proposed_names == candidate_names, "candidate asset list is not exactly bound to proposal payload names")
    expect(proposal.get("payloadCount") == len(candidate_names), "proposal payloadCount mismatch")
    expect(proposal.get("warning", "").startswith("DEVELOPMENT ONLY — NOT FOR PRODUCTION USE."), "proposal warning missing")
    report = complete_conflict_report(snapshot, candidate)
    expect(report["conflictCount"] == 0, "complete-set preflight found conflicts")
    receipt = {
        "schemaVersion": RECEIPT_SCHEMA,
        "createdAt": rfc3339_now(),
        "repository": REPOSITORY,
        "releaseTag": RELEASE_TAG,
        "releaseId": RELEASE_ID,
        "authority": authority,
        "candidateEnvelopeSha256": envelope_sha256,
        "candidateAssetListSha256": canonical_sha256(candidate_manifest),
        "proposalSha256": canonical_sha256(proposal),
        "intendedReleaseBodySha256": intended_body_sha256,
        "snapshotSha256": canonical_sha256(snapshot),
        "snapshotIdentitySha256": canonical_sha256(snapshot_identity(snapshot)),
        "snapshot": snapshot,
        "candidateAssets": candidate,
        "preflight": report,
        "state": "planned",
        "requiredConfirmationPrefix": f"UPLOAD {REPOSITORY} {RELEASE_TAG}",
        "residualRace": "Best-effort one-operator coordination and immediate snapshot recheck cannot eliminate TOCTOU.",
    }
    return receipt


def append_journal(path: Path, journal: dict[str, Any], event: dict[str, Any]) -> None:
    journal["events"].append({"at": rfc3339_now(), **event})
    write_canonical(path, journal, mode=0o600)
    expect(stat_mode(path) == 0o600, "journal permissions must remain 0600")


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def live_upload(path: Path, name: str) -> dict[str, Any]:
    # This endpoint is create-only: GitHub rejects an existing name. No clobber/delete/edit exists here.
    command = [
        "gh", "api", "--method", "POST",
        "-H", "Content-Type: application/octet-stream",
        "--input", os.fspath(path),
        f"repos/{REPOSITORY}/releases/{RELEASE_ID}/assets?name={name}",
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise WarehouseError(
            "create-only upload returned an unexpected API result; abort and resnapshot: "
            + result.stderr.decode("utf-8", "replace").strip()
        )
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise WarehouseError("create-only upload returned non-JSON; abort and resnapshot") from exc
    expect(response.get("name") == name and response.get("state") == "uploaded", "unexpected upload response identity")
    # Retain only non-secret, reproducible response fields.
    return {key: response.get(key) for key in ["id", "node_id", "name", "state", "size", "digest", "url", "browser_download_url", "created_at", "updated_at"]}


def reconcile(receipt: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    candidate = {row["name"]: row for row in receipt["candidateAssets"]}
    baseline = {row["name"]: row for row in receipt["snapshot"]["assets"]}
    observed = {row["name"]: row for row in snapshot["assets"]}
    foreign = []
    exact = []
    absent = []
    for name, expected in candidate.items():
        current = observed.get(name)
        if current is None:
            absent.append(name)
        elif current["sha256"] == expected["sha256"] and current["size"] == expected["size"]:
            exact.append(name)
        else:
            foreign.append(name)
    # Every non-candidate baseline asset must retain all FR-039 identity fields exactly.
    for name, previous in baseline.items():
        current = observed.get(name)
        prior_identity = {key: value for key, value in previous.items() if key != "inspection"}
        current_identity = None if current is None else {key: value for key, value in current.items() if key != "inspection"}
        if current_identity != prior_identity:
            foreign.append(name)
    return {
        "schemaVersion": "reconcile-report-v1",
        "exactCandidate": sorted(set(exact)),
        "absentCandidate": sorted(set(absent)),
        "foreignOrLegacyDrift": sorted(set(foreign)),
        "safeToResume": len(foreign) == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight")
    preflight.add_argument("--candidate-dir", type=Path, required=True)
    preflight.add_argument("--candidate-manifest", type=Path, required=True)
    preflight.add_argument("--proposal", type=Path, required=True)
    preflight.add_argument("--snapshot", type=Path, required=True)
    preflight.add_argument("--candidate-envelope", type=Path, required=True)
    preflight.add_argument("--authority", required=True)
    preflight.add_argument("--intended-release-body", type=Path, required=True)
    preflight.add_argument("--receipt", type=Path, required=True)
    preflight.add_argument("--report", type=Path)

    upload = sub.add_parser("upload")
    upload.add_argument("--receipt", type=Path, required=True)
    upload.add_argument("--candidate-dir", type=Path, required=True)
    upload.add_argument("--candidate-manifest", type=Path, required=True)
    upload.add_argument("--journal", type=Path, required=True)
    upload.add_argument("--confirm", required=True)
    upload.add_argument("--execute", action="store_true")

    rec = sub.add_parser("reconcile")
    rec.add_argument("--receipt", type=Path, required=True)
    rec.add_argument("--snapshot", type=Path, required=True)
    rec.add_argument("--report", type=Path, required=True)

    verify = sub.add_parser("verify-release")
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--output-snapshot", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "preflight":
            manifest = load_json(args.candidate_manifest)
            candidate = candidate_rows(args.candidate_dir, manifest)
            envelope = load_json(args.candidate_envelope)
            verify_envelope_candidate_binding(envelope, candidate)
            intended_body = args.intended_release_body.read_text(encoding="utf-8")
            expect(intended_body.startswith("> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.**"), "intended release body must put the development warning first")
            expect("`0.3.120` is mutable" in intended_body and "SHA-256" in intended_body, "intended release body lacks mutable-location/digest warning")
            snapshot = load_json(args.snapshot)
            report = complete_conflict_report(snapshot, candidate)
            if args.report:
                write_canonical(args.report, report)
            if report["conflictCount"]:
                raise WarehouseError(
                    f"preflight conflictCount={report['conflictCount']}; zero release/journal/catalog/index writes"
                )
            receipt = make_receipt(
                snapshot=snapshot,
                candidate=candidate,
                candidate_manifest=manifest,
                proposal=load_json(args.proposal),
                envelope_sha256=sha256_file(args.candidate_envelope),
                authority=args.authority,
                intended_body_sha256=sha256_file(args.intended_release_body),
            )
            write_canonical(args.receipt, receipt, mode=0o600)
            print(f"PASS zero-write preflight receiptSha256={canonical_sha256(receipt)} absent={report['absentCount']} noop={report['identicalCount']}")
        elif args.command == "upload":
            expect(args.execute, "live upload requires the explicit --execute switch")
            receipt = load_json(args.receipt)
            expect(receipt.get("schemaVersion") == RECEIPT_SCHEMA, "wrong receipt schema")
            expect(stat_mode(args.receipt) == 0o600, "receipt permissions must be 0600")
            manifest = load_json(args.candidate_manifest)
            candidate = candidate_rows(args.candidate_dir, manifest)
            expect(candidate == receipt["candidateAssets"], "candidate changed after receipt")
            receipt_hash = canonical_sha256(receipt)
            expected_confirmation = f"{receipt['requiredConfirmationPrefix']} {receipt_hash}"
            expect(args.confirm == expected_confirmation, "typed confirmation mismatch")
            observed = snapshot_release(independent_downloads=True, inspect=False)
            compare_snapshots(receipt["snapshot"], observed)
            journal = {
                "schemaVersion": JOURNAL_SCHEMA,
                "repository": REPOSITORY,
                "releaseTag": RELEASE_TAG,
                "receiptSha256": receipt_hash,
                "candidateEnvelopeSha256": receipt["candidateEnvelopeSha256"],
                "events": [],
                "state": "uploading",
            }
            append_journal(args.journal, journal, {"event": "stale-snapshot-recheck-pass"})
            existing = {row["name"]: row for row in observed["assets"]}
            for row in candidate:
                if row["name"] in existing:
                    append_journal(args.journal, journal, {"event": "identical-noop", "name": row["name"], "sha256": row["sha256"]})
                    continue
                try:
                    response = live_upload(args.candidate_dir / row["name"], row["name"])
                except WarehouseError as exc:
                    append_journal(args.journal, journal, {"event": "unexpected-api-result-abort", "name": row["name"], "message": "create-only API rejected or returned unexpected state"})
                    try:
                        raced_snapshot = snapshot_release(independent_downloads=True, inspect=False)
                        raced_report = reconcile(receipt, raced_snapshot)
                        append_journal(args.journal, journal, {"event": "post-race-full-resnapshot", "snapshotSha256": canonical_sha256(raced_snapshot), "safeExactCandidateOnly": raced_report["safeToResume"]})
                    except (WarehouseError, OSError, subprocess.SubprocessError):
                        append_journal(args.journal, journal, {"event": "post-race-resnapshot-failed", "manualResnapshotRequired": True})
                    journal["state"] = "aborted"
                    append_journal(args.journal, journal, {"event": "transaction-aborted", "manualReconcileRequired": True})
                    raise WarehouseError("upload aborted on duplicate/unexpected API state; use a fresh snapshot and reconcile") from exc
                append_journal(args.journal, journal, {"event": "create-response", "name": row["name"], "sha256": row["sha256"], "response": response})
            final_snapshot = snapshot_release(independent_downloads=True, inspect=False)
            report = reconcile(receipt, final_snapshot)
            expect(report["safeToResume"] and not report["absentCandidate"], "final full-release read-back failed")
            journal["state"] = "verified"
            append_journal(args.journal, journal, {"event": "full-api-download-readback-pass", "snapshotSha256": canonical_sha256(final_snapshot)})
            print("PASS upload verified; merge stable published catalog/index last")
        elif args.command == "reconcile":
            report = reconcile(load_json(args.receipt), load_json(args.snapshot))
            write_canonical(args.report, report)
            expect(report["safeToResume"], "foreign candidate bytes or legacy drift hard-stop reconciliation")
            print(f"PASS reconcile exact={len(report['exactCandidate'])} absent={len(report['absentCandidate'])}")
        elif args.command == "verify-release":
            receipt = load_json(args.receipt)
            observed = snapshot_release(independent_downloads=True, inspect=False)
            report = reconcile(receipt, observed)
            expect(report["safeToResume"] and not report["absentCandidate"], "complete release does not match exact candidate/legacy receipt")
            write_canonical(args.output_snapshot, observed)
            print(f"PASS complete release assets={len(observed['assets'])}")
        return 0
    except (WarehouseError, OSError, subprocess.SubprocessError) as exc:
        print(f"promotion: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
