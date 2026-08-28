#!/usr/bin/env python3
"""Manual, append-only warehouse promotion transaction tooling."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import secrets
import subprocess
import sys
import tempfile
from typing import Any
from urllib.parse import parse_qs, urlparse

from warehouse_lib import (
    RELEASE_ID,
    RELEASE_TAG,
    REPOSITORY,
    REPOSITORY_ID,
    WarehouseError,
    canonical_bytes,
    canonical_sha256,
    compare_snapshots,
    load_json,
    load_release_baseline,
    loads_json,
    rfc3339_now,
    safe_asset_name,
    sha256_file,
    snapshot_identity,
    snapshot_release,
    inspect_archive,
    validate_catalog,
    write_canonical,
    write_canonical_new,
)


RECEIPT_SCHEMA = "promotion-receipt-v1"
JOURNAL_SCHEMA = "promotion-journal-v1"
SNAPSHOT_KEYS = {"schemaVersion", "capturedAt", "apiBaseHost", "repository", "release", "pagination", "assets"}
REPOSITORY_KEYS = {"fullName", "id", "nodeId"}
RELEASE_KEYS = {
    "id", "nodeId", "tag", "name", "target", "draft", "prerelease", "immutable",
    "apiUrl", "uploadUrl", "browserUrl", "createdAt", "publishedAt", "updatedAt", "bodySha256",
}
PAGINATION_KEYS = {"perPage", "pages", "totalCount", "complete"}
PAGE_KEYS = {"page", "request", "count", "link", "etag"}
ASSET_KEYS = {
    "id", "nodeId", "name", "state", "size", "apiDigest", "sha256", "apiUrl",
    "downloadUrl", "contentType", "createdAt", "updatedAt",
}


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise WarehouseError(message)


def validate_json_schema(document: dict[str, Any], schema_path: Path) -> None:
    try:
        import jsonschema  # type: ignore
        from referencing import Registry, Resource  # type: ignore
    except ImportError as exc:
        raise WarehouseError("jsonschema is required for transaction validation") from exc
    schema = load_json(schema_path)
    registry = Registry()
    for local_path in schema_path.parent.glob("*.schema.json"):
        local_schema = load_json(local_path)
        resource = Resource.from_contents(local_schema)
        registry = registry.with_resource(local_path.resolve().as_uri(), resource)
        if isinstance(local_schema.get("$id"), str):
            registry = registry.with_resource(local_schema["$id"], resource)
    validator = jsonschema.Draft202012Validator(
        schema,
        registry=registry,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(validator.iter_errors(document), key=lambda error: list(error.absolute_path))
    if errors:
        raise WarehouseError("schema validation failed: " + "; ".join(error.message for error in errors[:10]))


def validate_release_snapshot(snapshot: dict[str, Any]) -> None:
    validate_json_schema(
        snapshot,
        Path(__file__).resolve().parents[1] / "metadata/schema/release-snapshot-v1.schema.json",
    )


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


def validate_initial_proposal(
    proposal: dict[str, Any], candidate: list[dict[str, Any]], envelope: dict[str, Any],
    planned_catalog: dict[str, Any] | None = None,
    *, family_contracts: dict[str, Any] | None = None,
    proof_contract: dict[str, Any] | None = None,
) -> None:
    root = Path(__file__).resolve().parents[1]
    validate_json_schema(proposal, root / "metadata/schema/warehouse-proposal-v1.schema.json")
    family_contracts = family_contracts or load_json(root / "metadata/contracts/families-v1.json")
    proof_contract = proof_contract or load_json(root / "metadata/contracts/proof-data-q8b-v1.json")
    if proposal["proposalId"] == "initial-31-v1":
        expected = load_json(root / "metadata/proposals/initial-31-v1.json")
        expect(proposal == expected, "proposal differs from the reviewed exact initial-31 contract")
    else:
        extension = proposal.get("contractExtension")
        expect(
            isinstance(extension, dict)
            and extension.get("familyContractsSha256") == canonical_sha256(family_contracts)
            and extension.get("proofContractsSha256") == canonical_sha256(proof_contract),
            "future proposal lacks a reviewed exact contract extension",
        )
    binary_names = proposal["binaryPayloads"]
    proof_names = proposal["proofPayloads"]
    expected_names = sorted(binary_names + proof_names)
    expect(len(expected_names) == len(set(expected_names)) and [row["name"] for row in candidate] == expected_names, "candidate is not the proposal's exact payload set")
    expect(proposal["payloadCount"] == len(expected_names), "proposal role/count mismatch")
    expect(proposal["compactPayloadCount"] == 0 and all("compact" not in name.lower() for name in expected_names), "Compact payloads are forbidden")
    payloads = [row for row in envelope.get("claims", {}).get("contentAssets", []) if row.get("role") == "payload"]
    roles = {row.get("name"): row.get("artifactKind") for row in payloads}
    expect(set(roles) == set(expected_names), "envelope payload role set differs from proposal")
    expect(all(roles[name] == "software" for name in binary_names), "binary proposal role must be software")
    expect(all(roles[name] == "proof-data" for name in proof_names), "proof proposal role must be proof-data")
    expect(isinstance(planned_catalog, dict), "preflight requires the reviewed planned artifact catalog")
    validate_catalog(
        planned_catalog, root / "metadata/schema/artifact-catalog-v1.schema.json",
        family_contracts_override=family_contracts, proof_contract_override=proof_contract,
    )
    planned_entries = [row for row in planned_catalog["entries"] if row["publicationState"] == "planned"]
    expect(planned_entries, "proposal catalog has no hidden planned rows")
    by_name = {row["asset"]["name"]: row for row in planned_entries}
    expect(set(by_name) == set(expected_names), "planned catalog rows differ from proposal payload names")
    expect(
        [{"name": name, "size": by_name[name]["asset"]["size"], "sha256": by_name[name]["asset"]["sha256"]} for name in expected_names]
        == candidate,
        "candidate bytes differ from the reviewed planned catalog",
    )
    expect(all(by_name[name]["artifactKind"] == "software" for name in binary_names), "planned binary row role mismatch")
    expect(all(by_name[name]["artifactKind"] == "proof-data" for name in proof_names), "planned proof row role mismatch")


def inspection_identity(inspection: dict[str, Any]) -> dict[str, Any]:
    return {
        "format": inspection["format"], "memberCount": inspection["memberCount"],
        "expandedSize": inspection["expandedSize"],
        "members": [
            {key: row[key] for key in ["path", "type", "size", "sha256", "storedMode", "installMode"] if key in row}
            for row in inspection["members"]
        ],
        "legacyAnomalies": inspection["legacyAnomalies"],
    }


def validate_candidate_payloads(candidate_dir: Path, planned_catalog: dict[str, Any]) -> None:
    by_name = {row["asset"]["name"]: row for row in planned_catalog["entries"] if row["publicationState"] == "planned"}
    for name in sorted(by_name):
        entry = by_name[name]
        observed = inspect_archive(candidate_dir / name, name)
        expect(inspection_identity(observed) == inspection_identity(entry["archive"]), f"candidate archive/member contract mismatch: {name}")


def validate_preflight_snapshot_transition(snapshot: dict[str, Any], intended_body_sha256: str) -> None:
    """Admit only the reviewed body transition over the immutable 66-asset baseline."""
    root = Path(__file__).resolve().parents[1]
    reviewed_body_sha256 = sha256_file(root / "metadata/templates/release-body.md")
    expect(intended_body_sha256 == reviewed_body_sha256, "intended release body differs from the exact reviewed template")
    baseline = load_release_baseline(root / "metadata/baselines/0.3.120-current.json")
    validate_release_snapshot(snapshot)
    expect(canonical_pagination_proof(snapshot), "preflight snapshot pagination is not canonical/complete")
    expect(unique_asset_identities(snapshot["assets"]), "preflight snapshot asset identities are not canonical/unique")
    expect(snapshot["schemaVersion"] == baseline["schemaVersion"] and snapshot["apiBaseHost"] == baseline["apiBaseHost"], "preflight snapshot authority differs from immutable baseline")
    expect(snapshot["repository"] == baseline["repository"], "preflight repository identity differs from immutable baseline")
    expected_assets = [{key: value for key, value in row.items() if key != "inspection"} for row in baseline["assets"]]
    observed_assets = [{key: value for key, value in row.items() if key != "inspection"} for row in snapshot["assets"]]
    expect(observed_assets == expected_assets, "preflight legacy asset set/identity differs from immutable baseline")
    for field in RELEASE_KEYS - {"bodySha256", "updatedAt"}:
        expect(snapshot["release"].get(field) == baseline["release"].get(field), f"preflight release {field} differs from immutable baseline")
    expect(
        snapshot["release"]["bodySha256"] == intended_body_sha256,
        "live release body is not the exact intended warning body; transition it and capture a fresh snapshot before preflight",
    )
    expect(snapshot["release"]["updatedAt"] >= baseline["release"]["updatedAt"], "preflight release update timestamp regressed")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def validate_prerequisite_record(record: dict[str, Any], *, live_recheck: bool) -> None:
    root = Path(__file__).resolve().parents[1]
    validate_json_schema(record, root / "metadata/schema/publisher-prerequisite-v1.schema.json")
    script_digest = sha256_file(root / "scripts/check-manual-publisher-prereqs.sh")
    expect(record["tool"]["scriptSha256"] == script_digest, "publisher prerequisite tool digest mismatch")
    if not live_recheck:
        return
    age = (datetime.now(timezone.utc) - parse_time(record["capturedAt"])).total_seconds()
    expect(-300 <= age <= 900, "publisher prerequisite record is stale or from the future")
    expect(Path.cwd().resolve() == root.resolve(), "publisher recheck must run from warehouse root")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    origin = subprocess.check_output(["git", "remote", "get-url", "origin"], text=True).strip()
    dirty = subprocess.check_output(["git", "status", "--porcelain=v1", "--untracked-files=all"], text=True)
    expect(
        head == record["checkout"]["head"]
        and origin == record["checkout"]["origin"]
        and not dirty,
        "publisher checkout state changed after prerequisite record",
    )
    gh_environment = {**os.environ, "GH_HOST": "github.com"}
    subprocess.run(["gh", "auth", "status", "--hostname", "github.com"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=gh_environment)
    account = subprocess.check_output(["gh", "api", "--hostname", "github.com", "user", "--jq", ".login"], text=True, env=gh_environment).strip()
    repository = loads_json(subprocess.check_output(["gh", "api", "--hostname", "github.com", f"repos/{REPOSITORY}"], env=gh_environment))
    release = loads_json(subprocess.check_output(["gh", "api", "--hostname", "github.com", f"repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}"], env=gh_environment))
    expect(account == record["account"], "publisher account changed after prerequisite record")
    expect(
        {"fullName": repository.get("full_name"), "id": repository.get("id"), "nodeId": repository.get("node_id")} == record["repository"]
        and any(repository.get("permissions", {}).get(key) is True for key in ["admin", "maintain", "push"]),
        "publisher repository identity/permission changed after prerequisite record",
    )
    expect(
        {
            "tag": release.get("tag_name"), "id": release.get("id"), "nodeId": release.get("node_id"),
            "draft": release.get("draft"), "prerelease": release.get("prerelease"),
            "immutable": release.get("immutable", False),
        } == record["release"],
        "publisher release identity changed after prerequisite record",
    )


def validate_candidate_verification_record(
    record: dict[str, Any], envelope_bytes: bytes, *, require_live: bool
) -> None:
    root = Path(__file__).resolve().parents[1]
    validate_json_schema(record, root / "metadata/schema/candidate-verification-v1.schema.json")
    expect(record["protocolManifestSha256"] == sha256_file(root / "protocol/forge-promotion-envelope-v1.json"), "candidate verification protocol manifest changed")
    expect(record["componentPolicy"]["manifestSha256"] == sha256_file(root / "protocol/forge-component-policy-v1.json"), "candidate component-policy manifest changed")
    expect(record["componentPolicy"]["minimumCommit"] == "ddd2838d0226eeaaca8f7a42ad82cba1a132bbfe" and record["componentPolicy"]["exactPinnedBlobs"] is True, "candidate component-policy remediation evidence missing")
    expect(record["envelopeSha256"] == hashlib.sha256(envelope_bytes).hexdigest(), "candidate verification envelope binding mismatch")
    expect(record["liveEvidenceSha256"] == canonical_sha256(record["liveEvidence"]), "candidate verification live-evidence binding mismatch")
    envelope = loads_json(envelope_bytes)
    claims = envelope["claims"]
    issuer = claims["issuer"]
    candidate = claims["candidateDraft"]
    staging = claims["staging"]
    transport = claims["transport"]
    expect(record["componentPolicy"]["issuerCommit"] == issuer["commitSha"], "candidate component-policy issuer differs from envelope issuer")
    expect(record["candidate"]["claimsDigest"] == envelope["claimsDigest"].removeprefix("sha256:"), "candidate verification claims binding mismatch")
    live = record["liveEvidence"]
    expect(
        live["protectedRef"]["commitSha"] == issuer["commitSha"]
        and live["workflowFile"]["commitSha"] == issuer["commitSha"]
        and live["workflowFile"]["blobSha"] == issuer["workflowSha"]
        and live["run"]["headSha"] == issuer["commitSha"],
        "candidate live protected-ref/workflow/run identity differs from envelope issuer",
    )
    expect(
        live["run"]["id"] == staging["runId"]
        and live["run"]["attempt"] == staging["runAttempt"]
        and live["stagingArtifact"]["id"] == staging["artifactId"]
        and live["stagingArtifact"]["runId"] == staging["runId"]
        and live["stagingArtifact"]["runAttempt"] == staging["runAttempt"]
        and live["stagingArtifact"]["archiveSha256"] == staging["archiveSha256"],
        "candidate live staging identity differs from envelope",
    )
    expect(
        live["release"]["id"] == candidate["releaseId"]
        and live["release"]["nodeId"] == candidate["releaseNodeId"]
        and live["release"]["repository"] == candidate["repository"]
        and live["release"]["tag"] == candidate["tag"]
        and live["release"]["targetCommitish"] == issuer["commitSha"]
        and record["candidate"]["releaseId"] == candidate["releaseId"]
        and record["candidate"]["releaseNodeId"] == candidate["releaseNodeId"]
        and record["candidate"]["tag"] == candidate["tag"],
        "candidate live release identity differs from envelope/record",
    )
    live_assets = live["releaseAssets"]
    expect([row["name"] for row in live_assets] == sorted(row["name"] for row in live_assets), "candidate live release assets are not uniquely sorted")
    by_name = {row["name"]: row for row in live_assets}
    expect(len(by_name) == len(live_assets), "candidate live release assets repeat a name")
    expected_assets = {
        row["name"]: {"name": row["name"], "size": row["size"], "sha256": row["sha256"]}
        for row in claims["contentAssets"]
    }
    expected_assets[transport["envelopeName"]] = {
        "name": transport["envelopeName"], "size": len(envelope_bytes),
        "sha256": hashlib.sha256(envelope_bytes).hexdigest(),
    }
    expect(transport["attestationBundleName"] in by_name and by_name[transport["attestationBundleName"]]["sha256"] == record["bundleSha256"], "candidate live attestation bundle identity differs from record")
    expect(all(by_name.get(name) == row for name, row in expected_assets.items()), "candidate live content/envelope assets differ from envelope claims")
    if require_live:
        expect(record["testOnly"] is False, "test-only candidate verification cannot authorize live preflight/upload")
        expected_content_identity = canonical_sha256([
            {"name": row["name"], "size": row["size"], "sha256": row["sha256"]}
            for row in sorted(claims["contentAssets"], key=lambda item: item["name"])
        ])
        expect(record["contentIdentitySha256"] == expected_content_identity, "candidate verification inert content identity differs from envelope claims")


def pinned_gh_json(endpoint: str) -> dict[str, Any]:
    environment = {**os.environ, "GH_HOST": "github.com"}
    result = subprocess.run(
        ["gh", "api", "--hostname", "github.com", endpoint],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
    )
    if result.returncode:
        raise WarehouseError("fresh forge GitHub API capture failed")
    value = loads_json(result.stdout)
    expect(isinstance(value, dict), "fresh forge GitHub API response is not an object")
    return value


def pinned_gh_download(endpoint: str, output: Path) -> str:
    environment = {**os.environ, "GH_HOST": "github.com"}
    with output.open("xb") as handle:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "-H", "Accept: application/octet-stream", endpoint],
            stdout=handle, stderr=subprocess.PIPE, env=environment,
        )
    if result.returncode:
        output.unlink(missing_ok=True)
        raise WarehouseError("fresh forge asset download failed")
    return sha256_file(output)


def fresh_verify_candidate(
    *, forge_checkout: Path, component_checkout: Path, envelope_path: Path,
    bundle_path: Path, candidate_dir: Path,
) -> dict[str, Any]:
    """Freshly host-capture candidate state/bytes, then invoke the audited raw verifier."""
    envelope_bytes = envelope_path.read_bytes()
    envelope = loads_json(envelope_bytes)
    expect(envelope_bytes == canonical_bytes(envelope), "candidate envelope is not canonical JSON")
    claims = envelope["claims"]
    candidate = claims["candidateDraft"]
    issuer = claims["issuer"]
    staging = claims["staging"]
    repository_name = "acedward/midnight-binary-forge"
    expect(candidate["repository"] == repository_name and issuer["repository"] == repository_name, "candidate forge repository is not exact")
    with tempfile.TemporaryDirectory(prefix="warehouse-forge-live-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        repository = pinned_gh_json(f"repos/{repository_name}")
        branch = pinned_gh_json(f"repos/{repository_name}/branches/main")
        workflow = pinned_gh_json(f"repos/{repository_name}/contents/.github/workflows/candidate.yml?ref={issuer['commitSha']}")
        run = pinned_gh_json(f"repos/{repository_name}/actions/runs/{staging['runId']}")
        artifact = pinned_gh_json(f"repos/{repository_name}/actions/artifacts/{staging['artifactId']}")
        release = pinned_gh_json(f"repos/{repository_name}/releases/{candidate['releaseId']}")
        expect(repository.get("full_name") == repository_name and repository.get("id") == 1349127482 and repository.get("node_id") == "R_kgDOUGoNOg", "fresh forge repository identity mismatch")
        expect(branch.get("protected") is True and branch.get("commit", {}).get("sha") == issuer["commitSha"], "fresh protected-main identity mismatch")
        expect(workflow.get("sha") == issuer["workflowSha"], "fresh candidate workflow blob mismatch")
        expect(run.get("head_sha") == issuer["commitSha"] and run.get("status") == "completed" and run.get("conclusion") == "success", "fresh candidate workflow run mismatch")
        expect(artifact.get("workflow_run", {}).get("id", staging["runId"]) == staging["runId"] and artifact.get("expired") is False, "fresh staging artifact identity/expiry mismatch")
        expect(release.get("id") == candidate["releaseId"] and release.get("node_id") == candidate["releaseNodeId"] and release.get("immutable") is True, "fresh immutable candidate release identity mismatch")

        staging_archive = root / "staging.zip"
        staging_digest = pinned_gh_download(f"repos/{repository_name}/actions/artifacts/{staging['artifactId']}/zip", staging_archive)
        expect(staging_digest == staging["archiveSha256"], "fresh staging archive digest mismatch")

        release_assets: list[dict[str, Any]] = []
        content_root = root / "content"
        content_root.mkdir(mode=0o700)
        by_claim = {row["name"]: row for row in claims["contentAssets"]}
        transport_names = {claims["transport"]["envelopeName"], claims["transport"]["attestationBundleName"]}
        observed_transport: dict[str, bytes] = {}
        environment = {**os.environ, "GH_HOST": "github.com"}
        raw_assets = subprocess.check_output(
            ["gh", "api", "--hostname", "github.com", "--paginate", "--slurp", f"repos/{repository_name}/releases/{candidate['releaseId']}/assets?per_page=100"],
            env=environment,
        )
        pages = loads_json(raw_assets)
        expect(isinstance(pages, list) and all(isinstance(page_rows, list) for page_rows in pages), "fresh forge asset pagination is malformed")
        asset_rows = [row for page_rows in pages for row in page_rows]
        expect(len(asset_rows) == len({row.get("name") for row in asset_rows}) and len(asset_rows) <= 1000, "fresh forge asset pagination is incomplete/duplicate")
        for row in sorted(asset_rows, key=lambda item: item["name"]):
            name = safe_asset_name(row["name"])
            local = root / ("release-" + name)
            digest = pinned_gh_download(f"repos/{repository_name}/releases/assets/{row['id']}", local)
            expect(local.stat().st_size == row["size"], f"fresh forge asset size mismatch: {name}")
            release_assets.append({"name": name, "size": row["size"], "sha256": digest})
            if name in by_claim:
                shutil.copyfile(local, content_root / name)
            if name in transport_names:
                observed_transport[name] = local.read_bytes()
        expect(observed_transport.get(claims["transport"]["envelopeName"]) == envelope_bytes, "provided envelope differs from fresh candidate release bytes")
        expect(observed_transport.get(claims["transport"]["attestationBundleName"]) == bundle_path.read_bytes(), "provided bundle differs from fresh candidate release bytes")
        expected_payloads = {row["name"]: (row["size"], row["sha256"]) for row in claims["contentAssets"] if row.get("role") == "payload"}
        for name, (size, digest) in expected_payloads.items():
            path = candidate_dir / name
            expect(path.is_file() and not path.is_symlink() and path.stat().st_size == size and sha256_file(path) == digest, f"local candidate differs from fresh signed claim: {name}")

        live = {
            "schemaVersion": "promotion-live-evidence-v1", "capturedAt": rfc3339_now(),
            "repository": {"fullName": repository["full_name"], "id": repository["id"], "nodeId": repository["node_id"]},
            "protectedRef": {"ref": "refs/heads/main", "commitSha": branch["commit"]["sha"], "protected": branch["protected"]},
            "workflowFile": {"path": ".github/workflows/candidate.yml", "commitSha": issuer["commitSha"], "blobSha": workflow["sha"]},
            "run": {"id": run["id"], "attempt": run["run_attempt"], "repository": repository_name, "workflowPath": run["path"], "event": run["event"], "headSha": run["head_sha"], "headRef": run["head_branch"], "status": run["status"], "conclusion": run["conclusion"]},
            "stagingArtifact": {"id": artifact["id"], "runId": staging["runId"], "runAttempt": staging["runAttempt"], "name": artifact["name"], "archiveSha256": staging_digest, "expired": artifact["expired"], "expiresAt": artifact["expires_at"]},
            "release": {"id": release["id"], "nodeId": release["node_id"], "repository": repository_name, "tag": release["tag_name"], "targetCommitish": release["target_commitish"], "url": release["html_url"], "draft": release["draft"], "prerelease": release["prerelease"], "immutable": release["immutable"]},
            "releaseAssets": release_assets,
        }
        live_path = root / "live.json"
        output = root / "verification.json"
        write_canonical(live_path, live, mode=0o600)
        subprocess.run(
            [os.fspath(Path(__file__).resolve().parent / "verify-candidate"), "--forge-checkout", os.fspath(forge_checkout), "--forge-component-checkout", os.fspath(component_checkout), "--envelope", os.fspath(envelope_path), "--bundle", os.fspath(bundle_path), "--live-evidence", os.fspath(live_path), "--content-dir", os.fspath(content_root), "--output", os.fspath(output)],
            check=True, env=environment,
        )
        record = load_json(output)
        validate_candidate_verification_record(record, envelope_bytes, require_live=True)
        return record


def validate_component_policy_checkout(record: dict[str, Any], checkout: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    pin = load_json(root / "protocol/forge-component-policy-v1.json")
    checkout = checkout.resolve()
    expect((checkout / ".git").exists(), "forge component-policy checkout is not a git checkout")
    head = subprocess.check_output(["git", "-C", os.fspath(checkout), "rev-parse", "HEAD"], text=True).strip()
    origin = subprocess.check_output(["git", "-C", os.fspath(checkout), "remote", "get-url", "origin"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", os.fspath(checkout), "status", "--porcelain=v1", "--untracked-files=all"], text=True)
    expect(not dirty and head == record["componentPolicy"]["issuerCommit"] and origin == record["componentPolicy"]["origin"], "component-policy checkout state differs from verification record")
    ancestry = subprocess.run(
        ["git", "-C", os.fspath(checkout), "merge-base", "--is-ancestor", pin["minimumCommitSha"], head],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    expect(ancestry.returncode == 0, "candidate issuer does not descend from audited component-policy remediation")
    for item in pin["files"]:
        path = checkout / item["path"]
        expect(path.is_file() and not path.is_symlink() and sha256_file(path) == item["sha256"], f"component-policy blob mismatch: {item['path']}")


def make_receipt(
    *,
    snapshot: dict[str, Any],
    candidate: list[dict[str, Any]],
    candidate_manifest: dict[str, Any],
    proposal: dict[str, Any],
    planned_catalog: dict[str, Any],
    envelope_bytes: bytes,
    authority: str,
    intended_body_bytes: bytes,
    publisher_prerequisite: dict[str, Any],
    candidate_verification: dict[str, Any],
) -> dict[str, Any]:
    envelope_sha256 = hashlib.sha256(envelope_bytes).hexdigest()
    intended_body_sha256 = hashlib.sha256(intended_body_bytes).hexdigest()
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
        "publisherPrerequisiteSha256": canonical_sha256(publisher_prerequisite),
        "publisherPrerequisite": publisher_prerequisite,
        "candidateVerificationSha256": canonical_sha256(candidate_verification),
        "candidateVerification": candidate_verification,
        "candidateEnvelopeSha256": envelope_sha256,
        "candidateEnvelopeBytesBase64": base64.b64encode(envelope_bytes).decode("ascii"),
        "candidateAssetListSha256": canonical_sha256(candidate_manifest),
        "candidateAssetManifest": candidate_manifest,
        "proposalSha256": canonical_sha256(proposal),
        "proposal": proposal,
        "plannedCatalogSha256": canonical_sha256(planned_catalog),
        "plannedCatalog": planned_catalog,
        "intendedReleaseBodySha256": intended_body_sha256,
        "intendedReleaseBodyBytesBase64": base64.b64encode(intended_body_bytes).decode("ascii"),
        "snapshotSha256": canonical_sha256(snapshot),
        "snapshotIdentitySha256": canonical_sha256(snapshot_identity(snapshot)),
        "snapshot": snapshot,
        "candidateAssets": candidate,
        "preflight": report,
        "journalNonce": secrets.token_hex(32),
        "state": "planned",
        "requiredConfirmationPrefix": f"UPLOAD {REPOSITORY} {RELEASE_TAG}",
        "residualRace": "Best-effort one-operator coordination and immediate snapshot recheck cannot eliminate TOCTOU.",
    }
    return receipt


def validate_receipt_bindings(receipt: dict[str, Any], candidate_manifest: dict[str, Any], *, allow_test_verification: bool = False) -> None:
    root = Path(__file__).resolve().parents[1]
    validate_json_schema(receipt, root / "metadata/schema/promotion-receipt-v1.schema.json")
    validate_release_snapshot(receipt["snapshot"])
    expect(receipt["candidateAssetManifest"] == candidate_manifest, "candidate manifest differs from embedded receipt object")
    expect(receipt["publisherPrerequisiteSha256"] == canonical_sha256(receipt["publisherPrerequisite"]), "publisher prerequisite digest binding mismatch")
    expect(receipt["candidateVerificationSha256"] == canonical_sha256(receipt["candidateVerification"]), "candidate verification digest binding mismatch")
    expect(receipt["authority"] == receipt["publisherPrerequisite"]["authorityRef"], "authority reference differs from prerequisite record")
    validate_prerequisite_record(receipt["publisherPrerequisite"], live_recheck=False)
    prerequisite_age_at_receipt = (parse_time(receipt["createdAt"]) - parse_time(receipt["publisherPrerequisite"]["capturedAt"])).total_seconds()
    expect(-300 <= prerequisite_age_at_receipt <= 900, "publisher prerequisite was stale or from the future when the receipt was created")
    expect(receipt["candidateAssetListSha256"] == canonical_sha256(candidate_manifest), "candidate manifest digest binding mismatch")
    expect(receipt["candidateAssets"] == candidate_manifest["assets"], "candidate assets differ from embedded manifest")
    expect(receipt["plannedCatalogSha256"] == canonical_sha256(receipt["plannedCatalog"]), "planned catalog digest binding mismatch")
    try:
        envelope_bytes = base64.b64decode(receipt["candidateEnvelopeBytesBase64"], validate=True)
        envelope = loads_json(envelope_bytes)
        intended_body = base64.b64decode(receipt["intendedReleaseBodyBytesBase64"], validate=True)
        intended_text = intended_body.decode("utf-8")
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError, WarehouseError) as exc:
        raise WarehouseError("receipt embedded evidence is malformed") from exc
    expect(receipt["candidateEnvelopeSha256"] == hashlib.sha256(envelope_bytes).hexdigest(), "candidate envelope digest binding mismatch")
    validate_candidate_verification_record(receipt["candidateVerification"], envelope_bytes, require_live=not allow_test_verification)
    verify_envelope_candidate_binding(envelope, receipt["candidateAssets"])
    validate_initial_proposal(receipt["proposal"], receipt["candidateAssets"], envelope, receipt["plannedCatalog"])
    expect(receipt["proposalSha256"] == canonical_sha256(receipt["proposal"]), "proposal digest binding mismatch")
    expect(receipt["intendedReleaseBodySha256"] == hashlib.sha256(intended_body).hexdigest(), "intended release-body digest binding mismatch")
    expect(intended_text.startswith("> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.**"), "intended release body must put the development warning first")
    expect("`0.3.120` is mutable" in intended_text and "SHA-256" in intended_text, "intended release body lacks mutable-location/digest warning")
    expect(receipt["snapshotSha256"] == canonical_sha256(receipt["snapshot"]), "snapshot digest binding mismatch")
    expect(receipt["snapshotIdentitySha256"] == canonical_sha256(snapshot_identity(receipt["snapshot"])), "snapshot identity digest binding mismatch")
    validate_preflight_snapshot_transition(receipt["snapshot"], receipt["intendedReleaseBodySha256"])
    expect(receipt["preflight"] == complete_conflict_report(receipt["snapshot"], receipt["candidateAssets"]), "preflight report binding mismatch")


def validate_journal(journal: dict[str, Any], receipt: dict[str, Any]) -> None:
    root = Path(__file__).resolve().parents[1]
    validate_json_schema(journal, root / "metadata/schema/promotion-journal-v1.schema.json")
    expect(
        journal["receiptSha256"] == canonical_sha256(receipt)
        and journal["candidateEnvelopeSha256"] == receipt["candidateEnvelopeSha256"]
        and journal["journalNonce"] == receipt["journalNonce"],
        "journal/receipt authentication binding mismatch",
    )
    previous = None
    for sequence, event in enumerate(journal["events"], start=1):
        expect(event["sequence"] == sequence and event["previousEventSha256"] == previous, "journal event sequence/hash chain mismatch")
        unsigned = {key: value for key, value in event.items() if key != "eventSha256"}
        expect(event["eventSha256"] == canonical_sha256(unsigned), "journal event digest mismatch")
        previous = event["eventSha256"]
    expect(journal["events"][0]["kind"] == "stale-snapshot-recheck-pass", "journal lacks its authenticated initial snapshot gate")
    if journal["state"] == "aborted":
        expect(journal["events"][-1]["kind"] == "transaction-aborted", "aborted journal lacks terminal abort event")
    if journal["state"] == "verified":
        expect(journal["events"][-1]["kind"] == "full-api-download-readback-pass", "verified journal lacks terminal full read-back")


def require_private_new_path(path: Path) -> None:
    expect(path.is_absolute(), "transaction record path must be absolute")
    expect(path.parent.is_dir() and not path.parent.is_symlink(), "transaction record parent must be a real directory")
    expect((path.parent.stat().st_mode & 0o077) == 0, "transaction record parent directory must be private (0700)")
    expect(not path.exists() and not path.is_symlink(), "transaction record output must be a new path")


def append_journal(path: Path, journal: dict[str, Any], event: dict[str, Any]) -> None:
    kind = event.pop("event")
    unsigned = {
        "sequence": len(journal["events"]) + 1, "at": rfc3339_now(), "kind": kind,
        "details": event, "previousEventSha256": journal["events"][-1]["eventSha256"] if journal["events"] else None,
    }
    journal["events"].append({**unsigned, "eventSha256": canonical_sha256(unsigned)})
    if len(journal["events"]) == 1:
        write_canonical_new(path, journal, mode=0o600)
    else:
        expect(path.is_file() and not path.is_symlink(), "journal disappeared or changed type during transaction")
        write_canonical(path, journal, mode=0o600)
    expect(stat_mode(path) == 0o600, "journal permissions must remain 0600")


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def live_upload(path: Path, expected: dict[str, Any]) -> dict[str, Any]:
    # `gh release upload` resolves the release-specific uploads.github.com URL. With no
    # --clobber it is create-only and GitHub rejects an existing name.
    name = expected["name"]
    expect(path.name == name and path.is_file() and not path.is_symlink(), "upload path/name identity mismatch")
    with tempfile.TemporaryDirectory(prefix="warehouse-upload-") as temporary:
        stage_root = Path(temporary)
        os.chmod(stage_root, 0o700)
        staged = stage_root / name
        with path.open("rb") as source, staged.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        os.chmod(staged, 0o400)
        expect(staged.stat().st_size == expected["size"] and sha256_file(staged) == expected["sha256"], "candidate changed before irreversible upload")
        command = [
            "gh", "release", "upload", RELEASE_TAG, os.fspath(staged),
            "--repo", f"github.com/{REPOSITORY}",
        ]
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={**os.environ, "GH_HOST": "github.com"})
    if result.returncode:
        # Do not copy CLI/auth output into the journal or exception.
        raise WarehouseError("create-only release upload was rejected; abort and resnapshot")
    return {
        "transport": "gh-release-upload",
        "repository": REPOSITORY,
        "releaseTag": RELEASE_TAG,
        "name": name,
        "result": "create-command-accepted",
    }


def parse_release_asset_link_header(value: Any) -> dict[str, int] | None:
    """Parse and bind a GitHub release-assets Link header to this exact release."""
    if value is None:
        return None
    expect(isinstance(value, str) and value, "pagination Link must be a non-empty string or null")
    relations: dict[str, int] = {}
    allowed_paths = {
        f"/repos/{REPOSITORY}/releases/{RELEASE_ID}/assets",
        f"/repositories/{REPOSITORY_ID}/releases/{RELEASE_ID}/assets",
    }
    for segment in value.split(","):
        match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="(first|prev|next|last)"\s*', segment)
        expect(match is not None, "pagination Link has a non-canonical relation")
        target, relation = match.groups()
        expect(relation not in relations, "pagination Link repeats a relation")
        parsed = urlparse(target)
        expect(
            parsed.scheme == "https"
            and parsed.hostname == "api.github.com"
            and parsed.port is None
            and parsed.username is None
            and parsed.password is None
            and parsed.path in allowed_paths
            and not parsed.fragment,
            "pagination Link targets a different API/repository/release",
        )
        try:
            query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        except ValueError as exc:
            raise WarehouseError("pagination Link query is malformed") from exc
        expect(set(query) == {"per_page", "page"} and query["per_page"] == ["100"] and len(query["page"]) == 1, "pagination Link query mismatch")
        expect(re.fullmatch(r"[1-9][0-9]*", query["page"][0]) is not None, "pagination Link page is invalid")
        relations[relation] = int(query["page"][0])
    return relations


def canonical_pagination_proof(snapshot: dict[str, Any]) -> bool:
    assets = snapshot.get("assets")
    pagination = snapshot.get("pagination", {})
    if not isinstance(assets, list) or not isinstance(pagination, dict) or set(pagination) != PAGINATION_KEYS:
        return False
    pages = pagination.get("pages")
    total = len(assets)
    expected_page_count = max(1, (total + 99) // 100)
    if (
        pagination.get("perPage") != 100
        or pagination.get("complete") is not True
        or pagination.get("totalCount") != total
        or not isinstance(pages, list)
        or len(pages) != expected_page_count
    ):
        return False
    for index, page in enumerate(pages, start=1):
        expected_count = min(100, max(0, total - ((index - 1) * 100)))
        expected_request = (
            f"https://api.github.com/repos/{REPOSITORY}/releases/{RELEASE_ID}/"
            f"assets?per_page=100&page={index}"
        )
        try:
            relations = parse_release_asset_link_header(page.get("link") if isinstance(page, dict) else None)
        except WarehouseError:
            return False
        expected_relations: dict[str, int] | None
        if expected_page_count == 1:
            expected_relations = None
        else:
            expected_relations = {}
            if index > 1:
                expected_relations.update({"first": 1, "prev": index - 1})
            if index < expected_page_count:
                expected_relations.update({"next": index + 1, "last": expected_page_count})
        if (
            not isinstance(page, dict)
            or set(page) != PAGE_KEYS
            or page.get("page") != index
            or page.get("count") != expected_count
            or page.get("request") != expected_request
            or relations != expected_relations
        ):
            return False
    return True


def unique_asset_identities(assets: Any) -> bool:
    if not isinstance(assets, list) or any(not isinstance(row, dict) for row in assets):
        return False
    names = [row.get("name") for row in assets]
    ids = [row.get("id") for row in assets]
    node_ids = [row.get("nodeId") for row in assets]
    return bool(
        all(isinstance(name, str) and name for name in names)
        and all(isinstance(asset_id, int) and not isinstance(asset_id, bool) and asset_id > 0 for asset_id in ids)
        and all(isinstance(node_id, str) and node_id for node_id in node_ids)
        and len(names) == len(set(names))
        and names == sorted(names)
        and len(ids) == len(set(ids))
        and len(node_ids) == len(set(node_ids))
    )


def snapshot_invariant_drift(receipt: dict[str, Any], snapshot: dict[str, Any]) -> list[str]:
    """Return every non-asset or completeness deviation outside exact candidate additions."""
    baseline = receipt["snapshot"]
    drift: list[str] = []

    if set(snapshot) != SNAPSHOT_KEYS:
        drift.append("snapshot-fields")
    for field in ["schemaVersion", "apiBaseHost"]:
        if snapshot.get(field) != baseline.get(field):
            drift.append(field)
    if set(snapshot.get("repository", {})) != REPOSITORY_KEYS or snapshot.get("repository") != baseline.get("repository"):
        drift.append("repository-identity")
    if not canonical_pagination_proof(baseline):
        drift.append("baseline-pagination-proof")
    if not unique_asset_identities(baseline.get("assets")):
        drift.append("baseline-asset-identity-uniqueness")

    release = snapshot.get("release", {})
    baseline_release = baseline.get("release", {})
    if set(release) != RELEASE_KEYS:
        drift.append("release-fields")
    for field in sorted(RELEASE_KEYS - {"updatedAt"}):
        if release.get(field) != baseline_release.get(field):
            drift.append(f"release-{field}")

    baseline_names = {row["name"] for row in baseline.get("assets", [])}
    planned_additions = {
        row["name"] for row in receipt.get("preflight", {}).get("rows", [])
        if row.get("disposition") == "absent"
    }
    observed_names = {row.get("name") for row in snapshot.get("assets", []) if isinstance(row, dict)}
    observed_additions = planned_additions & observed_names
    if release.get("updatedAt") != baseline_release.get("updatedAt"):
        if not observed_additions or not isinstance(release.get("updatedAt"), str) or release["updatedAt"] < baseline_release.get("updatedAt", ""):
            drift.append("release-updatedAt")

    assets = snapshot.get("assets")
    if not isinstance(assets, list):
        return sorted(set(drift + ["assets-not-array", "pagination-proof"]))
    names = [row.get("name") for row in assets if isinstance(row, dict)]
    if not unique_asset_identities(assets):
        drift.append("asset-identity-uniqueness")
    allowed_names = baseline_names | planned_additions
    if set(names) - allowed_names:
        drift.append("unexpected-assets")
    if baseline_names - set(names):
        drift.append("missing-baseline-assets")

    if not canonical_pagination_proof(snapshot):
        drift.append("pagination-proof")

    return sorted(set(drift))


def exact_added_asset(row: dict[str, Any], expected: dict[str, Any], baseline_ids: set[int]) -> bool:
    keys = set(row)
    if keys != ASSET_KEYS and keys != ASSET_KEYS | {"inspection"}:
        return False
    asset_id = row.get("id")
    return bool(
        isinstance(asset_id, int)
        and asset_id > 0
        and asset_id not in baseline_ids
        and isinstance(row.get("nodeId"), str)
        and row["nodeId"]
        and row.get("name") == expected["name"]
        and row.get("state") == "uploaded"
        and row.get("size") == expected["size"]
        and row.get("sha256") == expected["sha256"]
        and row.get("apiDigest") == f"sha256:{expected['sha256']}"
        and row.get("apiUrl") == f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset_id}"
        and row.get("downloadUrl") == f"https://github.com/{REPOSITORY}/releases/download/{RELEASE_TAG}/{expected['name']}"
        and isinstance(row.get("contentType"), str)
        and row["contentType"]
        and isinstance(row.get("createdAt"), str)
        and isinstance(row.get("updatedAt"), str)
    )


def reconcile(receipt: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any]:
    candidate = {row["name"]: row for row in receipt["candidateAssets"]}
    baseline = {row["name"]: row for row in receipt["snapshot"]["assets"]}
    observed = {
        row["name"]: row
        for row in snapshot.get("assets", [])
        if isinstance(row, dict) and isinstance(row.get("name"), str)
    }
    baseline_ids = {row["id"] for row in receipt["snapshot"]["assets"]}
    planned_additions = {
        row["name"] for row in receipt.get("preflight", {}).get("rows", [])
        if row.get("disposition") == "absent"
    }
    invariant_drift = snapshot_invariant_drift(receipt, snapshot)
    foreign = []
    exact = []
    absent = []
    for name, expected in candidate.items():
        current = observed.get(name)
        if current is None:
            absent.append(name)
        elif (
            current["sha256"] == expected["sha256"]
            and current["size"] == expected["size"]
            and (
                name not in planned_additions
                or exact_added_asset(current, expected, baseline_ids)
            )
        ):
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
        "snapshotInvariantDrift": invariant_drift,
        "safeToResume": len(foreign) == 0 and len(invariant_drift) == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    preflight = sub.add_parser("preflight")
    preflight.add_argument("--candidate-dir", type=Path, required=True)
    preflight.add_argument("--candidate-manifest", type=Path, required=True)
    preflight.add_argument("--proposal", type=Path, required=True)
    preflight.add_argument("--planned-catalog", type=Path, required=True)
    preflight.add_argument("--snapshot", type=Path, required=True)
    preflight.add_argument("--candidate-envelope", type=Path, required=True)
    preflight.add_argument("--authority", required=True)
    preflight.add_argument("--prerequisite-record", type=Path, required=True)
    preflight.add_argument("--candidate-bundle", type=Path, required=True)
    preflight.add_argument("--forge-checkout", type=Path, required=True)
    preflight.add_argument("--forge-component-checkout", type=Path, required=True)
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
    upload.add_argument("--resume", action="store_true")
    upload.add_argument("--resume-prerequisite-record", type=Path)
    upload.add_argument("--forge-component-checkout", type=Path, required=True)

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
            require_private_new_path(args.receipt)
            manifest = load_json(args.candidate_manifest)
            candidate = candidate_rows(args.candidate_dir, manifest)
            envelope_bytes = args.candidate_envelope.read_bytes()
            envelope = loads_json(envelope_bytes)
            verify_envelope_candidate_binding(envelope, candidate)
            proposal = load_json(args.proposal)
            planned_catalog = load_json(args.planned_catalog)
            validate_initial_proposal(proposal, candidate, envelope, planned_catalog)
            validate_candidate_payloads(args.candidate_dir, planned_catalog)
            intended_body_bytes = args.intended_release_body.read_bytes()
            intended_body = intended_body_bytes.decode("utf-8")
            expect(intended_body.startswith("> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.**"), "intended release body must put the development warning first")
            expect("`0.3.120` is mutable" in intended_body and "SHA-256" in intended_body, "intended release body lacks mutable-location/digest warning")
            snapshot = load_json(args.snapshot)
            validate_preflight_snapshot_transition(snapshot, hashlib.sha256(intended_body_bytes).hexdigest())
            publisher_prerequisite = load_json(args.prerequisite_record)
            validate_prerequisite_record(publisher_prerequisite, live_recheck=True)
            expect(args.authority == publisher_prerequisite["authorityRef"], "--authority differs from prerequisite record")
            candidate_verification = fresh_verify_candidate(
                forge_checkout=args.forge_checkout, component_checkout=args.forge_component_checkout,
                envelope_path=args.candidate_envelope, bundle_path=args.candidate_bundle,
                candidate_dir=args.candidate_dir,
            )
            validate_component_policy_checkout(candidate_verification, args.forge_component_checkout)
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
                proposal=proposal,
                planned_catalog=planned_catalog,
                envelope_bytes=envelope_bytes,
                authority=args.authority,
                intended_body_bytes=intended_body_bytes,
                publisher_prerequisite=publisher_prerequisite,
                candidate_verification=candidate_verification,
            )
            validate_receipt_bindings(receipt, manifest)
            validate_prerequisite_record(receipt["publisherPrerequisite"], live_recheck=True)
            validate_component_policy_checkout(receipt["candidateVerification"], args.forge_component_checkout)
            write_canonical_new(args.receipt, receipt, mode=0o600)
            print(f"PASS zero-write preflight receiptSha256={canonical_sha256(receipt)} absent={report['absentCount']} noop={report['identicalCount']}")
        elif args.command == "upload":
            expect(args.execute, "live upload requires the explicit --execute switch")
            receipt = load_json(args.receipt)
            expect(stat_mode(args.receipt) == 0o600, "receipt permissions must be 0600")
            if not args.resume:
                require_private_new_path(args.journal)
            manifest = load_json(args.candidate_manifest)
            validate_receipt_bindings(receipt, manifest)
            resume_prerequisite = None
            if args.resume:
                expect(args.resume_prerequisite_record is not None, "delayed resume requires a fresh prerequisite record")
                resume_prerequisite = load_json(args.resume_prerequisite_record)
                validate_prerequisite_record(resume_prerequisite, live_recheck=True)
                original_prerequisite = receipt["publisherPrerequisite"]
                for field in ["authorityRef", "githubHost", "account", "repository", "release", "checkout"]:
                    expect(resume_prerequisite[field] == original_prerequisite[field], f"resume prerequisite {field} differs from original authority")
            else:
                expect(args.resume_prerequisite_record is None, "fresh upload cannot consume a resume prerequisite")
                validate_prerequisite_record(receipt["publisherPrerequisite"], live_recheck=True)
            validate_component_policy_checkout(receipt["candidateVerification"], args.forge_component_checkout)
            candidate = candidate_rows(args.candidate_dir, manifest)
            expect(candidate == receipt["candidateAssets"], "candidate changed after receipt")
            receipt_hash = canonical_sha256(receipt)
            expected_confirmation = f"{receipt['requiredConfirmationPrefix']} {receipt_hash}"
            expect(args.confirm == expected_confirmation, "typed confirmation mismatch")
            observed = snapshot_release(independent_downloads=True, inspect=False)
            validate_release_snapshot(observed)
            if args.resume:
                expect(args.journal.is_file() and not args.journal.is_symlink(), "resume requires the existing regular journal")
                expect(stat_mode(args.journal) == 0o600, "resume journal permissions must be 0600")
                journal = load_json(args.journal)
                validate_journal(journal, receipt)
                expect(journal.get("state") in {"aborted", "uploading"}, "resume journal is not continuable")
                resume_report = reconcile(receipt, observed)
                expect(resume_report["safeToResume"], "resume full snapshot contains foreign/legacy/invariant drift")
                journal["state"] = "uploading"
                append_journal(
                    args.journal,
                    journal,
                    {
                        "event": "bound-resume-full-resnapshot-pass",
                        "freshPrerequisiteSha256": canonical_sha256(resume_prerequisite),
                        "snapshotSha256": canonical_sha256(observed),
                        "exactCandidate": resume_report["exactCandidate"],
                        "absentCandidate": resume_report["absentCandidate"],
                    },
                )
            else:
                compare_snapshots(receipt["snapshot"], observed)
                journal = {
                    "schemaVersion": JOURNAL_SCHEMA,
                    "repository": REPOSITORY,
                    "releaseTag": RELEASE_TAG,
                    "receiptSha256": receipt_hash,
                    "candidateEnvelopeSha256": receipt["candidateEnvelopeSha256"],
                    "journalNonce": receipt["journalNonce"],
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
                    response = live_upload(args.candidate_dir / row["name"], row)
                except WarehouseError as exc:
                    append_journal(args.journal, journal, {"event": "unexpected-api-result-abort", "name": row["name"], "message": "create-only API rejected or returned unexpected state"})
                    try:
                        raced_snapshot = snapshot_release(independent_downloads=True, inspect=False)
                        validate_release_snapshot(raced_snapshot)
                        raced_report = reconcile(receipt, raced_snapshot)
                        append_journal(args.journal, journal, {"event": "post-race-full-resnapshot", "snapshotSha256": canonical_sha256(raced_snapshot), "safeExactCandidateOnly": raced_report["safeToResume"]})
                    except (WarehouseError, OSError, subprocess.SubprocessError):
                        append_journal(args.journal, journal, {"event": "post-race-resnapshot-failed", "manualResnapshotRequired": True})
                    journal["state"] = "aborted"
                    append_journal(args.journal, journal, {"event": "transaction-aborted", "manualReconcileRequired": True})
                    raise WarehouseError("upload aborted on duplicate/unexpected API state; use a fresh snapshot and reconcile") from exc
                append_journal(args.journal, journal, {"event": "create-response", "name": row["name"], "sha256": row["sha256"], "response": response})
            final_snapshot = snapshot_release(independent_downloads=True, inspect=False)
            validate_release_snapshot(final_snapshot)
            report = reconcile(receipt, final_snapshot)
            expect(report["safeToResume"] and not report["absentCandidate"], "final full-release read-back failed")
            journal["state"] = "verified"
            append_journal(args.journal, journal, {"event": "full-api-download-readback-pass", "snapshotSha256": canonical_sha256(final_snapshot)})
            print("PASS upload verified; merge stable published catalog/index last")
        elif args.command == "reconcile":
            receipt = load_json(args.receipt)
            validate_receipt_bindings(receipt, receipt["candidateAssetManifest"])
            snapshot = load_json(args.snapshot)
            validate_release_snapshot(snapshot)
            report = reconcile(receipt, snapshot)
            write_canonical(args.report, report)
            expect(report["safeToResume"], "foreign candidate bytes or legacy drift hard-stop reconciliation")
            print(f"PASS reconcile exact={len(report['exactCandidate'])} absent={len(report['absentCandidate'])}")
        elif args.command == "verify-release":
            receipt = load_json(args.receipt)
            validate_receipt_bindings(receipt, receipt["candidateAssetManifest"])
            observed = snapshot_release(independent_downloads=True, inspect=False)
            validate_release_snapshot(observed)
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
