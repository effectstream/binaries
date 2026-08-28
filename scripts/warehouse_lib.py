#!/usr/bin/env python3
"""Read-only warehouse inventory, catalog, resolver, and transaction primitives."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from typing import Any, Iterable
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "effectstream/binaries"
REPOSITORY_ID = 1117580582
REPOSITORY_NODE_ID = "R_kgDOQpztJg"
RELEASE_TAG = "0.3.120"
RELEASE_ID = 270761136
RELEASE_NODE_ID = "RE_kwDOQpztJs4QI3yw"
RELEASE_URL = "https://github.com/effectstream/binaries/releases/tag/0.3.120"
WARNING = (
    "DEVELOPMENT ONLY — NOT FOR PRODUCTION USE. Release `0.3.120` is mutable; "
    "verify every downloaded SHA-256 against committed metadata before installation or execution."
)
STATES = ["planned", "uploading", "verified", "published", "revoked"]
STATE_TRANSITIONS = {
    "planned": {"uploading", "revoked"},
    "uploading": {"verified", "revoked"},
    "verified": {"published", "revoked"},
    "published": {"revoked"},
    "revoked": set(),
}


class WarehouseError(RuntimeError):
    pass


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise WarehouseError(message)


def canonical_bytes(value: Any) -> bytes:
    """Warehouse canonical JSON: scalar-only JSON with sorted UTF-8 keys and no floats."""

    def check(item: Any) -> None:
        if isinstance(item, float):
            raise WarehouseError("floating-point canonical values are forbidden")
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise WarehouseError("lone Unicode surrogate is forbidden") from exc
        elif isinstance(item, list):
            for child in item:
                check(child)
        elif isinstance(item, dict):
            expect(all(isinstance(key, str) for key in item), "canonical keys must be strings")
            for key, child in item.items():
                check(key)
                check(child)
        elif item is None or isinstance(item, (bool, int)):
            return
        else:
            raise WarehouseError(f"unsupported canonical JSON type: {type(item).__name__}")

    check(value)
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8") + b"\n"


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise WarehouseError(f"cannot load JSON {path}: {exc}") from exc


def write_canonical(path: Path, value: Any, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = canonical_bytes(value)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def gh_json(endpoint: str) -> Any:
    process = subprocess.run(
        ["gh", "api", endpoint], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if process.returncode:
        raise WarehouseError(
            f"GitHub API read failed for {endpoint}: "
            + process.stderr.decode("utf-8", "replace").strip()
        )
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise WarehouseError(f"GitHub API returned invalid JSON for {endpoint}") from exc


def gh_json_with_headers(endpoint: str) -> tuple[dict[str, str], Any]:
    process = subprocess.run(
        ["gh", "api", "-i", endpoint], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if process.returncode:
        raise WarehouseError(
            f"GitHub API read failed for {endpoint}: "
            + process.stderr.decode("utf-8", "replace").strip()
        )
    raw = process.stdout.replace(b"\r\n", b"\n")
    marker = raw.find(b"\n\n")
    expect(marker >= 0, "GitHub response does not contain a header/body boundary")
    header_text = raw[:marker].decode("utf-8", "replace")
    body = raw[marker + 2 :]
    headers: dict[str, str] = {}
    for line in header_text.splitlines()[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    try:
        return headers, json.loads(body)
    except json.JSONDecodeError as exc:
        raise WarehouseError(f"GitHub API returned invalid JSON for {endpoint}") from exc


def rfc3339_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_asset_name(name: str) -> str:
    expect(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is not None, "unsafe asset name")
    return name


def download_asset(url: str, output: Path, expected_size: int) -> str:
    expect(url.startswith(f"https://github.com/{REPOSITORY}/releases/download/{RELEASE_TAG}/"), "unexpected asset URL")
    request = urllib.request.Request(url, headers={"User-Agent": "effectstream-warehouse-verifier/1"})
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(request, timeout=180) as response, output.open("wb") as handle:
        expect(response.geturl().startswith("https://release-assets.githubusercontent.com/"), "download did not resolve to GitHub release storage")
        while True:
            chunk = response.read(4 * 1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)
            digest.update(chunk)
            total += len(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    expect(total == expected_size, f"independent download size mismatch: expected {expected_size}, observed {total}")
    return digest.hexdigest()


def octal_mode(value: int) -> str:
    return f"0{value & 0o777:03o}"


def install_mode(path: str, stored_mode: int, kind: str) -> str:
    base = PurePosixPath(path.rstrip("/")).name
    if kind == "directory":
        return "0755"
    if stored_mode & 0o111:
        return "0755"
    if base in {"celestia", "celestia-appd"} or re.search(
        r"^(avail-node|indexer-standalone|midnight-node|midnight-proof-server)(-|$)", base
    ):
        return "0755"
    return "0644"


def inspect_zip(path: Path) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    anomalies: set[str] = set()
    expanded = 0
    with zipfile.ZipFile(path) as archive:
        for info in archive.infolist():
            name = info.filename
            expect("\x00" not in name and not name.startswith("/"), f"unsafe legacy ZIP member {name!r}")
            parts = PurePosixPath(name).parts
            expect(".." not in parts, f"traversal legacy ZIP member {name!r}")
            stored = (info.external_attr >> 16) & 0xFFFF
            if info.is_dir():
                kind = "directory"
            elif stat.S_ISLNK(stored):
                kind = "symlink"
                anomalies.add("legacy-symlink")
            elif stored and not stat.S_ISREG(stored):
                kind = "other"
                anomalies.add("legacy-nonregular-member")
            else:
                kind = "file"
            mode = stored & 0o777
            if kind == "file" and mode == 0:
                anomalies.add("legacy-missing-stored-mode")
            if name.startswith("__MACOSX/") or PurePosixPath(name).name.startswith("._"):
                anomalies.add("legacy-appledouble")
            expanded += info.file_size
            members.append(
                {
                    "path": name,
                    "type": kind,
                    "size": info.file_size,
                    "storedMode": octal_mode(mode),
                    "installMode": install_mode(name, mode, kind),
                }
            )
    expect(members, "empty ZIP archive")
    return {
        "format": "zip",
        "memberCount": len(members),
        "expandedSize": expanded,
        "members": members,
        "legacyAnomalies": sorted(anomalies),
    }


def inspect_tar(path: Path) -> dict[str, Any]:
    members: list[dict[str, Any]] = []
    anomalies: set[str] = set()
    expanded = 0
    with tarfile.open(path, mode="r:gz") as archive:
        for info in archive.getmembers():
            name = info.name
            expect("\x00" not in name and not name.startswith("/"), f"unsafe legacy TAR member {name!r}")
            expect(".." not in PurePosixPath(name).parts, f"traversal legacy TAR member {name!r}")
            if info.isdir():
                kind = "directory"
            elif info.isfile():
                kind = "file"
            elif info.issym() or info.islnk():
                kind = "symlink"
                anomalies.add("legacy-link")
            else:
                kind = "other"
                anomalies.add("legacy-nonregular-member")
            if name.startswith("__MACOSX/") or PurePosixPath(name).name.startswith("._"):
                anomalies.add("legacy-appledouble")
            expanded += info.size
            members.append(
                {
                    "path": name,
                    "type": kind,
                    "size": info.size,
                    "storedMode": octal_mode(info.mode),
                    "installMode": install_mode(name, info.mode, kind),
                }
            )
    expect(members, "empty tar archive")
    return {
        "format": "tar.gz",
        "memberCount": len(members),
        "expandedSize": expanded,
        "members": members,
        "legacyAnomalies": sorted(anomalies),
    }


def inspect_archive(path: Path, name: str) -> dict[str, Any]:
    if name.endswith(".zip"):
        return inspect_zip(path)
    if name.endswith(".tar.gz"):
        return inspect_tar(path)
    return {
        "format": "raw",
        "memberCount": 1,
        "expandedSize": path.stat().st_size,
        "members": [
            {"path": name, "type": "file", "size": path.stat().st_size, "storedMode": "0644", "installMode": "0644"}
        ],
        "legacyAnomalies": [],
    }


def snapshot_release(*, independent_downloads: bool, inspect: bool, work_dir: Path | None = None) -> dict[str, Any]:
    repository = gh_json(f"repos/{REPOSITORY}")
    release = gh_json(f"repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}")
    expect(repository["full_name"] == REPOSITORY, "repository full-name mismatch")
    expect(repository["id"] == REPOSITORY_ID and repository["node_id"] == REPOSITORY_NODE_ID, "repository recreation detected")
    expect(release["id"] == RELEASE_ID and release["node_id"] == RELEASE_NODE_ID, "release recreation detected")
    expect(release["tag_name"] == RELEASE_TAG, "release tag mismatch")

    per_page = 100
    pages: list[dict[str, Any]] = []
    assets: list[dict[str, Any]] = []
    page = 1
    while True:
        endpoint = f"repos/{REPOSITORY}/releases/{RELEASE_ID}/assets?per_page={per_page}&page={page}"
        headers, rows = gh_json_with_headers(endpoint)
        expect(isinstance(rows, list), "asset page is not an array")
        pages.append(
            {
                "page": page,
                "request": f"https://api.github.com/{endpoint}",
                "count": len(rows),
                "link": headers.get("link"),
                "etag": headers.get("etag"),
            }
        )
        assets.extend(rows)
        if len(rows) < per_page:
            break
        expect('rel="next"' in headers.get("link", ""), "full asset page lacks next-page Link")
        page += 1
        expect(page <= 11, "release exceeds the supported 1000-asset bound")

    expect(len(assets) == len({row["id"] for row in assets}), "duplicate asset ID across pagination")
    expect(len(assets) == len({row["name"] for row in assets}), "duplicate asset name across pagination")
    expect(len(assets) == len(release["assets"]), "release embedded list and paginated list disagree")

    owned_temp = None
    if work_dir is None:
        owned_temp = tempfile.TemporaryDirectory(prefix="warehouse-snapshot-")
        work_dir = Path(owned_temp.name)
    else:
        work_dir.mkdir(parents=True, exist_ok=True)

    normalized_assets = []
    try:
        for index, row in enumerate(sorted(assets, key=lambda item: item["name"]), start=1):
            name = safe_asset_name(row["name"])
            api_digest = row.get("digest")
            expect(isinstance(api_digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", api_digest), f"missing API digest for {name}")
            independent = api_digest.removeprefix("sha256:")
            inspection = None
            if independent_downloads or inspect:
                local = work_dir / name
                independent = download_asset(row["browser_download_url"], local, row["size"])
                expect(api_digest == f"sha256:{independent}", f"API/download digest mismatch for {name}")
                if inspect:
                    inspection = inspect_archive(local, name)
                local.unlink()
            normalized = {
                "id": row["id"],
                "nodeId": row["node_id"],
                "name": name,
                "state": row["state"],
                "size": row["size"],
                "apiDigest": api_digest,
                "sha256": independent,
                "apiUrl": row["url"],
                "downloadUrl": row["browser_download_url"],
                "contentType": row["content_type"],
                "createdAt": row["created_at"],
                "updatedAt": row["updated_at"],
            }
            if inspection is not None:
                normalized["inspection"] = inspection
            normalized_assets.append(normalized)
            if independent_downloads:
                print(f"verified {index}/{len(assets)} {name}", file=os.sys.stderr, flush=True)
    finally:
        if owned_temp is not None:
            owned_temp.cleanup()

    body = release.get("body") or ""
    body_digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return {
        "schemaVersion": "release-snapshot-v1",
        "capturedAt": rfc3339_now(),
        "apiBaseHost": "api.github.com",
        "repository": {
            "fullName": repository["full_name"],
            "id": repository["id"],
            "nodeId": repository["node_id"],
        },
        "release": {
            "id": release["id"],
            "nodeId": release["node_id"],
            "tag": release["tag_name"],
            "name": release["name"],
            "target": release["target_commitish"],
            "draft": release["draft"],
            "prerelease": release["prerelease"],
            "immutable": release.get("immutable", False),
            "apiUrl": release["url"],
            "uploadUrl": release["upload_url"],
            "browserUrl": release["html_url"],
            "createdAt": release["created_at"],
            "publishedAt": release["published_at"],
            "updatedAt": release["updated_at"],
            "bodySha256": body_digest,
        },
        "pagination": {
            "perPage": per_page,
            "pages": pages,
            "totalCount": len(normalized_assets),
            "complete": True,
        },
        "assets": normalized_assets,
    }


FAMILY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("avail-node", re.compile(r"^avail-node-(linux|macos)-(amd64|arm64)-v(.+)[.]tar[.]gz$")),
    ("celestia-appd", re.compile(r"^celestia-appd-(linux|macos)-(amd64|arm64)-v(.+)[.]tar[.]gz$")),
    ("celestia-node", re.compile(r"^celestia-node-(linux|macos)-(amd64|arm64)-v(.+)[.]tar[.]gz$")),
    ("indexer-standalone", re.compile(r"^indexer-standalone-(linux|macos)-(amd64|arm64)-v(.+)[.]zip$")),
    ("midnight-node", re.compile(r"^midnight-node-(linux|macos)-(amd64|arm64)-(.+)[.]zip$")),
    ("midnight-node-toolkit", re.compile(r"^midnight-node-toolkit-(linux|macos)-(amd64|arm64)-(.+)[.]zip$")),
    ("midnight-proof-server", re.compile(r"^midnight-proof-server-(linux|macos)-(amd64|arm64)-(.+)[.]zip$")),
]


def parse_software_name(name: str) -> tuple[str, str, str, str, str | None]:
    for family, pattern in FAMILY_PATTERNS:
        match = pattern.fullmatch(name)
        if match:
            os_name, arch, tail = match.groups()
            variant = None
            version = tail
            if family == "midnight-proof-server" and tail.startswith("ledger-"):
                variant = "ledger"
                version = tail.removeprefix("ledger-")
            return family, os_name, arch, version, variant
    raise WarehouseError(f"asset does not follow a recognized software family: {name}")


def find_install(inspection: dict[str, Any]) -> tuple[str, str]:
    executable = [
        row for row in inspection["members"]
        if row["type"] == "file" and row["installMode"] == "0755"
    ]
    expect(executable, "archive has no recognizable installed executable")
    return executable[0]["path"], executable[0]["installMode"]


def catalog_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    expect(snapshot["schemaVersion"] == "release-snapshot-v1", "wrong snapshot schema")
    entries = []
    for asset in snapshot["assets"]:
        expect("inspection" in asset, f"snapshot lacks archive inspection for {asset['name']}")
        family, os_name, arch, version, variant = parse_software_name(asset["name"])
        platform = f"{os_name}/{arch}"
        install_path, mode = find_install(asset["inspection"])
        signing = None
        if os_name == "macos":
            signing = {
                "distributionSigningState": "legacy-unverified",
                "codeSignatureKind": "unknown",
                "cdhash": None,
                "authorities": [],
                "teamId": None,
                "hardenedRuntime": None,
                "strictVerification": "unknown",
            }
        semantic = f"{family}/{version}/{platform}"
        if variant:
            semantic += f"/{variant}"
        entry: dict[str, Any] = {
            "semanticId": semantic,
            "artifactKind": "software",
            "family": family,
            "version": version,
            "variant": variant,
            "platform": platform,
            "os": os_name,
            "arch": arch,
            "coverageTier": "legacy",
            "publicationState": "published",
            "distributionTier": "development-only",
            "releaseMutability": "mutable-warehouse",
            "asset": {key: asset[key] for key in [
                "id", "nodeId", "name", "state", "size", "apiDigest", "sha256",
                "apiUrl", "downloadUrl", "contentType", "createdAt", "updatedAt"
            ]},
            "archive": asset["inspection"],
            "install": {"path": install_path, "mode": mode},
            "source": {
                "method": "legacy-unknown",
                "repository": None,
                "commitSha": None,
                "license": None,
                "redistributionEvidence": None,
            },
            "evidence": {
                "sourceManifest": None,
                "checksums": None,
                "provenance": None,
                "sbom": None,
                "memberLineage": None,
            },
            "legacyProvenance": "legacy-unverified",
        }
        if signing:
            entry["signing"] = signing
        entries.append(entry)
    return {
        "schemaVersion": "artifact-catalog-v1",
        "repository": {"fullName": REPOSITORY, "id": REPOSITORY_ID, "nodeId": REPOSITORY_NODE_ID},
        "release": {"tag": RELEASE_TAG, "id": RELEASE_ID, "nodeId": RELEASE_NODE_ID, "url": RELEASE_URL, "mutable": True},
        "warning": WARNING,
        "entries": sorted(entries, key=lambda row: row["semanticId"]),
    }


def stable_index(catalog: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for entry in catalog["entries"]:
        if entry["publicationState"] != "published":
            continue
        rows.append(
            {
                "semanticId": entry["semanticId"],
                "artifactKind": entry["artifactKind"],
                "assetName": entry["asset"]["name"],
                "url": entry["asset"]["downloadUrl"],
                "sha256": entry["asset"]["sha256"],
            }
        )
    return {
        "schemaVersion": "artifact-index-v1",
        "releaseTag": RELEASE_TAG,
        "distributionTier": "development-only",
        "releaseMutability": "mutable-warehouse",
        "warning": WARNING,
        "entries": sorted(rows, key=lambda row: row["semanticId"]),
    }


def validate_catalog(catalog: dict[str, Any], schema_path: Path | None = None) -> None:
    if schema_path:
        try:
            import jsonschema  # type: ignore
        except ImportError as exc:
            raise WarehouseError("jsonschema is required for schema validation") from exc
        validator = jsonschema.Draft202012Validator(load_json(schema_path), format_checker=jsonschema.FormatChecker())
        errors = sorted(validator.iter_errors(catalog), key=lambda error: list(error.absolute_path))
        if errors:
            raise WarehouseError("schema validation failed: " + "; ".join(error.message for error in errors[:10]))

    expect(catalog.get("schemaVersion") == "artifact-catalog-v1", "wrong catalog schema")
    expect(catalog.get("warning") == WARNING, "required development warning mismatch")
    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    seen_tuples: set[tuple[Any, ...]] = set()
    for entry in catalog.get("entries", []):
        semantic = entry["semanticId"]
        name = entry["asset"]["name"]
        expect(semantic not in seen_ids, f"duplicate semantic ID: {semantic}")
        expect(name not in seen_names, f"duplicate asset name: {name}")
        seen_ids.add(semantic)
        seen_names.add(name)
        expect("compact" not in entry["family"].lower(), "Compact is direct-upstream only")
        expect("legacyLocations" not in entry, "legacyLocations is forbidden")
        expect(entry["asset"]["downloadUrl"].startswith(f"https://github.com/{REPOSITORY}/releases/download/{RELEASE_TAG}/"), "non-canonical release URL")
        expect(entry["asset"]["apiDigest"] == f"sha256:{entry['asset']['sha256']}", "API/download digest disagreement")
        expect(entry["distributionTier"] == "development-only", "wrong distribution tier")
        expect(entry["releaseMutability"] == "mutable-warehouse", "wrong release mutability")
        expect(entry["publicationState"] in STATES, "invalid publication state")
        source = entry["source"]
        if source["method"] != "legacy-unknown":
            expect(entry["legacyProvenance"] == "known", "non-legacy source must be known")
            expect(isinstance(source.get("repository"), str) and source["repository"], "known source repository required")
            expect(isinstance(source.get("commitSha"), str) and re.fullmatch(r"[0-9a-f]{40}", source["commitSha"]) is not None, "known source full commit required")
            expect(isinstance(source.get("license"), str) and source["license"], "known source license required")
            expect(isinstance(source.get("redistributionEvidence"), str) and source["redistributionEvidence"], "redistribution evidence required")
        if source["method"] == "build":
            expect(re.fullmatch(r"[0-9a-f]{64}", source.get("lockedDependenciesSha256", "")) is not None, "source build locked dependency digest required")
            expect(isinstance(source.get("toolchain"), str) and source["toolchain"], "source build toolchain required")
            expect(isinstance(source.get("flags"), list), "source build flags list required")
            expect(source.get("native") is True, "source build native=true required")
        if source["method"] in {"identity-mirror", "rename-only", "repackage"}:
            expect(isinstance(source.get("upstreamAssetId"), int) and source["upstreamAssetId"] > 0, "exact upstream asset ID required")
            expect(isinstance(source.get("upstreamAssetNodeId"), str) and source["upstreamAssetNodeId"], "exact upstream asset node ID required")
            expect(isinstance(source.get("upstreamAssetName"), str) and source["upstreamAssetName"], "exact upstream asset name required")
            expect(isinstance(source.get("upstreamAssetSize"), int) and source["upstreamAssetSize"] >= 0, "exact upstream asset size required")
            expect(re.fullmatch(r"[0-9a-f]{64}", source.get("upstreamAssetSha256", "")) is not None, "exact upstream asset digest required")
        if entry["artifactKind"] == "software":
            parsed = parse_software_name(name)
            expected = (entry["family"], entry["os"], entry["arch"], entry["version"], entry.get("variant"))
            expect(parsed == expected, f"family filename mismatch: {name}")
            tuple_key = ("software", entry["family"], entry["version"], entry["os"], entry["arch"], entry.get("variant"))
        else:
            expect(entry["platform"] == "noarch", "proof data must be noarch")
            expect("signing" not in entry and entry["evidence"].get("sbom") is None, "proof data cannot claim signing/SBOM")
            proof = entry["proofData"]
            if proof["kind"] == "srs":
                k = proof["k"]
                expect(proof["installedPath"] == f"bls_midnight_2p{k}" and proof["cacheAlias"] == f"bls_midnight_2p{k}", "SRS cache alias/path mismatch")
                if name == f"bls_midnight_2p{k}":
                    if k == 0:
                        expect(proof.get("officialAlias") is None, "K0 cannot claim ceremony alias")
                        expect(proof["srsGeneration"].startswith("midnight-ledger-provider-compat@"), "K0 provider provenance required")
                    else:
                        expect(proof.get("officialAlias") == f"midnight-srs-2p{k}", "K1+ official alias mismatch")
                        expect(proof["srsGeneration"] == "midnight-trusted-setup@3ea610263b228af24840f7b00661ee22360db6d8", "K1+ trusted setup generation mismatch")
                else:
                    correction = re.fullmatch(rf"midnight-srs-noarch-2p{k}-(ts-[0-9a-f]{{40}}|provider-[0-9a-f]{{40}}-sha256-[0-9a-f]{{64}}|sha256-[0-9a-f]{{64}})[.]bin", name)
                    expect(correction is not None, "changed same-K data requires full generation-qualified name")
            elif proof["kind"] == "ledger-static":
                semver = proof["ledgerStaticSemver"]
                manifest = proof["memberManifestSha256"]
                normal = f"midnight-ledger-static-noarch-{semver}.zip"
                correction = f"midnight-ledger-static-noarch-{semver}-manifest-sha256-{manifest}.zip"
                expect(name in {normal, correction}, "Ledger-static name/revision mismatch")
                if name == correction:
                    expect(proof.get("ledgerStaticRevision") == f"manifest-sha256:{manifest}", "same-semver correction revision mismatch")
                for consumer in proof["exactConsumers"]:
                    expect(consumer["ledgerStaticSemver"] == semver and consumer["cacheNamespace"] == proof["cacheNamespace"], "static data/consumer version mismatch")
            tuple_key = ("proof-data", proof["kind"], proof.get("k"), proof.get("srsGeneration"), proof.get("ledgerStaticSemver"), proof.get("memberManifestSha256"))
        expect(tuple_key not in seen_tuples, f"duplicate semantic tuple: {tuple_key}")
        seen_tuples.add(tuple_key)


def resolve_catalog(catalog: dict[str, Any], *, family: str | None, version: str | None, os_name: str | None, arch: str | None, variant: str | None, k: int | None, srs_generation: str | None, ledger_static: str | None, member_manifest: str | None) -> dict[str, Any]:
    aliases_os = {"darwin": "macos", "osx": "macos", "linux": "linux", "macos": "macos"}
    aliases_arch = {"x86_64": "amd64", "x64": "amd64", "aarch64": "arm64", "amd64": "amd64", "arm64": "arm64"}
    if os_name:
        expect(os_name in aliases_os, "unsupported OS selector")
        os_name = aliases_os[os_name]
    if arch:
        expect(arch in aliases_arch, "unsupported architecture selector")
        arch = aliases_arch[arch]
    rows = [entry for entry in catalog["entries"] if entry["publicationState"] == "published"]
    if k is not None:
        rows = [entry for entry in rows if entry["artifactKind"] == "proof-data" and entry["proofData"]["kind"] == "srs" and entry["proofData"].get("k") == k]
        generations = {entry["proofData"]["srsGeneration"] for entry in rows}
        if len(generations) > 1 and not srs_generation:
            raise WarehouseError("multiple SRS generations exist; --srs-generation is required")
        if srs_generation:
            rows = [entry for entry in rows if entry["proofData"]["srsGeneration"] == srs_generation]
    elif ledger_static:
        rows = [entry for entry in rows if entry["artifactKind"] == "proof-data" and entry["proofData"]["kind"] == "ledger-static" and entry["proofData"]["ledgerStaticSemver"] == ledger_static]
        manifests = {entry["proofData"]["memberManifestSha256"] for entry in rows}
        if len(manifests) > 1 and not member_manifest:
            raise WarehouseError("multiple Ledger-static revisions exist; full --member-manifest-sha256 is required")
        if member_manifest:
            expect(re.fullmatch(r"[0-9a-f]{64}", member_manifest) is not None, "member manifest selector must be a full SHA-256")
            rows = [entry for entry in rows if entry["proofData"]["memberManifestSha256"] == member_manifest]
    else:
        expect(all([family, version, os_name, arch]), "software resolution requires family/version/os/arch")
        rows = [entry for entry in rows if entry["artifactKind"] == "software" and entry["family"] == family and entry["version"] == version and entry["os"] == os_name and entry["arch"] == arch and entry.get("variant") == variant]
    expect(len(rows) == 1, f"resolution requires exactly one published match; observed {len(rows)}")
    entry = rows[0]
    return {
        "semanticId": entry["semanticId"],
        "url": entry["asset"]["downloadUrl"],
        "sha256": entry["asset"]["sha256"],
        "assetName": entry["asset"]["name"],
        "install": entry.get("install") or {
            "path": entry["proofData"]["installedPath"], "mode": entry["proofData"]["installedMode"]
        },
        "warning": WARNING,
    }


def snapshot_identity(snapshot: dict[str, Any]) -> dict[str, Any]:
    projected = json.loads(json.dumps(snapshot))
    projected.pop("capturedAt", None)
    for page in projected.get("pagination", {}).get("pages", []):
        # ETags may vary when only download counters or transport metadata changes; FR-039 fields remain exact.
        page.pop("etag", None)
    for asset in projected.get("assets", []):
        asset.pop("inspection", None)
    return projected


def compare_snapshots(expected: dict[str, Any], observed: dict[str, Any]) -> None:
    if snapshot_identity(expected) != snapshot_identity(observed):
        raise WarehouseError("canonical full-release snapshot drift detected")


def validate_transition(before: str, after: str) -> None:
    expect(before in STATE_TRANSITIONS and after in STATE_TRANSITIONS[before], f"invalid publication transition {before}->{after}")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot")
    snap.add_argument("--output", type=Path, required=True)
    snap.add_argument("--independent-downloads", action="store_true")
    snap.add_argument("--inspect", action="store_true")
    snap.add_argument("--work-dir", type=Path)

    backfill = sub.add_parser("backfill")
    backfill.add_argument("--snapshot", type=Path, required=True)
    backfill.add_argument("--catalog", type=Path, required=True)
    backfill.add_argument("--index", type=Path, required=True)

    validate = sub.add_parser("validate")
    validate.add_argument("--catalog", type=Path, default=ROOT / "metadata/releases/0.3.120.json")
    validate.add_argument("--schema", type=Path, default=ROOT / "metadata/schema/artifact-catalog-v1.schema.json")

    resolve = sub.add_parser("resolve")
    resolve.add_argument("--catalog", type=Path, default=ROOT / "metadata/releases/0.3.120.json")
    resolve.add_argument("--family")
    resolve.add_argument("--version")
    resolve.add_argument("--os", dest="os_name")
    resolve.add_argument("--arch")
    resolve.add_argument("--variant")
    resolve.add_argument("--k", type=int)
    resolve.add_argument("--srs-generation")
    resolve.add_argument("--ledger-static")
    resolve.add_argument("--member-manifest-sha256")

    drift = sub.add_parser("drift")
    drift.add_argument("--baseline", type=Path, required=True)
    drift.add_argument("--independent-downloads", action="store_true")

    transition = sub.add_parser("transition")
    transition.add_argument("--from", dest="before", required=True)
    transition.add_argument("--to", dest="after", required=True)

    args = parser.parse_args()
    try:
        if args.command == "snapshot":
            value = snapshot_release(independent_downloads=args.independent_downloads, inspect=args.inspect, work_dir=args.work_dir)
            write_canonical(args.output, value)
            print(f"PASS snapshot assets={len(value['assets'])} sha256={canonical_sha256(value)}")
        elif args.command == "backfill":
            catalog = catalog_from_snapshot(load_json(args.snapshot))
            write_canonical(args.catalog, catalog)
            write_canonical(args.index, stable_index(catalog))
            print(f"PASS backfill entries={len(catalog['entries'])}")
        elif args.command == "validate":
            catalog = load_json(args.catalog)
            validate_catalog(catalog, args.schema)
            print(f"PASS catalog entries={len(catalog['entries'])}")
        elif args.command == "resolve":
            result = resolve_catalog(load_json(args.catalog), family=args.family, version=args.version, os_name=args.os_name, arch=args.arch, variant=args.variant, k=args.k, srs_generation=args.srs_generation, ledger_static=args.ledger_static, member_manifest=args.member_manifest_sha256)
            print(canonical_bytes(result).decode("utf-8"), end="")
        elif args.command == "drift":
            baseline = load_json(args.baseline)
            observed = snapshot_release(independent_downloads=args.independent_downloads, inspect=False)
            compare_snapshots(baseline, observed)
            print(f"PASS no drift assets={len(observed['assets'])} captured={observed['capturedAt']}")
        elif args.command == "transition":
            validate_transition(args.before, args.after)
            print(f"PASS transition {args.before}->{args.after}")
        return 0
    except (WarehouseError, OSError, subprocess.SubprocessError) as exc:
        print(f"warehouse: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
