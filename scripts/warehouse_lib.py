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
import struct
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


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise WarehouseError(f"duplicate JSON key is forbidden: {key}")
        value[key] = item
    return value


def loads_json(data: str | bytes) -> Any:
    try:
        return json.loads(data, object_pairs_hook=reject_duplicate_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise WarehouseError(f"invalid JSON: {exc}") from exc


def load_json(path: Path) -> Any:
    try:
        return loads_json(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError, WarehouseError) as exc:
        raise WarehouseError(f"cannot load JSON {path}: {exc}") from exc


def load_release_baseline(path: Path) -> dict[str, Any]:
    value = load_json(path)
    if value.get("schemaVersion") != "current-release-baseline-pointer-v1":
        return value
    name = value.get("snapshotPath")
    expect(isinstance(name, str) and PurePosixPath(name).name == name, "current baseline pointer path is unsafe")
    target = path.parent / name
    expect(target.is_file() and not target.is_symlink(), "current baseline target is not a regular file")
    expect(sha256_file(target) == value.get("snapshotSha256"), "current baseline pointer digest mismatch")
    snapshot = load_json(target)
    expect(snapshot.get("schemaVersion") == "release-snapshot-v1", "current baseline target has wrong schema")
    return snapshot


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


def write_canonical_new(path: Path, value: Any, mode: int = 0o600) -> None:
    """Atomically publish canonical bytes without ever replacing an existing path."""
    data = canonical_bytes(value)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except FileExistsError as exc:
        raise WarehouseError(f"refusing to replace existing transaction record: {path}") from exc
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
        ["gh", "api", "--hostname", "github.com", endpoint], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "GH_HOST": "github.com"},
    )
    if process.returncode:
        raise WarehouseError(
            f"GitHub API read failed for {endpoint}: "
            + process.stderr.decode("utf-8", "replace").strip()
        )
    try:
        return loads_json(process.stdout)
    except WarehouseError as exc:
        raise WarehouseError(f"GitHub API returned invalid JSON for {endpoint}") from exc


def gh_json_with_headers(endpoint: str) -> tuple[dict[str, str], Any]:
    process = subprocess.run(
        ["gh", "api", "--hostname", "github.com", "-i", endpoint], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={**os.environ, "GH_HOST": "github.com"},
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
        return headers, loads_json(body)
    except WarehouseError as exc:
        raise WarehouseError(f"GitHub API returned invalid JSON for {endpoint}") from exc


def rfc3339_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_asset_name(name: str) -> str:
    expect(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is not None, "unsafe asset name")
    return name


def download_asset(url: str, output: Path, expected_size: int) -> str:
    expect(url.startswith(f"https://github.com/{REPOSITORY}/releases/download/{RELEASE_TAG}/"), "unexpected asset URL")
    last_error: Exception | None = None
    for attempt in range(1, 4):
        digest = hashlib.sha256()
        total = 0
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "effectstream-warehouse-verifier/1"})
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
        except (OSError, WarehouseError) as exc:
            last_error = exc
            output.unlink(missing_ok=True)
            if attempt == 3:
                break
    raise WarehouseError(f"independent download failed after three attempts: {last_error}")


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


def prebound_zip_directory(path: Path) -> None:
    """Reject oversized/ZIP64 central directories before ZipFile eagerly allocates them."""
    size = path.stat().st_size
    expect(size >= 22, "ZIP is shorter than its end-of-central-directory record")
    with path.open("rb") as handle:
        handle.seek(max(0, size - (65535 + 22)))
        tail = handle.read()
    offset = tail.rfind(b"PK\x05\x06")
    expect(offset >= 0 and len(tail) - offset >= 22, "ZIP end-of-central-directory record is missing")
    _, disk, start_disk, entries_disk, entries, directory_size, directory_offset, comment_size = struct.unpack_from("<4s4H2LH", tail, offset)
    absolute = size - len(tail) + offset
    expect(absolute + 22 + comment_size == size, "ZIP has a malformed trailing directory record")
    expect(disk == 0 and start_disk == 0 and entries_disk == entries, "multi-disk ZIP is forbidden")
    expect(entries != 0xFFFF and directory_size != 0xFFFFFFFF and directory_offset != 0xFFFFFFFF, "ZIP64 candidates are forbidden by the <2-GiB warehouse contract")
    expect(entries <= 100000, "ZIP exceeds the pre-allocation 100000-member limit")
    expect(directory_size <= 64 * 1024**2, "ZIP central directory exceeds the pre-allocation 64-MiB limit")
    expect(directory_offset + directory_size <= absolute, "ZIP central directory bounds are invalid")


def stream_sha256(handle: Any) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def inspect_zip(path: Path) -> dict[str, Any]:
    prebound_zip_directory(path)
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
            expect(expanded <= 16 * 1024**3, "legacy ZIP exceeds the bounded 16-GiB expanded-size inspection limit")
            member = {
                "path": name, "type": kind, "size": info.file_size,
                "storedMode": octal_mode(mode), "installMode": install_mode(name, mode, kind),
            }
            if kind == "file":
                with archive.open(info, "r") as payload:
                    member["sha256"] = stream_sha256(payload)
            members.append(member)
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
    with tarfile.open(path, mode="r|gz") as archive:
        for info in archive:
            expect(len(members) < 100000, "legacy TAR exceeds the bounded 100000-member inspection limit")
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
            expect(expanded <= 16 * 1024**3, "legacy TAR exceeds the bounded 16-GiB expanded-size inspection limit")
            member = {
                "path": name, "type": kind, "size": info.size,
                "storedMode": octal_mode(info.mode), "installMode": install_mode(name, info.mode, kind),
            }
            if kind == "file":
                payload = archive.extractfile(info)
                expect(payload is not None, f"cannot stream TAR member {name!r}")
                with payload:
                    member["sha256"] = stream_sha256(payload)
            members.append(member)
    expect(members, "empty tar archive")
    return {
        "format": "tar.gz",
        "memberCount": len(members),
        "expandedSize": expanded,
        "members": members,
        "legacyAnomalies": sorted(anomalies),
    }


def inspect_archive(path: Path, name: str) -> dict[str, Any]:
    expect(path.stat().st_size <= 2147483647, "candidate exceeds GitHub's <2-GiB asset limit")
    if name.endswith(".zip"):
        return inspect_zip(path)
    if name.endswith(".tar.gz"):
        return inspect_tar(path)
    return {
        "format": "raw",
        "memberCount": 1,
        "expandedSize": path.stat().st_size,
        "members": [
            {"path": name, "type": "file", "size": path.stat().st_size, "sha256": sha256_file(path), "storedMode": "0644", "installMode": "0644"}
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
        link = headers.get("link")
        has_next = isinstance(link, str) and 'rel="next"' in link
        if not has_next:
            break
        expect(len(rows) == per_page, "partial asset page unexpectedly claims a next page")
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


def install_matches_family(path: str, family: str) -> bool:
    basename = PurePosixPath(path).name
    return {
        "avail-node": basename.startswith("avail-node"),
        "celestia-appd": basename == "celestia-appd",
        "celestia-node": basename == "celestia",
        "indexer-standalone": basename.startswith("indexer-standalone"),
        "midnight-node": basename.startswith("midnight-node"),
        "midnight-node-toolkit": basename == "midnight-node-toolkit",
        "midnight-proof-server": basename.startswith("midnight-proof-server"),
    }.get(family, False)


def find_install(inspection: dict[str, Any], family: str) -> tuple[str, str]:
    executable = [
        row for row in inspection["members"]
        if row["type"] == "file"
        and row["installMode"] == "0755"
        and install_matches_family(row["path"], family)
    ]
    expect(executable, f"archive has no recognizable {family} installed executable")
    return executable[0]["path"], executable[0]["installMode"]


def catalog_from_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    expect(snapshot["schemaVersion"] == "release-snapshot-v1", "wrong snapshot schema")
    entries = []
    for asset in snapshot["assets"]:
        expect("inspection" in asset, f"snapshot lacks archive inspection for {asset['name']}")
        family, os_name, arch, version, variant = parse_software_name(asset["name"])
        platform = f"{os_name}/{arch}"
        install_path, mode = find_install(asset["inspection"], family)
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


def expected_q8b_consumers(contract: dict[str, Any]) -> list[dict[str, Any]]:
    positive = contract["exactCompatibility"]["positive"]
    return [
        {
            "proofServerVersion": positive["proofServerVersion"],
            "sourceCommit": positive["sourceCommit"],
            "imageDigest": digest,
            "ledgerStaticSemver": positive["ledgerStaticSemver"],
            "cacheNamespace": positive["cacheNamespace"],
        }
        for digest in positive["imageDigests"]
    ]


def ledger_member_manifest(members: list[dict[str, Any]]) -> str:
    rows = [
        {
            "path": row["path"],
            "bytes": row["size"],
            "sha256": row["sha256"],
            "mode": row["installMode"],
        }
        for row in sorted(members, key=lambda item: item["path"])
    ]
    return canonical_sha256({"schemaVersion": "ledger-static-member-manifest-v1", "members": rows})


def validate_archive_invariants(entry: dict[str, Any]) -> None:
    asset = entry["asset"]
    archive = entry["archive"]
    members = archive["members"]
    expect(archive["memberCount"] == len(members), "archive memberCount mismatch")
    expect(archive["expandedSize"] == sum(row["size"] for row in members), "archive expandedSize mismatch")
    names = [row["path"] for row in members]
    expect(len(names) == len(set(names)), "duplicate archive member path")
    for row in members:
        name = row["path"]
        expect("\x00" not in name and not name.startswith("/"), "unsafe absolute/NUL archive member")
        expect(".." not in PurePosixPath(name).parts, "unsafe traversal archive member")
        expect(row["type"] != "symlink", "archive symlink member is forbidden")

    name = asset["name"]
    if name.endswith(".tar.gz"):
        expect(archive["format"] == "tar.gz", "archive format/outer suffix mismatch")
    elif name.endswith(".zip"):
        expect(archive["format"] == "zip", "archive format/outer suffix mismatch")
    else:
        expect(entry["artifactKind"] == "proof-data" and archive["format"] == "raw", "raw archive format required")

    if entry["artifactKind"] == "software":
        install = entry["install"]
        installed = [row for row in members if row["path"] == install["path"] and row["type"] == "file"]
        expect(len(installed) == 1, "install path must name exactly one archive file")
        expect(install["mode"] == "0755" and installed[0]["installMode"] == "0755", "software install mode mismatch")
        if entry["legacyProvenance"] == "legacy-unverified":
            expect(install_matches_family(install["path"], entry["family"]), "legacy install path does not match software family")


def contract_template(value: str, entry: dict[str, Any]) -> str:
    return value.format(
        os=entry["os"], arch=entry["arch"], version=entry["version"],
    )


def validate_known_software_entry(entry: dict[str, Any], family_contract: dict[str, Any], coverage_policy: dict[str, list[str]]) -> None:
    platform = entry["platform"]
    tiers = [tier for tier, platforms in coverage_policy.items() if platform in platforms]
    expect(len(tiers) == 1 and entry["coverageTier"] == tiers[0], "known software coverageTier differs from the family coverage policy")
    expect(entry["archive"]["format"] == family_contract["archive"], "known software archive format differs from family contract")
    expect(entry["archive"].get("legacyAnomalies") == [], "known software cannot claim legacy archive anomalies")
    if entry["os"] == "macos":
        expect(entry["signing"]["distributionSigningState"] != "legacy-unverified", "known macOS software requires current signing inspection evidence")

    archive_members = entry["archive"]["members"]
    by_path = {row["path"]: row for row in archive_members}
    if entry["family"] == "midnight-node":
        executable = contract_template(family_contract["executableMember"], entry)
        prefix = family_contract["additionalPathPrefix"]
        expect(executable in by_path and len(by_path) > 1, "known Midnight node requires its exact root executable plus res/")
        expect(
            all(path == executable or path == prefix.rstrip("/") or path.startswith(prefix) for path in by_path),
            "known Midnight node contains a path outside the exact executable/res layout",
        )
    else:
        templates = family_contract.get("variantMembers") if entry.get("variant") else family_contract.get("members")
        expect(isinstance(templates, list) and templates, "software family lacks an exact member contract")
        expected_paths = [contract_template(value, entry) for value in templates]
        expect(set(by_path) == set(expected_paths) and len(by_path) == len(expected_paths), "known software member tree differs from family contract")
        executable = expected_paths[-1]

    expect(entry["install"] == {"path": executable, "mode": family_contract["installMode"]}, "known software install identity differs from family contract")
    for path, member in by_path.items():
        expect(member["type"] in {"file", "directory"}, "known software member type is not installable")
        if member["type"] == "file":
            expect(re.fullmatch(r"[0-9a-f]{64}", member.get("sha256", "")) is not None, "known software file lacks an exact member digest")
        if path == executable:
            expect(member["type"] == "file" and member["storedMode"] == "0755" and member["installMode"] == "0755", "known software executable mode mismatch")
        elif member["type"] == "directory":
            expect(member["storedMode"] == "0755" and member["installMode"] == "0755", "known software directory mode mismatch")
        else:
            expect(member["storedMode"] == "0644" and member["installMode"] == "0644", "known software data member mode mismatch")


def validate_repackage_entry(entry: dict[str, Any]) -> None:
    source = entry["source"]
    evidence = entry["evidence"]
    record = source.get("repackage")
    expect(isinstance(record, dict), "repackage requires a typed deterministic transformation record")
    expect(record.get("schemaVersion") == "deterministic-repackage-v1", "wrong repackage record schema")
    expect(record.get("algorithm") == "copy-verified-members-v1", "unsupported repackage algorithm")
    expect(record.get("memberOrder") == "utf8-bytewise-lexicographic" and record.get("pathPolicy") == "exact-mapping-only", "repackage ordering/path policy mismatch")
    archive = entry["archive"]
    expected_policy = {
        "zip": ("deflate-level-9", "zip-dos-epoch-1980-01-01T00:00:00Z", "1980-01-01T00:00:00Z"),
        "tar.gz": ("gzip-level-9", "unix-epoch-1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"),
    }.get(archive["format"])
    expect(expected_policy is not None, "repackage output must be a deterministic ZIP or tar.gz")
    compression, timestamp_policy, timestamp = expected_policy
    expect(record.get("archiveFormat") == archive["format"] and record.get("compression") == compression and record.get("timestampPolicy") == timestamp_policy, "repackage archive/compression/timestamp policy mismatch")
    expect(record.get("outputSize") == entry["asset"]["size"], "repackage output size mismatch")
    two_run = record.get("twoRun", {})
    output_digest = entry["asset"]["sha256"]
    expect(
        two_run.get("run1Sha256") == output_digest
        and two_run.get("run2Sha256") == output_digest
        and two_run.get("independentReadbackSha256") == output_digest,
        "repackage two-run/readback digest mismatch",
    )
    expect(
        isinstance(two_run.get("run1Runner"), str)
        and isinstance(two_run.get("run2Runner"), str)
        and two_run["run1Runner"]
        and two_run["run2Runner"]
        and two_run["run1Runner"] != two_run["run2Runner"],
        "repackage two-run evidence requires distinct runners",
    )
    mappings = record.get("members")
    expect(isinstance(mappings, list) and mappings, "repackage member mapping is empty")
    expect([row.get("outputPath") for row in mappings] == sorted(row.get("outputPath") for row in mappings), "repackage mappings must use exact UTF-8 path order")
    primary = mappings[0]
    expect(
        {
            "id": source.get("upstreamAssetId"),
            "nodeId": source.get("upstreamAssetNodeId"),
            "name": source.get("upstreamAssetName"),
            "url": source.get("upstreamAssetUrl"),
            "size": source.get("upstreamAssetSize"),
            "sha256": source.get("upstreamAssetSha256"),
        }
        == {
            "id": primary.get("inputAssetId"),
            "nodeId": primary.get("inputAssetNodeId"),
            "name": primary.get("inputAssetName"),
            "url": primary.get("inputAssetUrl"),
            "size": primary.get("inputAssetSize"),
            "sha256": primary.get("inputAssetSha256"),
        },
        "repackage primary upstream identity differs from typed member record",
    )
    expected_members = []
    for mapping in mappings:
        for field in ["inputAssetNodeId", "inputAssetName", "inputAssetUrl", "inputMemberPath", "outputPath"]:
            expect(isinstance(mapping.get(field), str) and mapping[field], f"repackage member {field} is missing")
        expect(isinstance(mapping.get("inputAssetId"), int) and mapping["inputAssetId"] > 0, "repackage input asset ID is invalid")
        expect(isinstance(mapping.get("inputAssetSize"), int) and mapping["inputAssetSize"] >= 0, "repackage input asset size is invalid")
        expect(re.fullmatch(r"[0-9a-f]{64}", mapping.get("inputAssetSha256", "")) is not None, "repackage input asset digest is invalid")
        expect(mapping.get("inputMemberSize") == mapping.get("outputSize") and mapping.get("inputMemberSha256") == mapping.get("outputSha256"), "repackage must copy exact verified member bytes")
        expect(mapping.get("timestamp") == timestamp, "repackage member timestamp policy mismatch")
        expected_members.append({
            "path": mapping["outputPath"], "type": "file", "size": mapping["outputSize"],
            "sha256": mapping["outputSha256"], "timestamp": mapping["timestamp"],
            "storedMode": mapping["storedMode"], "installMode": mapping["installMode"],
        })
    expect(archive["members"] == expected_members, "repackage output member tree differs from typed transformation record")
    expect(archive.get("legacyAnomalies") == [], "new deterministic repackage cannot claim legacy anomalies")
    for field in ["sourceManifest", "checksums", "provenance", "memberLineage"]:
        expect(isinstance(evidence.get(field), str) and evidence[field], f"repackage requires non-null {field} evidence")
    if entry["artifactKind"] == "software":
        expect(isinstance(evidence.get("sbom"), str) and evidence["sbom"], "software repackage requires non-null SBOM evidence")


def parse_rfc3339(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise WarehouseError("evidence timestamp is not valid RFC3339") from exc
    expect(parsed.utcoffset() is not None, "evidence timestamp must include an RFC3339 offset")
    return parsed


def validate_signing_evidence(entry: dict[str, Any]) -> None:
    signing = entry.get("signing")
    if not isinstance(signing, dict) or signing.get("distributionSigningState") != "DEVELOPER_ID_SIGNED_NOTARIZED_ONLINE_TICKET":
        return
    notarization = signing["notarization"]
    expect(re.fullmatch(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", notarization["submissionId"]) is not None, "notarization submissionId must be a canonical UUID")
    submitted = parse_rfc3339(notarization["submittedAt"])
    completed = parse_rfc3339(notarization["completedAt"])
    expect(submitted <= completed, "notarization completion precedes submission")
    for field in ["onlineTicket", "gatekeeper", "quarantinedDownloadSmoke"]:
        checked = parse_rfc3339(notarization[field]["checkedAt"])
        expect(completed <= checked, f"notarization {field} check precedes completion")


def validate_q8b_entry(entry: dict[str, Any], contract: dict[str, Any]) -> None:
    proof = entry["proofData"]
    asset = entry["asset"]
    archive = entry["archive"]
    expected_consumers = expected_q8b_consumers(contract)
    expect(proof["exactConsumers"] == expected_consumers, "proof-data exact compatibility mismatch")
    if proof["kind"] == "srs":
        expect("correctionCompatibility" not in proof, "SRS cannot carry Ledger-static correction compatibility")
        k = proof["k"]
        pinned = next((row for row in contract["srs"]["objects"] if row["k"] == k), None)
        expect(pinned is not None, "SRS K is outside the exact reviewed Q8=B inventory")
        literal = asset["name"] == pinned["assetName"]
        if literal:
            expect(asset["size"] == pinned["bytes"] and asset["sha256"] == pinned["sha256"], "literal SRS byte identity mismatch")
            expect(
                proof["installedPath"] == pinned["installedPath"]
                and proof["cacheAlias"] == pinned["installedPath"]
                and proof.get("officialAlias") == pinned["officialAlias"]
                and proof["srsGeneration"] == pinned["srsGeneration"],
                "literal SRS alias/generation mismatch",
            )
            expect(
                archive["format"] == "raw"
                and archive["memberCount"] == 1
                and archive["expandedSize"] == pinned["bytes"]
                and archive["members"] == [{
                    "path": pinned["installedPath"], "type": "file", "size": pinned["bytes"],
                    "sha256": pinned["sha256"], "storedMode": contract["srs"]["mode"],
                    "installMode": contract["srs"]["mode"],
                }],
                "literal SRS raw member contract mismatch",
            )
            expected_repo = contract["srs"]["providerRepository"] if k == 0 else contract["srs"]["trustedSetupRepository"]
            expected_commit = contract["srs"]["providerCommit"] if k == 0 else contract["srs"]["trustedSetupCommit"]
            expect(entry["source"]["repository"] == expected_repo and entry["source"]["commitSha"] == expected_commit, "literal SRS source mismatch")
        else:
            member = archive["members"]
            expect(
                archive["format"] == "raw"
                and len(member) == 1
                and member[0]["path"] == proof["installedPath"]
                and member[0].get("sha256") == asset["sha256"]
                and member[0]["size"] == asset["size"]
                and member[0]["storedMode"] == "0644"
                and member[0]["installMode"] == "0644",
                "generation-qualified SRS member mismatch",
            )
            expect(proof.get("officialAlias") == pinned["officialAlias"], "SRS correction official alias differs from selected K")
            prefix = f"midnight-srs-noarch-2p{k}-"
            expect(asset["name"].startswith(prefix) and asset["name"].endswith(".bin"), "SRS correction name does not encode selected K/generation")
            token = asset["name"][len(prefix):-4]
            source = entry["source"]
            sha_token = re.fullmatch(r"sha256-([0-9a-f]{64})", token)
            trusted_token = re.fullmatch(r"ts-([0-9a-f]{40})", token)
            provider_token = re.fullmatch(r"provider-([0-9a-f]{40})-sha256-([0-9a-f]{64})", token)
            expect(sum(match is not None for match in [sha_token, trusted_token, provider_token]) == 1, "SRS correction generation token is invalid")
            if trusted_token:
                commit = trusted_token.group(1)
                expect(proof["srsGeneration"] == f"midnight-trusted-setup@{commit}", "SRS ts token/generation mismatch")
                expect(source["repository"] == contract["srs"]["trustedSetupRepository"] and source["commitSha"] == commit, "SRS ts token/source mismatch")
            elif provider_token:
                commit, digest = provider_token.groups()
                expect(proof["srsGeneration"] == f"midnight-ledger-provider-compat@{commit}/sha256:{digest}", "SRS provider token/generation mismatch")
                expect(source["repository"] == contract["srs"]["providerRepository"] and source["commitSha"] == commit, "SRS provider token/source mismatch")
                expect(asset["sha256"] == digest, "SRS provider token/byte digest mismatch")
            else:
                assert sha_token is not None
                digest = sha_token.group(1)
                expect(proof["srsGeneration"] == f"sha256:{digest}" and asset["sha256"] == digest, "SRS sha256 token/generation/byte mismatch")
                expected_repo = contract["srs"]["providerRepository"] if k == 0 else contract["srs"]["trustedSetupRepository"]
                expected_commit = contract["srs"]["providerCommit"] if k == 0 else contract["srs"]["trustedSetupCommit"]
                expect(source["repository"] == expected_repo and source["commitSha"] == expected_commit, "SRS sha256 correction source differs from selected K")
    else:
        pinned = contract["ledgerStatic"]
        expected_paths = {row["path"] for row in pinned["members"]}
        observed_paths = {row["path"] for row in archive["members"]}
        expect(observed_paths == expected_paths and len(archive["members"]) == len(expected_paths), "Ledger-static exact 12-member tree mismatch")
        expect(all(row["type"] == "file" and row["storedMode"] == pinned["mode"] and row["installMode"] == pinned["mode"] and re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) for row in archive["members"]), "Ledger-static member hash/mode mismatch")
        computed_manifest = ledger_member_manifest(archive["members"])
        expect(proof["memberManifestSha256"] == computed_manifest, "Ledger-static member manifest mismatch")
        normal_name = pinned["assetName"]
        if asset["name"] == normal_name:
            expect("correctionCompatibility" not in proof, "normal Ledger-static cannot use correction-only compatibility evidence")
            expect(isinstance(pinned.get("memberManifestSha256"), str), "normal Ledger-static is blocked until Phase-3p member manifest is pinned")
            expect(isinstance(pinned.get("archiveSha256"), str) and isinstance(pinned.get("archiveBytes"), int), "normal Ledger-static archive identity is not pinned")
            expected_members = {
                row["path"]: (row["bytes"], row["sha256"], pinned["mode"])
                for row in pinned["members"]
            }
            observed_members = {
                row["path"]: (row["size"], row["sha256"], row["installMode"])
                for row in archive["members"]
            }
            expect(observed_members == expected_members, "normal Ledger-static member bytes differ from Q8=B")
            expect(proof["memberManifestSha256"] == pinned["memberManifestSha256"], "normal Ledger-static contract digest mismatch")
            expect(asset["sha256"] == pinned["archiveSha256"] and asset["size"] == pinned["archiveBytes"], "normal Ledger-static archive bytes mismatch")
        else:
            correction = f"midnight-ledger-static-noarch-{proof['ledgerStaticSemver']}-manifest-sha256-{computed_manifest}.zip"
            expect(asset["name"] == correction and proof.get("ledgerStaticRevision") == f"manifest-sha256:{computed_manifest}", "Ledger-static correction name/revision mismatch")
            compatibility = proof.get("correctionCompatibility")
            expect(isinstance(compatibility, dict), "Ledger-static correction requires reviewed compatibility evidence")
            consumer_commits = {row["sourceCommit"] for row in proof["exactConsumers"]}
            consumer_images = sorted(row["imageDigest"] for row in proof["exactConsumers"])
            expect(
                compatibility.get("schemaVersion") == "ledger-static-correction-compatibility-v1"
                and compatibility.get("memberManifestSha256") == computed_manifest
                and consumer_commits == {compatibility.get("sourceCommit")}
                and compatibility.get("sourceCommit") == entry["source"]["commitSha"]
                and compatibility.get("imageDigests") == consumer_images
                and compatibility.get("result") == "pass"
                and isinstance(compatibility.get("evidenceRef"), str) and compatibility["evidenceRef"]
                and re.fullmatch(r"[0-9a-f]{64}", compatibility.get("evidenceSha256", "")) is not None,
                "Ledger-static correction compatibility is not bound to manifest/source/images/evidence",
            )


def validate_catalog(
    catalog: dict[str, Any], schema_path: Path | None = None, *,
    family_contracts_override: dict[str, Any] | None = None,
    proof_contract_override: dict[str, Any] | None = None,
) -> None:
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
    expect(catalog.get("repository") == {"fullName": REPOSITORY, "id": REPOSITORY_ID, "nodeId": REPOSITORY_NODE_ID}, "catalog repository identity mismatch")
    expect(catalog.get("release") == {"tag": RELEASE_TAG, "id": RELEASE_ID, "nodeId": RELEASE_NODE_ID, "url": RELEASE_URL, "mutable": True}, "catalog release identity mismatch")
    proof_contract = proof_contract_override or load_json(ROOT / "metadata/contracts/proof-data-q8b-v1.json")
    family_contracts = family_contracts_override or load_json(ROOT / "metadata/contracts/families-v1.json")
    software_families = {row["family"]: row for row in family_contracts["softwareFamilies"]}
    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    seen_asset_ids: set[int] = set()
    seen_asset_node_ids: set[str] = set()
    seen_tuples: set[tuple[Any, ...]] = set()
    for entry in catalog.get("entries", []):
        semantic = entry["semanticId"]
        name = entry["asset"]["name"]
        planned = entry["publicationState"] == "planned"
        expect(semantic not in seen_ids, f"duplicate semantic ID: {semantic}")
        expect(name not in seen_names, f"duplicate asset name: {name}")
        seen_ids.add(semantic)
        seen_names.add(name)
        if planned:
            expect(set(entry["asset"]) == {"name", "state", "size", "sha256"} and entry["asset"]["state"] == "candidate", "planned row must carry only exact candidate byte identity")
        else:
            asset_id = entry["asset"]["id"]
            asset_node_id = entry["asset"]["nodeId"]
            expect(asset_id not in seen_asset_ids, f"duplicate destination asset ID: {asset_id}")
            expect(asset_node_id not in seen_asset_node_ids, f"duplicate destination asset node ID: {asset_node_id}")
            seen_asset_ids.add(asset_id)
            seen_asset_node_ids.add(asset_node_id)
        expect("compact" not in entry["family"].lower(), "Compact is direct-upstream only")
        expect("legacyLocations" not in entry, "legacyLocations is forbidden")
        if not planned:
            expect(entry["asset"]["downloadUrl"].startswith(f"https://github.com/{REPOSITORY}/releases/download/{RELEASE_TAG}/"), "non-canonical release URL")
            expect(entry["asset"]["apiDigest"] == f"sha256:{entry['asset']['sha256']}", "API/download digest disagreement")
            expect(entry["asset"]["apiUrl"] == f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{entry['asset']['id']}", "asset API ID/URL mismatch")
            expect(entry["asset"]["downloadUrl"] == f"https://github.com/{REPOSITORY}/releases/download/{RELEASE_TAG}/{name}", "asset download basename mismatch")
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
            for field in ["sourceManifest", "checksums", "provenance"]:
                expect(isinstance(entry["evidence"].get(field), str) and entry["evidence"][field], f"known source requires non-null {field} evidence")
            if entry["artifactKind"] == "software":
                expect(isinstance(entry["evidence"].get("sbom"), str) and entry["evidence"]["sbom"], "known software requires non-null SBOM evidence")
            else:
                expect(isinstance(entry["evidence"].get("memberLineage"), str) and entry["evidence"]["memberLineage"], "known proof data requires non-null member lineage evidence")
        if source["method"] == "build":
            expect(re.fullmatch(r"[0-9a-f]{64}", source.get("lockedDependenciesSha256", "")) is not None, "source build locked dependency digest required")
            expect(isinstance(source.get("toolchain"), str) and source["toolchain"], "source build toolchain required")
            expect(isinstance(source.get("flags"), list), "source build flags list required")
            expect(source.get("native") is True, "source build native=true required")
        if source["method"] in {"identity-mirror", "rename-only", "repackage"}:
            expect(isinstance(source.get("upstreamAssetId"), int) and source["upstreamAssetId"] > 0, "exact upstream asset ID required")
            expect(isinstance(source.get("upstreamAssetNodeId"), str) and source["upstreamAssetNodeId"], "exact upstream asset node ID required")
            expect(isinstance(source.get("upstreamAssetName"), str) and source["upstreamAssetName"], "exact upstream asset name required")
            expect(isinstance(source.get("upstreamAssetUrl"), str) and source["upstreamAssetUrl"].startswith("https://github.com/"), "exact upstream asset URL required")
            expect(isinstance(source.get("upstreamAssetSize"), int) and source["upstreamAssetSize"] >= 0, "exact upstream asset size required")
            expect(re.fullmatch(r"[0-9a-f]{64}", source.get("upstreamAssetSha256", "")) is not None, "exact upstream asset digest required")
        if source["method"] == "identity-mirror":
            expect(source["upstreamAssetName"] == name, "identity-mirror must retain exact upstream name")
            expect(source["upstreamAssetSize"] == entry["asset"]["size"], "identity-mirror size differs from upstream")
            expect(source["upstreamAssetSha256"] == entry["asset"]["sha256"], "identity-mirror digest differs from upstream")
            expect("renameMapping" not in source, "identity-mirror cannot carry a rename mapping")
        elif source["method"] == "rename-only":
            expect(source["upstreamAssetSize"] == entry["asset"]["size"], "rename-only size differs from upstream")
            expect(source["upstreamAssetSha256"] == entry["asset"]["sha256"], "rename-only digest differs from upstream")
            expect(source.get("renameMapping") == {"from": source["upstreamAssetName"], "to": name}, "rename-only exact old/new mapping required")
            expect(source["upstreamAssetName"] != name, "rename-only must actually rename")
        elif source["method"] == "repackage":
            expect("renameMapping" not in source, "repackage cannot masquerade as rename-only")
            validate_repackage_entry(entry)
        if source["method"] != "repackage":
            expect("repackage" not in source, "typed repackage evidence is allowed only for method=repackage")
        validate_archive_invariants(entry)
        validate_signing_evidence(entry)
        if entry["artifactKind"] == "software":
            expect(entry["family"] in software_families, "software family is absent from machine-readable family contracts")
            family_contract = software_families[entry["family"]]
            template = family_contract.get("variantTemplate") if entry.get("variant") else family_contract["nameTemplate"]
            expect(name == contract_template(template, entry), f"family filename mismatch: {name}")
            expect(entry["platform"] == f"{entry['os']}/{entry['arch']}", "software platform/os/arch mismatch")
            expect(("signing" in entry) == (entry["os"] == "macos"), "signing metadata presence must match macOS platform")
            expected_semantic = f"{entry['family']}/{entry['version']}/{entry['os']}/{entry['arch']}"
            if entry.get("variant"):
                expected_semantic += f"/{entry['variant']}"
            expect(semantic == expected_semantic, "software semanticId mismatch")
            if source["method"] != "legacy-unknown":
                validate_known_software_entry(entry, family_contract, family_contracts["coveragePolicy"])
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
                expected_semantic = f"srs/{k}/{proof['srsGeneration'].replace('@', '-').replace(':', '-')}"
                expect(semantic == expected_semantic, "SRS semanticId mismatch")
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
                expect(semantic == f"ledger-static/{semver}/{manifest}", "Ledger-static semanticId mismatch")
            validate_q8b_entry(entry, proof_contract)
            tuple_key = ("proof-data", proof["kind"], proof.get("k"), proof.get("srsGeneration"), proof.get("ledgerStaticSemver"), proof.get("memberManifestSha256"))
        expect(tuple_key not in seen_tuples, f"duplicate semantic tuple: {tuple_key}")
        seen_tuples.add(tuple_key)


def resolve_catalog(catalog: dict[str, Any], *, family: str | None, version: str | None, os_name: str | None, arch: str | None, variant: str | None, k: int | None, srs_generation: str | None, ledger_static: str | None, member_manifest: str | None) -> dict[str, Any]:
    software_present = any(value is not None for value in [family, version, os_name, arch, variant])
    srs_present = k is not None or srs_generation is not None
    static_present = ledger_static is not None or member_manifest is not None
    expect(sum([software_present, srs_present, static_present]) == 1, "resolution requires exactly one mutually exclusive software, SRS, or Ledger-static selector mode")
    if software_present:
        expect(all(value is not None for value in [family, version, os_name, arch]), "software resolution requires family/version/os/arch")
        expect(all(isinstance(value, str) and bool(value.strip()) for value in [family, version, os_name, arch]), "software selectors cannot be empty")
        if variant is not None:
            expect(isinstance(variant, str) and bool(variant.strip()), "software variant selector cannot be empty")
    elif srs_present:
        expect(k is not None, "SRS resolution requires K when an SRS generation is supplied")
        if srs_generation is not None:
            expect(isinstance(srs_generation, str) and bool(srs_generation.strip()), "SRS generation selector cannot be empty")
    else:
        expect(isinstance(ledger_static, str) and bool(ledger_static.strip()), "Ledger-static resolution requires a non-empty semver when a member manifest is supplied")
        if member_manifest is not None:
            expect(re.fullmatch(r"[0-9a-f]{64}", member_manifest) is not None, "member manifest selector must be a full SHA-256")
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
        if len(generations) > 1 and srs_generation is None:
            raise WarehouseError("multiple SRS generations exist; --srs-generation is required")
        if srs_generation is not None:
            rows = [entry for entry in rows if entry["proofData"]["srsGeneration"] == srs_generation]
    elif ledger_static is not None:
        rows = [entry for entry in rows if entry["artifactKind"] == "proof-data" and entry["proofData"]["kind"] == "ledger-static" and entry["proofData"]["ledgerStaticSemver"] == ledger_static]
        manifests = {entry["proofData"]["memberManifestSha256"] for entry in rows}
        if len(manifests) > 1 and member_manifest is None:
            raise WarehouseError("multiple Ledger-static revisions exist; full --member-manifest-sha256 is required")
        if member_manifest is not None:
            rows = [entry for entry in rows if entry["proofData"]["memberManifestSha256"] == member_manifest]
    else:
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


def validate_repository_state(
    catalog: dict[str, Any], index: dict[str, Any], previous_catalog: dict[str, Any]
) -> None:
    expect(index == stable_index(catalog), "committed stable index differs from deterministic published catalog projection")
    previous = {entry["semanticId"]: entry for entry in previous_catalog["entries"]}
    current = {entry["semanticId"]: entry for entry in catalog["entries"]}
    expect(set(previous) <= set(current), "append-only catalog cannot delete prior semantic IDs")
    for semantic, before in previous.items():
        after = current[semantic]
        before_state = before["publicationState"]
        after_state = after["publicationState"]
        if before_state != after_state:
            validate_transition(before_state, after_state)
        immutable_before = json.loads(json.dumps(before))
        immutable_after = json.loads(json.dumps(after))
        immutable_before.pop("publicationState")
        immutable_after.pop("publicationState")
        if before_state == "planned" and after_state == "uploading":
            planned_asset = immutable_before.pop("asset")
            uploaded_asset = immutable_after.pop("asset")
            expect(
                {key: uploaded_asset[key] for key in ["name", "size", "sha256"]}
                == {key: planned_asset[key] for key in ["name", "size", "sha256"]}
                and planned_asset.get("state") == "candidate"
                and uploaded_asset.get("state") == "uploaded",
                f"planned destination transition changed candidate bytes for {semantic}",
            )
        expect(immutable_before == immutable_after, f"append-only catalog bytes/identity changed for {semantic}")
    for semantic in set(current) - set(previous):
        expect(current[semantic]["publicationState"] == "planned", f"new catalog row must enter at planned state: {semantic}")


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
    validate.add_argument("--index", type=Path, default=ROOT / "metadata/index.json")
    validate.add_argument("--previous-catalog", type=Path)
    validate.add_argument("--baseline-snapshot", type=Path, default=ROOT / "metadata/baselines/0.3.120-initial.json")

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
            previous = (
                load_json(args.previous_catalog)
                if args.previous_catalog
                else catalog_from_snapshot(load_json(args.baseline_snapshot))
            )
            validate_repository_state(catalog, load_json(args.index), previous)
            print(f"PASS catalog entries={len(catalog['entries'])}")
        elif args.command == "resolve":
            result = resolve_catalog(load_json(args.catalog), family=args.family, version=args.version, os_name=args.os_name, arch=args.arch, variant=args.variant, k=args.k, srs_generation=args.srs_generation, ledger_static=args.ledger_static, member_manifest=args.member_manifest_sha256)
            print(canonical_bytes(result).decode("utf-8"), end="")
        elif args.command == "drift":
            baseline = load_release_baseline(args.baseline)
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
