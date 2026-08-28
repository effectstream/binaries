from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from warehouse_lib import (  # noqa: E402
    WarehouseError,
    load_json,
    load_release_baseline,
    resolve_catalog,
    stable_index,
    validate_baseline_change_rows,
    validate_catalog,
    validate_repository_state,
    validate_snapshot_catalog_binding,
    validate_transition,
)


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_json(ROOT / "metadata/releases/0.3.120.json")
        cls.schema = ROOT / "metadata/schema/artifact-catalog-v1.schema.json"

    def published_catalog(self) -> dict:
        catalog = copy.deepcopy(self.catalog)
        catalog["entries"] = [row for row in catalog["entries"] if row["publicationState"] == "published"]
        return catalog

    def known_software_catalog(self, family: str) -> tuple[dict, dict]:
        contracts = load_json(ROOT / "metadata/contracts/families-v1.json")
        contract = next(row for row in contracts["softwareFamilies"] if row["family"] == family)
        catalog = self.published_catalog()
        if family == "midnight-node-toolkit":
            entry = next(row for row in catalog["entries"] if row["family"] == "indexer-standalone" and row["platform"] == "linux/amd64")
            entry["family"] = family
            entry["version"] = "2.0.0-rc.4"
            entry["variant"] = None
            entry["semanticId"] = f"{family}/2.0.0-rc.4/linux/amd64"
            name = contract["nameTemplate"].format(os="linux", arch="amd64", version=entry["version"])
            entry["asset"]["name"] = name
            entry["asset"]["downloadUrl"] = f"https://github.com/effectstream/binaries/releases/download/0.3.120/{name}"
        else:
            entry = next(row for row in catalog["entries"] if row["family"] == family)

        coverage = next(tier for tier, platforms in contracts["coveragePolicy"].items() if entry["platform"] in platforms)
        entry["coverageTier"] = coverage
        entry["legacyProvenance"] = "known"
        entry["source"] = {
            "method": "build", "repository": "owner/source", "commitSha": "a" * 40,
            "license": "Apache-2.0", "redistributionEvidence": "LICENSE@a",
            "lockedDependenciesSha256": "b" * 64, "toolchain": "rustc@sha256:" + "c" * 64,
            "flags": [], "native": True,
        }
        entry["evidence"] = {
            "sourceManifest": "source-manifest.json", "checksums": "SHA256SUMS",
            "provenance": "provenance.intoto.jsonl", "sbom": "sbom.spdx.json",
            "memberLineage": None,
        }
        if entry["os"] == "macos":
            entry["signing"] = {
                "distributionSigningState": "UNSIGNED_DEVELOPMENT_ONLY",
                "codeSignatureKind": "none", "cdhash": None, "authorities": [],
                "teamId": None, "hardenedRuntime": False, "strictVerification": "fail",
            }
        values = {"os": entry["os"], "arch": entry["arch"], "version": entry["version"]}
        if family == "midnight-node":
            executable = contract["executableMember"].format(**values)
            paths = [executable, "res/config.json"]
        else:
            templates = contract.get("variantMembers") if entry.get("variant") else contract["members"]
            paths = [value.format(**values) for value in templates]
            executable = paths[-1]
        members = []
        for path in paths:
            is_executable = path == executable
            members.append({
                "path": path, "type": "file", "size": 1,
                "sha256": hashlib.sha256(path.encode()).hexdigest(),
                "storedMode": "0755" if is_executable else "0644",
                "installMode": "0755" if is_executable else "0644",
            })
        entry["archive"] = {
            "format": contract["archive"], "memberCount": len(members),
            "expandedSize": sum(row["size"] for row in members),
            "members": members, "legacyAnomalies": [],
        }
        entry["install"] = {"path": executable, "mode": "0755"}
        return catalog, entry

    def test_exact_legacy_backfill(self) -> None:
        validate_catalog(self.catalog, self.schema)
        legacy = [row for row in self.catalog["entries"] if row["source"]["method"] == "legacy-unknown"]
        initial = [row for row in self.catalog["entries"] if row["source"]["method"] != "legacy-unknown"]
        self.assertEqual((len(legacy), len(initial), len(self.catalog["entries"])), (66, 31, 97))
        self.assertEqual({row["publicationState"] for row in initial}, {initial[0]["publicationState"]})
        self.assertIn(initial[0]["publicationState"], {"uploading", "verified", "published"})
        self.assertEqual(len({row["semanticId"] for row in legacy}), 66)
        self.assertEqual(len({row["asset"]["name"] for row in legacy}), 66)
        for row in legacy:
            self.assertEqual(row["asset"]["apiDigest"], f"sha256:{row['asset']['sha256']}")
            self.assertEqual(row["publicationState"], "published")
            self.assertEqual(row["legacyProvenance"], "legacy-unverified")
            self.assertGreater(row["archive"]["memberCount"], 0)
            self.assertEqual(row["archive"]["memberCount"], len(row["archive"]["members"]))

    def test_alias_resolution_and_published_only(self) -> None:
        result = resolve_catalog(
            self.catalog, family="indexer-standalone", version="4.4.0-rc.1",
            os_name="darwin", arch="aarch64", variant=None, k=None,
            srs_generation=None, ledger_static=None, member_manifest=None,
        )
        self.assertEqual(result["assetName"], "indexer-standalone-macos-arm64-v4.4.0-rc.1.zip")
        changed = copy.deepcopy(self.catalog)
        target = next(row for row in changed["entries"] if row["asset"]["name"] == result["assetName"])
        target["publicationState"] = "verified"
        with self.assertRaisesRegex(WarehouseError, "observed 0"):
            resolve_catalog(
                changed, family="indexer-standalone", version="4.4.0-rc.1",
                os_name="macos", arch="arm64", variant=None, k=None,
                srs_generation=None, ledger_static=None, member_manifest=None,
            )
        self.assertEqual(len(stable_index(changed)["entries"]), 65)

    def test_indexer_rc3_outer_and_inner_names_are_exactly_bound(self) -> None:
        contracts = load_json(ROOT / "metadata/contracts/families-v1.json")
        indexer = next(row for row in contracts["softwareFamilies"] if row["family"] == "indexer-standalone")
        expected = [
            (
                f"indexer-standalone-{os_name}-{arch}-v4.4.0-rc.3.zip",
                f"indexer-standalone-{os_name}-{arch}-v4.4.0-rc.3",
            )
            for os_name, arch in [
                ("linux", "amd64"),
                ("linux", "arm64"),
                ("macos", "amd64"),
                ("macos", "arm64"),
            ]
        ]
        observed = [
            (
                indexer["nameTemplate"].format(os=os_name, arch=arch, version="4.4.0-rc.3"),
                indexer["members"][0].format(os=os_name, arch=arch, version="4.4.0-rc.3"),
            )
            for os_name, arch in [
                ("linux", "amd64"),
                ("linux", "arm64"),
                ("macos", "amd64"),
                ("macos", "arm64"),
            ]
        ]
        self.assertEqual(observed, expected)
        for outer, inner in observed:
            self.assertEqual(inner, outer.removesuffix(".zip"))

        wrong_inner = "indexer-standalone-{version}".format(version="4.4.0-rc.3")
        self.assertTrue(all(wrong_inner != inner for _, inner in expected))

    def test_unsupported_and_compact_fail(self) -> None:
        with self.assertRaises(WarehouseError):
            resolve_catalog(
                self.catalog, family="indexer-standalone", version="4.4.0-rc.1",
                os_name="windows", arch="amd64", variant=None, k=None,
                srs_generation=None, ledger_static=None, member_manifest=None,
            )
        changed = copy.deepcopy(self.catalog)
        changed["entries"][0]["family"] = "compactc"
        with self.assertRaisesRegex(WarehouseError, "Compact"):
            validate_catalog(changed)
        changed = copy.deepcopy(self.catalog)
        changed["entries"][0]["legacyLocations"] = []
        with self.assertRaisesRegex(WarehouseError, "legacyLocations"):
            validate_catalog(changed)

    def test_state_machine(self) -> None:
        for before, after in [
            ("planned", "uploading"), ("uploading", "verified"),
            ("verified", "published"), ("published", "revoked"),
        ]:
            validate_transition(before, after)
        for before, after in [("planned", "published"), ("published", "verified"), ("revoked", "published")]:
            with self.assertRaises(WarehouseError):
                validate_transition(before, after)

    def test_known_build_and_mirror_constraints_independent_of_forge(self) -> None:
        changed, entry = self.known_software_catalog("avail-node")
        validate_catalog(changed)
        for missing in ["lockedDependenciesSha256", "toolchain", "flags", "native"]:
            invalid = copy.deepcopy(changed)
            target = next(row for row in invalid["entries"] if row["semanticId"] == entry["semanticId"])
            target["source"].pop(missing)
            with self.assertRaises(WarehouseError, msg=missing):
                validate_catalog(invalid)

        mirror, entry = self.known_software_catalog("avail-node")
        entry["source"] = {
            "method": "identity-mirror", "repository": "owner/source", "commitSha": "a" * 40,
            "license": "Apache-2.0", "redistributionEvidence": "LICENSE@a",
            "upstreamAssetId": 123, "upstreamAssetNodeId": "RA_upstream",
            "upstreamAssetName": entry["asset"]["name"],
            "upstreamAssetUrl": "https://github.com/owner/source/releases/download/v1/" + entry["asset"]["name"],
            "upstreamAssetSize": entry["asset"]["size"],
            "upstreamAssetSha256": entry["asset"]["sha256"],
        }
        validate_catalog(mirror)
        for field, value in [
            ("upstreamAssetName", "different.tar.gz"),
            ("upstreamAssetSize", entry["asset"]["size"] + 1),
            ("upstreamAssetSha256", "f" * 64),
        ]:
            invalid = copy.deepcopy(mirror)
            target = next(row for row in invalid["entries"] if row["semanticId"] == entry["semanticId"])
            target["source"][field] = value
            with self.assertRaises(WarehouseError, msg=field):
                validate_catalog(invalid)

        renamed = copy.deepcopy(mirror)
        renamed_entry = next(row for row in renamed["entries"] if row["semanticId"] == entry["semanticId"])
        source = renamed_entry["source"]
        source["method"] = "rename-only"
        source["upstreamAssetName"] = "upstream-original.tar.gz"
        source["renameMapping"] = {"from": "upstream-original.tar.gz", "to": entry["asset"]["name"]}
        validate_catalog(renamed)
        renamed_entry["source"]["renameMapping"]["to"] = "wrong.tar.gz"
        with self.assertRaises(WarehouseError):
            validate_catalog(renamed)

    def test_known_software_coverage_layout_and_evidence_per_family(self) -> None:
        families = load_json(ROOT / "metadata/contracts/families-v1.json")["softwareFamilies"]
        for contract in families:
            catalog, entry = self.known_software_catalog(contract["family"])
            validate_catalog(catalog, self.schema)
            for mutate in [
                lambda row: row.update({"coverageTier": "optional" if row["coverageTier"] != "optional" else "required"}),
                lambda row: row["evidence"].update({"provenance": None}),
                lambda row: row["evidence"].update({"sbom": None}),
                lambda row: (
                    next(member for member in row["archive"]["members"] if member["path"] == row["install"]["path"]).update({"path": "nested/" + row["install"]["path"]}),
                    row["install"].update({"path": "nested/" + row["install"]["path"]}),
                ),
            ]:
                invalid = copy.deepcopy(catalog)
                target = next(row for row in invalid["entries"] if row["semanticId"] == entry["semanticId"])
                mutate(target)
                with self.assertRaises(WarehouseError, msg=f"{contract['family']} mutation"):
                    validate_catalog(invalid, self.schema)
            if entry["os"] == "macos":
                invalid = copy.deepcopy(catalog)
                target = next(row for row in invalid["entries"] if row["semanticId"] == entry["semanticId"])
                target["signing"] = {
                    "distributionSigningState": "legacy-unverified", "codeSignatureKind": "unknown",
                    "cdhash": None, "authorities": [], "teamId": None,
                    "hardenedRuntime": None, "strictVerification": "unknown",
                }
                with self.assertRaises(WarehouseError):
                    validate_catalog(invalid)

    def test_repackage_requires_exact_typed_two_run_transformation(self) -> None:
        catalog, entry = self.known_software_catalog("midnight-node-toolkit")
        member = entry["archive"]["members"][0]
        member["timestamp"] = "1980-01-01T00:00:00Z"
        upstream_name = "midnight-node-toolkit-linux-x86_64.tar.gz"
        upstream_url = "https://github.com/owner/source/releases/download/v1/" + upstream_name
        digest = entry["asset"]["sha256"]
        entry["source"] = {
            "method": "repackage", "repository": "owner/source", "commitSha": "a" * 40,
            "license": "Apache-2.0", "redistributionEvidence": "LICENSE@a",
            "upstreamAssetId": 123, "upstreamAssetNodeId": "RA_upstream",
            "upstreamAssetName": upstream_name, "upstreamAssetUrl": upstream_url,
            "upstreamAssetSize": 99, "upstreamAssetSha256": "d" * 64,
            "repackage": {
                "schemaVersion": "deterministic-repackage-v1", "algorithm": "copy-verified-members-v1",
                "archiveFormat": "zip", "compression": "deflate-level-9",
                "memberOrder": "utf8-bytewise-lexicographic", "timestampPolicy": "zip-dos-epoch-1980-01-01T00:00:00Z",
                "pathPolicy": "exact-mapping-only", "outputSize": entry["asset"]["size"],
                "members": [{
                    "inputAssetId": 123, "inputAssetNodeId": "RA_upstream", "inputAssetName": upstream_name,
                    "inputAssetUrl": upstream_url, "inputAssetSize": 99, "inputAssetSha256": "d" * 64,
                    "inputMemberPath": "midnight-node-toolkit", "inputMemberSize": member["size"],
                    "inputMemberSha256": member["sha256"], "outputPath": member["path"],
                    "outputSize": member["size"], "outputSha256": member["sha256"],
                    "storedMode": "0755", "installMode": "0755", "timestamp": member["timestamp"],
                }],
                "twoRun": {
                    "run1Sha256": digest, "run2Sha256": digest, "independentReadbackSha256": digest,
                    "run1Runner": "ubuntu-24.04-a", "run2Runner": "ubuntu-24.04-b",
                },
            },
        }
        entry["evidence"]["memberLineage"] = "member-lineage.json"
        validate_catalog(catalog, self.schema)
        for mutate in [
            lambda row: row["source"].pop("repackage"),
            lambda row: row["evidence"].update({"provenance": None}),
            lambda row: row["source"]["repackage"]["members"][0].update({"outputPath": "wrong"}),
            lambda row: row["source"]["repackage"]["members"][0].update({"inputMemberSha256": "e" * 64}),
            lambda row: row["source"]["repackage"]["members"][0].update({"timestamp": "1980-01-02T00:00:00Z"}),
            lambda row: row["source"]["repackage"]["twoRun"].update({"run2Sha256": "e" * 64}),
            lambda row: row["source"]["repackage"]["twoRun"].update({"run2Runner": "ubuntu-24.04-a"}),
            lambda row: row["source"].update({"upstreamAssetName": "other.zip"}),
        ]:
            invalid = copy.deepcopy(catalog)
            target = next(row for row in invalid["entries"] if row["semanticId"] == entry["semanticId"])
            mutate(target)
            with self.assertRaises(WarehouseError):
                validate_catalog(invalid, self.schema)

    def test_warning_and_macos_signing_states(self) -> None:
        changed = copy.deepcopy(self.catalog)
        entry = next(row for row in changed["entries"] if row["platform"] == "macos/arm64")
        entry["signing"] = {
            "distributionSigningState": "UNSIGNED_DEVELOPMENT_ONLY",
            "codeSignatureKind": "linker-adhoc", "cdhash": "A" * 40,
            "authorities": [], "teamId": None, "hardenedRuntime": False,
            "strictVerification": "pass",
        }
        validate_catalog(changed, self.schema)
        entry["signing"]["distributionSigningState"] = "production-ready"
        with self.assertRaisesRegex(WarehouseError, "schema validation"):
            validate_catalog(changed, self.schema)

        notarized = copy.deepcopy(self.catalog)
        signed = next(row for row in notarized["entries"] if row["platform"] == "macos/arm64")
        signed["signing"] = {
            "distributionSigningState": "DEVELOPER_ID_SIGNED_NOTARIZED_ONLINE_TICKET",
            "codeSignatureKind": "developer-id", "cdhash": "A" * 40,
            "authorities": ["Developer ID Application: Example (TEAMID1234)"],
            "teamId": "TEAMID1234", "hardenedRuntime": True, "strictVerification": "pass",
            "notarization": {
                "submissionId": "12345678-1234-1234-1234-123456789abc", "status": "Accepted",
                "submittedAt": "2026-08-28T00:00:00Z", "completedAt": "2026-08-28T00:01:00Z",
                "logSha256": "b" * 64, "logReference": "owner-record-1", "stapling": "not-applicable",
                "onlineTicket": {"result": "pass", "checkedAt": "2026-08-28T00:02:00Z"},
                "gatekeeper": {"result": "pass", "checkedAt": "2026-08-28T00:02:00Z"},
                "quarantinedDownloadSmoke": {"result": "pass", "checkedAt": "2026-08-28T00:03:00Z"},
            },
        }
        validate_catalog(notarized, self.schema)
        for mutate in [
            lambda value: value["signing"].pop("notarization"),
            lambda value: value["signing"].update({"codeSignatureKind": "none"}),
            lambda value: value["signing"]["notarization"]["onlineTicket"].update({"result": "fail"}),
            lambda value: value["signing"]["notarization"].pop("submissionId"),
            lambda value: value["signing"]["notarization"].update({"submissionId": "-" * 36}),
            lambda value: value["signing"]["notarization"].update({"completedAt": "2026-08-27T23:59:00Z"}),
            lambda value: value["signing"]["notarization"]["onlineTicket"].update({"checkedAt": "2026-08-28T00:00:30Z"}),
            lambda value: value["signing"]["notarization"]["gatekeeper"].update({"checkedAt": "2026-08-28T00:00:30Z"}),
            lambda value: value["signing"]["notarization"]["quarantinedDownloadSmoke"].update({"checkedAt": "2026-08-28T00:00:30Z"}),
        ]:
            invalid = copy.deepcopy(signed)
            mutate(invalid)
            catalog = copy.deepcopy(self.catalog)
            catalog["entries"][catalog["entries"].index(next(row for row in catalog["entries"] if row["semanticId"] == invalid["semanticId"]))] = invalid
            with self.assertRaises(WarehouseError):
                validate_catalog(catalog, self.schema)

        reverse = copy.deepcopy(changed)
        reverse_entry = next(row for row in reverse["entries"] if row["platform"] == "macos/arm64")
        reverse_entry["signing"] = copy.deepcopy(signed["signing"])
        reverse_entry["signing"]["distributionSigningState"] = "UNSIGNED_DEVELOPMENT_ONLY"
        reverse_entry["signing"].pop("notarization")
        with self.assertRaises(WarehouseError):
            validate_catalog(reverse, self.schema)

    def test_catalog_cross_field_invariants(self) -> None:
        cases = []
        base_entry = next(row for row in self.catalog["entries"] if row["platform"] == "macos/arm64")
        for mutate in [
            lambda row: row.update({"platform": "linux/amd64"}),
            lambda row: row.update({"semanticId": "arbitrary/id"}),
            lambda row: row["asset"].update({"apiUrl": "https://api.github.com/repos/effectstream/binaries/releases/assets/1"}),
            lambda row: row["asset"].update({"downloadUrl": "https://github.com/effectstream/binaries/releases/download/0.3.120/wrong.zip"}),
            lambda row: row["archive"].update({"memberCount": row["archive"]["memberCount"] + 1}),
            lambda row: row["archive"].update({"expandedSize": row["archive"]["expandedSize"] + 1}),
            lambda row: row["archive"]["members"][0].update({"path": "../escape"}),
            lambda row: row["install"].update({"path": "missing", "mode": "0644"}),
            lambda row: row.pop("signing"),
        ]:
            changed = copy.deepcopy(self.catalog)
            row = next(item for item in changed["entries"] if item["semanticId"] == base_entry["semanticId"])
            mutate(row)
            cases.append(changed)
        for changed in cases:
            with self.assertRaises(WarehouseError):
                validate_catalog(changed, self.schema)

    def test_resolver_rejects_mixed_or_orphan_selectors(self) -> None:
        common = dict(self.catalog)
        calls = [
            dict(family="indexer-standalone", version="4.4.0-rc.1", os_name="linux", arch="amd64", variant=None, k=None, srs_generation=None, ledger_static=None, member_manifest="a" * 64),
            dict(family=None, version=None, os_name=None, arch=None, variant=None, k=1, srs_generation=None, ledger_static="9.0.0", member_manifest=None),
            dict(family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation="sha256:" + "a" * 64, ledger_static=None, member_manifest=None),
            dict(family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation=None, ledger_static=None, member_manifest="a" * 64),
            dict(family="indexer-standalone", version=None, os_name="linux", arch="amd64", variant=None, k=None, srs_generation=None, ledger_static=None, member_manifest=None),
            dict(family=None, version=None, os_name=None, arch=None, variant=None, k=5, srs_generation="", ledger_static=None, member_manifest=None),
            dict(family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation=None, ledger_static="", member_manifest="a" * 64),
            dict(family="indexer-standalone", version="", os_name="linux", arch="amd64", variant=None, k=None, srs_generation=None, ledger_static=None, member_manifest=None),
            dict(family="indexer-standalone", version="4.4.0-rc.1", os_name="linux", arch="amd64", variant="", k=None, srs_generation=None, ledger_static=None, member_manifest=None),
        ]
        for arguments in calls:
            with self.assertRaises(WarehouseError):
                resolve_catalog(self.catalog, **arguments)

    def test_committed_index_and_state_transitions_are_bound(self) -> None:
        index = stable_index(self.catalog)
        validate_repository_state(self.catalog, index, copy.deepcopy(self.catalog))
        current = load_release_baseline(ROOT / "metadata/baselines/0.3.120-current.json")
        validate_snapshot_catalog_binding(self.catalog, current)
        extra = copy.deepcopy(current["assets"][0])
        extra.update({
            "id": 999999999, "nodeId": "RA_untracked_current_baseline",
            "name": "untracked-linux-amd64-v1.0.0.zip", "size": 1,
            "sha256": "f" * 64, "apiDigest": "sha256:" + "f" * 64,
            "apiUrl": "https://api.github.com/repos/effectstream/binaries/releases/assets/999999999",
            "downloadUrl": "https://github.com/effectstream/binaries/releases/download/0.3.120/untracked-linux-amd64-v1.0.0.zip",
        })
        extra.pop("inspection", None)
        current["assets"].append(extra)
        current["assets"].sort(key=lambda row: row["name"])
        current["pagination"]["totalCount"] += 1
        current["pagination"]["pages"][0]["count"] += 1
        with self.assertRaisesRegex(WarehouseError, "cataloged destination assets"):
            validate_snapshot_catalog_binding(self.catalog, current)

        validate_baseline_change_rows([
            "A\tmetadata/baselines/0.3.120-after-upload.json",
            "M\tmetadata/baselines/0.3.120-current.json",
        ])
        for forbidden in [
            "M\tmetadata/baselines/0.3.120-initial.json",
            "D\tmetadata/baselines/0.3.120-initial.json",
            "R100\tmetadata/baselines/0.3.120-initial.json\tmetadata/baselines/moved.json",
        ]:
            with self.assertRaisesRegex(WarehouseError, "immutable|rename"):
                validate_baseline_change_rows([forbidden])
        bad_index = copy.deepcopy(index)
        bad_index["entries"].pop()
        with self.assertRaises(WarehouseError):
            validate_repository_state(self.catalog, bad_index, copy.deepcopy(self.catalog))

        previous = copy.deepcopy(self.catalog)
        previous["entries"][0]["publicationState"] = "planned"
        with self.assertRaises(WarehouseError):
            validate_repository_state(self.catalog, index, previous)

        revoked = copy.deepcopy(self.catalog)
        revoked["entries"][0]["publicationState"] = "revoked"
        validate_repository_state(revoked, stable_index(revoked), self.catalog)

    def test_planned_rows_and_global_destination_identities_are_exact(self) -> None:
        _, entry = self.known_software_catalog("indexer-standalone")
        previous = copy.deepcopy(self.catalog)
        planned = copy.deepcopy(previous)
        entry = copy.deepcopy(entry)
        entry["version"] = "9.9.9"
        entry["semanticId"] = "indexer-standalone/9.9.9/linux/amd64"
        name = "indexer-standalone-linux-amd64-v9.9.9.zip"
        inner = name.removesuffix(".zip")
        entry["asset"] = {"name": name, "state": "candidate", "size": 7, "sha256": "a" * 64}
        entry["publicationState"] = "planned"
        entry["archive"] = {"format": "zip", "memberCount": 1, "expandedSize": 1, "members": [{
            "path": inner, "type": "file", "size": 1, "sha256": "b" * 64,
            "storedMode": "0755", "installMode": "0755",
        }], "legacyAnomalies": []}
        entry["install"] = {"path": inner, "mode": "0755"}
        planned["entries"].append(entry)
        planned["entries"].sort(key=lambda row: row["semanticId"])
        validate_catalog(planned, self.schema)
        validate_repository_state(planned, stable_index(planned), previous)
        self.assertEqual(len(stable_index(planned)["entries"]), 66)

        for mutate in [
            lambda row: row["asset"].update({"id": 999}),
            lambda row: row["asset"].update({"state": "uploaded"}),
            lambda row: row["asset"].pop("sha256"),
        ]:
            invalid = copy.deepcopy(planned)
            mutate(next(row for row in invalid["entries"] if row["semanticId"] == entry["semanticId"]))
            with self.assertRaises(WarehouseError):
                validate_catalog(invalid, self.schema)

        for identity_field in ["id", "nodeId"]:
            invalid = copy.deepcopy(self.catalog)
            invalid["entries"][1]["asset"][identity_field] = invalid["entries"][0]["asset"][identity_field]
            with self.assertRaises(WarehouseError):
                validate_catalog(invalid, self.schema)


if __name__ == "__main__":
    unittest.main()
