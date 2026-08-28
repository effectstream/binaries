from __future__ import annotations

import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from warehouse_lib import (  # noqa: E402
    WarehouseError,
    load_json,
    resolve_catalog,
    stable_index,
    validate_catalog,
    validate_repository_state,
    validate_transition,
)


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_json(ROOT / "metadata/releases/0.3.120.json")
        cls.schema = ROOT / "metadata/schema/artifact-catalog-v1.schema.json"

    def test_exact_legacy_backfill(self) -> None:
        validate_catalog(self.catalog, self.schema)
        self.assertEqual(len(self.catalog["entries"]), 66)
        self.assertEqual(len({row["semanticId"] for row in self.catalog["entries"]}), 66)
        self.assertEqual(len({row["asset"]["name"] for row in self.catalog["entries"]}), 66)
        for row in self.catalog["entries"]:
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
        changed = copy.deepcopy(self.catalog)
        entry = changed["entries"][0]
        entry["legacyProvenance"] = "known"
        entry["source"] = {
            "method": "build", "repository": "owner/source", "commitSha": "a" * 40,
            "license": "Apache-2.0", "redistributionEvidence": "LICENSE@a",
            "lockedDependenciesSha256": "b" * 64, "toolchain": "rustc 1.95.0",
            "flags": [], "native": True,
        }
        validate_catalog(changed)
        for missing in ["lockedDependenciesSha256", "toolchain", "flags", "native"]:
            invalid = copy.deepcopy(changed)
            invalid["entries"][0]["source"].pop(missing)
            with self.assertRaises(WarehouseError, msg=missing):
                validate_catalog(invalid)

        mirror = copy.deepcopy(self.catalog)
        entry = mirror["entries"][0]
        entry["legacyProvenance"] = "known"
        entry["source"] = {
            "method": "identity-mirror", "repository": "owner/source", "commitSha": "a" * 40,
            "license": "Apache-2.0", "redistributionEvidence": "LICENSE@a",
            "upstreamAssetId": 123, "upstreamAssetNodeId": "RA_upstream",
            "upstreamAssetName": entry["asset"]["name"], "upstreamAssetSize": entry["asset"]["size"],
            "upstreamAssetSha256": entry["asset"]["sha256"],
        }
        validate_catalog(mirror)
        for field, value in [
            ("upstreamAssetName", "different.tar.gz"),
            ("upstreamAssetSize", entry["asset"]["size"] + 1),
            ("upstreamAssetSha256", "f" * 64),
        ]:
            invalid = copy.deepcopy(mirror)
            invalid["entries"][0]["source"][field] = value
            with self.assertRaises(WarehouseError, msg=field):
                validate_catalog(invalid)

        renamed = copy.deepcopy(mirror)
        source = renamed["entries"][0]["source"]
        source["method"] = "rename-only"
        source["upstreamAssetName"] = "upstream-original.tar.gz"
        source["renameMapping"] = {"from": "upstream-original.tar.gz", "to": entry["asset"]["name"]}
        validate_catalog(renamed)
        renamed["entries"][0]["source"]["renameMapping"]["to"] = "wrong.tar.gz"
        with self.assertRaises(WarehouseError):
            validate_catalog(renamed)

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
        ]
        for arguments in calls:
            with self.assertRaises(WarehouseError):
                resolve_catalog(self.catalog, **arguments)

    def test_committed_index_and_state_transitions_are_bound(self) -> None:
        index = stable_index(self.catalog)
        validate_repository_state(self.catalog, index, copy.deepcopy(self.catalog))
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


if __name__ == "__main__":
    unittest.main()
