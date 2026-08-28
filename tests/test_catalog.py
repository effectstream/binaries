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


if __name__ == "__main__":
    unittest.main()
