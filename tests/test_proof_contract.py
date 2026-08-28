from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from warehouse_lib import WarehouseError, load_json, resolve_catalog, validate_catalog  # noqa: E402


def proof_entry(*, k: int | None = None, semver: str | None = None, manifest: str = "a" * 64, name: str | None = None, generation: str | None = None) -> dict:
    if k is not None:
        generation = generation or (
            "midnight-ledger-provider-compat@7a89f45d29792be7e09ca5eb246f1e69f0b2a179/sha256:59b30b3114a34ccbbfb599376e178fb8d9b3366cae2174c2f1da20e75847f823"
            if k == 0 else "midnight-trusted-setup@3ea610263b228af24840f7b00661ee22360db6d8"
        )
        asset_name = name or f"bls_midnight_2p{k}"
        proof = {
            "kind": "srs", "k": k, "srsGeneration": generation,
            "officialAlias": None if k == 0 else f"midnight-srs-2p{k}",
            "cacheAlias": f"bls_midnight_2p{k}", "installedPath": f"bls_midnight_2p{k}",
            "installedMode": "0644", "exactConsumers": exact_consumers(),
        }
        semantic = f"srs/{k}/{generation.replace('@', '-').replace(':', '-')}"
    else:
        assert semver
        asset_name = name or f"midnight-ledger-static-noarch-{semver}.zip"
        proof = {
            "kind": "ledger-static", "ledgerStaticSemver": semver, "cacheNamespace": "9",
            "memberManifestSha256": manifest, "ledgerStaticRevision": f"manifest-sha256:{manifest}",
            "installedPath": ".", "installedMode": "0644", "exactConsumers": exact_consumers(),
        }
        semantic = f"ledger-static/{semver}/{manifest}"
    return {
        "semanticId": semantic, "artifactKind": "proof-data", "family": "midnight-srs" if k is not None else "midnight-ledger-static",
        "variant": None, "platform": "noarch", "publicationState": "published",
        "distributionTier": "development-only", "releaseMutability": "mutable-warehouse",
        "asset": {"id": 999, "nodeId": "RA_fixture", "name": asset_name, "state": "uploaded", "size": 1,
                  "apiDigest": "sha256:" + "c" * 64, "sha256": "c" * 64,
                  "apiUrl": "https://api.github.com/repos/effectstream/binaries/releases/assets/999",
                  "downloadUrl": f"https://github.com/effectstream/binaries/releases/download/0.3.120/{asset_name}",
                  "contentType": "application/octet-stream", "createdAt": "2026-08-28T00:00:00Z", "updatedAt": "2026-08-28T00:00:00Z"},
        "archive": {"format": "raw" if k is not None else "zip", "memberCount": 1, "expandedSize": 1,
                    "members": [{"path": asset_name, "type": "file", "size": 1, "storedMode": "0644", "installMode": "0644"}], "legacyAnomalies": []},
        "source": {"method": "assemble-data", "repository": "midnightntwrk/midnight-ledger", "commitSha": "7a89f45d29792be7e09ca5eb246f1e69f0b2a179", "license": "Apache-2.0", "redistributionEvidence": "LICENSE@commit"},
        "evidence": {"sourceManifest": "forge", "checksums": "forge", "provenance": "forge", "sbom": None, "memberLineage": "forge"},
        "proofData": proof, "legacyProvenance": "known",
    }


def exact_consumers() -> list[dict]:
    return [
        {"proofServerVersion": "9.0.0-rc.5", "sourceCommit": "7a89f45d29792be7e09ca5eb246f1e69f0b2a179", "imageDigest": digest,
         "ledgerStaticSemver": "9.0.0", "cacheNamespace": "9"}
        for digest in ["sha256:d96a4d0f3f0f10f82698288443f2873a32fed180eb8f93c0bae83572c0a187a9", "sha256:4f02ca2734649eb238d13924df299b1c82bd5546ec928c5d67bdd0ce86dd0bd1"]
    ]


class ProofContractTests(unittest.TestCase):
    def test_exact_q8b_inventory(self) -> None:
        contract = load_json(ROOT / "metadata/contracts/proof-data-q8b-v1.json")
        objects = contract["srs"]["objects"]
        self.assertEqual([row["k"] for row in objects], list(range(20)))
        self.assertEqual([row["assetName"] for row in objects], [f"bls_midnight_2p{k}" for k in range(20)])
        self.assertEqual(sum(row["bytes"] for row in objects), 201334160)
        self.assertEqual(len(contract["ledgerStatic"]["members"]), 12)
        self.assertEqual(sum(row["bytes"] for row in contract["ledgerStatic"]["members"]), 21753130)
        self.assertEqual(contract["payloadCount"], 21)
        self.assertIsNone(objects[0]["officialAlias"])
        self.assertTrue(all(row["officialAlias"] == f"midnight-srs-2p{row['k']}" for row in objects[1:]))
        self.assertFalse(contract["exactCompatibility"]["static10Negative"]["static9Accepted"])

    def test_generation_and_static_revision_resolution(self) -> None:
        base = load_json(ROOT / "metadata/releases/0.3.120.json")
        generation_1 = proof_entry(k=5)
        generation_2 = proof_entry(k=5, name="midnight-srs-noarch-2p5-sha256-" + "d" * 64 + ".bin", generation="sha256:" + "d" * 64)
        generation_2["asset"]["id"] = 1000
        generation_2["asset"]["nodeId"] = "RA_fixture_2"
        generation_2["asset"]["apiUrl"] = "https://api.github.com/repos/effectstream/binaries/releases/assets/1000"
        generation_2["asset"]["sha256"] = "d" * 64
        generation_2["asset"]["apiDigest"] = "sha256:" + "d" * 64
        base["entries"].extend([generation_1, generation_2])
        validate_catalog(base, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")
        with self.assertRaisesRegex(WarehouseError, "generation"):
            resolve_catalog(base, family=None, version=None, os_name=None, arch=None, variant=None, k=5, srs_generation=None, ledger_static=None, member_manifest=None)
        result = resolve_catalog(base, family=None, version=None, os_name=None, arch=None, variant=None, k=5, srs_generation="sha256:" + "d" * 64, ledger_static=None, member_manifest=None)
        self.assertEqual(result["assetName"], generation_2["asset"]["name"])

        first = proof_entry(semver="9.0.0", manifest="a" * 64)
        second = proof_entry(semver="9.0.0", manifest="b" * 64, name="midnight-ledger-static-noarch-9.0.0-manifest-sha256-" + "b" * 64 + ".zip")
        second["asset"]["id"] = 1001
        second["asset"]["nodeId"] = "RA_fixture_3"
        second["asset"]["apiUrl"] = "https://api.github.com/repos/effectstream/binaries/releases/assets/1001"
        second["asset"]["sha256"] = "e" * 64
        second["asset"]["apiDigest"] = "sha256:" + "e" * 64
        another = load_json(ROOT / "metadata/releases/0.3.120.json")
        another["entries"].extend([first, second])
        validate_catalog(another, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")
        with self.assertRaisesRegex(WarehouseError, "Ledger-static"):
            resolve_catalog(another, family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation=None, ledger_static="9.0.0", member_manifest=None)
        result = resolve_catalog(another, family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation=None, ledger_static="9.0.0", member_manifest="b" * 64)
        self.assertEqual(result["assetName"], second["asset"]["name"])

    def test_static10_cannot_claim_static9(self) -> None:
        base = load_json(ROOT / "metadata/releases/0.3.120.json")
        invalid = proof_entry(semver="9.0.0")
        invalid["proofData"]["exactConsumers"][0]["ledgerStaticSemver"] = "10.0.0"
        base["entries"].append(invalid)
        with self.assertRaises(WarehouseError):
            validate_catalog(base)


if __name__ == "__main__":
    unittest.main()
