from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from warehouse_lib import WarehouseError, ledger_member_manifest, load_json, resolve_catalog, validate_catalog  # noqa: E402


CONTRACT = load_json(ROOT / "metadata/contracts/proof-data-q8b-v1.json")


def proof_entry(*, k: int | None = None, semver: str | None = None, name: str | None = None, generation: str | None = None, correction_seed: str | None = None) -> dict:
    if k is not None:
        pinned = CONTRACT["srs"]["objects"][k]
        generation = generation or pinned["srsGeneration"]
        asset_name = name or f"bls_midnight_2p{k}"
        literal = asset_name == pinned["assetName"]
        digest = pinned["sha256"] if literal else generation.removeprefix("sha256:")
        size = pinned["bytes"] if literal else 7
        proof = {
            "kind": "srs", "k": k, "srsGeneration": generation,
            "officialAlias": pinned["officialAlias"],
            "cacheAlias": f"bls_midnight_2p{k}", "installedPath": f"bls_midnight_2p{k}",
            "installedMode": "0644", "exactConsumers": exact_consumers(),
        }
        semantic = f"srs/{k}/{generation.replace('@', '-').replace(':', '-')}"
        members = [{"path": proof["installedPath"], "type": "file", "size": size, "sha256": digest, "storedMode": "0644", "installMode": "0644"}]
        source_repo = CONTRACT["srs"]["providerRepository"] if k == 0 else CONTRACT["srs"]["trustedSetupRepository"]
        source_commit = CONTRACT["srs"]["providerCommit"] if k == 0 else CONTRACT["srs"]["trustedSetupCommit"]
    else:
        assert semver
        members = [
            {"path": row["path"], "type": "file", "size": row["bytes"], "sha256": row["sha256"], "storedMode": "0644", "installMode": "0644"}
            for row in CONTRACT["ledgerStatic"]["members"]
        ]
        if correction_seed:
            members[0]["sha256"] = correction_seed * 64
        manifest = ledger_member_manifest(members)
        asset_name = name or (
            f"midnight-ledger-static-noarch-{semver}-manifest-sha256-{manifest}.zip"
            if correction_seed else f"midnight-ledger-static-noarch-{semver}.zip"
        )
        proof = {
            "kind": "ledger-static", "ledgerStaticSemver": semver, "cacheNamespace": "9",
            "memberManifestSha256": manifest, "ledgerStaticRevision": f"manifest-sha256:{manifest}",
            "installedPath": ".", "installedMode": "0644", "exactConsumers": exact_consumers(),
        }
        if correction_seed:
            proof["correctionCompatibility"] = {
                "schemaVersion": "ledger-static-correction-compatibility-v1",
                "memberManifestSha256": manifest,
                "sourceCommit": CONTRACT["srs"]["providerCommit"],
                "imageDigests": sorted(row["imageDigest"] for row in exact_consumers()),
                "result": "pass", "evidenceRef": f"compatibility-{manifest}.json",
                "evidenceSha256": "f" * 64,
            }
        semantic = f"ledger-static/{semver}/{manifest}"
        digest = (correction_seed or "c") * 64
        size = 1
        source_repo = "midnightntwrk/midnight-ledger"
        source_commit = CONTRACT["srs"]["providerCommit"]
    return {
        "semanticId": semantic, "artifactKind": "proof-data", "family": "midnight-srs" if k is not None else "midnight-ledger-static",
        "variant": None, "platform": "noarch", "publicationState": "published",
        "distributionTier": "development-only", "releaseMutability": "mutable-warehouse",
        "asset": {"id": 999, "nodeId": "RA_fixture", "name": asset_name, "state": "uploaded", "size": size,
                  "apiDigest": "sha256:" + digest, "sha256": digest,
                  "apiUrl": "https://api.github.com/repos/effectstream/binaries/releases/assets/999",
                  "downloadUrl": f"https://github.com/effectstream/binaries/releases/download/0.3.120/{asset_name}",
                  "contentType": "application/octet-stream", "createdAt": "2026-08-28T00:00:00Z", "updatedAt": "2026-08-28T00:00:00Z"},
        "archive": {"format": "raw" if k is not None else "zip", "memberCount": len(members), "expandedSize": sum(row["size"] for row in members),
                    "members": members, "legacyAnomalies": []},
        "source": {"method": "assemble-data", "repository": source_repo, "commitSha": source_commit, "license": "Apache-2.0", "redistributionEvidence": "LICENSE@commit"},
        "evidence": {"sourceManifest": "forge", "checksums": "forge", "provenance": "forge", "sbom": None, "memberLineage": "forge"},
        "proofData": proof, "legacyProvenance": "known",
    }


def exact_consumers() -> list[dict]:
    return [
        {"proofServerVersion": "9.0.0-rc.5", "sourceCommit": "7a89f45d29792be7e09ca5eb246f1e69f0b2a179", "imageDigest": digest,
         "ledgerStaticSemver": "9.0.0", "cacheNamespace": "9"}
        for digest in ["sha256:d96a4d0f3f0f10f82698288443f2873a32fed180eb8f93c0bae83572c0a187a9", "sha256:4f02ca2734649eb238d13924df299b1c82bd5546ec928c5d67bdd0ce86dd0bd1"]
    ]


def retarget_correction(entry: dict, *, name: str, generation: str, repository: str, commit: str) -> dict:
    entry = copy.deepcopy(entry)
    entry["asset"]["name"] = name
    entry["asset"]["downloadUrl"] = f"https://github.com/effectstream/binaries/releases/download/0.3.120/{name}"
    entry["proofData"]["srsGeneration"] = generation
    entry["semanticId"] = f"srs/{entry['proofData']['k']}/{generation.replace('@', '-').replace(':', '-')}"
    entry["source"]["repository"] = repository
    entry["source"]["commitSha"] = commit
    return entry


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

        blocked_normal = proof_entry(semver="9.0.0")
        blocked_catalog = load_json(ROOT / "metadata/releases/0.3.120.json")
        blocked_catalog["entries"].append(blocked_normal)
        with self.assertRaisesRegex(WarehouseError, "blocked until Phase-3p"):
            validate_catalog(blocked_catalog, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")

        first = proof_entry(semver="9.0.0", correction_seed="a")
        second = proof_entry(semver="9.0.0", correction_seed="b")
        second["asset"]["id"] = 1001
        second["asset"]["nodeId"] = "RA_fixture_3"
        second["asset"]["apiUrl"] = "https://api.github.com/repos/effectstream/binaries/releases/assets/1001"
        another = load_json(ROOT / "metadata/releases/0.3.120.json")
        another["entries"].extend([first, second])
        validate_catalog(another, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")
        with self.assertRaisesRegex(WarehouseError, "Ledger-static"):
            resolve_catalog(another, family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation=None, ledger_static="9.0.0", member_manifest=None)
        result = resolve_catalog(another, family=None, version=None, os_name=None, arch=None, variant=None, k=None, srs_generation=None, ledger_static="9.0.0", member_manifest=second["proofData"]["memberManifestSha256"])
        self.assertEqual(result["assetName"], second["asset"]["name"])

    def test_static10_cannot_claim_static9(self) -> None:
        base = load_json(ROOT / "metadata/releases/0.3.120.json")
        invalid = proof_entry(semver="9.0.0", correction_seed="d")
        invalid["proofData"]["exactConsumers"][0]["ledgerStaticSemver"] = "10.0.0"
        base["entries"].append(invalid)
        with self.assertRaises(WarehouseError):
            validate_catalog(base)

        correction = proof_entry(semver="9.0.0", correction_seed="d")
        for mutate in [
            lambda row: row["proofData"].pop("correctionCompatibility"),
            lambda row: row["proofData"]["correctionCompatibility"].update({"memberManifestSha256": "e" * 64}),
            lambda row: row["proofData"]["correctionCompatibility"].update({"sourceCommit": "e" * 40}),
            lambda row: row["proofData"]["correctionCompatibility"].update({"imageDigests": ["sha256:" + "e" * 64]}),
            lambda row: row["proofData"]["correctionCompatibility"].update({"result": "fail"}),
            lambda row: row["proofData"]["correctionCompatibility"].update({"evidenceSha256": "bad"}),
            lambda row: [consumer.update({"sourceCommit": "cd652d7" + "0" * 33, "ledgerStaticSemver": "10.0.0", "cacheNamespace": "10"}) for consumer in row["proofData"]["exactConsumers"]],
        ]:
            changed = copy.deepcopy(correction)
            mutate(changed)
            catalog = load_json(ROOT / "metadata/releases/0.3.120.json")
            catalog["entries"].append(changed)
            with self.assertRaises(WarehouseError):
                validate_catalog(catalog, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")

    def test_srs_correction_tokens_bind_generation_bytes_source_and_alias(self) -> None:
        trusted_repo = CONTRACT["srs"]["trustedSetupRepository"]
        provider_repo = CONTRACT["srs"]["providerRepository"]
        trusted_commit = "a" * 40
        provider_commit = "b" * 40
        digest = "d" * 64
        sha = proof_entry(
            k=5,
            name=f"midnight-srs-noarch-2p5-sha256-{digest}.bin",
            generation=f"sha256:{digest}",
        )
        ts = retarget_correction(
            sha,
            name=f"midnight-srs-noarch-2p5-ts-{trusted_commit}.bin",
            generation=f"midnight-trusted-setup@{trusted_commit}",
            repository=trusted_repo,
            commit=trusted_commit,
        )
        provider = retarget_correction(
            sha,
            name=f"midnight-srs-noarch-2p5-provider-{provider_commit}-sha256-{digest}.bin",
            generation=f"midnight-ledger-provider-compat@{provider_commit}/sha256:{digest}",
            repository=provider_repo,
            commit=provider_commit,
        )
        for entry in [sha, ts, provider]:
            base = load_json(ROOT / "metadata/releases/0.3.120.json")
            base["entries"].append(entry)
            validate_catalog(base, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")

        mutations = [
            (sha, lambda row: row["proofData"].update({"srsGeneration": "sha256:" + "e" * 64})),
            (sha, lambda row: row["proofData"].update({"officialAlias": "midnight-srs-2p6"})),
            (sha, lambda row: row["source"].update({"commitSha": "e" * 40})),
            (ts, lambda row: row["proofData"].update({"srsGeneration": "midnight-trusted-setup@" + "e" * 40})),
            (ts, lambda row: row["source"].update({"repository": provider_repo})),
            (ts, lambda row: row["source"].update({"commitSha": "e" * 40})),
            (provider, lambda row: row["proofData"].update({"srsGeneration": f"midnight-ledger-provider-compat@{provider_commit}/sha256:" + "e" * 64})),
            (provider, lambda row: row["source"].update({"repository": trusted_repo})),
            (provider, lambda row: row["source"].update({"commitSha": "e" * 40})),
            (provider, lambda row: row["asset"].update({"sha256": "e" * 64, "apiDigest": "sha256:" + "e" * 64})),
        ]
        for entry, mutate in mutations:
            base = load_json(ROOT / "metadata/releases/0.3.120.json")
            invalid = copy.deepcopy(entry)
            mutate(invalid)
            base["entries"].append(invalid)
            with self.assertRaises(WarehouseError):
                validate_catalog(base, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")

    def test_literal_q8b_rows_reject_identity_and_tree_mutations(self) -> None:
        for entry in [proof_entry(k=1), proof_entry(semver="9.0.0", correction_seed="e")]:
            base = load_json(ROOT / "metadata/releases/0.3.120.json")
            base["entries"].append(entry)
            validate_catalog(base, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")
            identity_mutation = (
                (lambda row: row["asset"].update({"size": row["asset"]["size"] + 1}))
                if entry["proofData"]["kind"] == "srs"
                else (lambda row: row["archive"].update({"expandedSize": row["archive"]["expandedSize"] + 1}))
            )
            for mutate in [
                identity_mutation,
                lambda row: row["archive"]["members"][0].update({"sha256": "f" * 64}),
                lambda row: row["proofData"]["exactConsumers"][0].update({"sourceCommit": "f" * 40}),
            ]:
                invalid = copy.deepcopy(base)
                mutate(invalid["entries"][-1])
                with self.assertRaises(WarehouseError):
                    validate_catalog(invalid, ROOT / "metadata/schema/artifact-catalog-v1.schema.json")


if __name__ == "__main__":
    unittest.main()
