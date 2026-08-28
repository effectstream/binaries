from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CleanRoomReadmeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.readme = (ROOT / "README.md").read_text(encoding="utf-8")

    def test_warning_is_first_and_all_eleven_contracts_are_documented(self) -> None:
        self.assertTrue(self.readme.startswith("> **DEVELOPMENT ONLY — NOT FOR PRODUCTION USE.**"))
        required = [
            "Permanent append-only rules", "Binary names, selectors, layouts, and coverage",
            "Choose the artifact operation", "Required metadata and evidence",
            "Prepare and validate a proposal", "Manual prerequisite and transaction sequence",
            "Executable examples and clean-room fixture", "Conflict, interruption, revocation, and drift",
            "macOS distribution signing", "Compact 0.34 direct-upstream policy", "Public proof-data guide",
            "explicit live-upload authority", "effective write permission", "numeric ID", "node ID",
            "inert", "mode-`0600` journal", "TOCTOU", "stable `published` catalog/index last",
            "atomic", "MIDNIGHT_PP", "K24/K25", "static-10",
        ]
        for text in required:
            self.assertIn(text, self.readme)

    def test_readme_linked_files_exist_and_example_executes(self) -> None:
        links = re.findall(r"\[[^]]+\]\(([^)]+)\)", self.readme)
        local = [link for link in links if not link.startswith(("https://", "http://", "#"))]
        for link in local:
            self.assertTrue((ROOT / link).exists(), link)
        result = subprocess.run(
            [str(ROOT / "scripts/resolve"), "--family", "indexer-standalone", "--version", "4.4.0-rc.1", "--os", "darwin", "--arch", "aarch64"],
            cwd=ROOT, text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["assetName"], "indexer-standalone-macos-arm64-v4.4.0-rc.1.zip")
        self.assertRegex(payload["sha256"], r"^[0-9a-f]{64}$")

    def test_future_addition_controls_are_unambiguous(self) -> None:
        contracts = json.loads((ROOT / "metadata/contracts/families-v1.json").read_text())
        proof = json.loads((ROOT / "metadata/contracts/proof-data-q8b-v1.json").read_text())
        self.assertEqual(contracts["proofData"]["srs"]["multipleGenerationSelection"], "explicit-full-generation-required")
        self.assertEqual(contracts["proofData"]["ledgerStatic"]["multipleRevisionSelection"], "full-memberManifestSha256-required")
        self.assertEqual(proof["futureScope"]["k20Plus"], "owner-reviewed-manifest-required")
        self.assertEqual(proof["futureScope"]["customOrProjectKeys"], "forbidden")
        self.assertTrue(proof["githubReleaseIsNotMidnightParamSource"])
        pin = json.loads((ROOT / "protocol/forge-promotion-envelope-v1.json").read_text())
        self.assertEqual(pin["commitSha"], "2052e6e3d47495b8404876092d34e7bcbd560690")
        self.assertEqual(pin["canonicalization"], "forge-canonical-json-v1")
        self.assertEqual(len(pin["files"]), 7)
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) for row in pin["files"]))

    def test_macos_handoff_has_no_secret_or_example_credential(self) -> None:
        text = (ROOT / "MACOS.md").read_text(encoding="utf-8")
        for pattern in [r"ghp_[A-Za-z0-9]", r"github_pat_", r"BEGIN PRIVATE KEY", r"AC_PASSWORD=", r"APPLE_ID=.*@"]:
            self.assertIsNone(re.search(pattern, text), pattern)
        for required in ["--options runtime", "--timestamp", "without `--deep`", "notarytool", "--wait", "stapling=not-applicable", "online ticket", "quarantine", "distinct family-conforming"]:
            self.assertIn(required, text)


if __name__ == "__main__":
    unittest.main()
