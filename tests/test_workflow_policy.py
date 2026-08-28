from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkflowPolicyTests(unittest.TestCase):
    def test_destination_workflows_are_read_only_and_never_release_write(self) -> None:
        workflows = list((ROOT / ".github/workflows").glob("*.yml"))
        self.assertTrue(workflows)
        for path in workflows:
            text = path.read_text()
            self.assertRegex(text, r"permissions:\s*\n\s*contents: read")
            for forbidden in ["pull_request_target", "gh release upload", "gh release edit", "gh release delete", "releases/270761136/assets?name=", "contents: write", "id-token: write"]:
                self.assertNotIn(forbidden, text, f"{path}: {forbidden}")

    def test_portable_heartbeat_fixtures(self) -> None:
        script = ROOT / "scripts/check-drift-heartbeat.sh"
        fresh = subprocess.run([str(script), "--fixture", str(ROOT / "tests/fixtures/heartbeat-fresh.json"), "--now", "2026-08-28T04:00:00Z"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(fresh.returncode, 0, fresh.stderr)
        self.assertIn("age_seconds=3600", fresh.stdout)
        for fixture in ["heartbeat-stale.json", "heartbeat-disabled.json"]:
            result = subprocess.run([str(script), "--fixture", str(ROOT / "tests/fixtures" / fixture), "--now", "2026-08-28T04:00:00Z"], cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0, fixture)
            self.assertIn("alert", result.stderr)


if __name__ == "__main__":
    unittest.main()
