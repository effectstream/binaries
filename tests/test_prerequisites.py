from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PrerequisiteTests(unittest.TestCase):
    def make_fixture(self, root: Path, permission: bool = True) -> tuple[Path, Path, str]:
        checkout = root / "checkout"
        checkout.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=checkout, check=True)
        subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=checkout, check=True)
        subprocess.run(["git", "config", "user.name", "Fixture"], cwd=checkout, check=True)
        (checkout / "README").write_text("fixture\n")
        subprocess.run(["git", "add", "README"], cwd=checkout, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=checkout, check=True)
        subprocess.run(["git", "remote", "add", "origin", "git@github.com:effectstream/binaries.git"], cwd=checkout, check=True)
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()

        bin_dir = root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(textwrap.dedent(f"""\
            #!/bin/sh
            if [ "$1 $2 $3" = "auth status --hostname" ]; then exit 0; fi
            if [ "$1 $2 $3 $4" = "api user --jq .login" ]; then echo acedward; exit 0; fi
            if [ "$1 $2" = "api repos/effectstream/binaries" ]; then
              echo '{{"full_name":"effectstream/binaries","id":1117580582,"node_id":"R_kgDOQpztJg","permissions":{{"admin":{str(permission).lower()},"maintain":false,"push":false}}}}'; exit 0
            fi
            if [ "$1 $2" = "api repos/effectstream/binaries/releases/tags/0.3.120" ]; then
              echo '{{"tag_name":"0.3.120","id":270761136,"node_id":"RE_kwDOQpztJs4QI3yw","draft":false,"prerelease":false,"immutable":false}}'; exit 0
            fi
            echo unexpected gh arguments >&2; exit 9
        """))
        gh.chmod(0o755)
        return checkout, bin_dir, head

    def run_probe(self, checkout: Path, bin_dir: Path, head: str, account: str = "acedward") -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        return subprocess.run(
            [str(ROOT / "scripts/check-manual-publisher-prereqs.sh"),
             "--repo", "effectstream/binaries", "--account", account, "--release", "0.3.120",
             "--reviewed-head", head, "--authority-ref", "owner-approval-fixture"],
            cwd=checkout, env=env, text=True, capture_output=True,
        )

    def test_exact_authority_checkout_identity_permission_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout, bin_dir, head = self.make_fixture(Path(temporary))
            result = self.run_probe(checkout, bin_dir, head)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("repository_id=1117580582", result.stdout)
            self.assertIn("release_id=270761136", result.stdout)
            self.assertNotIn("token", (result.stdout + result.stderr).lower())
            wrong = self.run_probe(checkout, bin_dir, "0" * 40)
            self.assertNotEqual(wrong.returncode, 0)
            wrong_account = self.run_probe(checkout, bin_dir, head, account="someoneelse")
            self.assertNotEqual(wrong_account.returncode, 0)

    def test_effective_permission_denied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            checkout, bin_dir, head = self.make_fixture(Path(temporary), permission=False)
            result = self.run_probe(checkout, bin_dir, head)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("permission", result.stderr)


if __name__ == "__main__":
    unittest.main()
