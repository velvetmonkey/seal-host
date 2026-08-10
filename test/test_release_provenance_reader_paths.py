#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Physical negative cases for the provenance-before-use reader checker."""

from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts/check_reader_release_paths.py"
VERIFY_BLOCK = re.compile(
    r"^python3 release_provenance\.py verify \\\n"
    r"(?:^.*\\\n)*?"
    r'^\s*--certificate-oidc-issuer "https://token\.actions\.githubusercontent\.com"\n',
    re.MULTILINE,
)


def run_checker(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CHECKER),
            "--root",
            str(root),
            "--published-tag",
            "v0.1.5",
        ],
        text=True,
        capture_output=True,
        check=False,
    )


class ReaderReleasePathTests(unittest.TestCase):
    def test_current_reader_paths_pass(self) -> None:
        result = run_checker(ROOT)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("provenance-before-use verified", result.stdout)

    def test_fresh_unverified_install_document_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reader-release-unverified-") as temp_dir:
            root = Path(temp_dir)
            docs = root / "docs"
            docs.mkdir()
            (docs / "UNVERIFIED-INSTALL.md").write_text(
                """# Unverified install

This prose mentions `python3 release_provenance.py verify` but never runs it.

```sh
mkdir -p .seal/release && cd .seal/release
gh release download v0.1.5 --repo velvetmonkey/seal-host \\
  --pattern seal-host-v0.1.5-linux-x86_64.tar.gz
tar xzf seal-host-v0.1.5-linux-x86_64.tar.gz
install -m 0755 seal-host-v0.1.5-linux-x86_64/bin/seal-host-rs /usr/local/bin/seal-host-rs
/usr/local/bin/seal-host-rs </dev/null
```
""",
                encoding="utf-8",
            )

            result = run_checker(root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("docs/UNVERIFIED-INSTALL.md", result.stderr)
        self.assertIn("release artifact use occurs before release_provenance.py verify", result.stderr)

    def test_removing_deploy_verification_is_refused(self) -> None:
        original = (ROOT / "docs/DEPLOY.md").read_text(encoding="utf-8")
        mutated, substitutions = VERIFY_BLOCK.subn("", original, count=1)
        self.assertEqual(1, substitutions, "DEPLOY verification command shape changed")

        with tempfile.TemporaryDirectory(prefix="reader-release-deploy-") as temp_dir:
            root = Path(temp_dir)
            docs = root / "docs"
            docs.mkdir()
            (docs / "DEPLOY.md").write_text(mutated, encoding="utf-8")

            result = run_checker(root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("docs/DEPLOY.md", result.stderr)
        self.assertIn("release artifact use occurs before release_provenance.py verify", result.stderr)


if __name__ == "__main__":
    unittest.main()
