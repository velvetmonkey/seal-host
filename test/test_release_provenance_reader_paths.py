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
    return run_checker_with_tags(root, ("v0.1.5", "v0.1.6"))


def run_checker_with_tags(root: Path, tags: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CHECKER),
            "--root",
            str(root),
            *[argument for tag in tags for argument in ("--published-tag", tag)],
        ],
        text=True,
        capture_output=True,
        check=False,
    )


class ReaderReleasePathTests(unittest.TestCase):
    def run_fixture(self, commands: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="reader-release-identity-") as temp_dir:
            root = Path(temp_dir)
            docs = root / "docs"
            docs.mkdir()
            (docs / "FIXTURE.md").write_text(commands, encoding="utf-8")
            return run_checker_with_tags(root, ("v0.1.0", "v0.2.0"))

    def test_current_reader_paths_pass(self) -> None:
        result = run_checker(ROOT)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Latest=v0.1.6, published=2", result.stdout)

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

    def test_stale_current_release_marker_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reader-release-stale-") as temp_dir:
            root = Path(temp_dir)
            (root / "README.md").write_text(
                "<!-- current-release: v0.1.5 -->\nCurrent release: v0.1.5.\n",
                encoding="utf-8",
            )
            result = run_checker(root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("current-release marker must be exactly v0.1.6", result.stderr)

    def test_stale_release_count_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reader-release-count-") as temp_dir:
            root = Path(temp_dir)
            (root / "README.md").write_text(
                "<!-- current-release: v0.1.6 -->\n"
                "Published `seal-host` releases: **1**.\n",
                encoding="utf-8",
            )
            result = run_checker(root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("stated published release count is 1, live count is 2", result.stderr)

    def test_unpublished_download_tag_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reader-release-tag-") as temp_dir:
            root = Path(temp_dir)
            (root / "README.md").write_text(
                "<!-- current-release: v0.1.6 -->\n```sh\ntag=v9.9.9\n```\n",
                encoding="utf-8",
            )
            result = run_checker(root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("release reference names unpublished v9.9.9", result.stderr)

    def test_absent_documented_asset_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="reader-release-asset-") as temp_dir:
            root = Path(temp_dir)
            (root / "README.md").write_text(
                "<!-- current-release: v0.1.6 -->\n"
                "`seal-host-v0.1.6-linux-s390x.tar.gz`\n",
                encoding="utf-8",
            )
            result = run_checker(root)

        self.assertNotEqual(0, result.returncode)
        self.assertIn("documented asset is absent from v0.1.6", result.stderr)

    def test_tag_mismatch_is_refused(self) -> None:
        result = self.run_fixture(
            """```sh
python3 release_provenance.py verify X/seal-host-v0.1.0-linux-x86_64.tar.gz
.seal/release/seal-host-v0.2.0-linux-x86_64/seal-host-rs --version
```
"""
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("release artifact identity does not match verified release", result.stderr)

    def test_directory_mismatch_is_refused(self) -> None:
        result = self.run_fixture(
            """```sh
gh release download v0.1.0 --repo velvetmonkey/seal-host --dir X --pattern seal-host-v0.1.0-linux-x86_64.tar.gz
python3 release_provenance.py verify X/seal-host-v0.1.0-linux-x86_64.tar.gz
Y/seal-host-v0.1.0-linux-x86_64/seal-host-rs --version
```
"""
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("release artifact identity does not match verified release", result.stderr)

    def test_artifact_mismatch_is_refused(self) -> None:
        result = self.run_fixture(
            """```sh
gh release download v0.1.0 --repo velvetmonkey/seal-host --dir X --pattern 'seal-host-v0.1.0-linux-*'
python3 release_provenance.py verify X/seal-host-v0.1.0-linux-aarch64.tar.gz
X/seal-host-v0.1.0-linux-x86_64/seal-host-rs --version
```
"""
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("release artifact identity does not match verified release", result.stderr)

    def test_matching_release_identity_passes(self) -> None:
        result = self.run_fixture(
            """```sh
gh release download v0.1.0 --repo velvetmonkey/seal-host --dir X --pattern seal-host-v0.1.0-linux-x86_64.tar.gz
python3 release_provenance.py verify X/seal-host-v0.1.0-linux-x86_64.tar.gz
X/seal-host-v0.1.0-linux-x86_64/seal-host-rs --version
```
"""
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_unparseable_release_identity_is_refused(self) -> None:
        result = self.run_fixture(
            """```sh
python3 release_provenance.py verify X/seal-host-v0.1.0-linux-x86_64.tar.gz
.seal/release/seal-host-${tag}/seal-host-rs --version
```
"""
        )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("release artifact identity is unknown", result.stderr)


if __name__ == "__main__":
    unittest.main()
