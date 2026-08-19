#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the retired public-reference gate."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "retired_public_reference_gate.py"
RETIRED = "can" + "ary"


class RetiredPublicReferenceGateTests(unittest.TestCase):
    def make_repo(self, files: dict[str, str]) -> Path:
        temporary = tempfile.TemporaryDirectory()
        def _cleanup() -> None:
            if os.environ.get("KEEP_TMP") in ("1", "true"):
                return
            temporary.cleanup()
        self.addCleanup(_cleanup)
        root = Path(temporary.name)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        for relative, text in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        return root

    def run_gate(
        self, root: Path, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(GATE), "--root", str(root), *arguments],
            text=True,
            capture_output=True,
        )

    def test_clean_tracked_public_export_input_passes(self) -> None:
        root = self.make_repo({"README.md": "current public materials\n"})
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS retired public reference absent", result.stdout)

    def test_reference_in_document_fails_with_file_and_line(self) -> None:
        root = self.make_repo({"docs/page.md": f"first\nretired {RETIRED} demo\n"})
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"docs/page.md:2:retired {RETIRED} demo", result.stderr)

    def test_reference_in_shipped_code_also_fails(self) -> None:
        root = self.make_repo({"demo/example.py": f'NAME = "{RETIRED}"\n'})
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 1)
        self.assertIn("demo/example.py:1:", result.stderr)

    def test_untracked_file_is_not_part_of_export_input(self) -> None:
        root = self.make_repo({"README.md": "clean\n"})
        (root / "notes.md").write_text(RETIRED, encoding="utf-8")
        result = self.run_gate(root)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_assembled_export_includes_untracked_vendored_text(self) -> None:
        root = self.make_repo({"README.md": "clean\n"})
        vendor = root / "vendor" / "dependency"
        vendor.mkdir(parents=True)
        (vendor / "claim.md").write_text(RETIRED, encoding="utf-8")
        result = self.run_gate(root, "--all-files")
        self.assertEqual(result.returncode, 1)
        self.assertIn("vendor/dependency/claim.md:1:", result.stderr)


if __name__ == "__main__":
    unittest.main()
