#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed regression tests for public-source identity scrubbing."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRUB = ROOT / "scripts" / "public_scrub.py"
GOLDEN_HEX = ROOT / "rust/tests/vectors/envelope_v23_twin_expected.hex"


class PublicScrubTests(unittest.TestCase):
    def make_public_tree(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        tree = Path(temporary.name) / "source"
        (tree / "receipt-verifier/wasm").mkdir(parents=True)
        for name in ("LICENSE", "NOTICE"):
            shutil.copy2(ROOT / name, tree / name)
        shutil.copy2(ROOT / "receipt-verifier/wasm/seal.wasm", tree / "receipt-verifier/wasm/seal.wasm")
        return temporary, tree

    def scrub(self, tree: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(SCRUB), str(tree)],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_rewrite_is_length_safe_inside_the_real_golden_hex_vector(self) -> None:
        temporary, tree = self.make_public_tree()
        with temporary:
            vector = tree / "golden.hex"
            original = GOLDEN_HEX.read_bytes()
            midpoint = len(original) // 2
            tampered = original[:midpoint] + b"/home/monkey/" + original[midpoint:]
            vector.write_bytes(tampered)

            result = self.scrub(tree)

            self.assertEqual(result.returncode, 0, result.stderr)
            rewritten = vector.read_bytes()
            self.assertEqual(len(rewritten), len(tampered))
            self.assertNotIn(b"/home/monkey/", rewritten)
            self.assertIn(b"/workspace/x/", rewritten)

    def test_binary_home_match_fails_loudly_with_its_offset(self) -> None:
        temporary, tree = self.make_public_tree()
        with temporary:
            binary = tree / "unknown-format"
            binary.write_bytes(b"\x00prefix/home/monkey/suffix")

            result = self.scrub(tree)

            self.assertEqual(result.returncode, 1)
            self.assertIn("refusing HOME rewrite in NUL-bearing file: unknown-format at byte offset 7", result.stderr)
            self.assertEqual(binary.read_bytes(), b"\x00prefix/home/monkey/suffix")

    def test_absent_input_fails(self) -> None:
        result = self.scrub(ROOT / "does-not-exist")

        self.assertEqual(result.returncode, 1)
        self.assertIn("usage: public_scrub.py SOURCE_TREE", result.stderr)

    def test_empty_input_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = self.scrub(Path(temporary))

        self.assertEqual(result.returncode, 1)
        self.assertIn("root LICENSE and NOTICE are required", result.stderr)

    def test_unreadable_input_fails(self) -> None:
        temporary, tree = self.make_public_tree()
        with temporary:
            unreadable = tree / "unreadable"
            unreadable.symlink_to("missing-target")

            result = self.scrub(tree)

        self.assertEqual(result.returncode, 1)
        self.assertIn("unable to classify public file unreadable", result.stderr)


if __name__ == "__main__":
    unittest.main()
