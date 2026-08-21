#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed tests for the public fleet-claim pin gate.

The gate is not a repository-wide stale-claim scanner. It only proves that the
approved, delimited fleet-claim blocks on required reader surfaces still match
human-reviewed hashes.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "public_fleet_claim_gate.py"
ALLOWLIST = Path("scripts/fleet-claim-allow.json")
REQUIRED_READER_FILES = (
    Path("README.md"),
    Path("NOTICE.md"),
    Path("EVIDENCE.md"),
    Path("SECURITY.md"),
    Path("docs/FRONT-PAGE-REFERENCE.md"),
)
BEGIN = "<!-- FLEET-CLAIM:BEGIN -->"
END = "<!-- FLEET-CLAIM:END -->"


def run_gate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


def copy_reader_tree(target: Path) -> None:
    for relative in REQUIRED_READER_FILES:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, destination)
    allow_destination = target / ALLOWLIST
    allow_destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ROOT / ALLOWLIST, allow_destination)


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"{old!r} not present in {path}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


class PublicFleetClaimGateTests(unittest.TestCase):
    def test_current_reader_surfaces_pass(self) -> None:
        result = run_gate(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS public fleet claim pin gate", result.stdout)

    def test_text_outside_blocks_is_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-outside-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            with (root / "README.md").open("a", encoding="utf-8") as handle:
                handle.write("\nThe Seal repositories are private.\n")

            result = run_gate(root)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS public fleet claim pin gate", result.stdout)

    def test_hash_mismatch_names_file_and_block(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-mismatch-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            replace_once(root / "README.md", "private/proprietary", "private/proprietary ")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("README.md: block 1 sha256 mismatch", result.stderr)

    def test_zero_blocks_on_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-zero-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            replace_once(root / "NOTICE.md", BEGIN + "\n", "")
            replace_once(root / "NOTICE.md", END + "\n", "")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOTICE.md: zero fleet-claim blocks", result.stderr)

    def test_unterminated_marker_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-unterminated-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            replace_once(root / "EVIDENCE.md", END + "\n", "")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EVIDENCE.md: unterminated fleet-claim marker", result.stderr)

    def test_nested_marker_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-nested-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            replace_once(root / "SECURITY.md", "is false", f"{BEGIN}\nis false")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECURITY.md", result.stderr)
        self.assertIn("nested fleet-claim marker", result.stderr)

    def test_duplicated_marker_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-duplicated-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            replace_once(root / "README.md", BEGIN, f"{BEGIN} {BEGIN}")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("README.md", result.stderr)
        self.assertIn("duplicated fleet-claim marker", result.stderr)

    def test_pin_entry_for_absent_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-absent-pin-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            allow_path = root / ALLOWLIST
            data = json.loads(allow_path.read_text(encoding="utf-8"))
            data["surfaces"]["docs/GONE.md"] = [
                "0" * 64,
            ]
            allow_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pin entry names absent file docs/GONE.md", result.stderr)

    def test_absent_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-absent-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "NOTICE.md").unlink()

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOTICE.md: absent required reader surface", result.stderr)

    def test_required_surface_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-directory-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "SECURITY.md").unlink()
            (root / "SECURITY.md").mkdir()

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECURITY.md: not a readable file", result.stderr)

    def test_empty_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-empty-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "EVIDENCE.md").write_text("", encoding="utf-8")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EVIDENCE.md: empty reader surface", result.stderr)

    def test_non_utf8_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-utf8-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "README.md").write_bytes(b"\xff\xfe\x00")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("README.md: unreadable UTF-8 input", result.stderr)


if __name__ == "__main__":
    unittest.main()
