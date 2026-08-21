#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Physical negative cases for the public fleet claim gate."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "public_fleet_claim_gate.py"

SENTENCE_CASES = (
    ("Access to the Seal repositories is restricted to authorised reviewers.", True),
    ("The Seal repositories have not yet been open sourced.", True),
    ("Please request access before viewing the Seal repositories.", True),
    ("seal-host is an invite-only repository.", True),
    ("The mcp-seal-dev source is not publicly available.", True),
    ("Only authorized evaluators may use the seal-assurance-kit repository.", True),
    ("seal-live-demo remains internal-only during the pre-award period.", True),
    ("seal-check remains a private repository.", True),
    ("The seal-verify-action repository is closed-source.", True),
    ("`seal` is not public.", True),
    ("witness-check is a private repository.", False),
    ("The witness-check repository stays private and is never published.", False),
    ("witness-check is private; seal-host is public and Apache-2.0.", False),
    ("Put one gate between an agent and the effect it wants to cause.", False),
    ("Every decision leaves replayable evidence.", False),
    (
        "Seal enforces authorization at the effect boundary; "
        "it does not claim to read agent intent.",
        False,
    ),
    ("The seal-check repository is public and Apache-2.0.", False),
    ("A private deployment may use Seal to protect an internal tool.", False),
)

LEGACY_SENTENCES = (
    "All Seal-family repositories are currently private",
    "links resolve only for authorized evaluators",
    "both in private repos",
    "private Seal product-family repos",
    "checked private repos",
    "This repository is **PRIVATE, pre-award**",
    "Access stays private until each layer reaches its release point",
    "Do NOT push this repository to a public remote pre-award",
    "Names the private repositories",
    "stays the private source of truth",
    "user-owned private repository",
    "private umbrella story",
    "private kit repo",
)


def run_gate(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


def copy_reader_tree(target: Path) -> None:
    for name in ("README.md", "NOTICE.md", "EVIDENCE.md", "SECURITY.md"):
        shutil.copy2(ROOT / name, target / name)
    docs = target / "docs"
    docs.mkdir()
    for source in (ROOT / "docs").glob("*.md"):
        shutil.copy2(source, docs / source.name)


def write_reader_tree(target: Path, sentence: str) -> None:
    for name in ("README.md", "NOTICE.md", "EVIDENCE.md", "SECURITY.md"):
        (target / name).write_text("Current public reader surface.\n", encoding="utf-8")
    docs = target / "docs"
    docs.mkdir()
    (docs / "FRONT-PAGE-REFERENCE.md").write_text(sentence + "\n", encoding="utf-8")


class PublicFleetClaimGateTests(unittest.TestCase):
    def test_current_reader_surfaces_pass(self) -> None:
        result = run_gate(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS public fleet claim gate", result.stdout)

    def test_tampered_private_family_claim_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-claim-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            readme = root / "README.md"
            readme.write_text(
                readme.read_text(encoding="utf-8")
                + "\n_All Seal-family repositories are currently private; "
                + "these links resolve only for authorised evaluators._\n",
                encoding="utf-8",
            )

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("README.md", result.stderr)
        self.assertIn("stale private-era fleet claim", result.stderr)

    def test_sentence_verdict_table(self) -> None:
        for sentence, refused in SENTENCE_CASES:
            with self.subTest(sentence=sentence, expected="REFUSED" if refused else "ALLOWED"):
                with tempfile.TemporaryDirectory(prefix="public-fleet-sentence-") as temporary:
                    root = Path(temporary)
                    write_reader_tree(root, sentence)
                    result = run_gate(root)
                if refused:
                    self.assertNotEqual(result.returncode, 0, sentence)
                    self.assertIn("stale private-era fleet claim", result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("PASS public fleet claim gate", result.stdout)

    def test_all_thirteen_historical_patterns_remain_refused(self) -> None:
        for sentence in LEGACY_SENTENCES:
            with self.subTest(sentence=sentence):
                with tempfile.TemporaryDirectory(prefix="public-fleet-legacy-") as temporary:
                    root = Path(temporary)
                    write_reader_tree(root, sentence)
                    result = run_gate(root)
                self.assertNotEqual(result.returncode, 0, sentence)
                self.assertIn("stale private-era fleet claim", result.stderr)

    def test_absent_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-absent-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "NOTICE.md").unlink()

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("NOTICE.md: absent required reader surface", result.stderr)

    def test_empty_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-empty-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "EVIDENCE.md").write_text("", encoding="utf-8")

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("EVIDENCE.md: empty reader surface", result.stderr)

    def test_unreadable_required_surface_is_refused(self) -> None:
        with tempfile.TemporaryDirectory(prefix="public-fleet-unreadable-") as temporary:
            root = Path(temporary)
            copy_reader_tree(root)
            (root / "SECURITY.md").unlink()
            (root / "SECURITY.md").mkdir()

            result = run_gate(root)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SECURITY.md: not a readable file", result.stderr)


if __name__ == "__main__":
    unittest.main()
