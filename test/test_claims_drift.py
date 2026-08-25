#!/usr/bin/env python3
"""Regression tests for local and cross-repository claims drift."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "claims-surface-drift.mjs"
REPOSITORIES = (
    "seal",
    "seal-host",
    "seal-check",
    "seal-live-demo",
    "seal-verify-action",
    "seal-assurance-kit",
    "mcp-seal-dev",
)
BLOCK = (
    "<!-- truthbox:begin -->\n"
    "> **Runtime profile: `compatible`.**\n"
    "> **Claim:** the family check must agree.\n"
    "> **Non-claim:** a hash match is not a deployment proof.\n"
    "<!-- truthbox:end -->\n"
)


class ClaimsDriftTests(unittest.TestCase):
    def family_root(self) -> Path:
        temporary = Path(tempfile.mkdtemp(prefix="familyfetch3-family-", dir="/home/monkey/scratch"))
        self.addCleanup(shutil.rmtree, temporary)
        for repo in REPOSITORIES:
            docs = temporary / repo / "docs"
            docs.mkdir(parents=True)
            (docs / "TRUTH-BOX.md").write_text(BLOCK, encoding="utf-8")
        return temporary

    def run_family(self, family_root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["node", str(SCRIPT), "--family-root", str(family_root)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
        )

    def test_matching_family_is_green(self) -> None:
        family = self.family_root()
        result = self.run_family(family)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("family truth-box hashes match across all seven repos", result.stdout)

    def test_tamper_red_restore_green(self) -> None:
        family = self.family_root()
        target = family / "seal-check" / "docs" / "TRUTH-BOX.md"
        original = target.read_text(encoding="utf-8")
        target.write_text(original.replace("family check must agree", "tampered family claim"), encoding="utf-8")
        red = self.run_family(family)
        self.assertEqual(red.returncode, 1, red.stdout + red.stderr)
        self.assertIn("FAMILY CLAIMS DRIFT", red.stderr)

        target.write_text(original, encoding="utf-8")
        green = self.run_family(family)
        self.assertEqual(green.returncode, 0, green.stdout + green.stderr)

    def test_absent_input_fails(self) -> None:
        family = self.family_root()
        (family / "seal-check" / "docs" / "TRUTH-BOX.md").unlink()
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("seal-check has no marked truth box", result.stderr)
        self.assertIn("found 0 candidates, 0 marked", result.stderr)

    def test_empty_input_fails(self) -> None:
        family = self.family_root()
        (family / "seal-check" / "docs" / "TRUTH-BOX.md").write_text("", encoding="utf-8")
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_unreadable_input_fails(self) -> None:
        family = self.family_root()
        target = family / "seal-check" / "docs" / "TRUTH-BOX.md"
        target.chmod(0o000)
        try:
            result = self.run_family(family)
        finally:
            target.chmod(0o644)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("seal-check truth-box candidate unreadable", result.stderr)

    def test_moved_input_is_discovered_with_its_location(self) -> None:
        family = self.family_root()
        source = family / "seal" / "docs" / "TRUTH-BOX.md"
        target = family / "seal" / "docs" / "relocated" / "TRUTH-BOX.md"
        target.parent.mkdir()
        source.replace(target)
        result = self.run_family(family)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS  family seal truth-box found at docs/relocated/TRUTH-BOX.md", result.stdout)

    def test_unmarked_decoy_is_absent_with_candidate_count(self) -> None:
        family = self.family_root()
        target = family / "seal" / "docs" / "TRUTH-BOX.md"
        target.write_text("# Template\nnot a truth box\n", encoding="utf-8")
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("seal has no marked truth box; found 1 candidate, 0 marked", result.stderr)

    def test_unmarked_decoy_does_not_hide_real_marked_file(self) -> None:
        family = self.family_root()
        decoy = family / "seal" / "docs" / "templates" / "TRUTH-BOX.md"
        decoy.parent.mkdir()
        decoy.write_text("# Template\nnot a truth box\n", encoding="utf-8")
        result = self.run_family(family)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS  family seal truth-box found at docs/TRUTH-BOX.md", result.stdout)

    def test_two_marked_inputs_are_refused_with_both_paths(self) -> None:
        family = self.family_root()
        source = family / "seal" / "docs" / "TRUTH-BOX.md"
        duplicate = family / "seal" / "docs" / "relocated" / "TRUTH-BOX.md"
        duplicate.parent.mkdir()
        duplicate.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("seal has ambiguous marked truth boxes", result.stderr)
        self.assertIn("docs/TRUTH-BOX.md", result.stderr)
        self.assertIn("docs/relocated/TRUTH-BOX.md", result.stderr)

    def test_depth_five_input_is_absent_with_explained_bound(self) -> None:
        family = self.family_root()
        source = family / "seal" / "docs" / "TRUTH-BOX.md"
        target = family / "seal" / "docs" / "a" / "b" / "c" / "d" / "e" / "TRUTH-BOX.md"
        target.parent.mkdir(parents=True)
        source.replace(target)
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("absence is bounded: only candidates at at most 4 nested directories are eligible", result.stderr)
        self.assertIn("search stopped at that depth bound before docs/a/b/c/d/e", result.stderr)

    def test_symlink_input_is_absent_with_named_skip(self) -> None:
        family = self.family_root()
        source = family / "seal" / "docs" / "TRUTH-BOX.md"
        real = family / "seal" / "elsewhere" / "real-truth.md"
        real.parent.mkdir()
        source.replace(real)
        source.symlink_to(real)
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("skipped symlink candidate: docs/TRUTH-BOX.md", result.stderr)

    def test_missing_repository_and_mismatch_are_reported_together(self) -> None:
        family = self.family_root()
        shutil.rmtree(family / "seal-check")
        target = family / "seal-live-demo" / "docs" / "TRUTH-BOX.md"
        target.write_text(BLOCK.replace("family check must agree", "different family claim"), encoding="utf-8")
        result = self.run_family(family)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("FAMILY MISSING repositories: seal-check", result.stdout)
        self.assertIn("FAMILY CLAIMS DRIFT", result.stderr)
        self.assertIn("seal-live-demo", result.stderr)


if __name__ == "__main__":
    unittest.main()
