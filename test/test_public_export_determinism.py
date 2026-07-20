#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for cross-run public export determinism."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PublicExportDeterminismTests(unittest.TestCase):
    def test_workflow_compares_two_separate_exporter_runs(self) -> None:
        workflow = (ROOT / ".github/workflows/public-export.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("scripts/export_public.sh"), 2)
        self.assertIn("scripts/compare_public_exports.sh", workflow)

    def test_exporter_no_longer_compares_two_archives_inside_one_run(self) -> None:
        exporter = (ROOT / "scripts/export_public.sh").read_text(encoding="utf-8")
        self.assertNotIn("SOURCE_B", exporter)
        self.assertNotIn("source-b.tar.gz", exporter)

    def test_checksum_manifest_contains_only_relative_paths(self) -> None:
        exporter = (ROOT / "scripts/export_public.sh").read_text(encoding="utf-8")
        self.assertIn('(cd "$SIGNED" && sha256sum *.tar.gz *.cdx.json > SHA256SUMS)', exporter)
        self.assertNotIn('sha256sum "$SIGNED"/', exporter)


if __name__ == "__main__":
    unittest.main()
