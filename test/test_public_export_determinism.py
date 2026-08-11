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

    def test_final_tarball_gets_a_separate_credential_isolated_build(self) -> None:
        workflow = (ROOT / ".github/workflows/public-export.yml").read_text(encoding="utf-8")
        verifier = (ROOT / "scripts/verify_public_source_build.sh").read_text(encoding="utf-8")
        self.assertIn("clean-source-build:", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("scripts/verify_public_source_build.sh", workflow)
        self.assertIn("env -i", verifier)
        self.assertIn("GIT_CONFIG_GLOBAL=/dev/null", verifier)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", verifier)
        self.assertIn("GIT_TERMINAL_PROMPT=0", verifier)
        self.assertIn("GIT_SSH_COMMAND=/bin/false", verifier)
        self.assertIn("LEANBUILD=lake", verifier)

    def test_export_vendors_the_private_source_dependency(self) -> None:
        exporter = (ROOT / "scripts/export_public.sh").read_text(encoding="utf-8")
        preparer = (ROOT / "scripts/prepare_public_source.py").read_text(encoding="utf-8")
        self.assertIn("scripts/prepare_public_source.py", exporter)
        self.assertIn('moreLinkArgs = ["vendor/mcp-seal/c/build/libsealcrypto.o"]', preparer)

    def test_export_removes_retired_upstream_docs_then_gates_assembled_tree(self) -> None:
        exporter = (ROOT / "scripts" / "export_public.sh").read_text(encoding="utf-8")
        preparer = (ROOT / "scripts" / "prepare_public_source.py").read_text(encoding="utf-8")
        self.assertIn('("ASSURANCE_CASE.md", "ROADMAP_ARIA_TA2.md")', preparer)
        self.assertIn("retired_public_reference_gate.py", exporter)
        self.assertIn('--root "$SOURCE" --all-files', exporter)


if __name__ == "__main__":
    unittest.main()
