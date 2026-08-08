#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Static CI regressions for release proofs that must be consumed after production."""

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseProofConsumerTests(unittest.TestCase):
    def test_public_export_verifies_produced_signatures(self) -> None:
        workflow = (ROOT / ".github/workflows/public-export.yml").read_text(encoding="utf-8")
        self.assertIn("scripts/verify_public_export.sh", workflow)
        verifier = (ROOT / "scripts/verify_public_export.sh").read_text(encoding="utf-8")
        self.assertIn("cosign verify-blob", verifier)

    def test_public_export_rejects_a_tampered_blob(self) -> None:
        verifier = (ROOT / "scripts/verify_public_export.sh").read_text(encoding="utf-8")
        self.assertIn("tampered blob unexpectedly verified", verifier)

    def test_release_signs_and_verifies_seal_provenance(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn("id: attest", workflow)
        self.assertIn("cosign sign-blob", workflow)
        self.assertIn("scripts/release_provenance.py create", workflow)
        self.assertIn("scripts/release_provenance.py verify", workflow)
        self.assertIn("SEAL-RELEASE-PROVENANCE.json", workflow)
        self.assertIn("SEAL-RELEASE-PROVENANCE.sigstore.json", workflow)

    def test_release_replacement_is_explicit_and_not_github_attestation(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertNotIn("actions/attest", workflow)
        self.assertNotIn("gh attestation", workflow)
        self.assertIn("GitHub artifact attestations are unavailable", workflow)
        claims = (ROOT / "CLAIMS.md").read_text(encoding="utf-8")
        limits = (ROOT / "docs/LIMITATIONS.md").read_text(encoding="utf-8")
        self.assertIn("GitHub artifact attestations are not available", claims)
        self.assertIn("GitHub artifact attestations are unavailable", limits)

    def test_release_publication_is_after_the_fail_closed_provenance_gate(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        verify = workflow.index("scripts/release_provenance.py verify")
        aggregate = workflow.index(
            "name: Require every isolated CI step to pass", verify
        )
        publish = workflow.index("name: Publish immutable release assets", aggregate)
        self.assertLess(verify, aggregate)
        self.assertLess(aggregate, publish)

    def test_release_verifier_is_a_downloadable_signed_subject(self) -> None:
        workflow = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        gate = (ROOT / "scripts/release_provenance.py").read_text(encoding="utf-8")
        docs = (ROOT / "docs/RELEASE-PROVENANCE.md").read_text(encoding="utf-8")
        self.assertIn("install -m 0755 ../scripts/release_provenance.py", workflow)
        self.assertIn('VERIFIER_NAME = "release_provenance.py"', gate)
        self.assertIn("--pattern release_provenance.py", docs)

    def test_every_install_path_requires_signed_provenance(self) -> None:
        for relative in ("docs/DEPLOY.md", "docs/GETTING-STARTED.md", "CONFIG.md"):
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("release_provenance.py verify", text)
                self.assertIn("SEAL-RELEASE-PROVENANCE.sigstore.json", text)

    def test_cosign_installer_uses_immutable_commit(self) -> None:
        for relative in (
            ".github/workflows/release.yml",
            ".github/workflows/public-export.yml",
        ):
            with self.subTest(path=relative):
                workflow = (ROOT / relative).read_text(encoding="utf-8")
                self.assertNotIn("sigstore/cosign-installer@v", workflow)
                self.assertIn(
                    "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6",
                    workflow,
                )

    def test_release_provenance_negative_tests_have_executable_assertions(self) -> None:
        source = (ROOT / "test/test_release_provenance.py").read_text(encoding="utf-8")
        methods = {
            node.name: node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.FunctionDef)
        }
        for required in (
            "test_absent_provenance_refuses",
            "test_invalid_signature_refuses",
            "test_digest_mismatch_refuses",
            "test_valid_provenance_passes",
            "test_unavailable_verifier_refuses",
            "test_silent_verifier_success_refuses",
        ):
            with self.subTest(test=required):
                self.assertIn(required, methods)
                assertions = [
                    node
                    for node in ast.walk(methods[required])
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr.startswith("assert")
                ]
                self.assertTrue(assertions, f"{required} has no executable assertions")


if __name__ == "__main__":
    unittest.main()
