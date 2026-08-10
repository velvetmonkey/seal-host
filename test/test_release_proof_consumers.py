#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Static CI regressions for release proofs that must be consumed after production."""

import ast
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
ZERO_INSTALL_PATH_DECLARATIONS = {
    "docs/DEPLOY.md": "Supported production deployment paths: **0**.",
    "docs/GETTING-STARTED.md": "Supported clean-machine onboarding paths: **0**.",
    "CONFIG.md": "Supported clean-machine installation paths: **0**.",
}
ZERO_RELEASE_DECLARATION = "Published `seal-host` releases: **0**."
RELEASE_DOWNLOAD_COMMANDS = (
    (
        "GitHub CLI release download",
        re.compile(r"\bgh\s+release\s+download\b", re.IGNORECASE),
    ),
    (
        "direct release asset URL",
        re.compile(
            r"https?://github\.com/velvetmonkey/seal-host/releases/download/",
            re.IGNORECASE,
        ),
    ),
)
ZERO_INSTALL_PATH_COMMANDS = RELEASE_DOWNLOAD_COMMANDS + (
    (
        "release provenance verification",
        re.compile(r"\brelease_provenance\.py\s+verify\b", re.IGNORECASE),
    ),
    (
        "seal-host curl or wget download",
        re.compile(r"\b(?:curl|wget)\b[^\n]*(?:seal-host|velvetmonkey/seal-host)", re.IGNORECASE),
    ),
    (
        "seal-host archive extraction",
        re.compile(r"\b(?:tar|unzip)\b[^\n]*seal-host", re.IGNORECASE),
    ),
    (
        "source build script",
        re.compile(r"\b(?:bash\s+)?(?:\./)?scripts/build_all\.sh\b", re.IGNORECASE),
    ),
    (
        "Cargo build or install",
        re.compile(r"\bcargo\s+(?:build|install)\b", re.IGNORECASE),
    ),
)


def normalized_text(text: str) -> str:
    """Collapse prose wrapping so Markdown line breaks carry no semantics."""
    return " ".join(text.split())


def contains_normalized(text: str, declaration: str) -> bool:
    return normalized_text(declaration) in normalized_text(text)


def command_surfaces(text: str) -> str:
    """Extract shell fences and bare command lines, joining continuations."""
    fenced = re.findall(r"```(?:sh|bash|shell)?\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    command_start = re.compile(
        r"^\s*(?:\$\s*)?(?:(?:sudo|env)\s+)*(?:"
        r"gh|curl|wget|tar|unzip|bash|cargo|"
        r"python3\s+release_provenance\.py|(?:\./)?scripts/build_all\.sh"
        r")\b",
        re.IGNORECASE,
    )
    bare_commands = [line for line in text.splitlines() if command_start.search(line)]
    return "\n".join(
        [*bare_commands, *(normalized_text(block) for block in fenced)]
    )


def matching_commands(text: str, patterns: tuple[tuple[str, re.Pattern[str]], ...]) -> list[str]:
    surfaces = command_surfaces(text)
    return [label for label, pattern in patterns if pattern.search(surfaces)]


def assert_release_document_state(test: unittest.TestCase, text: str) -> None:
    if contains_normalized(text, ZERO_RELEASE_DECLARATION):
        test.assertTrue(
            contains_normalized(text, "There is no reader verification procedure"),
            "zero releases require an explicit absent reader-procedure statement",
        )
        test.assertEqual(
            [],
            matching_commands(text, RELEASE_DOWNLOAD_COMMANDS),
            "zero releases cannot carry a release download command",
        )
    else:
        test.assertIn("--pattern release_provenance.py", text)


def assert_install_document_state(
    test: unittest.TestCase, text: str, zero_declaration: str
) -> None:
    if contains_normalized(text, zero_declaration):
        test.assertEqual(
            [],
            matching_commands(text, ZERO_INSTALL_PATH_COMMANDS),
            "zero install paths cannot carry an executable install command",
        )
    else:
        test.assertIn("release_provenance.py verify", text)
        test.assertIn("SEAL-RELEASE-PROVENANCE.sigstore.json", text)


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
        self.assertIn(
            'install -m 0755 "$GITHUB_WORKSPACE/scripts/release_provenance.py"',
            workflow,
        )
        self.assertIn('VERIFIER_NAME = "release_provenance.py"', gate)
        assert_release_document_state(self, docs)

    def test_every_install_path_requires_signed_provenance(self) -> None:
        for relative, zero_declaration in ZERO_INSTALL_PATH_DECLARATIONS.items():
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                assert_install_document_state(self, text, zero_declaration)

    def test_zero_install_path_declaration_has_no_install_command(self) -> None:
        for relative, zero_declaration in ZERO_INSTALL_PATH_DECLARATIONS.items():
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                if contains_normalized(text, zero_declaration):
                    assert_install_document_state(self, text, zero_declaration)

    def test_zero_state_detection_ignores_line_wrapping(self) -> None:
        declarations = [ZERO_RELEASE_DECLARATION, *ZERO_INSTALL_PATH_DECLARATIONS.values()]
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                differently_wrapped = "\n\t".join(declaration.split())
                self.assertTrue(contains_normalized(differently_wrapped, declaration))

    def test_zero_install_path_refuses_contradictory_commands(self) -> None:
        zero = ZERO_INSTALL_PATH_DECLARATIONS["docs/GETTING-STARTED.md"]
        commands = {
            "GitHub CLI release download": (
                "gh release download v0.1.5 --repo velvetmonkey/seal-host"
            ),
            "direct release asset URL": (
                "curl -fL https://github.com/velvetmonkey/seal-host/releases/"
                "download/v0.1.5/seal-host-rs -o /usr/local/bin/seal-host-rs"
            ),
            "seal-host curl or wget download": (
                "wget https://downloads.example/seal-host-rs -O /usr/local/bin/seal-host-rs"
            ),
            "seal-host archive extraction": (
                "tar xzf seal-host-v0.1.5-linux-x86_64.tar.gz"
            ),
            "source build script": "bash scripts/build_all.sh",
            "Cargo build or install": "cargo install --git https://example/seal-host",
            "release provenance verification": "python3 release_provenance.py verify",
        }
        for expected, command in commands.items():
            with self.subTest(command=command):
                contradictory = f"{zero}\n```sh\n{command}\n```\n"
                with self.assertRaisesRegex(AssertionError, "executable install command"):
                    assert_install_document_state(self, contradictory, zero)
                self.assertIn(
                    expected,
                    matching_commands(contradictory, ZERO_INSTALL_PATH_COMMANDS),
                )

    def test_both_zero_path_controls_refuse_a_wrapped_contradiction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="control04-zero-path-") as temp_dir:
            root = Path(temp_dir)
            for relative, declaration in ZERO_INSTALL_PATH_DECLARATIONS.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(declaration.split()) + "\n", encoding="utf-8")

            getting_started = root / "docs/GETTING-STARTED.md"
            with getting_started.open("a", encoding="utf-8") as stream:
                stream.write(
                    "```sh\n"
                    "curl -fL https://github.com/velvetmonkey/seal-host/releases/"
                    "download/v9.9.9/seal-host-rs -o /usr/local/bin/seal-host-rs\n"
                    "```\n"
                )

            with patch.object(sys.modules[__name__], "ROOT", root):
                for method_name in (
                    "test_every_install_path_requires_signed_provenance",
                    "test_zero_install_path_declaration_has_no_install_command",
                ):
                    with self.subTest(control=method_name):
                        control = ReleaseProofConsumerTests(method_name)
                        with self.assertRaisesRegex(
                            AssertionError, "executable install command"
                        ):
                            getattr(control, method_name)()

    def test_nonzero_install_path_still_requires_signed_provenance(self) -> None:
        dishonest = (
            "Supported clean-machine onboarding paths: **1**.\n"
            "```sh\n"
            "curl -fL https://github.com/velvetmonkey/seal-host/releases/"
            "download/v9.9.9/seal-host-rs -o /usr/local/bin/seal-host-rs\n"
            "```\n"
        )
        with self.assertRaisesRegex(AssertionError, "release_provenance.py verify"):
            assert_install_document_state(
                self,
                dishonest,
                ZERO_INSTALL_PATH_DECLARATIONS["docs/GETTING-STARTED.md"],
            )

    def test_release_document_zero_and_nonzero_states(self) -> None:
        zero = (
            "Published `seal-host`\nreleases: **0**.\n"
            "There is no reader\nverification procedure because none exists.\n"
        )
        assert_release_document_state(self, zero)

        contradictory_zero = (
            zero
            + "```sh\n"
            + "curl -fL https://github.com/velvetmonkey/seal-host/releases/"
            + "download/v0.1.5/release_provenance.py\n"
            + "```\n"
        )
        with self.assertRaisesRegex(AssertionError, "release download command"):
            assert_release_document_state(self, contradictory_zero)

        with self.assertRaisesRegex(AssertionError, "--pattern release_provenance.py"):
            assert_release_document_state(self, "Published releases: **1**.\n")
        assert_release_document_state(
            self,
            "Published releases: **1**.\n--pattern release_provenance.py\n",
        )

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
