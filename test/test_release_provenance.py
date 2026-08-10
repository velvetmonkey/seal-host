#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "release_provenance.py"
IDENTITY = (
    "https://github.com/velvetmonkey/seal-host/.github/workflows/"
    "release.yml@refs/tags/v0.1.2"
)
ISSUER = "https://token.actions.githubusercontent.com"


class ReleaseProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.release = self.root / "release"
        self.release.mkdir()
        self.tarballs = [
            self.release / f"seal-host-v0.1.2-linux-{arch}.tar.gz"
            for arch in ("aarch64", "x86_64")
        ]
        self.sboms = [
            self.release / f"seal-host-v0.1.2-linux-{arch}.cdx.json"
            for arch in ("aarch64", "x86_64")
        ]
        for path in self.tarballs:
            path.write_bytes(f"exact tarball bytes for {path.name}".encode())
        for path in self.sboms:
            path.write_bytes(b'{"bomFormat":"CycloneDX"}\n')
        self.verifier = self.release / "release_provenance.py"
        shutil.copyfile(GATE, self.verifier)
        self.payloads = self.tarballs + self.sboms + [self.verifier]
        self.write_checksums()
        self.tarball = self.tarballs[-1]
        self.sbom = self.sboms[-1]
        self.statement = self.release / "SEAL-RELEASE-PROVENANCE.json"
        self.bundle = self.release / "SEAL-RELEASE-PROVENANCE.sigstore.json"
        self.bundle.write_text("{}\n", encoding="utf-8")
        self.good_cosign = self.executable("cosign-good", "echo 'Verified OK'")
        self.bad_cosign = self.executable(
            "cosign-bad", "echo 'invalid signature' >&2; exit 1"
        )
        self.silent_cosign = self.executable("cosign-silent", "exit 0")
        created = self.run_create()
        self.assertEqual(created.returncode, 0, created.stdout + created.stderr)

    def write_checksums(self) -> None:
        payloads = sorted(self.payloads, key=lambda path: path.name)
        (self.release / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in payloads
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def executable(self, name: str, body: str) -> Path:
        path = self.root / name
        path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def run_create(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(GATE),
                "create",
                "--release-dir",
                str(self.release),
                "--release-version",
                "v0.1.2",
                "--output",
                str(self.statement),
                "--signer-identity",
                IDENTITY,
                "--oidc-issuer",
                ISSUER,
            ],
            text=True,
            capture_output=True,
            check=False,
        )

    def run_verify(
        self,
        *,
        cosign: Path | None = None,
        cosign_sha256: str | None = None,
        statement: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(GATE),
                "verify",
                "--release-dir",
                str(self.release),
                "--release-version",
                "v0.1.2",
                "--statement",
                str(statement or self.statement),
                "--bundle",
                str(self.bundle),
                "--key",
                str(self.root / "test.pub"),
                "--expected-signer-identity",
                IDENTITY,
                "--expected-oidc-issuer",
                ISSUER,
                "--cosign",
                str(cosign or self.good_cosign),
                "--cosign-sha256",
                cosign_sha256
                or hashlib.sha256((cosign or self.good_cosign).read_bytes()).hexdigest(),
            ],
            text=True,
            capture_output=True,
            check=False,
            env=env or {**os.environ, "PATH": str(self.root)},
        )

    def test_statement_binds_every_payload_and_carries_non_claims(self) -> None:
        statement = json.loads(self.statement.read_text(encoding="utf-8"))
        self.assertEqual(
            [subject["name"] for subject in statement["subject"]],
            [
                "SHA256SUMS",
                "release_provenance.py",
                "seal-host-v0.1.2-linux-aarch64.cdx.json",
                "seal-host-v0.1.2-linux-aarch64.tar.gz",
                "seal-host-v0.1.2-linux-x86_64.cdx.json",
                "seal-host-v0.1.2-linux-x86_64.tar.gz",
            ],
        )
        self.assertEqual(len(statement["predicate"]["nonClaims"]), 6)
        self.assertIn("not a GitHub artifact attestation", statement["predicate"]["nonClaims"][0])
        self.assertNotIn("buildContext", statement["predicate"])

    def test_valid_provenance_passes(self) -> None:
        result = self.run_verify()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "PASS release provenance: valid signature and 6 exact subject digests",
            result.stdout,
        )

    def test_absent_provenance_refuses(self) -> None:
        self.statement.unlink()
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing provenance statement", result.stderr)

    def test_invalid_signature_refuses(self) -> None:
        result = self.run_verify(cosign=self.bad_cosign)
        self.assertEqual(result.returncode, 1)
        self.assertIn("cosign signature verification failed: invalid signature", result.stderr)

    def test_digest_mismatch_refuses(self) -> None:
        self.tarball.write_bytes(b"different published bytes")
        self.write_checksums()
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("subject digest mismatch for SHA256SUMS", result.stderr)

    def test_unavailable_verifier_refuses(self) -> None:
        result = self.run_verify(
            cosign=self.root / "not-installed", cosign_sha256="0" * 64
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("cosign verifier unavailable", result.stderr)

    def test_shadow_verifier_refuses(self) -> None:
        established = self.executable("cosign", "echo 'Verified OK'")
        shadow = self.root / "shadow"
        shadow.mkdir()
        self.executable("shadow/cosign", "echo 'shadow verifier' >&2; exit 1")
        environment = {**os.environ, "PATH": f"{shadow}{os.pathsep}{os.environ['PATH']}"}
        result = self.run_verify(cosign=established, env=environment)
        self.assertEqual(result.returncode, 1)
        self.assertIn("PATH selects", result.stderr)
        self.assertIn("before established verifier", result.stderr)

    def test_cosign_digest_mismatch_refuses(self) -> None:
        expected = hashlib.sha256(self.good_cosign.read_bytes()).hexdigest()
        with self.good_cosign.open("ab") as executable:
            executable.write(b"# altered")
        result = self.run_verify(cosign_sha256=expected)
        self.assertEqual(result.returncode, 1)
        self.assertIn("cosign verifier digest mismatch", result.stderr)

    def test_missing_cosign_arguments_fail_loudly(self) -> None:
        command = [
            sys.executable,
            str(GATE),
            "verify",
            "--release-dir",
            str(self.release),
            "--release-version",
            "v0.1.2",
            "--statement",
            str(self.statement),
            "--bundle",
            str(self.bundle),
            "--key",
            str(self.root / "test.pub"),
            "--expected-signer-identity",
            IDENTITY,
            "--expected-oidc-issuer",
            ISSUER,
        ]
        for missing in ("--cosign", "--cosign-sha256"):
            with self.subTest(missing=missing):
                arguments = command.copy()
                if missing == "--cosign-sha256":
                    arguments.extend(["--cosign", str(self.good_cosign)])
                result = subprocess.run(arguments, text=True, capture_output=True, check=False)
                self.assertEqual(result.returncode, 2)
                self.assertIn(f"the following arguments are required: {missing}", result.stderr)

    def test_silent_verifier_success_refuses(self) -> None:
        result = self.run_verify(cosign=self.silent_cosign)
        self.assertEqual(result.returncode, 1)
        self.assertIn("success without verification evidence", result.stderr)

    def test_missing_honest_non_claim_refuses(self) -> None:
        statement = json.loads(self.statement.read_text(encoding="utf-8"))
        statement["predicate"]["nonClaims"].pop()
        self.statement.write_text(json.dumps(statement), encoding="utf-8")
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("honest non-claims are missing or changed", result.stderr)

    def test_unattested_install_script_refuses(self) -> None:
        (self.release / "install.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("neither signed subjects nor provenance metadata: install.sh", result.stderr)

    def test_unattested_windows_zip_refuses(self) -> None:
        (self.release / "seal-host-v0.1.2-windows.zip").write_bytes(b"zip")
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("seal-host-v0.1.2-windows.zip", result.stderr)

    def test_partial_architecture_matrix_refuses(self) -> None:
        self.tarballs[0].unlink()
        self.sboms[0].unlink()
        self.payloads = [path for path in self.payloads if path.exists()]
        self.write_checksums()
        result = self.run_verify()
        self.assertEqual(result.returncode, 1)
        self.assertIn("release payload set is incomplete", result.stderr)
        self.assertIn("aarch64", result.stderr)


if __name__ == "__main__":
    unittest.main()
