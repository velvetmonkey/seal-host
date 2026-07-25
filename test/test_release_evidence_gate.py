#!/usr/bin/env python3

import json
import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "release_evidence_gate.py"


class ReleaseEvidenceGateTests(unittest.TestCase):
    def run_gate(
        self,
        results: dict[str, str],
        *,
        token_configured: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["RELEASE_EVIDENCE_NEEDS"] = json.dumps(
            {job: {"result": result} for job, result in results.items()}
        )
        env["RELEASE_EVIDENCE_PRIVATE_TOKEN_CONFIGURED"] = str(
            token_configured
        ).lower()
        return subprocess.run(
            ["python3", str(GATE)],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_rejects_skipped_job_and_names_it(self) -> None:
        result = self.run_gate(
            {"build": "skipped", "rust-conformance": "success"}
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "::error::release-evidence: build was not successful "
            "(result: skipped)",
            result.stdout,
        )

    def test_rejects_failed_job_and_names_it(self) -> None:
        result = self.run_gate(
            {"build": "success", "rust-conformance": "failure"}
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "::error::release-evidence: rust-conformance was not successful "
            "(result: failure)",
            result.stdout,
        )

    def test_accepts_only_successful_jobs(self) -> None:
        result = self.run_gate(
            {"build": "success", "rust-conformance": "success"}
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn(
            "release-evidence: PASS (all required jobs succeeded)",
            result.stdout,
        )

    def test_rejects_tokenless_success_that_skipped_private_evidence(self) -> None:
        result = self.run_gate(
            {
                "build": "success",
                "rust-conformance": "success",
                "contract-freeze": "success",
                "cargo-audit": "success",
                "rust-sbom": "success",
            },
            token_configured=False,
        )

        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "::error::release-evidence: build was not successful "
            "(result: skipped) (job result: success; "
            "SEAL_CI_READ_TOKEN not configured)",
            result.stdout,
        )
        self.assertIn(
            "::error::release-evidence: rust-conformance was not successful "
            "(result: skipped) (job result: success; "
            "SEAL_CI_READ_TOKEN not configured)",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
