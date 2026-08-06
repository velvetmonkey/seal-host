#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "tag_release_gate.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
SHA = "a" * 40


def recorded_state(*, evidence: str = "success", include_run: bool = True) -> dict:
    ci_runs = []
    if include_run:
        ci_runs.append(
            {
                "id": 202,
                "event": "push",
                "head_branch": "v1.2.3",
                "head_sha": SHA,
                "created_at": "2026-08-06T12:00:00Z",
                "status": "completed",
                "conclusion": "success" if evidence == "success" else "failure",
            }
        )
    return {
        "release_run": {
            "id": 101,
            "event": "push",
            "head_branch": "v1.2.3",
            "head_sha": SHA,
            "path": ".github/workflows/release.yml@refs/tags/v1.2.3",
            "created_at": "2026-08-06T12:00:00Z",
        },
        "ci_runs": {"workflow_runs": ci_runs},
        "jobs_by_run": {
            "202": {
                "jobs": [
                    {
                        "name": "rust-conformance",
                        "status": "completed",
                        "conclusion": evidence,
                    },
                    {
                        "name": "release-evidence",
                        "status": "completed",
                        "conclusion": evidence,
                    }
                ]
            }
        },
    }


class TagReleaseGateTests(unittest.TestCase):
    def run_gate(self, state: dict | None, **env_changes: str) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "GITHUB_REPOSITORY": "velvetmonkey/seal-host",
                "GITHUB_SHA": SHA,
                "GITHUB_RUN_ID": "101",
            }
        )
        env.update(env_changes)
        command = [
            "python3",
            str(GATE),
            "--timeout-seconds",
            "0",
            "--poll-seconds",
            "0",
        ]
        if state is not None:
            command.extend(["--state-json", json.dumps(state)])
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_red_acceptance_refuses_and_names_release_evidence(self) -> None:
        result = self.run_gate(recorded_state(evidence="failure"))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("release-evidence=failure", result.stdout)
        self.assertIn("CI run unsuccessful jobs: release-evidence, rust-conformance", result.stdout)
        self.assertIn(
            "required CI job release-evidence was not successful "
            "(conclusion: failure)",
            result.stdout,
        )

    def test_green_acceptance_passes(self) -> None:
        result = self.run_gate(recorded_state())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            "PASS (CI run 202 consumed release-evidence=success)", result.stdout
        )

    def test_missing_ci_run_fails_closed_and_explains_silence(self) -> None:
        result = self.run_gate(recorded_state(include_run=False))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("waiting for this tag push's CI run to appear", result.stdout)
        self.assertIn(
            "could not obtain completed CI release-evidence within 0 seconds",
            result.stdout,
        )

    def test_missing_api_token_fails_closed(self) -> None:
        result = self.run_gate(None, GITHUB_TOKEN="")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("GITHUB_TOKEN is not set", result.stdout)

    def test_missing_evidence_job_fails_closed(self) -> None:
        state = recorded_state()
        state["jobs_by_run"]["202"]["jobs"] = []
        result = self.run_gate(state)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "did not report required job release-evidence; "
            "job data may be missing or expired",
            result.stdout,
        )

    def test_release_workflow_invokes_gate_without_continue_on_error(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        gate_start = workflow.index("  ci-acceptance:")
        gate_end = workflow.index("\n  fleet-gate:", gate_start)
        gate = workflow[gate_start:gate_end]

        self.assertIn("actions: read", gate)
        self.assertIn("run: python3 scripts/tag_release_gate.py", gate)
        self.assertNotIn("continue-on-error", gate)


if __name__ == "__main__":
    unittest.main()
