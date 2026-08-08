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
REQUIRED = ("ci.yml", "golden-path.yml", "security.yml")
RUN_IDS = {"ci.yml": 202, "golden-path.yml": 303, "security.yml": 404}


def workflow_run(workflow: str, *, status: str, conclusion: str | None) -> dict:
    return {
        "id": RUN_IDS[workflow],
        "event": "push",
        "head_branch": "v1.2.3",
        "head_sha": SHA,
        "created_at": "2026-08-06T12:00:00Z",
        "status": status,
        "conclusion": conclusion,
    }


def recorded_state(
    *,
    ci: str = "success",
    golden_path: str = "success",
    security: str = "success",
    evidence: str = "success",
) -> dict:
    """Build a full recording. Per-workflow values are `success`, `failure`,
    `pending`, or `absent`."""
    states = {"ci.yml": ci, "golden-path.yml": golden_path, "security.yml": security}
    runs_by_workflow: dict[str, dict] = {}
    for workflow, state in states.items():
        if state == "absent":
            runs_by_workflow[workflow] = {"workflow_runs": []}
        elif state == "pending":
            runs_by_workflow[workflow] = {
                "workflow_runs": [
                    workflow_run(workflow, status="in_progress", conclusion=None)
                ]
            }
        else:
            runs_by_workflow[workflow] = {
                "workflow_runs": [
                    workflow_run(workflow, status="completed", conclusion=state)
                ]
            }
    return {
        "release_run": {
            "id": 101,
            "event": "push",
            "head_branch": "v1.2.3",
            "head_sha": SHA,
            "path": ".github/workflows/release.yml@refs/tags/v1.2.3",
            "created_at": "2026-08-06T12:00:00Z",
        },
        "runs_by_workflow": runs_by_workflow,
        "jobs_by_run": {
            "202": {
                "jobs": [
                    {
                        "name": "rust-conformance",
                        "status": "completed",
                        "conclusion": "success" if ci == "success" else "failure",
                    },
                    {
                        "name": "release-evidence",
                        "status": "completed",
                        "conclusion": evidence if ci == "success" else "failure",
                    },
                ]
            },
            "303": {
                "jobs": [
                    {
                        "name": "deterministic-shell",
                        "status": "completed",
                        "conclusion": "success" if golden_path == "success" else "failure",
                    }
                ]
            },
            "404": {
                "jobs": [
                    {
                        "name": "codeql",
                        "status": "completed",
                        "conclusion": "success" if security == "success" else "failure",
                    }
                ]
            },
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

    def test_red_ci_refuses_naming_commit_and_failing_checks(self) -> None:
        result = self.run_gate(recorded_state(ci="failure"))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"refusing to publish commit {SHA}", result.stdout)
        self.assertIn("acceptance FAILED", result.stdout)
        self.assertIn("ci.yml run 202 concluded failure", result.stdout)
        self.assertIn(
            "failing checks: release-evidence, rust-conformance", result.stdout
        )

    def test_red_golden_path_refuses_even_when_ci_is_green(self) -> None:
        result = self.run_gate(recorded_state(golden_path="failure"))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"refusing to publish commit {SHA}", result.stdout)
        self.assertIn("golden-path.yml run 303 concluded failure", result.stdout)
        self.assertIn("failing checks: deterministic-shell", result.stdout)

    def test_red_security_refuses_even_when_ci_is_green(self) -> None:
        result = self.run_gate(recorded_state(security="failure"))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("security.yml run 404 concluded failure", result.stdout)
        self.assertIn("failing checks: codeql", result.stdout)

    def test_pending_run_refuses_and_is_distinguished_from_failed(self) -> None:
        result = self.run_gate(recorded_state(golden_path="pending"))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"refusing to publish commit {SHA}", result.stdout)
        self.assertIn(
            "acceptance still IN PROGRESS (pending, not failed): "
            "golden-path.yml run 303 (status: in_progress)",
            result.stdout,
        )
        self.assertIn("a pending acceptance run is not success", result.stdout)
        self.assertNotIn("acceptance FAILED", result.stdout)

    def test_absent_run_refuses_and_names_the_missing_workflow(self) -> None:
        result = self.run_gate(recorded_state(security="absent"))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"refusing to publish commit {SHA}", result.stdout)
        self.assertIn("NO acceptance run exists for: security.yml", result.stdout)
        self.assertIn("missing evidence is not success", result.stdout)
        self.assertNotIn("acceptance FAILED", result.stdout)

    def test_pending_and_absent_are_reported_as_distinct_reasons(self) -> None:
        result = self.run_gate(
            recorded_state(golden_path="pending", security="absent")
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("acceptance still IN PROGRESS (pending, not failed)", result.stdout)
        self.assertIn("NO acceptance run exists for: security.yml", result.stdout)

    def test_green_acceptance_passes_and_names_all_workflows(self) -> None:
        result = self.run_gate(recorded_state())

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"PASS (commit {SHA}: ci.yml, golden-path.yml, security.yml "
            "all completed successfully, including CI release-evidence)",
            result.stdout,
        )

    def test_missing_evidence_job_fails_closed_despite_green_run(self) -> None:
        state = recorded_state()
        state["jobs_by_run"]["202"]["jobs"] = []
        result = self.run_gate(state)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            f"refusing to publish commit {SHA}: CI run 202 did not report "
            "required job release-evidence",
            result.stdout,
        )

    def test_failed_evidence_job_fails_closed_despite_green_run(self) -> None:
        result = self.run_gate(recorded_state(evidence="failure"))

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            f"refusing to publish commit {SHA}: acceptance FAILED — required "
            "CI job release-evidence concluded failure",
            result.stdout,
        )

    def test_ambiguous_multiple_runs_refuse(self) -> None:
        state = recorded_state()
        runs = state["runs_by_workflow"]["ci.yml"]["workflow_runs"]
        runs.append(dict(runs[0], id=999))
        result = self.run_gate(state)

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "tag push matched multiple ci.yml runs (202, 999); refusing ambiguity",
            result.stdout,
        )

    def test_missing_api_token_fails_closed(self) -> None:
        result = self.run_gate(None, GITHUB_TOKEN="")

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("GITHUB_TOKEN is not set", result.stdout)

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
