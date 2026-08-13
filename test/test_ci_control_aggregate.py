#!/usr/bin/env python3
"""Regression tests for fail-closed CI control aggregation."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
AGGREGATE = ROOT / "scripts" / "ci_control_aggregate.py"
sys.path.insert(0, str(ROOT / "scripts"))
import ci_control_aggregate as aggregate  # noqa: E402
from ci_control_aggregate import Control, workflow_controls  # noqa: E402


def declared_ids(workflow: str = "ci.yml", job: str = "build") -> list[str]:
    return sorted(
        control.control_id
        for control in workflow_controls()
        if control.workflow == workflow and control.job == job
    )


def full_success_steps(
    workflow: str = "ci.yml", job: str = "build"
) -> dict[str, dict[str, str]]:
    return {
        control_id: {"outcome": "success", "conclusion": "success"}
        for control_id in declared_ids(workflow, job)
    }


class CiControlAggregateTests(unittest.TestCase):
    def controls_from_yaml(self, source: str) -> set[Control]:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            workflows = Path(directory)
            (workflows / "probe.yml").write_text(source, encoding="utf-8")
            with mock.patch.object(aggregate, "WORKFLOWS", workflows):
                return workflow_controls()

    def run_aggregate(
        self,
        steps: object | None,
        *,
        allowlist: Path | None = None,
        workflow: str = "ci.yml",
        job: str = "build",
        clear_identity: bool = False,
        workflow_ref: str | None = None,
        job_env: str | None = None,
        dependencies: object | None = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if clear_identity:
            env.pop("GITHUB_WORKFLOW_REF", None)
            env.pop("GITHUB_JOB", None)
        else:
            if workflow_ref is not None:
                env["GITHUB_WORKFLOW_REF"] = workflow_ref
            else:
                env["GITHUB_WORKFLOW_REF"] = (
                    f"velvetmonkey/seal-host/.github/workflows/{workflow}"
                    "@refs/heads/test"
                )
            env["GITHUB_JOB"] = job if job_env is None else job_env
        if steps is None:
            env.pop("SEAL_CONTROL_STEPS", None)
        else:
            env["SEAL_CONTROL_STEPS"] = json.dumps(steps)
        if dependencies is None:
            env.pop("SEAL_CONTROL_DEPENDENCIES", None)
        else:
            env["SEAL_CONTROL_DEPENDENCIES"] = json.dumps(dependencies)
        command = ["python3", str(AGGREGATE)]
        if allowlist is not None:
            command.extend(["--allowlist", str(allowlist)])
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_build_job_declares_control_33(self) -> None:
        """Pin control_33 by name so deleting it from ci.yml breaks a test."""
        self.assertIn(
            Control("ci.yml", "build", "control_33"),
            workflow_controls(),
        )
        self.assertIn("control_33", declared_ids("ci.yml", "build"))

    def test_bare_control_id_is_declared(self) -> None:
        controls = self.controls_from_yaml(
            "jobs:\n  build:\n    steps:\n      - id: control_01\n"
        )
        self.assertIn(Control("probe.yml", "build", "control_01"), controls)

    def test_single_quoted_control_id_is_declared(self) -> None:
        controls = self.controls_from_yaml(
            "jobs:\n  build:\n    steps:\n      - id: 'control_02'\n"
        )
        self.assertIn(Control("probe.yml", "build", "control_02"), controls)

    def test_double_quoted_control_id_is_declared(self) -> None:
        controls = self.controls_from_yaml(
            'jobs:\n  build:\n    steps:\n      - id: "control_03"\n'
        )
        self.assertIn(Control("probe.yml", "build", "control_03"), controls)

    def test_control_id_with_trailing_comment_is_declared(self) -> None:
        controls = self.controls_from_yaml(
            "jobs:\n  build:\n    steps:\n      - id: control_04 # measured gate\n"
        )
        self.assertIn(Control("probe.yml", "build", "control_04"), controls)

    def test_unparseable_workflow_fails_loudly(self) -> None:
        source = (
            "jobs:\n"
            "  build:\n"
            "    matrix: [unterminated\n"
            "    steps:\n"
            "      - id: control_01\n"
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            workflows = Path(directory)
            workflow = workflows / "malformed.yml"
            workflow.write_text(source, encoding="utf-8")
            allowlist = workflows / "allowlist.json"
            allowlist.write_text(
                json.dumps({"version": 1, "controls": []}), encoding="utf-8"
            )
            with mock.patch.object(aggregate, "WORKFLOWS", workflows):
                with self.assertRaises(aggregate.WorkflowParseError) as raised:
                    workflow_controls()
                resolved = aggregate.resolve_identity(
                    workflow_ref=(
                        "velvetmonkey/seal-host/.github/workflows/"
                        "malformed.yml@refs/heads/test"
                    ),
                    job="build",
                )
                with mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                    exit_code = aggregate.main(allowlist)
        message = str(raised.exception)
        self.assertIn("malformed.yml", message)
        self.assertIn("not valid YAML", message)
        self.assertIsInstance(resolved, str)
        self.assertIn("malformed.yml", resolved)
        self.assertIn("not valid YAML", resolved)
        self.assertEqual(exit_code, 1)
        self.assertIn("malformed.yml", output.getvalue())
        self.assertIn("not valid YAML", output.getvalue())

    def test_quoted_control_id_cannot_hide_from_completeness(self) -> None:
        source = (
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - id: control_01\n"
            '      - id: "control_02"\n'
        )
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            temporary = Path(directory)
            workflows = temporary / "workflows"
            workflows.mkdir()
            (workflows / "probe.yml").write_text(source, encoding="utf-8")
            allowlist = temporary / "allowlist.json"
            allowlist.write_text(
                json.dumps({"version": 1, "controls": []}), encoding="utf-8"
            )
            environment = {
                "GITHUB_WORKFLOW_REF": (
                    "velvetmonkey/seal-host/.github/workflows/"
                    "probe.yml@refs/heads/test"
                ),
                "GITHUB_JOB": "build",
                "SEAL_CONTROL_STEPS": json.dumps(
                    {"control_01": {"outcome": "success"}}
                ),
            }
            with (
                mock.patch.object(aggregate, "WORKFLOWS", workflows),
                mock.patch.dict(os.environ, environment, clear=True),
                mock.patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                exit_code = aggregate.main(allowlist)
        self.assertEqual(exit_code, 1)
        self.assertIn(
            "declared CI control missing from measurement: "
            "probe.yml:build:control_02",
            output.getvalue(),
        )

    def test_honest_full_payload_is_green(self) -> None:
        steps = full_success_steps()
        self.assertIn("control_33", steps)
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        count = len(steps)
        self.assertIn(f"{count} passed", result.stdout)
        self.assertIn(f"{count} reported", result.stdout)
        self.assertIn(f"{count} declared", result.stdout)

    def test_omitting_control_33_fails_completeness(self) -> None:
        steps = full_success_steps()
        del steps["control_33"]
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "declared CI control missing from measurement: ci.yml:build:control_33",
            result.stdout,
        )
        self.assertIn("1 missing", result.stdout)

    def test_single_control_payload_fails_completeness(self) -> None:
        result = self.run_aggregate(
            {"control_01": {"outcome": "success", "conclusion": "success"}}
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("declared CI control missing from measurement", result.stdout)
        self.assertIn("control_33", result.stdout)
        self.assertIn("missing", result.stdout)

    def test_attest_only_payload_fails_completeness(self) -> None:
        result = self.run_aggregate(
            {"attest": {"outcome": "success", "conclusion": "success"}}
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("declared CI control missing from measurement", result.stdout)
        self.assertIn("control_33", result.stdout)

    def test_partial_census_without_control_33_fails(self) -> None:
        """User repro shape: many successes, control_33 absent entirely."""
        steps = {
            name: {"outcome": "success", "conclusion": "success"}
            for name in declared_ids()
            if name != "control_33"
        }
        # Pad with synthetic extras so the reported count is large while the
        # declared control is still missing — the defect the probe hit.
        for index in range(100, 112):
            steps[f"control_{index}"] = {
                "outcome": "success",
                "conclusion": "success",
            }
        self.assertNotIn("control_33", steps)
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "declared CI control missing from measurement: ci.yml:build:control_33",
            result.stdout,
        )

    def test_missing_identity_fails_closed(self) -> None:
        result = self.run_aggregate(full_success_steps(), clear_identity=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("GITHUB_WORKFLOW_REF is missing", result.stdout)

    def test_workflow_ref_missing_at_ref_fails(self) -> None:
        """No @ref at all must not resolve as a workflow path."""
        result = self.run_aggregate(
            full_success_steps(),
            workflow_ref="velvetmonkey/seal-host/.github/workflows/ci.yml",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("missing @ref", result.stdout)
        self.assertIn("GITHUB_WORKFLOW_REF rejected", result.stdout)

    def test_workflow_ref_empty_at_ref_fails(self) -> None:
        result = self.run_aggregate(
            full_success_steps(),
            workflow_ref="velvetmonkey/seal-host/.github/workflows/ci.yml@",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("empty @ref", result.stdout)
        self.assertIn("GITHUB_WORKFLOW_REF rejected", result.stdout)

    def test_workflow_ref_whitespace_at_ref_fails(self) -> None:
        result = self.run_aggregate(
            full_success_steps(),
            workflow_ref="velvetmonkey/seal-host/.github/workflows/ci.yml@   ",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("@ref is empty or whitespace-only", result.stdout)

    def test_workflow_ref_not_under_workflows_dir_fails(self) -> None:
        result = self.run_aggregate(
            full_success_steps(),
            workflow_ref="velvetmonkey/seal-host/not-workflows/ci.yml@refs/heads/test",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not under .github/workflows/", result.stdout)

    def test_workflow_ref_unknown_workflow_file_fails(self) -> None:
        result = self.run_aggregate(
            full_success_steps(),
            workflow_ref=(
                "velvetmonkey/seal-host/.github/workflows/"
                "does-not-exist.yml@refs/heads/test"
            ),
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("not present under .github/workflows/", result.stdout)
        self.assertIn("does-not-exist.yml", result.stdout)

    def test_workflow_ref_path_traversal_file_fails(self) -> None:
        result = self.run_aggregate(
            full_success_steps(),
            workflow_ref=(
                "velvetmonkey/seal-host/.github/workflows/"
                "../ci.yml@refs/heads/test"
            ),
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("single path segment", result.stdout)

    def test_empty_or_whitespace_job_fails(self) -> None:
        for job_env in ("", "   ", "\t"):
            with self.subTest(job_env=repr(job_env)):
                result = self.run_aggregate(
                    full_success_steps(), job_env=job_env
                )
                self.assertEqual(
                    result.returncode, 1, result.stdout + result.stderr
                )
                if job_env == "":
                    self.assertIn("GITHUB_JOB is missing", result.stdout)
                else:
                    self.assertIn(
                        "GITHUB_JOB is empty or whitespace-only", result.stdout
                    )

    def test_unknown_job_fails_closed(self) -> None:
        result = self.run_aggregate(
            {"control_01": {"outcome": "success", "conclusion": "success"}},
            job="does-not-exist",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("GITHUB_JOB rejected", result.stdout)
        self.assertIn("does not exist in workflow 'ci.yml'", result.stdout)
        self.assertIn("does-not-exist", result.stdout)

    def test_failure_remains_red_after_continue_on_error(self) -> None:
        steps = full_success_steps()
        steps["control_01"] = {"outcome": "failure", "conclusion": "success"}
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("control_01", result.stdout)
        self.assertIn("1 failed", result.stdout)

    def test_installer_failure_and_dependents_are_unrunnable(self) -> None:
        steps = full_success_steps()
        reason = "pinned elan v4.2.3 installer download failed: curl exit 22"
        steps["control_05"] = {
            "outcome": "failure",
            "conclusion": "success",
            "outputs": {"unrunnable": "true", "unrunnable-reason": reason},
        }
        steps["control_01"] = {"outcome": "failure", "conclusion": "success"}
        result = self.run_aggregate(
            steps, dependencies={"control_05": ["control_01"]}
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("INFRASTRUCTURE: 0 failed, 2 unrunnable", result.stdout)
        self.assertIn(f"infrastructure cause: control_05: {reason}", result.stdout)
        self.assertIn(f"UNRUNNABLE: control_05 — {reason}", result.stdout)
        self.assertIn(
            f"UNRUNNABLE: control_01 — blocked by control_05: {reason}",
            result.stdout,
        )
        self.assertNotIn("isolated CI step failed", result.stdout)

    def test_real_control_failure_is_not_unrunnable(self) -> None:
        steps = full_success_steps()
        steps["control_01"] = {"outcome": "failure", "conclusion": "success"}
        result = self.run_aggregate(
            steps, dependencies={"control_05": ["control_01"]}
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL: 1 failed, 0 unrunnable", result.stdout)
        self.assertIn("isolated CI step failed: control_01", result.stdout)
        self.assertNotIn("UNRUNNABLE", result.stdout)

    def test_semantic_attestation_id_is_aggregated(self) -> None:
        # attest is not declared on the build job; inject it as an extra
        # reported step so a failed attestation still reddens the aggregate.
        steps = full_success_steps()
        steps["attest"] = {"outcome": "failure", "conclusion": "success"}
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("attest", result.stdout)

    def test_missing_or_vacuous_results_fail_closed(self) -> None:
        for steps in (None, {}, {"setup": {"outcome": "success"}}):
            with self.subTest(steps=steps):
                result = self.run_aggregate(steps)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_skipped_control_off_allowlist_fails(self) -> None:
        steps = full_success_steps()
        steps["control_01"] = {"outcome": "skipped", "conclusion": "skipped"}
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("ci.yml:build:control_01", result.stdout)

    def test_skipped_control_on_allowlist_passes_with_successes(self) -> None:
        steps = full_success_steps()
        steps["control_03"] = {"outcome": "skipped", "conclusion": "skipped"}
        result = self.run_aggregate(steps)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("allowed to skip: ci.yml:build:control_03", result.stdout)
        self.assertIn("1 skipped", result.stdout)
        self.assertIn(f"{len(steps) - 1} passed", result.stdout)

    def test_all_allowlisted_skips_with_zero_successes_fails(self) -> None:
        """Floor: zero successful observations is not a pass, even if skips are allowed."""
        job = "export-surface"
        ids = declared_ids("ci.yml", job)
        self.assertGreaterEqual(len(ids), 1)
        steps = {
            control_id: {"outcome": "skipped", "conclusion": "skipped"}
            for control_id in ids
        }
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            allowlist = Path(directory) / "allowlist.json"
            allowlist.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "controls": [
                            {
                                "workflow": "ci.yml",
                                "job": job,
                                "id": control_id,
                                "reason": "Test allowlist entry for all-skip floor.",
                            }
                            for control_id in ids
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_aggregate(steps, allowlist=allowlist, job=job)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("no successful control observations", result.stdout)
        self.assertIn("0 passed", result.stdout)

    def test_missing_allowlist_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            missing = Path(directory) / "missing.json"
            result = self.run_aggregate(full_success_steps(), allowlist=missing)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("skip allowlist is missing", result.stdout)

    def test_unparseable_allowlist_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            invalid = Path(directory) / "invalid.json"
            invalid.write_text("{not JSON\n", encoding="utf-8")
            result = self.run_aggregate(full_success_steps(), allowlist=invalid)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("skip allowlist is not valid JSON", result.stdout)

    def test_unknown_control_in_allowlist_fails(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            unknown = Path(directory) / "unknown.json"
            unknown.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "controls": [
                            {
                                "workflow": "ci.yml",
                                "job": "build",
                                "id": "control_99",
                                "reason": "Deliberately unknown test control.",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_aggregate(full_success_steps(), allowlist=unknown)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(
            "allowlisted control does not exist in any workflow: "
            "ci.yml:build:control_99",
            result.stdout,
        )


if __name__ == "__main__":
    unittest.main()
