#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Behavioural tests for the PyYAML provisioning population gate.

Every test here builds a fixture tree and requires the gate to go RED on it.
A gate that only ever passes on the real tree proves nothing; these are the
tampers that show it can fail, and fail for the stated reason.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "workflow_pyyaml_gate.py"

AGGREGATOR = """\
import yaml
print(yaml.__version__)
"""

PROVISION = """\
      - name: Provision PyYAML for the workflow-inspecting gates
        uses: ./.github/actions/pyyaml
"""

CHECKOUT = """\
      - id: control_01
        continue-on-error: true
        uses: actions/checkout@v6.0.3
"""

SETUP_PYTHON = """\
      - id: control_02
        continue-on-error: true
        uses: actions/setup-python@v6.0.0
"""

CONSUMER = """\
      - name: Require every isolated CI step to pass
        run: python3 scripts/ci_control_aggregate.py
"""


class WorkflowPyyamlGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / "test").mkdir()
        (self.root / ".github" / "workflows").mkdir(parents=True)
        (self.root / ".github" / "actions" / "pyyaml").mkdir(parents=True)
        (self.root / ".github" / "actions" / "pyyaml" / "action.yml").write_text(
            "name: Provision PyYAML\nruns:\n  using: composite\n  steps: []\n",
            encoding="utf-8",
        )
        (self.root / "scripts" / "ci_control_aggregate.py").write_text(
            AGGREGATOR, encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_workflow(self, name: str, steps: str, job: str = "demo") -> None:
        (self.root / ".github" / "workflows" / name).write_text(
            textwrap.dedent(
                f"""\
                name: {name}
                on:
                  push:
                jobs:
                  {job}:
                    runs-on: ubuntu-latest
                    steps:
                """
            )
            + steps,
            encoding="utf-8",
        )

    def run_gate(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(GATE), "--root", str(self.root), "--no-exemptions"],
            text=True,
            capture_output=True,
            check=False,
        )

    # ------------------------------------------------------------------ green

    def test_provisioned_job_passes(self) -> None:
        self.write_workflow("ci.yml", CHECKOUT + PROVISION + CONSUMER)
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_job_that_needs_nothing_needs_no_provisioning(self) -> None:
        self.write_workflow("ci.yml", CHECKOUT + PROVISION + CONSUMER)
        self.write_workflow(
            "other.yml",
            CHECKOUT + "      - run: echo unrelated\n",
            job="unrelated",
        )
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # -------------------------------------------------------------- the tamper

    def test_consumer_without_provisioning_fails(self) -> None:
        """The population defect itself: a job runs the script, never installs."""
        self.write_workflow("ci.yml", CHECKOUT + PROVISION + CONSUMER)
        self.write_workflow("new.yml", CHECKOUT + CONSUMER, job="fifth")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("new.yml:fifth", result.stderr)
        self.assertIn("never uses ./.github/actions/pyyaml", result.stderr)

    def test_provisioning_after_the_consumer_fails(self) -> None:
        self.write_workflow("ci.yml", CHECKOUT + CONSUMER + PROVISION)
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("after the PyYAML consumer", result.stderr)

    def test_setup_python_after_provisioning_fails(self) -> None:
        """The exact shape that reddened main: a shadowing interpreter."""
        self.write_workflow(
            "ci.yml", CHECKOUT + PROVISION + SETUP_PYTHON + CONSUMER
        )
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("actions/setup-python at step index", result.stderr)

    def test_a_newly_yaml_dependent_script_pulls_its_jobs_in(self) -> None:
        """The population is derived, not enumerated.

        A script that gains `import yaml` must immediately make every job that
        runs it a job that needs provisioning, with no roster edit anywhere.
        """
        self.write_workflow("ci.yml", CHECKOUT + PROVISION + CONSUMER)
        self.write_workflow(
            "new.yml",
            CHECKOUT + "      - run: python3 scripts/fresh_gate.py\n",
            job="fresh",
        )
        (self.root / "scripts" / "fresh_gate.py").write_text(
            "print('no yaml yet')\n", encoding="utf-8"
        )
        self.assertEqual(self.run_gate().returncode, 0)

        (self.root / "scripts" / "fresh_gate.py").write_text(
            "import yaml\nprint(yaml.__version__)\n", encoding="utf-8"
        )
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("new.yml:fresh", result.stderr)

    def test_transitive_dependency_counts(self) -> None:
        """A test that imports the aggregator needs PyYAML just as much.

        test/test_ci_control_aggregate.py is exactly this shape, and it is one
        of the two contract-freeze steps that failed on main.
        """
        self.write_workflow("ci.yml", CHECKOUT + PROVISION + CONSUMER)
        (self.root / "test" / "test_aggregate.py").write_text(
            "import sys\nsys.path.insert(0, 'scripts')\nimport ci_control_aggregate\n",
            encoding="utf-8",
        )
        self.write_workflow(
            "new.yml",
            CHECKOUT + "      - run: python3 test/test_aggregate.py\n",
            job="indirect",
        )
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("new.yml:indirect", result.stderr)

    def test_missing_composite_action_fails(self) -> None:
        self.write_workflow("ci.yml", CHECKOUT + PROVISION + CONSUMER)
        (self.root / ".github" / "actions" / "pyyaml" / "action.yml").unlink()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("shared provisioning action is missing", result.stderr)

    def test_no_consumer_anywhere_is_not_a_vacuous_pass(self) -> None:
        self.write_workflow("ci.yml", CHECKOUT + "      - run: echo hi\n")
        (self.root / "scripts" / "ci_control_aggregate.py").unlink()
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("vacuously", result.stderr)

    # ------------------------------------------------------- exemption hygiene

    def test_a_stale_exemption_is_a_hard_failure(self) -> None:
        """An exemption may not outlive the job it excuses."""
        sys.path.insert(0, str(ROOT / "scripts"))
        import workflow_pyyaml_gate as gate  # noqa: PLC0415

        self.write_workflow("ci.yml", CHECKOUT + PROVISION + CONSUMER)
        failures = gate.check(
            self.root, exemptions={("ci.yml", "gone"): "job was deleted"}
        )
        self.assertTrue(
            any("no longer exists" in failure for failure in failures), failures
        )

    def test_an_exempted_job_that_uses_the_action_is_a_failure(self) -> None:
        sys.path.insert(0, str(ROOT / "scripts"))
        import workflow_pyyaml_gate as gate  # noqa: PLC0415

        self.write_workflow("ci.yml", CHECKOUT + PROVISION + CONSUMER)
        failures = gate.check(
            self.root, exemptions={("ci.yml", "demo"): "no longer needed"}
        )
        self.assertTrue(
            any("delete the exemption" in failure for failure in failures), failures
        )

    def test_the_live_exemption_table_is_not_stale(self) -> None:
        """Every recorded exemption must still name a real, needing job.

        The table is empty as of 2026-08-08: its only entry excused
        ci.yml:rust-conformance-lean, which the Lean-execution consolidation
        deletes, and the entry's own recorded reason instructed that it be
        removed together with the job. This assertion is not relaxed by that
        -- an empty expectation is the strictest form it can take, because any
        exemption added later fails here until it is argued for in the report.
        The gate's ability to catch a stale entry is proved by
        test_a_stale_exemption_is_a_hard_failure above, which injects one.
        """
        sys.path.insert(0, str(ROOT / "scripts"))
        import workflow_pyyaml_gate as gate  # noqa: PLC0415

        self.assertEqual(gate.check(ROOT), [])
        self.assertEqual(
            set(gate.EXEMPTIONS),
            set(),
            "a new exemption is a new hole; state it in the report before adding it",
        )


if __name__ == "__main__":
    unittest.main()
