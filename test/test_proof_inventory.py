#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "proof_inventory.py"
SPEC = importlib.util.spec_from_file_location("proof_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
inventory = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = inventory
SPEC.loader.exec_module(inventory)


class ProofInventoryTests(unittest.TestCase):
    def make_root(self, directory: str) -> Path:
        root = Path(directory)
        (root / "Host").mkdir()
        (root / "Test").mkdir()
        (root / ".github/workflows").mkdir(parents=True)
        (root / "lakefile.toml").write_text(
            'name = "fixture"\n'
            'testDriver = "lean_tests"\n'
            'defaultTargets = ["ci_root"]\n\n'
            '[[lean_lib]]\nname = "HostLib"\nglobs = ["Host.+"]\n\n'
            '[[lean_exe]]\nname = "ci_root"\nroot = "Test.CiRoot"\n\n'
            '[[lean_exe]]\nname = "lean_tests"\nroot = "Test.CiRoot"\n',
            encoding="utf-8",
        )
        (root / ".github/workflows/ci.yml").write_text(
            "name: CI\non: [push, pull_request]\njobs:\n  build:\n    steps:\n"
            "      - id: control_a\n        run: lake build\n"
            "      - id: control_b\n        run: lake test\n",
            encoding="utf-8",
        )
        (root / "proof-build-targets.toml").write_text(
            "[[invocation]]\n"
            'workflow = "ci.yml"\njob = "build"\nstep = "control_a"\n'
            'kind = "build"\ntarget = ""\nguard = ""\n\n'
            "[[invocation]]\n"
            'workflow = "ci.yml"\njob = "build"\nstep = "control_b"\n'
            'kind = "test"\ntarget = ""\nguard = ""\n',
            encoding="utf-8",
        )
        (root / "Test/CiRoot.lean").write_text(
            "import Host.Wired\n", encoding="utf-8"
        )
        (root / "Host/Wired.lean").write_text(
            "theorem wired : True := by trivial\n", encoding="utf-8"
        )
        return root

    def add_step(self, root: Path, step_id: str, script: str, step_if: str | None = None) -> None:
        workflow = root / ".github/workflows/ci.yml"
        block = f"      - id: {step_id}\n"
        if step_if is not None:
            block += f"        if: {step_if}\n"
        body = "\n".join(f"          {line}" for line in script.splitlines())
        block += f"        run: |\n{body}\n"
        workflow.write_text(workflow.read_text(encoding="utf-8") + block, encoding="utf-8")

    def add_row(self, root: Path, **fields: str) -> None:
        manifest = root / "proof-build-targets.toml"
        row = "\n[[invocation]]\n" + "".join(f'{key} = "{value}"\n' for key, value in fields.items())
        manifest.write_text(manifest.read_text(encoding="utf-8") + row, encoding="utf-8")

    def add_workflow(self, root: Path, name: str, trigger: str, target: str) -> None:
        (root / ".github/workflows" / name).write_text(
            f"name: Trigger probe\n{trigger}\njobs:\n  probe:\n    steps:\n"
            f"      - id: control_probe\n        run: lake build {target}\n",
            encoding="utf-8",
        )
        self.add_row(
            root,
            workflow=name,
            job="probe",
            step="control_probe",
            kind="build",
            target=target,
            guard="",
        )

    def plant_orphan(self, root: Path, module: str = "Host.Planted") -> None:
        path = root / (module.replace(".", "/") + ".lean")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("theorem planted : True := by trivial\n", encoding="utf-8")

    def assert_construction_does_not_reach(self, script: str, step_if: str | None = None) -> None:
        """A never-executed construction must not launder the planted orphan."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            self.plant_orphan(root)
            self.add_step(root, "control_probe", script, step_if)
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Planted", result.stdout)
            self.assertNotIn("REACHED\tHost.Planted", result.stdout)

    def assert_declaration_refused(self, script: str, step_if: str | None = None) -> None:
        """Declaring the construction on purpose must be refused, not honoured."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            self.plant_orphan(root)
            self.add_step(root, "control_probe", script, step_if)
            self.add_row(
                root,
                workflow="ci.yml",
                job="build",
                step="control_probe",
                kind="build",
                target="Host.Planted",
                guard="",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Planted", result.stdout)
            self.assertNotIn("REACHED\tHost.Planted", result.stdout)

    def run_gate(self, root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(root)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def assert_orphan_source(self, source: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Evasion.lean").write_text(source, encoding="utf-8")
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Evasion", result.stdout)

    def test_workflow_build_closure_is_reached(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_gate(self.make_root(directory))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("REACHED=1", result.stdout)
            self.assertIn("REACHED\tHost.Wired", result.stdout)

    def test_orphan_control_is_red_and_names_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Planted.lean").write_text(
                "theorem planted_orphan : True := by trivial\n", encoding="utf-8"
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Planted", result.stdout)
            self.assertIn("ORPHAN PROOF MODULE: Host.Planted", result.stderr)

    def test_protected_theorem_is_detected(self) -> None:
        self.assert_orphan_source("protected theorem t : True := by trivial\n")

    def test_private_theorem_is_detected(self) -> None:
        self.assert_orphan_source("private theorem t : True := by trivial\n")

    def test_same_line_attribute_theorem_is_detected(self) -> None:
        self.assert_orphan_source("@[simp] theorem t : True := by trivial\n")

    def test_nonrec_theorem_is_detected(self) -> None:
        self.assert_orphan_source("nonrec theorem t : True := by trivial\n")

    def test_indented_theorem_is_detected(self) -> None:
        self.assert_orphan_source("  theorem t : True := by trivial\n")

    def test_comment_markers_in_strings_do_not_hide_theorem(self) -> None:
        self.assert_orphan_source(
            'def openMarker : String := "/-"\n'
            "theorem visible_after_string : True := by trivial\n"
            'def closeMarker : String := "-/"\n'
        )

    def test_comment_markers_in_raw_strings_do_not_hide_theorem(self) -> None:
        self.assert_orphan_source(
            'def markers : String := r#"/- an embedded " quote -/"#\n'
            "theorem visible_after_raw_string : True := by trivial\n"
        )

    def test_severance_control_is_red_and_names_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Test/CiRoot.lean").write_text("", encoding="utf-8")
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Wired", result.stdout)
            self.assertIn("ORPHAN PROOF MODULE: Host.Wired", result.stderr)

    def test_one_character_local_root_typo_is_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Typo.lean").write_text(
                "import Hosts.Wired\n"
                "theorem typo_probe : True := by trivial\n",
                encoding="utf-8",
            )
            (root / "Test/CiRoot.lean").write_text(
                "import Host.Wired\nimport Host.Typo\n", encoding="utf-8"
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("UNCLASSIFIED\tHost.Typo", result.stdout)
            self.assertIn("cannot resolve import Hosts.Wired", result.stderr)

    def test_nonexistent_upstream_import_is_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/Upstream.lean").write_text(
                "import Mathlib.CompletelyFakeInventoryControl\n"
                "theorem upstream_probe : True := by trivial\n",
                encoding="utf-8",
            )
            (root / "Test/CiRoot.lean").write_text(
                "import Host.Wired\nimport Host.Upstream\n", encoding="utf-8"
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("UNCLASSIFIED\tHost.Upstream", result.stdout)
            self.assertIn(
                "cannot resolve import Mathlib.CompletelyFakeInventoryControl",
                result.stderr,
            )

    def test_circular_import_is_unclassified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Host/CycleA.lean").write_text(
                "import Host.CycleB\n"
                "theorem cycle_probe : True := by trivial\n",
                encoding="utf-8",
            )
            (root / "Host/CycleB.lean").write_text(
                "import Host.CycleA\n", encoding="utf-8"
            )
            (root / "Test/CiRoot.lean").write_text(
                "import Host.Wired\nimport Host.CycleA\n", encoding="utf-8"
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("UNCLASSIFIED\tHost.CycleA", result.stdout)
            self.assertIn("circular local import", result.stderr)

    def test_comments_strings_and_modifiers_do_not_evade_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Test/CiRoot.lean").write_text(
                "import Host.Wired\nimport Host.Prefixes\n", encoding="utf-8"
            )
            (root / "Host/Prefixes.lean").write_text(
                '/- theorem fake : False := by trivial -/\n'
                'def prose : String := "theorem alsoFake : False"\n'
                "@[simp] protected theorem real : True := by trivial\n",
                encoding="utf-8",
            )
            report = inventory.evaluate(root)
            row = next(row for row in report.rows if row.module == "Host.Prefixes")
            self.assertEqual(row.declarations, 1)
            self.assertEqual(row.status, "REACHED")

    def test_workflow_comments_and_echoes_are_not_builds(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text(
                "name: CI\non: push\njobs:\n  build:\n    steps:\n"
                "      - id: control_a\n"
                "        run: |\n"
                "          # lake build Host.NotACommand\n"
                '          echo "lake build Host.NotACommand"\n'
                "          echo lake build Host.AlsoNotACommand\n"
                "          lake build\n",
                encoding="utf-8",
            )
            steps = inventory.read_workflow_steps(root)
            found, errors = inventory.discover_lake_commands(steps)
            self.assertEqual(errors, [])
            self.assertEqual(len(found), 1)
            self.assertEqual(found[0].kind, "build")
            self.assertEqual(found[0].target, "")

    # -- the five never-executed constructions, each named, each tested -------
    #
    # Layer one: none of them may grant REACHED, because nothing found in
    # workflow text grants anything. Layer two: declaring one on purpose in
    # proof-build-targets.toml must be refused rather than honoured.

    def test_w1_echoed_lake_command_does_not_reach(self) -> None:
        self.assert_construction_does_not_reach("echo lake build Host.Planted")

    def test_w1_echoed_lake_command_cannot_be_declared(self) -> None:
        self.assert_declaration_refused("echo lake build Host.Planted")

    def test_w2_constant_false_branch_does_not_reach(self) -> None:
        self.assert_construction_does_not_reach(
            "if false; then\n  lake build Host.Planted\nfi"
        )

    def test_w2_constant_false_branch_cannot_be_declared(self) -> None:
        self.assert_declaration_refused(
            "if false; then\n  lake build Host.Planted\nfi"
        )

    def test_w3_heredoc_body_does_not_reach(self) -> None:
        self.assert_construction_does_not_reach(
            'cat > /tmp/never.sh <<"EOF"\nlake build Host.Planted\nEOF\necho wrote it'
        )

    def test_w3_heredoc_body_cannot_be_declared(self) -> None:
        self.assert_declaration_refused(
            'cat > /tmp/never.sh <<"EOF"\nlake build Host.Planted\nEOF\necho wrote it'
        )

    def test_w4_statically_disabled_step_does_not_reach(self) -> None:
        self.assert_construction_does_not_reach(
            "lake build Host.Planted", step_if="${{ false }}"
        )

    def test_w4_statically_disabled_step_cannot_be_declared(self) -> None:
        self.assert_declaration_refused(
            "lake build Host.Planted", step_if="${{ false }}"
        )

    def test_w5_command_after_unconditional_exit_does_not_reach(self) -> None:
        self.assert_construction_does_not_reach("exit 0\nlake build Host.Planted")

    def test_w5_command_after_unconditional_exit_cannot_be_declared(self) -> None:
        self.assert_declaration_refused("exit 0\nlake build Host.Planted")

    # -- the parser is used only to refute -----------------------------------

    def test_line_continuation_does_not_destroy_the_inventory(self) -> None:
        """A trailing backslash previously zeroed every counter in the report."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            self.add_step(root, "control_probe", "lake build \\\n  Host.Wired")
            report = inventory.evaluate(root)
            self.assertEqual(len(report.rows), 1)
            self.assertTrue(
                any("undeclared lake invocation" in error for error in report.errors),
                report.errors,
            )

    def test_undeclared_live_invocation_fails_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            self.add_step(root, "control_probe", "lake build Host.Wired")
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("undeclared lake invocation", result.stderr)

    def test_declared_step_that_does_not_exist_fails_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            self.add_row(
                root,
                workflow="ci.yml",
                job="build",
                step="control_imaginary",
                kind="build",
                target="Host.Wired",
                guard="",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("declared workflow/job/step does not exist", result.stderr)

    def test_manual_only_workflow_is_named_and_cannot_grant_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Test/CiRoot.lean").write_text("", encoding="utf-8")
            self.add_workflow(
                root,
                "manual-probe.yml",
                "on:\n  workflow_dispatch:",
                "Host.Wired",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("credited-invocations=2", result.stdout)
            self.assertIn("trigger-excepted=1", result.stdout)
            self.assertIn(
                "TRIGGER-EXCEPTED\tmanual-probe.yml:probe:control_probe",
                result.stdout,
            )
            self.assertIn("ORPHANED\tHost.Wired", result.stdout)

    def test_tag_only_workflow_is_named_and_cannot_grant_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Test/CiRoot.lean").write_text("", encoding="utf-8")
            self.add_workflow(
                root,
                "tag-probe.yml",
                'on:\n  push:\n    tags: ["v*"]',
                "Host.Wired",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("TRIGGER-EXCEPTED\ttag-probe.yml:probe:control_probe", result.stdout)
            self.assertIn("push trigger is tag-only", result.stdout)
            self.assertIn("ORPHANED\tHost.Wired", result.stdout)

    def test_inverse_removing_push_loses_each_ci_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8").replace(
                    "on: [push, pull_request]", "on: [pull_request]"
                ),
                encoding="utf-8",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("credited-invocations=0", result.stdout)
            self.assertIn("trigger-excepted=2", result.stdout)
            self.assertIn("ci.yml:build:control_a", result.stdout)
            self.assertIn("ci.yml:build:control_b", result.stdout)
            self.assertIn("ORPHANED\tHost.Wired", result.stdout)

    def test_unparseable_trigger_fails_closed_without_credit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8").replace(
                    "on: [push, pull_request]", "on: {push: null}"
                ),
                encoding="utf-8",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("credited-invocations=0", result.stdout)
            self.assertIn("cannot classify workflow trigger", result.stderr)
            self.assertIn("flow mappings are unsupported", result.stderr)
            self.assertIn("ORPHANED\tHost.Wired", result.stdout)

    def test_default_branch_filter_refutes_main(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8").replace(
                    "on: [push, pull_request]",
                    "on:\n  push:\n    branches: [develop]\n  pull_request:",
                ),
                encoding="utf-8",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("push.branches excludes refs/heads/main", result.stdout)
            self.assertIn("credited-invocations=0", result.stdout)

    def test_extended_branch_pattern_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8").replace(
                    "on: [push, pull_request]",
                    'on:\n  push:\n    branches: ["ma+n"]\n  pull_request:',
                ),
                encoding="utf-8",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("credited-invocations=0", result.stdout)
            self.assertIn("unsupported branch-pattern metacharacters", result.stderr)

    def test_guard_drift_is_detected(self) -> None:
        """Removing a step's if: guard must not pass silently."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            self.add_step(root, "control_probe", "lake build Host.Wired", step_if="${{ true }}")
            self.add_row(
                root,
                workflow="ci.yml",
                job="build",
                step="control_probe",
                kind="build",
                target="Host.Wired",
                guard="",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("declared guard", result.stderr)

    def test_rejected_row_confers_no_reachability(self) -> None:
        """A row that fails the cross-check must not still print REACHED."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.make_root(directory)
            (root / "Test/CiRoot.lean").write_text("", encoding="utf-8")
            self.plant_orphan(root, "Host.Solo")
            self.add_row(
                root,
                workflow="ci.yml",
                job="build",
                step="control_imaginary",
                kind="build",
                target="Host.Solo",
                guard="",
            )
            result = self.run_gate(root)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("ORPHANED\tHost.Solo", result.stdout)
            self.assertNotIn("REACHED\tHost.Solo", result.stdout)

    def test_conditional_early_exit_leaves_later_commands_alive(self) -> None:
        """golden-path.yml:92-102 -- a guarded exit 0 must not kill the builds."""
        commands = inventory.analyze_shell(
            'if git diff --quiet; then\n  echo no changes\n  exit 0\nfi\n'
            "lake build Host.Wired\n"
        )
        build = next(command for command in commands if command.words[0] == "lake")
        self.assertFalse(build.dead)
        self.assertTrue(build.conditional)

    def test_command_position_survives_a_semicolon_and_a_pipe(self) -> None:
        """ci.yml:191 -- `set -o pipefail; lake exe axiom_check 2>&1 | tee f`."""
        commands = inventory.analyze_shell(
            "set -o pipefail; lake exe axiom_check 2>&1 | tee /tmp/axioms.txt\n"
        )
        build = next(command for command in commands if command.words[0] == "lake")
        self.assertEqual(build.words, ("lake", "exe", "axiom_check"))
        self.assertFalse(build.dead)
        self.assertFalse(build.conditional)

    def test_exception_is_named_and_not_laundered_as_reached(self) -> None:
        self.assertEqual(
            set(inventory.EXCEPTIONS), {"Host.CanonicalL0Liveness"}
        )
        self.assertIn(
            "Ben, 2026-08-01", inventory.EXCEPTIONS["Host.CanonicalL0Liveness"]
        )


if __name__ == "__main__":
    unittest.main()
