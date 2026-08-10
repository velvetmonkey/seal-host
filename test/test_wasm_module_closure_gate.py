#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wasm_module_closure_gate.py"
SPEC = importlib.util.spec_from_file_location("wasm_module_closure_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)

EXPORT_SCRIPT = ROOT / "scripts" / "export_surface_gate.py"
EXPORT_SPEC = importlib.util.spec_from_file_location(
    "export_surface_gate", EXPORT_SCRIPT
)
assert EXPORT_SPEC is not None and EXPORT_SPEC.loader is not None
export_gate = importlib.util.module_from_spec(EXPORT_SPEC)
sys.modules[EXPORT_SPEC.name] = export_gate
EXPORT_SPEC.loader.exec_module(export_gate)


class WasmModuleClosureGateTests(unittest.TestCase):
    def test_non_vacuity_floor_is_review_pinned(self) -> None:
        self.assertEqual(
            gate.MODULE_COUNT_FLOOR,
            25,
            "review the wasm MODULES non-vacuity floor explicitly",
        )

    def test_current_wasm_modules_are_closed_under_local_imports(self) -> None:
        report = gate.evaluate()
        self.assertTrue(report.passed, "\n".join(report.errors))
        self.assertEqual(len(report.parsed_modules), 27)
        self.assertEqual(report.missing, ())

    def test_empty_modules_array_hits_non_vacuity_floor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build_core = root / "build_core.sh"
            build_core.write_text("MODULES=()\n", encoding="utf-8")
            report = gate.evaluate(root, build_core)
            self.assertFalse(report.passed)
            self.assertIn("parsed 0 MODULES; refusing vacuous", "\n".join(report.errors))

    def test_unparseable_modules_array_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            build_core = Path(directory) / "build_core.sh"
            build_core.write_text("NOT_MODULES=(Ffi)\n", encoding="utf-8")
            with self.assertRaisesRegex(gate.GateError, "cannot parse MODULES array"):
                gate.parse_modules(build_core)

    def test_reassigned_modules_array_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            build_core = Path(directory) / "build_core.sh"
            build_core.write_text(
                "MODULES=(Ffi)\nMODULES+=(Host/Canonical)\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(gate.GateError, "multiple MODULES assignments"):
                gate.parse_modules(build_core)

    def test_listed_module_without_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            modules = []
            for index in range(gate.MODULE_COUNT_FLOOR - 1):
                name = f"Extra{index}"
                modules.append(name)
                (root / f"{name}.lean").write_text(
                    f"def x{index} := {index}\n",
                    encoding="utf-8",
                )
            modules.append("Host/Missing")
            build_core = root / "build_core.sh"
            build_core.write_text(
                f"MODULES=({' '.join(modules)})\n",
                encoding="utf-8",
            )
            report = gate.evaluate(root, build_core)
            self.assertFalse(report.passed)
            self.assertIn(
                "cannot resolve Lean module Host/Missing imported by MODULES",
                "\n".join(report.errors),
            )

    def test_imported_local_module_must_be_listed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Host").mkdir()
            (root / "Ffi.lean").write_text("import Host.Helper\n", encoding="utf-8")
            (root / "Host" / "Helper.lean").write_text("def helper := 1\n", encoding="utf-8")
            extras = []
            for index in range(gate.MODULE_COUNT_FLOOR - 1):
                name = f"Extra{index}"
                extras.append(name)
                (root / f"{name}.lean").write_text(
                    f"def x{index} := {index}\n",
                    encoding="utf-8",
                )
            build_core = root / "build_core.sh"
            build_core.write_text(
                f"MODULES=(Ffi {' '.join(extras)})\n",
                encoding="utf-8",
            )
            report = gate.evaluate(root, build_core)
            self.assertFalse(report.passed)
            self.assertEqual(report.missing, ("Host.Helper",))
            self.assertIn("Host/Helper", "\n".join(report.errors))


class ExportSurfaceRosterTests(unittest.TestCase):
    """Pin native and wasm roster membership in both directions."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_pinned(
        self, path: Path, name: str, expected: frozenset[str]
    ) -> None:
        findings = export_gate.Findings()
        export_gate.require_exact_roster(
            findings, path.name, path, name, expected
        )
        self.assertEqual(findings.total, 0, findings.sections)

    def roster_copy(self, source: Path, old: str, new: str) -> Path:
        target = Path(self.temporary.name) / source.name
        text = source.read_text(encoding="utf-8")
        self.assertIn(old, text)
        target.write_text(text.replace(old, new, 1), encoding="utf-8")
        return target

    def test_checked_in_rosters_match_all_four_membership_pins(self) -> None:
        self.assert_pinned(
            export_gate.BUILD_FFI_SO,
            "PROJECT_MODULES",
            export_gate.PINNED_PROJECT_MODULES,
        )
        self.assert_pinned(
            export_gate.BUILD_FFI_SO,
            "MCP_MODULES",
            export_gate.PINNED_MCP_MODULES,
        )
        self.assert_pinned(
            export_gate.BUILD_CORE,
            "MODULES",
            export_gate.PINNED_WASM_MODULES,
        )
        self.assert_pinned(
            export_gate.BUILD_CORE,
            "SEAL_MODULES",
            export_gate.PINNED_SEAL_MODULES,
        )

    def test_added_undeclared_project_entry_fails_both_rosters(self) -> None:
        cases = (
            (
                export_gate.BUILD_FFI_SO,
                "PROJECT_MODULES",
                export_gate.PINNED_PROJECT_MODULES,
                "PROJECT_MODULES=(\n",
                "PROJECT_MODULES=(\n  Host/Record\n",
            ),
            (
                export_gate.BUILD_CORE,
                "MODULES",
                export_gate.PINNED_WASM_MODULES,
                "MODULES=(\n",
                "MODULES=(\n  Host/Record\n",
            ),
        )
        for source, name, expected, old, new in cases:
            with self.subTest(name=name):
                tampered = self.roster_copy(source, old, new)
                findings = export_gate.Findings()
                export_gate.require_exact_roster(
                    findings, source.name, tampered, name, expected
                )
                self.assertEqual(findings.total, 1)
                self.assertIn(
                    "undeclared=['Host/Record']", str(findings.sections)
                )

    def test_removed_declared_project_entry_fails_both_rosters(self) -> None:
        cases = (
            (
                export_gate.BUILD_FFI_SO,
                "PROJECT_MODULES",
                export_gate.PINNED_PROJECT_MODULES,
            ),
            (
                export_gate.BUILD_CORE,
                "MODULES",
                export_gate.PINNED_WASM_MODULES,
            ),
        )
        for source, name, expected in cases:
            with self.subTest(name=name):
                tampered = self.roster_copy(source, "  Ffi\n", "")
                findings = export_gate.Findings()
                export_gate.require_exact_roster(
                    findings, source.name, tampered, name, expected
                )
                self.assertEqual(findings.total, 1)
                self.assertIn("missing=['Ffi']", str(findings.sections))

    def test_added_and_removed_entries_fail_both_mcp_roster_pins(self) -> None:
        cases = (
            (
                export_gate.BUILD_FFI_SO,
                "MCP_MODULES",
                export_gate.PINNED_MCP_MODULES,
            ),
            (
                export_gate.BUILD_CORE,
                "SEAL_MODULES",
                export_gate.PINNED_SEAL_MODULES,
            ),
        )
        for source, name, expected in cases:
            with self.subTest(name=name, direction="addition"):
                tampered = self.roster_copy(
                    source, "  SealCore ", "  SealCore Seal/Undeclared "
                )
                findings = export_gate.Findings()
                export_gate.require_exact_roster(
                    findings, source.name, tampered, name, expected
                )
                self.assertIn("Seal/Undeclared", str(findings.sections))
            with self.subTest(name=name, direction="removal"):
                tampered = self.roster_copy(source, "  SealCore ", "  ")
                findings = export_gate.Findings()
                export_gate.require_exact_roster(
                    findings, source.name, tampered, name, expected
                )
                self.assertIn("SealCore", str(findings.sections))

    def test_absent_input_fails(self) -> None:
        path = Path(self.temporary.name) / "absent.sh"
        with self.assertRaisesRegex(export_gate.GateError, "cannot read"):
            export_gate.require_exact_roster(
                export_gate.Findings(),
                "absent",
                path,
                "MODULES",
                frozenset({"Ffi"}),
            )

    def test_empty_file_and_empty_array_fail(self) -> None:
        path = Path(self.temporary.name) / "empty.sh"
        path.write_text("", encoding="utf-8")
        with self.assertRaisesRegex(export_gate.GateError, "found 0"):
            export_gate.require_exact_roster(
                export_gate.Findings(),
                "empty",
                path,
                "MODULES",
                frozenset({"Ffi"}),
            )
        path.write_text("MODULES=()\n", encoding="utf-8")
        with self.assertRaisesRegex(export_gate.GateError, "is empty"):
            export_gate.require_exact_roster(
                export_gate.Findings(),
                "empty",
                path,
                "MODULES",
                frozenset({"Ffi"}),
            )

    def test_malformed_input_fails(self) -> None:
        path = Path(self.temporary.name) / "malformed.sh"
        path.write_text("MODULES=(Ffi\n", encoding="utf-8")
        with self.assertRaisesRegex(export_gate.GateError, "unterminated"):
            export_gate.require_exact_roster(
                export_gate.Findings(),
                "malformed",
                path,
                "MODULES",
                frozenset({"Ffi"}),
            )

    def test_unreadable_input_fails(self) -> None:
        path = Path(self.temporary.name) / "unreadable.sh"
        path.write_text("MODULES=(Ffi)\n", encoding="utf-8")
        with mock.patch.object(
            Path, "read_text", side_effect=PermissionError("permission denied")
        ):
            with self.assertRaisesRegex(
                export_gate.GateError, "cannot read.*permission denied"
            ):
                export_gate.require_exact_roster(
                    export_gate.Findings(),
                    "unreadable",
                    path,
                    "MODULES",
                    frozenset({"Ffi"}),
                )


if __name__ == "__main__":
    unittest.main()
