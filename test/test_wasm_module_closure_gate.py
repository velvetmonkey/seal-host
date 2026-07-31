#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "wasm_module_closure_gate.py"
SPEC = importlib.util.spec_from_file_location("wasm_module_closure_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


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
        self.assertEqual(len(report.parsed_modules), 26)
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


if __name__ == "__main__":
    unittest.main()
