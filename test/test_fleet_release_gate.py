#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the release fleet lock's fail-closed boundary."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fleet_release_gate.py"
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
REPOSITORIES = (
    "seal-check",
    "seal-assurance-kit",
    "seal-verify-action",
    "seal-demo",
    "seal-live-demo",
)


class FleetReleaseGateTests(unittest.TestCase):
    def run_gate(self, lock_contents: str | None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="fleet-gate-test-") as temporary:
            root = Path(temporary)
            (root / "scripts").mkdir()
            (root / "release").mkdir()
            shutil.copy2(SCRIPT, root / "scripts" / SCRIPT.name)
            lock = root / "release" / "fleet-lock.json"
            if lock_contents is not None:
                lock.write_text(lock_contents, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(root / "scripts" / SCRIPT.name), "--validate-lock"],
                text=True,
                capture_output=True,
                timeout=10,
            )

    def valid_lock(self) -> dict[str, object]:
        return {
            "schema": 1,
            "kernel_sha256": "a" * 64,
            "repositories": {
                name: {
                    "url": f"https://example.invalid/{name}.git",
                    "commit": "b" * 40,
                    "wasm": ["kernel/seal.wasm"],
                }
                for name in REPOSITORIES
            },
        }

    def test_missing_lock_exits_nonzero(self) -> None:
        result = self.run_gate(None)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fleet lock rejected", result.stderr)

    def test_empty_lock_exits_nonzero(self) -> None:
        result = self.run_gate("")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fleet lock rejected", result.stderr)

    def test_unknown_lock_key_exits_nonzero(self) -> None:
        lock = self.valid_lock()
        lock["unknown"] = True
        result = self.run_gate(json.dumps(lock))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("fleet lock rejected", result.stderr)

    def test_release_workflow_runs_fleet_gate(self) -> None:
        # The fleet gate command lives exactly once, in the reusable
        # acceptance workflow (roadmap 8y item 8); the release workflow must
        # invoke that workflow so the tag path still runs the gate.
        acceptance = (
            ROOT / ".github" / "workflows" / "acceptance.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("python3 scripts/fleet_release_gate.py", acceptance)
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("uses: ./.github/workflows/acceptance.yml", workflow)
        self.assertIn("secrets: inherit", workflow)


if __name__ == "__main__":
    unittest.main()
