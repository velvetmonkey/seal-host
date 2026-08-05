#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Structural guards for the three-workflow runner disk-capacity split."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

from test_ci_control_reporting import job_step_blocks


ROOT = Path(__file__).resolve().parents[1]
FUZZ_COMMAND = (
    "cargo +nightly fuzz run hostile_ingress -- -max_total_time=60 -timeout=5"
)


class RunnerCapacityTopologyTests(unittest.TestCase):
    def test_security_fuzz_still_runs_real_fuzz(self) -> None:
        jobs = job_step_blocks(ROOT / ".github" / "workflows" / "security.yml")
        lean = "\n".join("\n".join(step) for step in jobs["fuzz-hostile-ingress-lean"])
        fuzz = "\n".join("\n".join(step) for step in jobs["fuzz-hostile-ingress"])
        self.assertIn("security-lean-aggregate -- lake test", lean)
        self.assertNotIn(FUZZ_COMMAND, lean)
        self.assertIn(FUZZ_COMMAND, fuzz)
        self.assertIn("python3 ../scripts/ci_disk_telemetry.py security-fuzz", fuzz)
        self.assertNotIn(" lake test", fuzz)

    def test_golden_path_acceptance_still_runs_real_demos(self) -> None:
        jobs = job_step_blocks(ROOT / ".github" / "workflows" / "golden-path.yml")
        lean = "\n".join("\n".join(step) for step in jobs["lean-aggregate"])
        shell = "\n".join("\n".join(step) for step in jobs["deterministic-shell"])
        self.assertIn("golden-lean-aggregate -- lake test", lean)
        self.assertNotIn("./demo/run c1", lean)
        self.assertIn("golden-rust-acceptance", shell)
        self.assertIn("./demo/run c1", shell)
        self.assertIn("./demo/run c2", shell)
        self.assertIn("python3 demo/golden_path.py filesystem", shell)
        self.assertNotIn(" lake test", shell)

    def test_ci_rust_conformance_still_runs_real_conformance(self) -> None:
        jobs = job_step_blocks(ROOT / ".github" / "workflows" / "ci.yml")
        lean = "\n".join("\n".join(step) for step in jobs["rust-conformance-lean"])
        rust = "\n".join("\n".join(step) for step in jobs["rust-conformance"])
        self.assertIn("ci-lean-aggregate -- lake test", lean)
        self.assertNotIn("cargo build --release --bins", lean)
        self.assertNotIn("cargo test --no-fail-fast", lean)
        self.assertIn(
            "python3 ../scripts/ci_disk_telemetry.py ci-rust-release -- "
            "cargo build --release --bins",
            rust,
        )
        self.assertIn("ci-free-ballast", rust)
        self.assertIn("/usr/share/dotnet", rust)
        self.assertIn("cargo test --no-fail-fast", rust)
        self.assertIn("cargo test --test envelope_v23_twin", rust)
        self.assertIn("SEAL_THREE_WAY_CASES=25000", rust)
        self.assertIn("scripts/build_ffi_so.sh", rust)
        self.assertNotIn(" lake test", rust)
        self.assertNotIn("ci-lean-aggregate", rust)

    def test_telemetry_phases_cover_all_three_workflows(self) -> None:
        security = (ROOT / ".github" / "workflows" / "security.yml").read_text(
            encoding="utf-8"
        )
        golden = (ROOT / ".github" / "workflows" / "golden-path.yml").read_text(
            encoding="utf-8"
        )
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("security-lean-aggregate", security)
        self.assertIn("security-fuzz", security)
        self.assertIn("golden-lean-aggregate", golden)
        self.assertIn("golden-rust-acceptance", golden)
        self.assertIn("ci-lean-aggregate", ci)
        self.assertIn("ci-free-ballast", ci)
        self.assertIn("ci-rust-release", ci)


if __name__ == "__main__":
    unittest.main()
