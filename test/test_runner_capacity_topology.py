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

# The release-evidence conjunction, pinned EXACTLY. Reviewed 2026-08-05.
#
# `release-evidence` is the only job in any workflow that consumes
# `toJSON(needs)` as evidence: `scripts/release_evidence_gate.py` fails unless
# every job REPORTED to it succeeded. It is therefore silent about any job that
# is not in the list. Until this pulse two top-level ci.yml jobs were missing,
# and nothing observed the omission:
#   * export-surface        gates the four hand-maintained export surfaces
#                           against `Ffi.lean`. One of them is the
#                           `scripts/build_ffi_so.sh` roster that release.yml
#                           control_10 runs to produce the shipped
#                           `libsealffi.so`; two more (the wasm C wrapper and
#                           the emscripten allow-list) fail SILENTLY at link.
#                           This gate runs in exactly one place fleet-wide.
#   * kernel-hash-footprint gates `release/kernel-hash-footprint.json` and
#                           proves every fleet-lock repository was scanned. The
#                           identical two steps are release.yml `fleet-gate`
#                           control_03/control_04, and `publish` needs
#                           `fleet-gate` — so a stale footprint hard-blocks
#                           publication at tag time while push CI stayed green.
#
# The earlier monotonicity proof over this list was a proof about the LISTED
# set; it could not see an omission. Completeness is what this pin asserts, in
# both directions:
#   1. set(needs) == PIN            — a removal AND an addition are visible.
#   2. every ci.yml job (minus the  — a NEW ci.yml job that nobody wired into
#      gate itself, minus EXEMPT)     the conjunction is visible too, which is
#      == PIN                         the failure mode that produced this pin.
# Bump this literal only with the reason written down, the way the run-step
# inventory pin in test/pins_gate_meta.test.mjs is bumped.
RELEASE_EVIDENCE_NEEDS = frozenset(
    {
        "export-surface",
        "kernel-hash-footprint",
        "build",
        "rust-conformance",
        "contract-freeze",
        "cargo-audit",
        "rust-sbom",
    }
)
# Top-level ci.yml jobs deliberately OUTSIDE the conjunction. Empty today. An
# entry here is a written claim that the job enforces nothing release-relevant;
# "prior design" is not such a claim.
RELEASE_EVIDENCE_EXEMPT: frozenset[str] = frozenset()


def workflow_job_ids(path: Path) -> set[str]:
    """Every job id declared under `jobs:`, including step-less `uses:` jobs.

    job_step_blocks() only sees jobs that carry their own steps, so a job
    that delegates to a reusable workflow (`uses: ./.github/workflows/...`)
    is invisible to it. Conjunction-completeness checks must enumerate ALL
    jobs: a delegating job outside the conjunction would otherwise be exactly
    the invisible-omission failure mode this file exists to prevent.
    """
    ids: set[str] = set()
    in_jobs = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if re.fullmatch(r"[A-Za-z0-9_-]+:.*", line):
            in_jobs = line.startswith("jobs:")
            continue
        if in_jobs:
            job = re.fullmatch(r"  ([a-z0-9-]+):", line)
            if job:
                ids.add(job.group(1))
    return ids


def job_needs(path: Path) -> dict[str, list[str]]:
    """Return each job's declared `needs:` names, in declaration order."""
    needs: dict[str, list[str]] = {}
    current_job: str | None = None
    in_needs = False

    for line in path.read_text(encoding="utf-8").splitlines():
        job = re.fullmatch(r"  ([a-z0-9-]+):", line)
        if job:
            current_job = job.group(1)
            in_needs = False
            continue
        if current_job is None:
            continue
        inline = re.fullmatch(r"    needs: (.+)", line)
        if inline:
            value = inline.group(1).strip()
            if value.startswith("["):
                value = value.strip("[]")
            needs[current_job] = [
                name.strip().strip("\"'")
                for name in value.split(",")
                if name.strip()
            ]
            in_needs = False
            continue
        if line == "    needs:":
            needs[current_job] = []
            in_needs = True
            continue
        if in_needs:
            item = re.fullmatch(r"      - (\S+)", line)
            if item:
                needs[current_job].append(item.group(1))
            else:
                in_needs = False
    return needs


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
        lean = "\n".join("\n".join(step) for step in jobs["build"])
        rust = "\n".join("\n".join(step) for step in jobs["rust-conformance"])
        self.assertNotIn("rust-conformance-lean", jobs)
        self.assertIn("lake test 2>&1 | tee /tmp/axioms.txt", lean)
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
        self.assertNotRegex(rust, r"(?m)^\s*run: lake build\s*$")

    def test_release_evidence_conjunction_is_exactly_the_pinned_set(self) -> None:
        ci = ROOT / ".github" / "workflows" / "ci.yml"
        declared = job_needs(ci).get("release-evidence")
        self.assertIsNotNone(declared, "release-evidence declares no needs")
        self.assertEqual(
            len(declared), len(set(declared)), f"duplicate needs: {declared}"
        )
        self.assertEqual(
            set(declared),
            set(RELEASE_EVIDENCE_NEEDS),
            "release-evidence.needs drifted from the pinned set; a job was "
            "added or REMOVED without review",
        )

    def test_every_ci_job_reaches_the_release_evidence_gate(self) -> None:
        ci = ROOT / ".github" / "workflows" / "ci.yml"
        gated = workflow_job_ids(ci) - {"release-evidence"}
        self.assertEqual(
            gated - RELEASE_EVIDENCE_EXEMPT,
            set(RELEASE_EVIDENCE_NEEDS),
            "a top-level ci.yml job is outside the release-evidence "
            "conjunction and outside RELEASE_EVIDENCE_EXEMPT; its failure "
            "cannot fail the gate",
        )

    def test_release_publish_conjunction_covers_every_sibling_job(self) -> None:
        release = ROOT / ".github" / "workflows" / "release.yml"
        jobs = workflow_job_ids(release)
        self.assertEqual(
            set(job_needs(release)["publish"]),
            jobs - {"publish"},
            "release.yml publish must depend on every other job in the "
            "workflow; publication is the irreversible effect",
        )

    def test_telemetry_phases_cover_capacity_sensitive_workflows(self) -> None:
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
        self.assertNotIn("ci-lean-aggregate", ci)
        self.assertIn("ci-free-ballast", ci)
        self.assertIn("ci-rust-release", ci)


if __name__ == "__main__":
    unittest.main()
