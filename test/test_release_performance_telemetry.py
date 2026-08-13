#!/usr/bin/env python3
"""Behavioral tests for release performance JSONL instrumentation."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TELEMETRY = ROOT / "scripts" / "release_performance_telemetry.py"


class ReleasePerformanceTelemetryTests(unittest.TestCase):
    def run_probe(self, cache: Path, report: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["python3", str(TELEMETRY), "--phase", "probe", "--architecture", "x86_64",
             "--report", str(report), "--cache-key", "deliberate-key", "--cache-path", str(cache),
             "--cache-mode", "restore", "--", "bash", "-c", f"mkdir -p {cache}; printf restored > {cache}/entry"],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )

    def test_miss_then_hit_are_named_and_diffable(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            root = Path(directory)
            cache, report = root / "cache", root / "report.jsonl"
            miss = self.run_probe(cache, report)
            hit = self.run_probe(cache, report)
            self.assertEqual(miss.returncode, 0, miss.stdout + miss.stderr)
            self.assertEqual(hit.returncode, 0, hit.stdout + hit.stderr)
            events = [json.loads(line) for line in report.read_text(encoding="utf-8").splitlines()]
        finished = [event for event in events if event["event"] == "phase-finish"]
        self.assertEqual(finished[0]["cache_miss_count"], 1)
        self.assertEqual(finished[0]["caches"][0]["key"], "deliberate-key")
        self.assertGreater(finished[0]["caches"][0]["bytes_restored"], 0)
        self.assertEqual(finished[1]["cache_hit_count"], 1)
        self.assertEqual(finished[1]["caches"][0]["bytes_saved"], 0)

    def test_release_matrix_emits_and_uploads_both_architectures(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("runner: ubuntu-24.04", workflow)
        self.assertIn("runner: ubuntu-24.04-arm", workflow)
        self.assertIn("aggregate-lean-tests", workflow)
        self.assertIn("release-performance-${{ matrix.arch }}.jsonl", workflow)
        self.assertIn("release-performance-${{ github.ref_name }}-linux-${{ matrix.arch }}", workflow)


if __name__ == "__main__":
    unittest.main()
