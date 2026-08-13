#!/usr/bin/env python3
"""Emit diffable release-phase and cache observations without changing builds."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def directory_bytes(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def resources(path: Path) -> dict[str, int]:
    stat = os.statvfs(path)
    memory: dict[str, int] = {}
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition(":")
        if separator and key in {"MemTotal", "MemAvailable"}:
            memory[key] = int(value.split()[0]) * 1024
    return {
        "disk_capacity_bytes": stat.f_blocks * stat.f_frsize,
        "disk_available_bytes": stat.f_bavail * stat.f_frsize,
        "memory_total_bytes": memory["MemTotal"],
        "memory_available_bytes": memory["MemAvailable"],
    }


def emit(report: Path, event: dict[str, object]) -> None:
    line = json.dumps(event, sort_keys=True, separators=(",", ":"))
    print(f"RELEASE_PERF {line}", flush=True)
    with report.open("a", encoding="utf-8") as stream:
        stream.write(line + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True)
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--cache-key", action="append", default=[])
    parser.add_argument("--cache-path", action="append", default=[])
    parser.add_argument("--cache-mode", choices=("observe", "restore"), default="observe")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if len(args.cache_key) != len(args.cache_path):
        parser.error("--cache-key and --cache-path must occur equally often")
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")

    args.report.parent.mkdir(parents=True, exist_ok=True)
    cache_before = [directory_bytes(Path(path)) for path in args.cache_path]
    start = time.monotonic()
    emit(args.report, {
        "schema": "seal-release-performance-v1", "event": "phase-start",
        "architecture": args.architecture, "phase": args.phase,
        "resources": resources(Path.cwd()),
    })
    completed = subprocess.run(command, check=False)
    wall_ms = round((time.monotonic() - start) * 1000)
    cache_after = [directory_bytes(Path(path)) for path in args.cache_path]
    caches = []
    for key, path, before, after in zip(args.cache_key, args.cache_path, cache_before, cache_after):
        hit = before > 0
        caches.append({
            "key": key, "path": path, "local_hit": hit, "local_miss": not hit,
            "bytes_before": before, "bytes_after": after,
            "bytes_restored": max(after - before, 0) if args.cache_mode == "restore" else 0,
            # The release job has no cache-save action. Do not relabel generated
            # build output as cache bytes saved.
            "bytes_saved": 0,
        })
    emit(args.report, {
        "schema": "seal-release-performance-v1", "event": "phase-finish",
        "architecture": args.architecture, "phase": args.phase,
        "wall_ms": wall_ms, "command_rc": completed.returncode,
        "cache_hit_count": sum(cache["local_hit"] for cache in caches),
        "cache_miss_count": sum(cache["local_miss"] for cache in caches),
        "caches": caches, "resources": resources(Path.cwd()),
    })
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
