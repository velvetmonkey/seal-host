#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Measure filesystem use while running one CI workload without hiding its exit."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import threading


def disk_sample(path: Path) -> tuple[int, int, int]:
    stats = os.statvfs(path)
    capacity = stats.f_blocks * stats.f_frsize
    used = (stats.f_blocks - stats.f_bfree) * stats.f_frsize
    available = stats.f_bavail * stats.f_frsize
    return capacity, used, available


def emit(
    phase: str,
    event: str,
    capacity: int,
    used: int,
    available: int,
    **extra: int,
) -> None:
    fields = {
        "phase": phase,
        "event": event,
        "capacity_bytes": capacity,
        "used_bytes": used,
        "available_bytes": available,
        **extra,
    }
    print(
        "DISK_TELEMETRY "
        + " ".join(f"{key}={value}" for key, value in fields.items()),
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase")
    parser.add_argument("--path", type=Path, default=Path.cwd())
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    command = args.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    if args.interval_seconds <= 0:
        parser.error("--interval-seconds must be positive")

    path = args.path.resolve()
    initial = disk_sample(path)
    peak_used = initial[1]
    minimum_available = initial[2]
    samples = 1
    stopped = threading.Event()
    lock = threading.Lock()

    emit(args.phase, "initial", *initial)

    def sample_until_stopped() -> None:
        nonlocal peak_used, minimum_available, samples
        while not stopped.wait(args.interval_seconds):
            _, used, available = disk_sample(path)
            with lock:
                peak_used = max(peak_used, used)
                minimum_available = min(minimum_available, available)
                samples += 1

    sampler = threading.Thread(target=sample_until_stopped, daemon=True)
    sampler.start()
    try:
        completed = subprocess.run(command, check=False)
    except OSError as error:
        print(
            f"DISK_TELEMETRY phase={args.phase} command_error={error}",
            file=sys.stderr,
        )
        command_rc = 127
    else:
        command_rc = completed.returncode
    finally:
        stopped.set()
        sampler.join()

    final = disk_sample(path)
    with lock:
        peak_used = max(peak_used, final[1])
        minimum_available = min(minimum_available, final[2])
        samples += 1

    emit(
        args.phase,
        "peak",
        final[0],
        peak_used,
        minimum_available,
        growth_bytes=max(0, peak_used - initial[1]),
        samples=samples,
    )
    emit(args.phase, "final", *final, command_rc=command_rc)
    return command_rc


if __name__ == "__main__":
    sys.exit(main())
