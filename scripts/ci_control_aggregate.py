#!/usr/bin/env python3
"""Fail a CI job when any isolated workflow step reported a failure."""

from __future__ import annotations

import json
import os
import sys


def main() -> int:
    raw = os.environ.get("SEAL_CONTROL_STEPS")
    if raw is None:
        print("::error::SEAL_CONTROL_STEPS is missing; refusing to pass without control results")
        return 1

    try:
        steps = json.loads(raw)
    except json.JSONDecodeError as error:
        print(f"::error::SEAL_CONTROL_STEPS is not valid JSON: {error}")
        return 1

    if not isinstance(steps, dict):
        print("::error::SEAL_CONTROL_STEPS must be a JSON object")
        return 1

    controls = {
        name: value
        for name, value in steps.items()
        if name.startswith("control_")
    }
    if not controls:
        print("::error::no control results were reported; refusing to pass vacuously")
        return 1

    failed: list[str] = []
    skipped: list[str] = []
    malformed: list[str] = []
    for name, result in controls.items():
        if not isinstance(result, dict) or not isinstance(result.get("outcome"), str):
            malformed.append(name)
            continue
        outcome = result["outcome"]
        if outcome == "failure":
            failed.append(name)
        elif outcome == "skipped":
            skipped.append(name)
        elif outcome != "success":
            malformed.append(f"{name} ({outcome})")

    for name in failed:
        print(f"::error::isolated CI step failed: {name}")
    for name in malformed:
        print(f"::error::isolated CI step has no passing terminal outcome: {name}")

    if failed or malformed:
        print(
            f"FAIL: {len(failed)} failed, {len(malformed)} invalid, "
            f"{len(skipped)} skipped, {len(controls)} reported"
        )
        return 1

    print(
        f"PASS: {len(controls) - len(skipped)} passed, "
        f"{len(skipped)} skipped, {len(controls)} reported"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
