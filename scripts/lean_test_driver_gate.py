#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail closed when Lake's aggregate test wiring diverges from its runner."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
DRIVER_NAME = "lean_tests"
DRIVER_ROOT = "Test.LeanTests"
CHILD_ARRAY = re.compile(
    r"private\s+def\s+testBinaries\s*:\s*Array\s+String\s*:=\s*#\[(.*?)\]",
    re.DOTALL,
)
CHILD_LINE = re.compile(r'\s*"([A-Za-z0-9_-]+)"\s*,?\s*(?:--.*)?')
FULL_DRIVER_LOOP = re.compile(r"(?m)^\s*for\s+name\s+in\s+testBinaries\s+do\s*$")
COUNT_MISMATCH_GUARD = re.compile(
    r"(?m)^\s*if\s+(?:ran|passed\.size)\s*!=\s*expectedTestCount\s+then\s*$"
)
COUNT_MISMATCH_DIAGNOSTIC = "COUNT MISMATCH"


def read_children(path: Path) -> tuple[list[str], list[str]]:
    failures: list[str] = []
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        return [], [f"cannot read {path}: {error}"]

    match = CHILD_ARRAY.search(source)
    if match is None:
        return [], [f"cannot find the testBinaries array in {path}"]

    children: list[str] = []
    for line_number, line in enumerate(match.group(1).splitlines(), start=1):
        if not line.strip():
            continue
        child = CHILD_LINE.fullmatch(line)
        if child is None:
            failures.append(
                f"cannot parse testBinaries entry {line_number} inside its array: {line.strip()}"
            )
        else:
            children.append(child.group(1))

    if not children:
        failures.append("testBinaries is empty; refusing to pass vacuously")
    duplicates = sorted({name for name in children if children.count(name) > 1})
    if duplicates:
        failures.append(f"testBinaries contains duplicates: {', '.join(duplicates)}")
    return children, failures


def runtime_driver_failures(path: Path) -> list[str]:
    """Refuse a driver that can silently run only a prefix of its roster."""
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as error:
        return [f"cannot read runtime driver {path}: {error}"]

    # Small wiring fixtures contain only Lake declarations. Audit runtime
    # shape when the actual executable driver is present.
    if "def main : IO UInt32" not in source:
        return []

    failures: list[str] = []
    loop = FULL_DRIVER_LOOP.search(source)
    if loop is None:
        failures.append(
            "LeanTests driver must iterate the complete testBinaries array; "
            "partial iteration such as testBinaries.take is forbidden"
        )

    guard = COUNT_MISMATCH_GUARD.search(source)
    if guard is None:
        failures.append(
            "LeanTests driver must refuse when the number of tests run "
            "differs from the literal expectedTestCount"
        )
    if COUNT_MISMATCH_DIAGNOSTIC not in source:
        failures.append(
            "LeanTests driver must emit COUNT MISMATCH evidence for a partial run"
        )
    if loop is not None and guard is not None and guard.start() < loop.end():
        failures.append(
            "LeanTests COUNT MISMATCH guard must occur after the complete run loop"
        )
    return failures


def check(root: Path) -> list[str]:
    lakefile = root / "lakefile.toml"
    source = root / "Test" / "LeanTests.lean"
    children, failures = read_children(source)
    failures.extend(runtime_driver_failures(source))

    try:
        with lakefile.open("rb") as handle:
            package = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        failures.append(f"cannot parse {lakefile}: {error}")
        return failures

    if package.get("testDriver") != DRIVER_NAME:
        failures.append(
            f"package testDriver must be {DRIVER_NAME!r}, got {package.get('testDriver')!r}"
        )

    executables = package.get("lean_exe", [])
    if not isinstance(executables, list):
        failures.append("lakefile lean_exe declarations are not an array of tables")
        return failures

    driver_tables = [
        item
        for item in executables
        if isinstance(item, dict) and item.get("name") == DRIVER_NAME
    ]
    if len(driver_tables) != 1:
        failures.append(
            f"expected exactly one {DRIVER_NAME!r} lean_exe, found {len(driver_tables)}"
        )
        return failures

    driver = driver_tables[0]
    if driver.get("root") != DRIVER_ROOT:
        failures.append(
            f"{DRIVER_NAME}.root must be {DRIVER_ROOT!r}, got {driver.get('root')!r}"
        )

    needs = driver.get("needs")
    if not isinstance(needs, list) or not all(isinstance(name, str) for name in needs):
        suspicious = sorted(key for key in driver if key.lower().startswith("needs"))
        detail = f"; similarly named fields: {', '.join(suspicious)}" if suspicious else ""
        failures.append(f"{DRIVER_NAME}.needs must be an array of strings{detail}")
    elif needs != children:
        missing = [name for name in children if name not in needs]
        extra = [name for name in needs if name not in children]
        failures.append(
            f"{DRIVER_NAME}.needs does not exactly match testBinaries in source order"
            f"; missing={missing!r}; extra={extra!r}"
        )

    declared = {
        item.get("name")
        for item in executables
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    undeclared = [name for name in children if name not in declared]
    if undeclared:
        failures.append(
            f"testBinaries names without a matching lean_exe: {', '.join(undeclared)}"
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()

    failures = check(arguments.root.resolve())
    if failures:
        print("FAIL: Lean test-driver wiring is not exhaustive:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    children, _ = read_children(arguments.root / "Test" / "LeanTests.lean")
    print(
        f"PASS: {DRIVER_NAME}.needs exactly matches all {len(children)} "
        "children derived from Test/LeanTests.lean"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
