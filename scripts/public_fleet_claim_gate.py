#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Pin approved fleet-claim blocks on required public reader surfaces.

This gate proves less than the old stale-claim detector claimed to prove.
It does not scan the repository, and it does not catch a privacy/access claim
written outside a delimited block. The checked claim is only this: approved
fleet-claim text on the required reader surfaces has not changed without a
recorded pin update.

Required surfaces must contain one or more exact regions:

    <!-- FLEET-CLAIM:BEGIN -->
    approved text
    <!-- FLEET-CLAIM:END -->

A person updates the allowlist by editing the approved text, running
`python3 scripts/public_fleet_claim_gate.py --print-hashes`, reviewing the
printed hashes, and committing the text and `scripts/fleet-claim-allow.json`
together. CI never updates pins automatically.

By the usual classification test this mechanism is INJECTED: unwrapped
privacy/access claims can be added while this check stays green.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = Path("scripts/fleet-claim-allow.json")
REQUIRED_READER_FILES = (
    Path("README.md"),
    Path("NOTICE.md"),
    Path("EVIDENCE.md"),
    Path("SECURITY.md"),
    Path("docs/FRONT-PAGE-REFERENCE.md"),
)
BEGIN_MARKER = "<!-- FLEET-CLAIM:BEGIN -->"
END_MARKER = "<!-- FLEET-CLAIM:END -->"


def readable_text(path: Path, root: Path) -> tuple[str | None, str | None]:
    relative = path.relative_to(root)
    if not path.exists():
        return None, f"{relative}: absent required reader surface"
    if not path.is_file():
        return None, f"{relative}: not a readable file"
    try:
        raw = path.read_bytes()
    except OSError as error:
        return None, f"{relative}: unreadable input: {error}"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        return None, f"{relative}: unreadable UTF-8 input: {error}"
    if not text.strip():
        return None, f"{relative}: empty reader surface"
    return text, None


def normalise_block(inner: str) -> bytes:
    """Return the exact bytes pinned for one approved block."""
    normalised = inner.replace("\r\n", "\n").replace("\r", "\n")
    if normalised.endswith("\n"):
        normalised = normalised[:-1]
    return normalised.encode("utf-8")


def block_hash(inner: str) -> str:
    return hashlib.sha256(normalise_block(inner)).hexdigest()


def claim_blocks(text: str, relative: Path) -> tuple[list[str], list[str]]:
    problems: list[str] = []
    blocks: list[str] = []
    active: list[str] | None = None

    lines = text.splitlines(keepends=True)
    for line_number, line in enumerate(lines, 1):
        begin_count = line.count(BEGIN_MARKER)
        end_count = line.count(END_MARKER)
        if begin_count > 1 or end_count > 1:
            problems.append(f"{relative}:{line_number}: duplicated fleet-claim marker")
            continue
        if begin_count and end_count:
            problems.append(f"{relative}:{line_number}: duplicated fleet-claim marker")
            continue
        if begin_count:
            if active is not None:
                problems.append(f"{relative}:{line_number}: nested fleet-claim marker")
            elif line.strip() != BEGIN_MARKER:
                problems.append(f"{relative}:{line_number}: fleet-claim marker must stand alone")
            else:
                active = []
            continue
        if end_count:
            if active is None:
                problems.append(f"{relative}:{line_number}: duplicated fleet-claim marker")
            elif line.strip() != END_MARKER:
                problems.append(f"{relative}:{line_number}: fleet-claim marker must stand alone")
            else:
                blocks.append("".join(active))
                active = None
            continue
        if active is not None:
            active.append(line)

    if active is not None:
        problems.append(f"{relative}: unterminated fleet-claim marker")
    if not blocks and not problems:
        problems.append(f"{relative}: zero fleet-claim blocks")
    return blocks, problems


def load_allowlist(root: Path) -> tuple[dict[str, list[str]] | None, list[str]]:
    path = root / ALLOWLIST
    if not path.exists():
        return None, [f"{ALLOWLIST}: absent fleet-claim allowlist"]
    try:
        data: Any = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        return None, [f"{ALLOWLIST}: unreadable input: {error}"]
    except UnicodeDecodeError as error:
        return None, [f"{ALLOWLIST}: unreadable UTF-8 input: {error}"]
    except json.JSONDecodeError as error:
        return None, [f"{ALLOWLIST}: invalid JSON: {error}"]

    surfaces = data.get("surfaces") if isinstance(data, dict) else None
    if not isinstance(surfaces, dict):
        return None, [f"{ALLOWLIST}: missing object field 'surfaces'"]

    pins: dict[str, list[str]] = {}
    problems: list[str] = []
    for name, hashes in surfaces.items():
        if not isinstance(name, str) or not isinstance(hashes, list):
            problems.append(f"{ALLOWLIST}: invalid pin entry for {name!r}")
            continue
        if not (root / name).exists():
            problems.append(f"{ALLOWLIST}: pin entry names absent file {name}")
        parsed_hashes: list[str] = []
        for index, value in enumerate(hashes, 1):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(char not in "0123456789abcdef" for char in value)
            ):
                problems.append(f"{ALLOWLIST}: invalid sha256 for {name} block {index}")
                continue
            parsed_hashes.append(value)
        pins[name] = parsed_hashes
    return pins, problems


def failures(root: Path) -> list[str]:
    problems: list[str] = []
    if not root.exists():
        return [f"{root}: absent root"]
    if not root.is_dir():
        return [f"{root}: root is not a directory"]

    pins, pin_problems = load_allowlist(root)
    problems.extend(pin_problems)

    for relative in REQUIRED_READER_FILES:
        text, problem = readable_text(root / relative, root)
        if problem is not None:
            problems.append(problem)
            continue
        blocks, block_problems = claim_blocks(text, relative)
        problems.extend(block_problems)
        if pins is None:
            continue
        expected = pins.get(relative.as_posix())
        if expected is None:
            problems.append(f"{ALLOWLIST}: missing pin entry for {relative}")
            continue
        if len(expected) != len(blocks):
            problems.append(
                f"{relative}: block count mismatch: found {len(blocks)}, pinned {len(expected)}"
            )
            continue
        for index, (inner, pinned) in enumerate(zip(blocks, expected), 1):
            actual = block_hash(inner)
            if actual != pinned:
                problems.append(
                    f"{relative}: block {index} sha256 mismatch: expected {pinned}, got {actual}"
                )

    if pins is not None:
        required = {path.as_posix() for path in REQUIRED_READER_FILES}
        for name in sorted(set(pins) - required):
            problems.append(f"{ALLOWLIST}: pin entry is not a required surface: {name}")
    return problems


def print_hashes(root: Path) -> int:
    output: dict[str, list[str]] = {}
    problems: list[str] = []
    for relative in REQUIRED_READER_FILES:
        text, problem = readable_text(root / relative, root)
        if problem is not None:
            problems.append(problem)
            continue
        blocks, block_problems = claim_blocks(text, relative)
        problems.extend(block_problems)
        output[relative.as_posix()] = [block_hash(block) for block in blocks]
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--print-hashes",
        action="store_true",
        help="print current fleet-claim block hashes for human allowlist review",
    )
    args = parser.parse_args()
    root = args.root.resolve()
    if args.print_hashes:
        return print_hashes(root)
    problems = failures(root)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print("PASS public fleet claim pin gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
