#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse stale private-era claims on current public fleet surfaces."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_READER_FILES = (
    Path("README.md"),
    Path("NOTICE.md"),
    Path("EVIDENCE.md"),
    Path("SECURITY.md"),
    Path("docs/FRONT-PAGE-REFERENCE.md"),
)
STALE_PATTERNS = (
    re.compile(r"\bAll Seal-family repositories are currently private\b", re.IGNORECASE),
    re.compile(r"\blinks resolve only for authori[sz]ed evaluators\b", re.IGNORECASE),
    re.compile(r"\bboth in private repos\b", re.IGNORECASE),
    re.compile(r"\bprivate Seal product-family repos\b", re.IGNORECASE),
    re.compile(r"\bchecked private repos\b", re.IGNORECASE),
    re.compile(r"\bThis repository is \*\*PRIVATE,\s*pre-award\*\*", re.IGNORECASE),
    re.compile(r"\bAccess stays private until each layer reaches its release point\b", re.IGNORECASE),
    re.compile(r"\bDo NOT push this repository to a public remote pre-award\b", re.IGNORECASE),
    re.compile(r"\bNames the private repositories\b", re.IGNORECASE),
    re.compile(r"\bstays the private source of truth\b", re.IGNORECASE),
    re.compile(r"\buser-owned private repository\b", re.IGNORECASE),
    re.compile(r"\bprivate umbrella story\b", re.IGNORECASE),
    re.compile(r"\bprivate kit repo\b", re.IGNORECASE),
)


def reader_files(root: Path) -> list[Path]:
    files = [
        root / "README.md",
        root / "NOTICE.md",
        root / "EVIDENCE.md",
        root / "SECURITY.md",
    ]
    docs = root / "docs"
    if docs.exists():
        files.extend(docs.glob("*.md"))
    return sorted(path for path in files if path.exists())


def readable_text(path: Path, root: Path) -> tuple[str | None, str | None]:
    relative = path.relative_to(root)
    if not path.exists():
        return None, f"{relative}: absent required reader surface"
    if not path.is_file():
        return None, f"{relative}: not a readable file"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        return None, f"{relative}: unreadable input: {error}"
    except UnicodeDecodeError as error:
        return None, f"{relative}: unreadable UTF-8 input: {error}"
    if not text.strip():
        return None, f"{relative}: empty reader surface"
    return text, None


def failures(root: Path) -> list[str]:
    problems: list[str] = []
    if not root.exists():
        return [f"{root}: absent root"]
    if not root.is_dir():
        return [f"{root}: root is not a directory"]

    for relative in REQUIRED_READER_FILES:
        _, problem = readable_text(root / relative, root)
        if problem is not None:
            problems.append(problem)

    files = reader_files(root)
    if not files:
        problems.append(f"{root}: no reader surfaces found")
        return problems

    for path in files:
        text, problem = readable_text(path, root)
        if problem is not None:
            problems.append(problem)
            continue
        relative = path.relative_to(root)
        for line_number, line in enumerate(text.splitlines(), 1):
            for pattern in STALE_PATTERNS:
                if pattern.search(line):
                    problems.append(
                        f"{relative}:{line_number}: stale private-era fleet claim: {line.strip()}"
                    )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    problems = failures(args.root.resolve())
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print("PASS public fleet claim gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
