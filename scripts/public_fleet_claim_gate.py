#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse stale private-era claims on current public fleet surfaces."""

from __future__ import annotations

import argparse
import json
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
FAMILY_REPOS = tuple(json.loads((ROOT / "scripts/family-repos.json").read_text(encoding="utf-8")))
FAMILY_PHRASES = (
    r"seal(?:[- ]family)? repositor(?:y|ies)",
    r"seal(?:[- ]family)? repos?",
    r"`seal`",
    r"\bseal (?=(?:is|remains|stays|has|was|will)\b)",
)
RESTRICTION_VOCABULARY = (
    r"private",
    r"not (?:public|publicly available)",
    r"restricted",
    r"authori[sz]ed (?:evaluators|reviewers)",
    r"request access",
    r"not yet (?:been )?open sourced",
    r"pre-award",
    r"closed[ -]source",
    r"invite[ -]only",
    r"internal[ -]only",
    r"(?:unavailable|not available) to the public",
    r"access(?: is| remains| stays)? (?:controlled|gated)",
)

# These exact historical claims remain as regression signatures. The semantic
# detector below is what catches new wording; this list preserves all thirteen
# already-proved failures, including fragments that do not name their subject.
LEGACY_STALE_PATTERNS = (
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


def _name_pattern(name: str) -> str:
    """Match a repository name without treating it as part of a longer slug."""
    return rf"(?<![\w-]){re.escape(name)}(?![\w-])"


FAMILY_REPO_PATTERNS = tuple(
    _name_pattern(name)
    for name in sorted(
        (repo for repo in FAMILY_REPOS if repo != "seal"),
        key=len,
        reverse=True,
    )
)
FAMILY_SUBJECT = re.compile(
    "(?:" + "|".join((*FAMILY_REPO_PATTERNS, *FAMILY_PHRASES)) + ")",
    re.IGNORECASE,
)
RESTRICTION = re.compile(
    "(?:" + "|".join(RESTRICTION_VOCABULARY) + ")",
    re.IGNORECASE,
)


def stale_claim(line: str) -> bool:
    """Return true when a line makes a private-era claim about the public family."""
    if any(pattern.search(line) for pattern in LEGACY_STALE_PATTERNS):
        return True
    subject = FAMILY_SUBJECT.search(line)
    if subject is None:
        return False

    # The normal assertion shape names the repository/family first and then
    # predicates restricted availability of it. Limit the span so an unrelated
    # restriction later on a long line is not joined to the name.
    if RESTRICTION.search(line, subject.end(), min(len(line), subject.end() + 160)):
        return True

    # Imperative/access wording naturally puts the restriction first. Require
    # an access/view/use connector, or an explicit repository noun, so phrases
    # such as "private kernel (`mcp-seal-dev`)" do not become availability claims.
    prefix = line[max(0, subject.start() - 160):subject.start()]
    restriction = RESTRICTION.search(prefix)
    if restriction is None:
        return False
    between = prefix[restriction.end():]
    return bool(
        re.search(
            r"\b(?:access|accessing|view|viewing|use|using|clone|cloning)\b",
            between,
            re.IGNORECASE,
        )
        or re.search(
            r"^\s+(?:repositor(?:y|ies)|repos?)\b",
            line[subject.end():],
            re.IGNORECASE,
        )
        or re.search(r"seal(?:[- ]family)? repos", subject.group(0), re.IGNORECASE)
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
            if stale_claim(line):
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
