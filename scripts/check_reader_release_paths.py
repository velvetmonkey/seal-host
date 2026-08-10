#!/usr/bin/env python3
"""Refuse unpublished or unverified reader-facing release artifact paths."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "velvetmonkey/seal-host"
RELEASE_PATH = re.compile(r"\.seal/release/")
RELEASE_TAG = re.compile(r"seal-host-(v[0-9]+\.[0-9]+\.[0-9]+)[-/]")
RELEASE_DOWNLOAD = re.compile(
    r"^\s*(?:\$\s*)?(?:(?:sudo|env)\s+)*(?:"
    r"gh\s+release\s+download\b|"
    r"(?:curl|wget)\b[^\n]*github\.com/velvetmonkey/seal-host/releases/download/)" ,
    re.IGNORECASE,
)
PROVENANCE_VERIFY = re.compile(
    r"^\s*(?:\$\s*)?(?:(?:sudo|env)\s+)*python3\s+"
    r"(?:\./)?release_provenance\.py\s+verify\b",
    re.IGNORECASE,
)
RELEASE_SPECIFIC = re.compile(
    r"\.seal/release/|seal-host-(?:v[0-9]+\.[0-9]+\.[0-9]+|\$\{?tag\}?)",
    re.IGNORECASE,
)
RELEASE_USE = re.compile(
    r"^\s*(?:\$\s*)?(?:(?:sudo|env)\s+)*(?:"
    r"(?:tar|unzip|install|cp)\b|"
    r"(?:export\s+)?SEAL_BIN\s*=|"
    r"(?:['\"]?[^\s'\"]*/)?seal-host-rs\b|"
    r"['\"]?\$\{?SEAL_BIN\}?['\"]?\b"
    r")",
    re.IGNORECASE,
)


def reader_files(root: Path) -> list[Path]:
    files = [root / "README.md", root / "CONFIG.md", root / "deploy/container/compose.yaml"]
    files.extend((root / "docs").glob("*.md"))
    files.extend((root / "profiles/hosts").glob("*.json"))
    return sorted(path for path in files if path.is_file())


def published_tags() -> set[str]:
    if shutil.which("gh") is None:
        raise RuntimeError("gh is unavailable; cannot establish published releases")
    result = subprocess.run(
        ["gh", "release", "list", "--repo", REPOSITORY, "--limit", "100", "--json", "tagName"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no output"
        raise RuntimeError(f"cannot establish published releases: {detail}")
    try:
        return {item["tagName"] for item in json.loads(result.stdout)}
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise RuntimeError(f"cannot parse published releases: {error}") from error


def logical_lines(path: Path) -> list[tuple[int, str]]:
    """Return backslash-continued lines with their first physical line number."""
    result: list[tuple[int, str]] = []
    start = 0
    parts: list[str] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not parts:
            start = line_number
        stripped = line.rstrip()
        parts.append(stripped[:-1] if stripped.endswith("\\") else stripped)
        if not stripped.endswith("\\"):
            result.append((start, " ".join(parts)))
            parts = []
    if parts:
        result.append((start, " ".join(parts)))
    return result


def release_use_failures(path: Path, root: Path) -> list[str]:
    failures: list[str] = []
    release_downloaded = False
    provenance_verified = False
    for line_number, line in logical_lines(path):
        if RELEASE_DOWNLOAD.search(line):
            release_downloaded = True
            provenance_verified = False
        if PROVENANCE_VERIFY.search(line):
            provenance_verified = True
        release_specific_use = RELEASE_SPECIFIC.search(line) and RELEASE_USE.search(line)
        downloaded_release_use = release_downloaded and RELEASE_USE.search(line)
        if (release_specific_use or downloaded_release_use) and not provenance_verified:
            failures.append(
                f"{path.relative_to(root)}:{line_number}: release artifact use occurs before "
                f"release_provenance.py verify: {line.strip()}"
            )
    return failures


def check(root: Path, tags: set[str]) -> list[str]:
    failures: list[str] = []
    for path in reader_files(root):
        failures.extend(release_use_failures(path, root))
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not RELEASE_PATH.search(line):
                continue
            tag = RELEASE_TAG.search(line)
            if tag is None:
                failures.append(
                    f"{path.relative_to(root)}:{line_number}: release artifact path has no publishable tag: {line.strip()}"
                )
            elif tag.group(1) not in tags:
                failures.append(
                    f"{path.relative_to(root)}:{line_number}: release artifact path names unpublished {tag.group(1)}: {line.strip()}"
                )
    return failures


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument(
        "--published-tag",
        action="append",
        default=[],
        help="use an established published tag instead of querying GitHub (repeatable)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    if args.published_tag:
        tags = set(args.published_tag)
    else:
        try:
            tags = published_tags()
        except RuntimeError as error:
            print(f"FAIL reader release paths: {error}", file=sys.stderr)
            return 1

    failures = check(root, tags)

    if failures:
        print("FAIL reader release paths:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("PASS reader release paths: published tags and provenance-before-use verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
