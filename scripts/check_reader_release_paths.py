#!/usr/bin/env python3
"""Refuse reader-facing paths to release artifacts that are not published."""

from __future__ import annotations

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


def reader_files() -> list[Path]:
    files = [ROOT / "README.md", ROOT / "CONFIG.md", ROOT / "deploy/container/compose.yaml"]
    files.extend((ROOT / "docs").glob("*.md"))
    files.extend((ROOT / "profiles/hosts").glob("*.json"))
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


def main() -> int:
    try:
        tags = published_tags()
    except RuntimeError as error:
        print(f"FAIL reader release paths: {error}", file=sys.stderr)
        return 1

    failures: list[str] = []
    for path in reader_files():
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not RELEASE_PATH.search(line):
                continue
            tag = RELEASE_TAG.search(line)
            if tag is None:
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: release artifact path has no publishable tag: {line.strip()}"
                )
            elif tag.group(1) not in tags:
                failures.append(
                    f"{path.relative_to(ROOT)}:{line_number}: release artifact path names unpublished {tag.group(1)}: {line.strip()}"
                )

    if failures:
        print("FAIL reader release paths:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("PASS reader release paths: no unpublished release artifact paths")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
