#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Refuse a retired product name on any seal-host published surface.

Published surface means every UTF-8 text file tracked by seal-host, because
``export_public.sh`` archives the tracked tree, plus every body of an already
published GitHub release. README, ``docs/``, checked-in release-note sources,
and other reader documents are therefore covered without a hand-maintained
allow-list. The dependency vendored later by ``prepare_public_source.py`` is
upstream-authored source and is outside the seal-host surface checked here.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    ".c", ".cjs", ".css", ".html", ".js", ".json", ".lean", ".md",
    ".mjs", ".py", ".rs", ".sh", ".toml", ".txt", ".yml", ".yaml",
}
TEXT_NAMES = {"Dockerfile", "Dockerfile.release"}
# Keep the retired spelling out of the public export even in this gate's own
# implementation. These are its lowercase ASCII code points.
RETIRED = bytes((99, 97, 110, 97, 114, 121)).decode("ascii")


def fail(message: str) -> None:
    print(f"retired public reference gate failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def tracked_files(root: Path) -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"cannot enumerate the tracked public-export input: {error}")
    return [
        root / name.decode("utf-8")
        for name in result.stdout.split(b"\0")
        if name
    ]


def text_hits(label: str, text: str) -> list[str]:
    return [
        f"{label}:{line_number}:{line}"
        for line_number, line in enumerate(text.splitlines(), start=1)
        if RETIRED in line.casefold()
    ]


def tree_hits(root: Path) -> list[str]:
    hits: list[str] = []
    for path in tracked_files(root):
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in TEXT_NAMES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        except OSError as error:
            fail(f"cannot read tracked file {path.relative_to(root)}: {error}")
        hits.extend(text_hits(str(path.relative_to(root)), text))
    return hits


def github_release_hits(repository: str, token: str) -> list[str]:
    hits: list[str] = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repository}/releases?per_page=100&page={page}"
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urlopen(request, timeout=30) as response:
                releases = json.load(response)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
            fail(f"cannot read published GitHub releases for {repository}: {error}")
        if not isinstance(releases, list):
            fail("GitHub releases response is not a list")
        for release in releases:
            if not isinstance(release, dict) or release.get("draft"):
                continue
            tag = release.get("tag_name")
            body = release.get("body")
            if not isinstance(tag, str) or not isinstance(body, str):
                fail("published GitHub release has no string tag_name/body")
            hits.extend(text_hits(f"github-release:{tag}", body))
        if len(releases) < 100:
            return hits
        page += 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--github-releases", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    root = args.root.resolve()
    if not root.is_dir():
        fail(f"root is not a directory: {root}")

    hits = tree_hits(root)
    if args.github_releases:
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not repository or not token:
            fail("--github-releases requires GITHUB_REPOSITORY and GITHUB_TOKEN")
        release_hits = github_release_hits(repository, token)
        hits.extend(release_hits)

    if hits:
        print("retired public reference gate failed:", file=sys.stderr)
        for hit in hits:
            print(f"  {hit}", file=sys.stderr)
        raise SystemExit(1)
    release_status = (
        " and published GitHub release bodies" if args.github_releases else ""
    )
    print(f"PASS retired public reference absent from tracked public-export text{release_status}")


if __name__ == "__main__":
    main()
