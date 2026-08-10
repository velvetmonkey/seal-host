#!/usr/bin/env python3
"""Refuse stale, unpublished, absent, or unverified reader release paths."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fnmatch
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "velvetmonkey/seal-host"
CURRENT_RELEASE_DOCS = {
    Path("CONFIG.md"),
    Path("README.md"),
    Path("docs/DEPLOY.md"),
    Path("docs/FRONT-PAGE-REFERENCE.md"),
    Path("docs/GETTING-STARTED.md"),
    Path("docs/RELEASE-PROVENANCE.md"),
}
CURRENT_RELEASE_MARKER = re.compile(
    r"<!--\s*current-release:\s*(v[0-9]+\.[0-9]+\.[0-9]+)\s*-->"
)
PINNED_RELEASE = re.compile(
    r"(?:\btag\s*=\s*|gh\s+release\s+download\s+|"
    r"github\.com/velvetmonkey/seal-host/releases/(?:download|tag)/)"
    r"['\"]?(v[0-9]+\.[0-9]+\.[0-9]+)",
    re.IGNORECASE,
)
RELEASE_COUNT = (
    re.compile(r"Published\s+`seal-host`\s+releases:\s*\*\*(\d+)\*\*", re.IGNORECASE),
    re.compile(r"`seal-host`\s+has\s+\*\*(\d+)\*\*\s+published\s+releases?", re.IGNORECASE),
    re.compile(r"Published\s+releases:\s*\*\*(\d+)\*\*", re.IGNORECASE),
)
VERSIONED_ASSET = re.compile(
    r"\b(seal-host-(v[0-9]+\.[0-9]+\.[0-9]+)-linux-"
    r"[A-Za-z0-9_]+\.(?:tar\.gz|cdx\.json))\b"
)
DOWNLOAD_PATTERN = re.compile(
    r"--pattern\s+(?:\"([^\"]+)\"|'([^']+)'|([^\s]+))",
    re.IGNORECASE,
)
RELEASE_PATH = re.compile(r"\.seal/release/")
RELEASE_TAG = re.compile(r"seal-host-(v[0-9]+\.[0-9]+\.[0-9]+)[-/]")
RELEASE_DOWNLOAD = re.compile(
    r"^\s*(?:\$\s*)?(?:(?:sudo|env)\s+)*(?:"
    r"gh\s+release\s+download\b|"
    r"(?:curl|wget)\b[^\n]*github\.com/velvetmonkey/seal-host/releases/download/)",
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


@dataclass(frozen=True)
class ReleaseCatalog:
    tags: frozenset[str]
    latest_tag: str
    assets: dict[str, frozenset[str]]


def standard_assets(tag: str) -> frozenset[str]:
    return frozenset(
        {
            "release_provenance.py",
            f"seal-host-{tag}-linux-aarch64.cdx.json",
            f"seal-host-{tag}-linux-aarch64.tar.gz",
            f"seal-host-{tag}-linux-x86_64.cdx.json",
            f"seal-host-{tag}-linux-x86_64.tar.gz",
            "SEAL-RELEASE-PROVENANCE.json",
            "SEAL-RELEASE-PROVENANCE.sigstore.json",
            "SHA256SUMS",
        }
    )


def version_key(tag: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in tag.removeprefix("v").split("."))


def fixed_catalog(tags: set[str]) -> ReleaseCatalog:
    if not tags:
        raise RuntimeError("no published releases were supplied")
    latest_tag = max(tags, key=version_key)
    return ReleaseCatalog(
        tags=frozenset(tags),
        latest_tag=latest_tag,
        assets={tag: standard_assets(tag) for tag in tags},
    )


def reader_files(root: Path) -> list[Path]:
    files = [root / "README.md", root / "CONFIG.md", root / "deploy/container/compose.yaml"]
    files.extend((root / "docs").glob("*.md"))
    files.extend((root / "profiles/hosts").glob("*.json"))
    return sorted(path for path in files if path.is_file())


def published_releases() -> ReleaseCatalog:
    if shutil.which("gh") is None:
        raise RuntimeError("gh is unavailable; cannot establish published releases")
    releases_result = subprocess.run(
        [
            "gh",
            "api",
            "--paginate",
            "--slurp",
            f"repos/{REPOSITORY}/releases?per_page=100",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if releases_result.returncode:
        detail = releases_result.stderr.strip() or releases_result.stdout.strip() or "no output"
        raise RuntimeError(f"cannot establish published releases: {detail}")
    latest_result = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/releases/latest"],
        text=True,
        capture_output=True,
        check=False,
    )
    if latest_result.returncode:
        detail = latest_result.stderr.strip() or latest_result.stdout.strip() or "no output"
        raise RuntimeError(f"cannot establish Latest release: {detail}")
    try:
        pages = json.loads(releases_result.stdout)
        releases = [
            item
            for page in pages
            for item in page
            if not item["draft"] and item["published_at"] is not None
        ]
        latest = json.loads(latest_result.stdout)
        tags = frozenset(item["tag_name"] for item in releases)
        latest_tag = latest["tag_name"]
        assets = {
            item["tag_name"]: frozenset(asset["name"] for asset in item["assets"])
            for item in releases
        }
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise RuntimeError(f"cannot parse published releases: {error}") from error
    if latest_tag not in tags:
        raise RuntimeError(f"Latest release {latest_tag} is absent from the published release list")
    return ReleaseCatalog(tags=tags, latest_tag=latest_tag, assets=assets)


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


def check(root: Path, catalog: ReleaseCatalog) -> list[str]:
    failures: list[str] = []
    for path in reader_files(root):
        relative = path.relative_to(root)
        text = path.read_text(encoding="utf-8")
        failures.extend(release_use_failures(path, root))
        for line_number, line in enumerate(text.splitlines(), 1):
            if not RELEASE_PATH.search(line):
                pass
            else:
                tag = RELEASE_TAG.search(line)
                if tag is None:
                    failures.append(
                        f"{relative}:{line_number}: release artifact path has no publishable tag: {line.strip()}"
                    )
                elif tag.group(1) not in catalog.tags:
                    failures.append(
                        f"{relative}:{line_number}: release artifact path names unpublished {tag.group(1)}: {line.strip()}"
                    )

            for pinned in PINNED_RELEASE.finditer(line):
                tag_name = pinned.group(1)
                if tag_name not in catalog.tags:
                    failures.append(
                        f"{relative}:{line_number}: release reference names unpublished {tag_name}: {line.strip()}"
                    )
                elif relative in CURRENT_RELEASE_DOCS and tag_name != catalog.latest_tag:
                    failures.append(
                        f"{relative}:{line_number}: current release command names {tag_name}, Latest is {catalog.latest_tag}: {line.strip()}"
                    )

            for asset in VERSIONED_ASSET.finditer(line):
                asset_name, tag_name = asset.groups()
                if tag_name not in catalog.assets:
                    failures.append(
                        f"{relative}:{line_number}: documented asset names unpublished {tag_name}: {asset_name}"
                    )
                elif asset_name not in catalog.assets[tag_name]:
                    failures.append(
                        f"{relative}:{line_number}: documented asset is absent from {tag_name}: {asset_name}"
                    )

        normalized = " ".join(text.split())
        for count_pattern in RELEASE_COUNT:
            for count in count_pattern.finditer(normalized):
                stated = int(count.group(1))
                if stated != len(catalog.tags):
                    failures.append(
                        f"{relative}: stated published release count is {stated}, live count is {len(catalog.tags)}"
                    )

        if relative in CURRENT_RELEASE_DOCS:
            markers = CURRENT_RELEASE_MARKER.findall(text)
            if markers != [catalog.latest_tag]:
                observed = ", ".join(markers) if markers else "none"
                failures.append(
                    f"{relative}: current-release marker must be exactly {catalog.latest_tag}; observed {observed}"
                )
            for line_number, line in logical_lines(path):
                if not RELEASE_DOWNLOAD.search(line):
                    continue
                for pattern in DOWNLOAD_PATTERN.finditer(line):
                    documented = next(group for group in pattern.groups() if group is not None)
                    resolved = documented.replace("${tag}", catalog.latest_tag).replace(
                        "$tag", catalog.latest_tag
                    )
                    if not any(
                        fnmatch.fnmatchcase(asset, resolved)
                        for asset in catalog.assets[catalog.latest_tag]
                    ):
                        failures.append(
                            f"{relative}:{line_number}: download pattern matches no asset in {catalog.latest_tag}: {documented}"
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
        try:
            catalog = fixed_catalog(set(args.published_tag))
        except (RuntimeError, ValueError) as error:
            print(f"FAIL reader release paths: {error}", file=sys.stderr)
            return 1
    else:
        try:
            catalog = published_releases()
        except RuntimeError as error:
            print(f"FAIL reader release paths: {error}", file=sys.stderr)
            return 1

    failures = check(root, catalog)

    if failures:
        print("FAIL reader release paths:", file=sys.stderr)
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(
        "PASS reader release paths: "
        f"Latest={catalog.latest_tag}, published={len(catalog.tags)}, "
        "assets and provenance-before-use verified"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
