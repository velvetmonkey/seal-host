#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Vendor the pinned private Lean source dependency into a public export."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys


PRIVATE_PACKAGE_NAME = "«mcp-seal»"
PRIVATE_PACKAGE_URL = "https://github.com/velvetmonkey/mcp-seal-dev.git"
PUBLIC_PATH = "vendor/mcp-seal"


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"public dependency vendoring failed: {message}")


def run(*args: str, stdout=None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(args, check=True, stdout=stdout)
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"command failed ({' '.join(args)}): {error}")


def rewrite_lakefile(path: Path, revision: str) -> None:
    text = path.read_text(encoding="utf-8")
    blocks = list(re.finditer(r"(?ms)^\[\[require\]\]\n.*?(?=^\[\[|\Z)", text))
    matches = [
        match
        for match in blocks
        if re.search(r'^name\s*=\s*"mcp-seal"\s*$', match.group(), re.MULTILINE)
    ]
    if len(matches) != 1:
        fail(f"expected one mcp-seal requirement in {path}, found {len(matches)}")
    block = matches[0]
    expected_url = re.search(r'^git\s*=\s*"([^"]+)"\s*$', block.group(), re.MULTILINE)
    expected_rev = re.search(r'^rev\s*=\s*"([0-9a-f]{40})"\s*$', block.group(), re.MULTILINE)
    if expected_url is None or expected_url.group(1) != PRIVATE_PACKAGE_URL:
        fail(f"unexpected mcp-seal URL in {path}")
    if expected_rev is None or expected_rev.group(1) != revision:
        fail(f"mcp-seal revision disagreement in {path}")
    replacement = '[[require]]\nname = "mcp-seal"\npath = "vendor/mcp-seal"\n\n'
    path.write_text(text[: block.start()] + replacement + text[block.end() :], encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: prepare_public_source.py SOURCE_TREE MCP_SEAL_GIT_CHECKOUT")
    source = Path(sys.argv[1]).resolve()
    checkout = Path(sys.argv[2]).resolve()
    if not source.is_dir() or not checkout.is_dir():
        fail("source tree and mcp-seal checkout must both be directories")

    manifest_path = source / "lake-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    packages = [package for package in manifest.get("packages", []) if package.get("name") == PRIVATE_PACKAGE_NAME]
    if len(packages) != 1:
        fail(f"expected one {PRIVATE_PACKAGE_NAME} manifest entry, found {len(packages)}")
    package = packages[0]
    if package.get("type") != "git" or package.get("url") != PRIVATE_PACKAGE_URL:
        fail("mcp-seal manifest entry is not the expected private Git dependency")
    revision = package.get("rev")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        fail("mcp-seal manifest revision is not a full Git object ID")
    if package.get("inputRev") != revision:
        fail("mcp-seal rev and inputRev disagree")

    run("git", "-C", str(checkout), "cat-file", "-e", f"{revision}^{{commit}}")
    vendor = source / PUBLIC_PATH
    if vendor.exists():
        fail(f"refusing to replace existing {vendor}")
    vendor.mkdir(parents=True)
    archive = subprocess.Popen(
        ["git", "-C", str(checkout), "archive", "--format=tar", revision],
        stdout=subprocess.PIPE,
    )
    assert archive.stdout is not None
    extract = subprocess.run(["tar", "-xf", "-", "-C", str(vendor)], stdin=archive.stdout)
    archive.stdout.close()
    archive_status = archive.wait()
    if archive_status != 0 or extract.returncode != 0:
        fail(f"could not archive pinned mcp-seal revision {revision}")

    rewrite_lakefile(source / "lakefile.toml", revision)
    package.clear()
    package.update(
        {
            "type": "path",
            "scope": "",
            "name": PRIVATE_PACKAGE_NAME,
            "manifestFile": "lake-manifest.json",
            "inherited": False,
            "configFile": "lakefile.toml",
            "dir": PUBLIC_PATH,
        }
    )
    manifest_path.write_text(json.dumps(manifest, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    if PRIVATE_PACKAGE_URL in (source / "lakefile.toml").read_text(encoding="utf-8"):
        fail("private URL remains in root lakefile")
    if PRIVATE_PACKAGE_URL in manifest_path.read_text(encoding="utf-8"):
        fail("private URL remains in root manifest")
    print(f"PASS vendored mcp-seal {revision} at {PUBLIC_PATH} and rewrote the public dependency graph")


if __name__ == "__main__":
    main()
