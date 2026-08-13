#!/usr/bin/env python3
"""Install the repository-pinned elan release and expose CI failure metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PIN = ROOT / ".github" / "elan-version.json"
DEFAULT_RELEASE_ROOT = "https://github.com/leanprover/elan/releases/download"
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
SHA256 = re.compile(r"[0-9a-f]{64}")
SUPPORTED_MACHINES = {"x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64"}


class InstallError(Exception):
    """A pinned installer could not be resolved, downloaded, or run."""


def load_pin(path: Path, machine: str | None = None) -> tuple[str, str, str]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InstallError(f"cannot read elan pin {path}: {error}") from error
    if not isinstance(document, dict) or set(document) != {"version", "assets"}:
        raise InstallError("elan pin must contain exactly version and assets")
    version = document["version"]
    assets = document["assets"]
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise InstallError(f"invalid pinned elan version: {version!r}")
    detected = machine or platform.machine()
    architecture = SUPPORTED_MACHINES.get(detected)
    if architecture is None:
        raise InstallError(f"unsupported runner architecture: {detected}")
    target = f"{architecture}-unknown-linux-gnu"
    if platform.system() != "Linux" and machine is None:
        raise InstallError(f"unsupported runner operating system: {platform.system()}")
    checksum = assets.get(target) if isinstance(assets, dict) else None
    if not isinstance(checksum, str) or SHA256.fullmatch(checksum) is None:
        raise InstallError(f"missing or invalid SHA-256 for elan target {target}")
    return version, target, checksum


def resolved_installer(pin_path: Path, release_root: str, machine: str | None = None) -> tuple[str, str, str]:
    version, target, checksum = load_pin(pin_path, machine)
    url = f"{release_root.rstrip('/')}/{version}/elan-{target}.tar.gz"
    return version, url, checksum


def write_output(name: str, value: str) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path is None:
        return
    if "\n" in value or "\r" in value:
        raise InstallError(f"refusing multiline GitHub output {name}")
    with Path(output_path).open("a", encoding="utf-8") as stream:
        stream.write(f"{name}={value}\n")


def download(url: str, destination: Path) -> None:
    result = subprocess.run(
        ["curl", "-sSfL", "--connect-timeout", "10", "--output", str(destination), url],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().replace("\n", "; ")
        raise InstallError(f"download failed ({detail or f'curl exit {result.returncode}'})")


def verify(path: Path, expected: str) -> None:
    observed = hashlib.sha256(path.read_bytes()).hexdigest()
    if observed != expected:
        raise InstallError(f"SHA-256 mismatch: expected {expected}, observed {observed}")


def extract_installer(archive: Path, destination: Path) -> None:
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            member = next((item for item in bundle.getmembers() if Path(item.name).name == "elan-init"), None)
            if member is None or not member.isfile():
                raise InstallError("elan archive contains no regular elan-init executable")
            source = bundle.extractfile(member)
            if source is None:
                raise InstallError("elan archive elan-init could not be read")
            destination.write_bytes(source.read())
    except (tarfile.TarError, OSError) as error:
        raise InstallError(f"cannot unpack elan archive: {error}") from error
    destination.chmod(0o700)


def install(url: str, checksum: str, *, download_only: bool) -> None:
    with tempfile.TemporaryDirectory(prefix="seal-elan-") as temporary:
        directory = Path(temporary)
        archive = directory / "elan.tar.gz"
        download(url, archive)
        verify(archive, checksum)
        if download_only:
            return
        installer = directory / "elan-init"
        extract_installer(archive, installer)
        subprocess.run([str(installer), "-y", "--default-toolchain", "none"], check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    parser.add_argument("--release-root", default=DEFAULT_RELEASE_ROOT)
    parser.add_argument("--machine", choices=sorted(SUPPORTED_MACHINES))
    parser.add_argument("--resolve-only", action="store_true")
    parser.add_argument("--download-only", action="store_true")
    parser.add_argument(
        "--mathlib-cache",
        action="store_true",
        help="restore the Mathlib cache after installing the pinned toolchain",
    )
    arguments = parser.parse_args()

    version = "unknown"
    url = "unresolved"
    phase = "installer"
    try:
        version, url, checksum = resolved_installer(arguments.pin, arguments.release_root, arguments.machine)
        print(f"elan-version={version}")
        print(f"elan-installer-url={url}")
        print(f"elan-installer-sha256={checksum}")
        write_output("elan-version", version)
        if arguments.resolve_only:
            return 0
        install(url, checksum, download_only=arguments.download_only)
        if not arguments.download_only:
            bin_directory = Path.home() / ".elan" / "bin"
            for program in ("elan", "lean", "lake"):
                subprocess.run([str(bin_directory / program), "--version"], check=True)
            if arguments.mathlib_cache:
                phase = "Mathlib cache setup"
                subprocess.run(
                    [str(bin_directory / "lake"), "exe", "cache", "get"], check=True
                )
            github_path = os.environ.get("GITHUB_PATH")
            if github_path is not None:
                with Path(github_path).open("a", encoding="utf-8") as stream:
                    stream.write(f"{bin_directory}\n")
        write_output("unrunnable", "false")
        print(f"Pinned elan {version} verified from {urlparse(url).netloc or 'local source'}")
        return 0
    except (InstallError, OSError, subprocess.CalledProcessError) as error:
        reason = f"pinned elan {version} {phase} could not run from {url}: {error}"
        print(f"::error::{reason}")
        try:
            write_output("unrunnable", "true")
            write_output("unrunnable-reason", reason)
        except InstallError as output_error:
            print(f"::error::{output_error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
