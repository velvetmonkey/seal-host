#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate Seal config-signing and approval-signing key files fail closed."""

from __future__ import annotations

import argparse
import hmac
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from typing import Callable


ROOT = Path(__file__).resolve().parents[1]
KEY_FILENAMES = (
    "approval.key",
    "config.key",
    "config.pub",
    "approval.pub",
)
HEX_32_BYTES = re.compile(r"[0-9a-f]{64}")
GenerateKeypair = Callable[[], tuple[str, str]]
DerivePublicKey = Callable[[str], str]


def _load_key_generators() -> tuple[
    GenerateKeypair,
    DerivePublicKey,
    GenerateKeypair,
    DerivePublicKey,
]:
    """Load the repository's signer helpers from their source directory."""
    tools_dir = ROOT / "test" / "tools"
    sys.path.insert(0, str(tools_dir))
    try:
        from sign_approval import (  # type: ignore[import-not-found]
            generate_approval_keypair,
            public_key_hex_from_private as approval_public_from_private,
        )
        from sign_config import (  # type: ignore[import-not-found]
            generate_keypair,
            public_key_hex_from_private as config_public_from_private,
        )
    finally:
        sys.path.remove(str(tools_dir))
    return (
        generate_keypair,
        config_public_from_private,
        generate_approval_keypair,
        approval_public_from_private,
    )


def _validated_pair(
    label: str,
    generate: GenerateKeypair,
    derive_public: DerivePublicKey,
) -> tuple[str, str]:
    private, public = generate()
    for kind, value in (("private", private), ("public", public)):
        if not isinstance(value, str) or HEX_32_BYTES.fullmatch(value) is None:
            raise ValueError(f"{label} {kind} key is not 64 lowercase hex characters")
    if not hmac.compare_digest(derive_public(private), public):
        raise ValueError(f"{label} public key does not match its private key")
    return private, public


def _write_complete_keyset(output_dir: Path, values: dict[str, str]) -> None:
    targets = {name: output_dir / name for name in KEY_FILENAMES}
    existing = [str(path) for path in targets.values() if path.exists()]
    if existing:
        raise FileExistsError("refusing to overwrite existing key file(s): " + ", ".join(existing))

    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    staging_dir = Path(tempfile.mkdtemp(prefix=".seal-keygen-", dir=output_dir))
    os.chmod(staging_dir, 0o700)
    published: list[Path] = []
    try:
        staged: dict[str, Path] = {}
        for index, name in enumerate(KEY_FILENAMES):
            path = staging_dir / f"value-{index}.tmp"
            with path.open("x", encoding="ascii") as stream:
                os.chmod(path, 0o600)
                stream.write(values[name] + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            staged[name] = path

        # Hard-linking refuses to overwrite a concurrently-created target.
        # Roll back every published link if any member cannot be installed.
        for name in KEY_FILENAMES:
            target = targets[name]
            os.link(staged[name], target)
            published.append(target)

        directory_fd = os.open(output_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        for target in reversed(published):
            target.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)


def generate_keys(output_dir: Path) -> tuple[Path, ...]:
    for staging_dir in output_dir.glob(".seal-keygen-*"):
        shutil.rmtree(staging_dir)

    (
        generate_config,
        derive_config_public,
        generate_approval,
        derive_approval_public,
    ) = _load_key_generators()
    config_private, config_public = _validated_pair(
        "config", generate_config, derive_config_public
    )
    approval_private, approval_public = _validated_pair(
        "approval", generate_approval, derive_approval_public
    )
    values = {
        "approval.key": approval_private,
        "config.key": config_private,
        "config.pub": config_public,
        "approval.pub": approval_public,
    }
    _write_complete_keyset(output_dir, values)
    return tuple(output_dir / name for name in KEY_FILENAMES)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(".seal"),
        help="directory for approval.key, config.key, config.pub, and approval.pub",
    )
    args = parser.parse_args()
    try:
        paths = generate_keys(args.out_dir)
    except Exception as error:
        print(f"key generation failed: {error}", file=sys.stderr)
        return 1
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
