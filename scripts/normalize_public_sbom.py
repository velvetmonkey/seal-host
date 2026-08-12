#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Remove exporter scratch paths from a cargo-cyclonedx JSON document."""

import json
from pathlib import Path
import sys
from typing import Any


STABLE_RUST_ROOT = "/seal-host-public-source/rust"


def normalize(value: Any, scratch_root: str) -> tuple[Any, int]:
    if isinstance(value, str):
        return value.replace(scratch_root, STABLE_RUST_ROOT), value.count(scratch_root)
    if isinstance(value, list):
        normalized = []
        replacements = 0
        for item in value:
            item, count = normalize(item, scratch_root)
            normalized.append(item)
            replacements += count
        return normalized, replacements
    if isinstance(value, dict):
        normalized = {}
        replacements = 0
        for key, item in value.items():
            item, count = normalize(item, scratch_root)
            normalized[key] = item
            replacements += count
        return normalized, replacements
    return value, 0


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: normalize_public_sbom.py SBOM SCRATCH_RUST_ROOT")

    sbom_path = Path(sys.argv[1])
    scratch_root = str(Path(sys.argv[2]).resolve())
    document = json.loads(sbom_path.read_text(encoding="utf-8"))
    document, replacements = normalize(document, scratch_root)
    if replacements == 0:
        raise SystemExit(f"SBOM contains no scratch-root references: {scratch_root}")

    rendered = json.dumps(document, indent=2) + "\n"
    if scratch_root in rendered:
        raise SystemExit(f"SBOM still contains scratch-root references: {scratch_root}")
    sbom_path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
