#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate a complete doctrine demo artifact directory."""

import argparse
from pathlib import Path

from doctrine import validate_trace


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", type=Path)
    args = parser.parse_args()
    validate_trace(args.artifact_dir)
    print(f"PASS doctrine trace: {args.artifact_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
