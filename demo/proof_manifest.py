#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generate a demo proof manifest from existing Lean axiom pins."""

import argparse
from pathlib import Path

from doctrine import generate_proof_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("theorem", nargs="+")
    args = parser.parse_args()
    generate_proof_manifest(args.output, args.theorem)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
