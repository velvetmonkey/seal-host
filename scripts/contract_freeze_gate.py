#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Freeze gate for the staged V2.3 effect-envelope host contract.

The V2.3 contract surface — the prose contract doc, the Rust encoder source,
the shared twin corpus, the Lean-generated expectation file, the twin/host
test sources, and the Lean lane source — is pinned by SHA-256 in
``docs/effect-envelope-v23.freeze.json``. Any byte change to a pinned file
without a matching manifest update exits non-zero, so the contract cannot
drift without an explicit re-freeze commit.

This gate deliberately needs no Lean, no cargo, and no private dependency
token: it is plain-stdlib Python over checked-in files, so it can run
unconditionally on every push, including the tokenless CI path where the
``cargo test --test envelope_v23_twin`` step is skipped.

Beyond file hashes, three anchors are cross-checked on every run (including
``--refreeze``, so a re-freeze cannot silently bypass them):

* the ``LEAN_GUARD_MSGS_GOLDEN_HEX`` literal in ``rust/tests/envelope_v23_twin.rs``,
* the golden-vector hex literal in ``rust/tests/envelope_v23.rs``,
* the ``golden-fable`` line of ``rust/tests/vectors/envelope_v23_twin_expected.hex``

must be byte-identical, and the expectation file must carry exactly one line
per corpus vector.

Usage:
    python3 scripts/contract_freeze_gate.py             # verify (CI)
    python3 scripts/contract_freeze_gate.py --refreeze  # deliberate re-freeze
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "effect-envelope-v23.freeze.json"
SCHEMA = "seal-effect-envelope-v23-freeze/v1"
ALLOWED_KEYS = {"schema", "comment", "frozen"}

FROZEN_FILES = (
    "docs/EFFECT-ENVELOPE-V23.md",
    "rust/src/envelope_v23.rs",
    "rust/tests/envelope_v23.rs",
    "rust/tests/envelope_v23_twin.rs",
    "rust/tests/vectors/envelope_v23_twin_corpus.json",
    "rust/tests/vectors/envelope_v23_twin_expected.hex",
    "scripts/envelope_v23_twin_lane.lean",
)

TWIN_TEST = ROOT / "rust" / "tests" / "envelope_v23_twin.rs"
HOST_TEST = ROOT / "rust" / "tests" / "envelope_v23.rs"
CORPUS = ROOT / "rust" / "tests" / "vectors" / "envelope_v23_twin_corpus.json"
EXPECTED = ROOT / "rust" / "tests" / "vectors" / "envelope_v23_twin_expected.hex"
GOLDEN_VECTOR = "golden-fable"


def fail(message: str) -> None:
    print(f"ERROR  {message}", file=sys.stderr)
    sys.exit(1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_hex_literal(path: Path, pattern: str) -> str:
    found = set(re.findall(pattern, path.read_text(encoding="utf-8")))
    if len(found) != 1:
        fail(f"{path.relative_to(ROOT)}: expected exactly one golden hex "
             f"literal matching {pattern!r}, found {len(found)}; "
             "the anchor check is dead, refusing")
    return found.pop()


def check_anchors() -> None:
    """The frozen literals must agree with each other and with the corpus."""
    for relative in FROZEN_FILES:
        if not (ROOT / relative).is_file():
            fail(f"frozen contract file missing: {relative}")

    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    vectors = corpus.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        fail("corpus has no vectors array")
    names = [v.get("name") for v in vectors]
    if GOLDEN_VECTOR not in names:
        fail(f"corpus lost its {GOLDEN_VECTOR!r} vector")
    golden_index = names.index(GOLDEN_VECTOR)

    expected_lines = EXPECTED.read_text(encoding="utf-8").splitlines()
    if len(expected_lines) != len(vectors):
        fail(f"expectation/corpus vector count mismatch: "
             f"{len(expected_lines)} expectation lines, {len(vectors)} corpus vectors")

    # "7365616c2e6566666563742f7631" is hex("seal.effect/v1"), the message
    # magic — every full golden literal starts with it.
    twin_literal = extract_hex_literal(
        TWIN_TEST, r'"(7365616c2e6566666563742f7631[0-9a-f]+)"')
    host_literal = extract_hex_literal(
        HOST_TEST, r'"(7365616c2e6566666563742f7631[0-9a-f]+)"')
    expectation_golden = expected_lines[golden_index]

    if twin_literal != host_literal:
        fail("the #guard_msgs golden literal in envelope_v23_twin.rs and the "
             "golden vector literal in envelope_v23.rs are not byte-identical")
    if expectation_golden != twin_literal:
        fail(f"expectation line for {GOLDEN_VECTOR!r} does not equal the "
             "#guard_msgs golden literal pinned in the twin test")


def current_hashes() -> dict[str, str]:
    return {relative: sha256(ROOT / relative) for relative in FROZEN_FILES}


def load_manifest() -> dict[str, str]:
    if not MANIFEST.is_file():
        fail(f"manifest rejected: {MANIFEST.relative_to(ROOT)} is missing; "
             "run scripts/contract_freeze_gate.py --refreeze to create it")
    try:
        doc = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"manifest rejected: not JSON ({error})")
    if not isinstance(doc, dict):
        fail("manifest rejected: top level must be an object")
    unknown = set(doc) - ALLOWED_KEYS
    if unknown:
        fail(f"manifest rejected: unknown keys {sorted(unknown)}")
    if doc.get("schema") != SCHEMA:
        fail(f"manifest rejected: schema must be {SCHEMA!r}")
    frozen = doc.get("frozen")
    if (not isinstance(frozen, dict)
            or set(frozen) != set(FROZEN_FILES)
            or not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                       for v in frozen.values())):
        fail("manifest rejected: 'frozen' must map exactly the gated contract "
             "files to 64-hex SHA-256 digests")
    return frozen


def write_manifest(hashes: dict[str, str]) -> None:
    doc = {
        "schema": SCHEMA,
        "comment": (
            "SHA-256 freeze of the staged V2.3 effect-envelope contract "
            "surface. Verified unconditionally in CI by "
            "scripts/contract_freeze_gate.py; a deliberate contract change "
            "must rerun it with --refreeze and commit this file in the same "
            "change."
        ),
        "frozen": dict(sorted(hashes.items())),
    }
    MANIFEST.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    if argv not in ([], ["--refreeze"]):
        print(__doc__, file=sys.stderr)
        return 2

    check_anchors()
    hashes = current_hashes()

    if argv == ["--refreeze"]:
        write_manifest(hashes)
        print(f"re-froze {len(hashes)} contract files into "
              f"{MANIFEST.relative_to(ROOT)}")
        return 0

    frozen = load_manifest()
    drifted = [relative for relative in FROZEN_FILES
               if frozen[relative] != hashes[relative]]
    if drifted:
        for relative in drifted:
            print(f"DRIFT  {relative}", file=sys.stderr)
        print(
            "ERROR  the V2.3 contract surface changed without an explicit "
            "re-freeze. If the change is deliberate and reviewed, run "
            "scripts/contract_freeze_gate.py --refreeze and commit the "
            "manifest with it.",
            file=sys.stderr,
        )
        return 1

    print(f"PASS  {len(hashes)} frozen V2.3 contract files match "
          f"{MANIFEST.relative_to(ROOT)}; golden anchors agree")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
