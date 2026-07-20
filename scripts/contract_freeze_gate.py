#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Freeze gate for the staged V2.3 effect-envelope host contract.

The V2.3 contract surface — the prose contract doc, the Rust encoder source,
the shared twin corpus, the Lean-generated expectation file, the twin/host
test sources, and the Lean lane source — is pinned by SHA-256 in both
``docs/effect-envelope-v23.freeze.json`` and an independently maintained
review baseline below. ``--refreeze`` updates only the manifest. A contract
change therefore also requires a conspicuous, manually reviewed gate-code
change; file plus manifest cannot certify themselves.

This gate deliberately needs no Lean, no cargo, and no private dependency
token: it is standard-library Python over checked-in files plus Git's tracked
path inventory, so it can run unconditionally on every push, including the
tokenless CI path where the ``cargo test --test envelope_v23_twin`` step is
skipped.

The Git-tracked contents of every frozen directory are enumerated, so a new
tracked contract vector cannot hide outside the manifest. Untracked build and
editor debris is deliberately ignored.

Beyond the independent baseline, three relational anchors are cross-checked
on every run (including ``--refreeze``):

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
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "effect-envelope-v23.freeze.json"
SCHEMA = "seal-effect-envelope-v23-freeze/v1"
ALLOWED_KEYS = {"schema", "comment", "frozen"}

REQUIRED_FROZEN_FILES = (
    "docs/EFFECT-ENVELOPE-V23.md",
    "rust/src/envelope_v23.rs",
    "rust/tests/envelope_v23.rs",
    "rust/tests/envelope_v23_twin.rs",
    "rust/tests/vectors/envelope_v23_twin_corpus.json",
    "rust/tests/vectors/envelope_v23_twin_expected.hex",
    "scripts/envelope_v23_twin_lane.lean",
)

# Every Git-tracked file in these directories is part of the frozen contract
# surface. Keep this narrow: docs/, rust/src/, rust/tests/, and scripts/ also
# contain unrelated contracts and implementation files.
FROZEN_DIRECTORIES = (
    "rust/tests/vectors",
)

# This is deliberately separate from the writable manifest. `--refreeze`
# never changes it. Updating a frozen contract therefore requires a reviewer-
# visible code change naming every newly approved digest, rather than allowing
# the file and its manifest entry to approve one another.
REVIEWED_HASHES = {
    "docs/EFFECT-ENVELOPE-V23.md":
        "2257776a0acf5d0b53e44e87d77af27eccdbb9bdc481ae49ea66ff51e9674e01",
    "rust/src/envelope_v23.rs":
        "e38f42940d4b587705ccd6c3dee4a24ae53bc60487d9fcce352336f8a39d3a34",
    "rust/tests/envelope_v23.rs":
        "d17c37db02cb82ac329c05d55db09fccc4bafc96e1ca461082467ed18bed9b33",
    "rust/tests/envelope_v23_twin.rs":
        "3023bd4b93dd33c807cafbbc6b43f1d6842476f5a7523c55ec5c0cf7ee08464d",
    "rust/tests/vectors/envelope_v23_twin_corpus.json":
        "d177022f1ba2a7aea9ce4913684c3b827858692387cbae72aaef47a027668fe7",
    "rust/tests/vectors/envelope_v23_twin_expected.hex":
        "762756a6a6368a9a024886763d9aad96dcb0e58536bff793d50ac030ca4649fc",
    "scripts/envelope_v23_twin_lane.lean":
        "b28149576feffbf84e7922d0f2948f1ab425285ade9b0033277e17752e853e03",
}

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


def frozen_files() -> tuple[str, ...]:
    """Return required files plus every tracked file in frozen directories."""
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--", *FROZEN_DIRECTORIES],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        detail = getattr(error, "stderr", b"")
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace").strip()
        fail(f"cannot enumerate tracked frozen directories with git: {detail or error}")

    try:
        tracked = {
            item.decode("utf-8")
            for item in result.stdout.split(b"\0")
            if item
        }
    except UnicodeDecodeError as error:
        fail(f"tracked frozen path is not UTF-8: {error}")

    return tuple(sorted(set(REQUIRED_FROZEN_FILES) | tracked))


def extract_hex_literal(path: Path, pattern: str) -> str:
    found = set(re.findall(pattern, path.read_text(encoding="utf-8")))
    if len(found) != 1:
        fail(f"{path.relative_to(ROOT)}: expected exactly one golden hex "
             f"literal matching {pattern!r}, found {len(found)}; "
             "the anchor check is dead, refusing")
    return found.pop()


def check_anchors(paths: tuple[str, ...]) -> None:
    """The frozen literals must agree with each other and with the corpus."""
    for relative in paths:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
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


def current_hashes(paths: tuple[str, ...]) -> dict[str, str]:
    return {relative: sha256(ROOT / relative) for relative in paths}


def read_manifest(*, allow_missing: bool = False) -> dict[str, str]:
    if not MANIFEST.is_file():
        if allow_missing:
            return {}
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
            or not all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                       for v in frozen.values())):
        fail("manifest rejected: 'frozen' must map paths to 64-hex SHA-256 digests")
    return frozen


def load_manifest(paths: tuple[str, ...]) -> dict[str, str]:
    frozen = read_manifest()
    if set(frozen) != set(paths):
        missing = sorted(set(paths) - set(frozen))
        extra = sorted(set(frozen) - set(paths))
        for relative in missing:
            print(f"UNFROZEN  {relative}", file=sys.stderr)
        for relative in extra:
            print(f"STALE     {relative}", file=sys.stderr)
        fail("manifest must map exactly the Git-tracked frozen contract surface")
    return frozen


def check_reviewed_baseline(hashes: dict[str, str]) -> None:
    """Reject content that has only approved itself via the manifest."""
    mismatch = False
    for relative in sorted(set(hashes) | set(REVIEWED_HASHES)):
        current = hashes.get(relative)
        reviewed = REVIEWED_HASHES.get(relative)
        if current != reviewed:
            mismatch = True
            print(
                f"REVIEW  {relative}  reviewed={reviewed or '-'} current={current or '-'}",
                file=sys.stderr,
            )
    if mismatch:
        fail(
            "contract content is absent from or differs from the independent "
            "review baseline; --refreeze cannot approve this change. A reviewer "
            "must inspect the contract diff and update REVIEWED_HASHES by hand"
        )


def write_manifest(hashes: dict[str, str]) -> None:
    doc = {
        "schema": SCHEMA,
        "comment": (
            "SHA-256 freeze of the staged V2.3 effect-envelope contract "
            "surface. Verified unconditionally in CI against the independent "
            "REVIEWED_HASHES baseline in scripts/contract_freeze_gate.py. A "
            "deliberate contract change must update that baseline by hand "
            "after review, then run --refreeze locally; CI refreezes are "
            "forbidden."
        ),
        "frozen": dict(sorted(hashes.items())),
    }
    MANIFEST.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


def report_refreeze(old: dict[str, str], new: dict[str, str]) -> None:
    changed = False
    for relative in sorted(set(old) | set(new)):
        before = old.get(relative)
        after = new.get(relative)
        if before == after:
            continue
        changed = True
        action = "ADD" if before is None else "REMOVE" if after is None else "UPDATE"
        print(f"REFREEZE {action:6} {relative}")
        print(f"         old={before or '-'}")
        print(f"         new={after or '-'}")
    if not changed:
        print("REFREEZE no manifest digest changes")


def main(argv: list[str]) -> int:
    if argv not in ([], ["--refreeze"]):
        print(__doc__, file=sys.stderr)
        return 2

    if argv == ["--refreeze"]:
        if ("CI" in os.environ
                or os.environ.get("GITHUB_ACTIONS") == "true"
                or os.environ.get("CONTRACT_FREEZE_CI") == "1"):
            fail("--refreeze is forbidden on a CI runner")

    paths = frozen_files()
    check_anchors(paths)
    hashes = current_hashes(paths)
    check_reviewed_baseline(hashes)

    if argv == ["--refreeze"]:
        old = read_manifest(allow_missing=True)
        report_refreeze(old, hashes)
        write_manifest(hashes)
        print(f"re-froze {len(hashes)} contract files into "
              f"{MANIFEST.relative_to(ROOT)}")
        return 0

    frozen = load_manifest(paths)
    drifted = [relative for relative in paths
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
          f"{MANIFEST.relative_to(ROOT)}; independent review baseline and "
          "golden anchors agree")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
