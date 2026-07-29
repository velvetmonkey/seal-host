#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Freeze gate for the staged V2.3 effect-envelope host contract.

The V2.3 contract surface — the prose contract doc, the Rust encoder source,
the shared twin corpus, the Lean-generated expectation file, the twin/host
test sources, and the Lean lane source — is pinned by contract-view SHA-256
in both
``docs/effect-envelope-v23.freeze.json`` and an independently maintained
review baseline below. ``--refreeze`` updates only the manifest. A contract
change therefore also requires a conspicuous, manually reviewed gate-code
change; file plus manifest cannot certify themselves.

Contract views are deliberately simple and language-specific:

* Markdown, JSON, hex, and unknown file kinds are byte-exact. The Markdown is
  the normative prose contract, while JSON and hex are wire corpora.
* Rust hashes executable source after lexical comments are removed and
  inter-token whitespace is collapsed. In test sources only, the identifier
  after a plain ``#[test] fn`` is canonicalised; the test body remains frozen.
* Lean hashes executable source with the same comment and whitespace rules.

The scanners understand strings, character literals, Rust raw strings, and
nested block comments, so comment delimiters and whitespace inside literals
remain contract bytes.

The checked-in manifest predates contract views and contains whole-file
digests. ``LEGACY_CONTRACT_VIEWS`` bridges that one-time migration without a
ceremonial refreeze: an exact approved contract view yields its old stored
digest. Any contract-view change yields the new digest directly. Once a file
has a real reviewed contract change, its legacy entry is no longer involved.

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
        "ab1cdb0c95f05b2703957f4f54c687e8e38f613803969b6372a77cad127348eb",
    "rust/src/envelope_v23.rs":
        "15edd4a02d73da36f0d2d8f72934d28a097547c3fed505fda4e736dfab0cbdbe",
    "rust/tests/envelope_v23.rs":
        "5558a435d43c7947dcb990bf1a72447723fa65a100d204e46a985fd21e3e4581",
    "rust/tests/envelope_v23_twin.rs":
        "6bab05228b6b42b10f3ded8361f580a60cd80d3512db7b6cb8c9bfadea2a090a",
    "rust/tests/vectors/envelope_v23_twin_corpus.json":
        "ce9048af3df4a2edc70c09b3bb9c6f7b920ac53775d0a0a1e8c5efc5b0075cd1",
    "rust/tests/vectors/envelope_v23_twin_expected.hex":
        "7fd50361da59fef0d157829bbf4268c4fc9cd213a8fed57b3503865a1e6c5e15",
    "scripts/envelope_v23_twin_lane.lean":
        "9ce45fd3850a4643986a936df049eb6f65992b4170b55f7f727a469eaac8292d",
}

# One-time compatibility for the manifest and review baseline written before
# contract views existed. Each value is the contract-view SHA-256 derived from
# the file already approved by REVIEWED_HASHES. A matching view returns only
# REVIEWED_HASHES[path]; this table cannot name an alternative accepted output.
# Executable drift changes the view digest and is returned directly.
LEGACY_CONTRACT_VIEWS = {
    "rust/src/envelope_v23.rs":
        "0a99165671c5d41818026d9029f45fef417bc93cc6c409153f2ace01be2b9e21",
    "rust/tests/envelope_v23.rs":
        "a46fd72e295800c4ea8fbe8a1c3ab50eeb989d70407800b15237eac875662df5",
    "rust/tests/envelope_v23_twin.rs":
        "91779c32813b82ba49d8216f6f7b93285c29fe953c1c9c5e6e254e3f7b457e68",
    "scripts/envelope_v23_twin_lane.lean":
        "dfca3de0cf4d4e4891dd393ea9ea2dd819f73025cb58dfe3868e9bf8abf885d8",
}

TWIN_TEST = ROOT / "rust" / "tests" / "envelope_v23_twin.rs"
HOST_TEST = ROOT / "rust" / "tests" / "envelope_v23.rs"
CORPUS = ROOT / "rust" / "tests" / "vectors" / "envelope_v23_twin_corpus.json"
EXPECTED = ROOT / "rust" / "tests" / "vectors" / "envelope_v23_twin_expected.hex"
GOLDEN_VECTOR = "golden-fable"


def fail(message: str) -> None:
    print(f"ERROR  {message}", file=sys.stderr)
    sys.exit(1)


def _copy_quoted(data: bytes, start: int, quote: int) -> int:
    """Return the first byte after a conventional escaped string/character."""
    index = start + 1
    while index < len(data):
        if data[index] == ord("\\"):
            index += 2
        elif data[index] == quote:
            return index + 1
        else:
            index += 1
    return len(data)


def _rust_raw_string_end(data: bytes, start: int) -> int | None:
    """Return the end of a Rust r###"..."### literal starting at ``start``."""
    index = start
    if data[index:index + 2] in (b"br", b"cr"):
        index += 2
    elif data[index:index + 1] == b"r":
        index += 1
    else:
        return None
    hashes = 0
    while index < len(data) and data[index] == ord("#"):
        hashes += 1
        index += 1
    if index >= len(data) or data[index] != ord('"'):
        return None
    close = b'"' + (b"#" * hashes)
    found = data.find(close, index + 1)
    return len(data) if found == -1 else found + len(close)


def _looks_like_char_literal(data: bytes, start: int) -> bool:
    """Distinguish a short character literal from an identifier apostrophe."""
    end = start + 1
    if end >= len(data) or data[end] in b"\r\n'":
        return False
    if data[end] == ord("\\"):
        end += 2
        if end < len(data) and data[end - 1] == ord("u") and data[end] == ord("{"):
            close = data.find(b"}", end + 1)
            end = len(data) if close == -1 else close + 1
    else:
        first = data[end]
        width = (
            1 if first < 0x80 else
            2 if first & 0xE0 == 0xC0 else
            3 if first & 0xF0 == 0xE0 else
            4 if first & 0xF8 == 0xF0 else
            1
        )
        end += width
    return end < len(data) and data[end] == ord("'")


def _without_comments(
    data: bytes, *, line_open: bytes, block_open: bytes, block_close: bytes,
    rust_literals: bool,
) -> bytes:
    """Return code tokens with comments removed and whitespace canonicalised."""
    output = bytearray()

    def append_space() -> None:
        if output and output[-1] != ord(" "):
            output.append(ord(" "))

    index = 0
    while index < len(data):
        if data.startswith(line_open, index):
            append_space()
            newline = data.find(b"\n", index + len(line_open))
            if newline == -1:
                break
            index = newline + 1
            continue
        if data.startswith(block_open, index):
            append_space()
            index += len(block_open)
            depth = 1
            while index < len(data) and depth:
                if data.startswith(block_open, index):
                    depth += 1
                    index += len(block_open)
                elif data.startswith(block_close, index):
                    depth -= 1
                    index += len(block_close)
                else:
                    index += 1
            continue
        if rust_literals:
            raw_end = _rust_raw_string_end(data, index)
            if raw_end is not None:
                output.extend(data[index:raw_end])
                index = raw_end
                continue
            if data[index:index + 2] in (b'b"', b'c"'):
                end = _copy_quoted(data, index + 1, ord('"'))
                output.extend(data[index:end])
                index = end
                continue
            if data[index:index + 2] == b"b'" and _looks_like_char_literal(data, index + 1):
                end = _copy_quoted(data, index + 1, ord("'"))
                output.extend(data[index:end])
                index = end
                continue
            if data[index] == ord("'") and not _looks_like_char_literal(data, index):
                output.append(data[index])
                index += 1
                continue
        if data[index] == ord("'") and not _looks_like_char_literal(data, index):
            output.append(data[index])
            index += 1
            continue
        if data[index] in (ord('"'), ord("'")):
            end = _copy_quoted(data, index, data[index])
            output.extend(data[index:end])
            index = end
            continue
        if data[index] in b" \t\r\n\v\f":
            append_space()
            index += 1
            while index < len(data) and data[index] in b" \t\r\n\v\f":
                index += 1
            continue
        output.append(data[index])
        index += 1
    return bytes(output).strip()


def contract_view(relative: str, path: Path) -> bytes:
    """Return the deterministic bytes whose digest represents ``relative``."""
    data = path.read_bytes()
    if path.suffix == ".rs":
        view = _without_comments(
            data,
            line_open=b"//",
            block_open=b"/*",
            block_close=b"*/",
            rust_literals=True,
        )
        if relative.startswith("rust/tests/"):
            view = re.sub(
                rb"(#\s*\[\s*test\s*\]\s*fn\s+)[A-Za-z_][A-Za-z0-9_]*",
                rb"\1<test-name>",
                view,
            )
        return view
    if path.suffix == ".lean":
        return _without_comments(
            data,
            line_open=b"--",
            block_open=b"/-",
            block_close=b"-/",
            rust_literals=False,
        )
    return data


def contract_sha256(relative: str, path: Path) -> str:
    digest = hashlib.sha256(contract_view(relative, path)).hexdigest()
    legacy = LEGACY_CONTRACT_VIEWS.get(relative)
    if legacy is not None and digest == legacy:
        return REVIEWED_HASHES[relative]
    return digest


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

    # "7365616c2e6566666563742f7632" is hex("seal.effect/v2"), the message
    # magic — every full golden literal starts with it.
    twin_literal = extract_hex_literal(
        TWIN_TEST, r'"(7365616c2e6566666563742f7632[0-9a-f]+)"')
    host_literal = extract_hex_literal(
        HOST_TEST, r'"(7365616c2e6566666563742f7632[0-9a-f]+)"')
    expectation_golden = expected_lines[golden_index]

    if twin_literal != host_literal:
        fail("the #guard_msgs golden literal in envelope_v23_twin.rs and the "
             "golden vector literal in envelope_v23.rs are not byte-identical")
    if expectation_golden != twin_literal:
        fail(f"expectation line for {GOLDEN_VECTOR!r} does not equal the "
             "#guard_msgs golden literal pinned in the twin test")


def current_hashes(paths: tuple[str, ...]) -> dict[str, str]:
    return {
        relative: contract_sha256(relative, ROOT / relative)
        for relative in paths
    }


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
