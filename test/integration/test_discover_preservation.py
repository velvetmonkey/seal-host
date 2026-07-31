#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Raw-wire closure fixture for the transparent server/discover route."""

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from test_host_rs import PUBKEY, ROOT, write_config

BIN = Path(os.environ.get("SEAL_HOST_BIN", ROOT / "rust/target/debug/seal-host-rs"))
REQUEST = b' { "params" : { "_meta" : { "io.modelcontextprotocol/clientCapabilities" : {}, "io.modelcontextprotocol/clientInfo" : { "version" : "0.0-odd", "name" : "byte-client" }, "io.modelcontextprotocol/protocolVersion" : "2026-07-28" } }, "method" : "server/discover", "id" : 73, "jsonrpc" : "2.0" }\n'
RESPONSE = ' { "result" : { "_meta" : { "io.modelcontextprotocol/serverInfo" : { "version" : "00.0+odd", "name" : "Odd Child / Δ" } }, "resultType" : "complete", "capabilities" : { "resources" : { "subscribe" : false }, "tools" : { "listChanged" : true } }, "supportedVersions" : [ "2026-07-28" ] }, "id" : 73, "jsonrpc" : "2.0" }\n'.encode()
CHILD = "import pathlib,sys; raw=sys.stdin.buffer.readline(); pathlib.Path(sys.argv[1]).write_bytes(raw); sys.stdout.buffer.write(bytes.fromhex(sys.argv[2])); sys.stdout.buffer.flush()"


def _quoted_end(source: bytes, start: int, quote: int) -> int:
    index = start + 1
    while index < len(source):
        if source[index] == ord("\\"):
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    return len(source)


def _rust_raw_string_end(source: bytes, start: int) -> int | None:
    index = start
    if source[index:index + 2] in (b"br", b"cr"):
        index += 2
    elif source[index:index + 1] == b"r":
        index += 1
    else:
        return None
    hashes = 0
    while index < len(source) and source[index] == ord("#"):
        hashes += 1
        index += 1
    if index >= len(source) or source[index] != ord('"'):
        return None
    close = b'"' + (b"#" * hashes)
    found = source.find(close, index + 1)
    return len(source) if found == -1 else found + len(close)


def _looks_like_char_literal(source: bytes, start: int) -> bool:
    index = start + 1
    if index >= len(source) or source[index] in b"\r\n'":
        return False
    if source[index] == ord("\\"):
        index += 2
        if (index < len(source) and source[index - 1] == ord("u")
                and source[index] == ord("{")):
            close = source.find(b"}", index + 1)
            index = len(source) if close == -1 else close + 1
    else:
        first = source[index]
        width = (1 if first < 0x80 else
                 2 if first & 0xE0 == 0xC0 else
                 3 if first & 0xF0 == 0xE0 else
                 4 if first & 0xF8 == 0xF0 else 1)
        index += width
    return index < len(source) and source[index] == ord("'")


def strip_source_comments(source: bytes, suffix: str) -> bytes:
    """Blank Rust/Lean comments without hiding literals from the guard."""
    if suffix == ".rs":
        line_open, block_open, block_close = b"//", b"/*", b"*/"
        rust_literals = True
    elif suffix == ".lean":
        line_open, block_open, block_close = b"--", b"/-", b"-/"
        rust_literals = False
    else:
        raise ValueError(f"unsupported production source suffix: {suffix}")

    stripped = bytearray(source)

    def blank(start: int, end: int) -> None:
        for offset in range(start, end):
            if stripped[offset] not in b"\r\n":
                stripped[offset] = ord(" ")

    index = 0
    while index < len(source):
        if source.startswith(line_open, index):
            end = source.find(b"\n", index + len(line_open))
            end = len(source) if end == -1 else end
            blank(index, end)
            index = end
            continue

        if source.startswith(block_open, index):
            start = index
            index += len(block_open)
            depth = 1
            while index < len(source) and depth:
                if source.startswith(block_open, index):
                    depth += 1
                    index += len(block_open)
                elif source.startswith(block_close, index):
                    depth -= 1
                    index += len(block_close)
                else:
                    index += 1
            blank(start, index)
            continue

        if rust_literals:
            raw_end = _rust_raw_string_end(source, index)
            if raw_end is not None:
                index = raw_end
                continue

        if source[index] == ord('"'):
            index = _quoted_end(source, index, ord('"'))
            continue
        if (source[index] == ord("'")
                and _looks_like_char_literal(source, index)):
            index = _quoted_end(source, index, ord("'"))
            continue
        index += 1

    return bytes(stripped)


def assert_comment_stripper_contract() -> None:
    keys = (b'"protocolVersion"', b'\\"protocolVersion\\"')
    comments = {
        ".rs": (b'// "protocolVersion" \\"protocolVersion\\"\n'
                b'/* outer "protocolVersion" '
                b'/* nested \\"protocolVersion\\" */ */'),
        ".lean": (b'-- "protocolVersion" \\"protocolVersion\\"\n'
                  b'/- outer "protocolVersion" '
                  b'/- nested \\"protocolVersion\\" -/ -/'),
    }
    literals = {
        ".rs": (b'const PLAIN: &str = "protocolVersion";\n'
                b'const ESCAPED: &str = "\\\"protocolVersion\\\"";'),
        ".lean": (b'def plain := "protocolVersion"\n'
                  b'def escaped := "\\\"protocolVersion\\\""'),
    }
    for suffix in comments:
        stripped_comments = strip_source_comments(comments[suffix], suffix)
        stripped_literals = strip_source_comments(literals[suffix], suffix)
        assert all(key not in stripped_comments for key in keys), \
            f"{suffix} comment stripping left guarded response fields visible"
        assert all(key in stripped_literals for key in keys), \
            f"{suffix} comment stripping hid guarded response literals"


def assert_no_production_fabricator() -> None:
    # M.2 must observe the `server/discover` request method to derive the
    # per-session scalar revision. That request-side literal is not response
    # fabrication. Keep this static supplement scoped to response fields; the
    # runtime assertions below remain the authority for byte preservation.
    keys = (b'"protocolVersion"', b'\\"protocolVersion\\"',
            b'"supportedVersions"', b'\\"supportedVersions\\"',
            b'"capabilities"', b'\\"capabilities\\"',
            b'"serverInfo"', b'\\"serverInfo\\"',
            b'"resultType"', b'\\"resultType\\"')
    sources = list((ROOT / "rust/src").rglob("*.rs"))
    sources += list((ROOT / "Host").rglob("*.lean")) + [ROOT / "Ffi.lean"]
    found = [(str(path.relative_to(ROOT)), key.decode())
             for path in sources
             for source in [strip_source_comments(path.read_bytes(), path.suffix)]
             for key in keys if key in source]
    assert not found, f"DISCOVER PRODUCTION FABRICATION PATH FOUND: {found}"


def run_once(root: Path, tag: str) -> tuple[bytes, bytes]:
    run = root / tag
    run.mkdir(mode=0o700)
    approvals = run / "approvals.ndjson"
    approvals.write_bytes(b"")
    config = write_config(run, approvals)
    observed = run / "child-request.bin"
    proc = subprocess.Popen(
        [str(BIN), "--insecure-development-mode", "--config", str(config),
         "--pubkey", PUBKEY, "--", sys.executable, "-c", CHILD, str(observed), RESPONSE.hex()],
        cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    proc.stdin.write(REQUEST)
    proc.stdin.flush()
    delivered = proc.stdout.readline()
    proc.stdin.close()
    delivered += proc.stdout.read()
    stderr = proc.stderr.read()
    proc.wait(timeout=20)
    assert proc.returncode == 0, f"DISCOVER HOST FAILURE run={tag} status={proc.returncode} stderr={stderr.decode(errors='replace')}"
    ingress = observed.read_bytes()
    assert ingress == REQUEST, f"DISCOVER REQUEST BYTE DIVERGENCE run={tag} expected_sha256={hashlib.sha256(REQUEST).hexdigest()} actual_sha256={hashlib.sha256(ingress).hexdigest()}"
    assert delivered == RESPONSE, f"DISCOVER RESPONSE BYTE DIVERGENCE run={tag} expected_sha256={hashlib.sha256(RESPONSE).hexdigest()} actual_sha256={hashlib.sha256(delivered).hexdigest()}"
    return ingress, delivered


def main() -> int:
    assert BIN.is_file(), f"build first: missing {BIN}"
    assert_comment_stripper_contract()
    assert_no_production_fabricator()
    with tempfile.TemporaryDirectory(prefix="seal-discover-preservation-") as td:
        first = run_once(Path(td), "first")
        second = run_once(Path(td), "twin")
    assert first == second, "DISCOVER POSITIVE TWIN DIVERGENCE: byte-identical runs delivered different bytes"
    print(f"DISCOVER REQUEST BYTES GREEN sha256={hashlib.sha256(REQUEST).hexdigest()} length={len(REQUEST)}")
    print(f"DISCOVER RESPONSE BYTES GREEN sha256={hashlib.sha256(RESPONSE).hexdigest()} length={len(RESPONSE)}")
    print("DISCOVER NO-FABRICATION GREEN protocolVersion=absent capabilities=child-exact serverInfo=Odd Child / Δ")
    print("DISCOVER PRODUCTION NO-FABRICATION GREEN response-source-literals=absent")
    print("DISCOVER POSITIVE TWIN GREEN request=byte-identical response=byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
