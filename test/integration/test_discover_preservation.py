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


def assert_no_production_fabricator() -> None:
    keys = (b'"protocolVersion"', b'\\"protocolVersion\\"', b'"capabilities"',
            b'\\"capabilities\\"', b'"serverInfo"', b'\\"serverInfo\\"',
            b'"server/discover"', b'\\"server/discover\\"')
    sources = list((ROOT / "rust/src").rglob("*.rs"))
    sources += list((ROOT / "Host").rglob("*.lean")) + [ROOT / "Ffi.lean"]
    found = [(str(path.relative_to(ROOT)), key.decode())
             for path in sources for key in keys if key in path.read_bytes()]
    assert not found, f"DISCOVER PRODUCTION FABRICATION PATH FOUND: {found}"


def run_once(root: Path, tag: str) -> tuple[bytes, bytes]:
    run = root / tag
    run.mkdir()
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
    assert_no_production_fabricator()
    with tempfile.TemporaryDirectory(prefix="seal-discover-preservation-") as td:
        first = run_once(Path(td), "first")
        second = run_once(Path(td), "twin")
    assert first == second, "DISCOVER POSITIVE TWIN DIVERGENCE: byte-identical runs delivered different bytes"
    print(f"DISCOVER REQUEST BYTES GREEN sha256={hashlib.sha256(REQUEST).hexdigest()} length={len(REQUEST)}")
    print(f"DISCOVER RESPONSE BYTES GREEN sha256={hashlib.sha256(RESPONSE).hexdigest()} length={len(RESPONSE)}")
    print("DISCOVER NO-FABRICATION GREEN protocolVersion=absent capabilities=child-exact serverInfo=Odd Child / Δ")
    print("DISCOVER PRODUCTION NO-FABRICATION GREEN source-literals=absent")
    print("DISCOVER POSITIVE TWIN GREEN request=byte-identical response=byte-identical")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
