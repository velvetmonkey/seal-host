#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""V3.1 exact-byte downstream MCP parser agreement experiment.

For every Rust/Lean parser-boundary divergence in JSONTestSuite, this script:

1. embeds the untouched corpus bytes in the same fixed envelope as
   rust/tests/external_json_corpus.rs;
2. asks the compiled Lean oracle for the production CanonicalAction;
3. sends the LF-terminated frame through the real seal-host-rs binary;
4. reads Lean's approval target from the real block response;
5. appends that target to an isolated file approval channel and resends the
   byte-identical frame; and
6. records the isolated downstream server's response and parser observation.

The 500-level nesting vector is intentionally not bypassed around Seal. The
production host's depth guard rejects it before classification or forwarding.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import select
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

# The Lean oracle prints huge-exponent JSON numbers as fully expanded integer
# literals (10k+ digits). This limit applies only to THIS script's reading of
# the oracle's stdout — downstream servers receive the original e-notation
# bytes and are not affected by it.
sys.set_int_max_str_digits(2_000_000)

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "rust/tests/corpora/JSONTestSuite/test_parsing"
HOST = ROOT / "rust/target/debug/seal-host-rs"
LEAN_ORACLE = ROOT / ".lake/build/bin/downstream_parser_oracle"
NODE_OBSERVER = ROOT / "scripts/v31_node_observer.mjs"
PYTHON_OBSERVER = ROOT / "scripts/v31_python_observer"
SIGN_TOOLS = ROOT / "test/tools"

CALL_PREFIX = (
    b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
    b'"params":{"name":"external.json_corpus","arguments":'
)
CALL_SUFFIX = b"}}"

VECTORS = [
    "i_number_neg_int_huge_exp.json",
    "i_number_pos_double_huge_exp.json",
    "i_number_real_neg_overflow.json",
    "i_number_real_pos_overflow.json",
    "i_number_real_underflow.json",
    "i_number_too_big_neg_int.json",
    "i_number_too_big_pos_int.json",
    "i_number_very_big_negative_int.json",
    "i_string_1st_surrogate_but_2nd_missing.json",
    "i_string_1st_valid_surrogate_2nd_invalid.json",
    "i_string_incomplete_surrogate_and_escape_valid.json",
    "i_string_incomplete_surrogate_pair.json",
    "i_string_incomplete_surrogates_escape_valid.json",
    "i_string_invalid_lonely_surrogate.json",
    "i_string_invalid_surrogate.json",
    "i_string_inverted_surrogates_U+1D11E.json",
    "i_string_lone_second_surrogate.json",
    "i_structure_500_nested_arrays.json",
]
NEGATIVE_CONTROLS = ["y_object_simple.json"]

INIT = (
    b'{"jsonrpc":"2.0","id":0,"method":"initialize","params":'
    b'{"protocolVersion":"2025-03-26","capabilities":{},'
    b'"clientInfo":{"name":"seal-v31","version":"1"}}}\n'
)
INITIALIZED = b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n'


@dataclass(frozen=True)
class Server:
    name: str
    command: tuple[str, ...]
    env: dict[str, str]


def node_server(name: str, entry: Path, env: dict[str, str] | None = None) -> Server:
    return Server(
        name,
        ("node", "--import", str(NODE_OBSERVER), str(entry)),
        env or {},
    )


def required_path(variable: str) -> Path:
    value = os.environ.get(variable)
    if not value:
        raise RuntimeError(f"{variable} must name the installed downstream server entry point")
    return Path(value).expanduser()


def servers(vault: Path, database: Path) -> list[Server]:
    python_env = {
        "PYTHONPATH": str(PYTHON_OBSERVER)
        + (os.pathsep + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")
    }
    return [
        node_server(
            "github-mcp-server@2025.4.8",
            required_path("SEAL_V31_GITHUB_MCP_ENTRY"),
        ),
        node_server(
            "patchright-lite-mcp-server@1.0.0",
            required_path("SEAL_V31_PATCHRIGHT_MCP_ENTRY"),
        ),
        node_server(
            "flywheel-memory@2.12.20",
            required_path("SEAL_V31_FLYWHEEL_MCP_ENTRY"),
            {
                "PROJECT_PATH": str(vault),
                "FLYWHEEL_TRANSPORT": "stdio",
                "FLYWHEEL_SKIP_EMBEDDINGS": "true",
                "FLYWHEEL_SKIP_FTS5": "true",
                "FLYWHEEL_WATCH": "false",
            },
        ),
        Server(
            "roundtable-ai@0.5.1 (Python MCP 1.27.2)",
            (
                str(required_path("SEAL_V31_ROUNDTABLE_MCP_COMMAND")),
                "--agents",
                "codex",
                "--working-dir",
                str(vault),
            ),
            python_env,
        ),
        Server(
            "seal sqlite demo@1.0.0 (toy)",
            (
                "python3",
                str(ROOT / "demo/sqlite_mcp_server.py"),
                "--database",
                str(database),
            ),
            python_env,
        ),
    ]


def read_line(stream, timeout: float) -> bytes | None:
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready:
        return None
    line = stream.readline()
    return line or None


def lean_action(judged: bytes, work: Path) -> dict:
    path = work / "judged.json"
    path.write_bytes(judged)
    result = subprocess.run(
        [str(LEAN_ORACLE), str(path)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Lean oracle failed: {result.stderr.strip()}")
    return json.loads(result.stdout)


def config(work: Path, approvals: Path) -> tuple[Path, str]:
    sys.path.insert(0, str(SIGN_TOOLS))
    from sign_config import generate_keypair, sign_payload

    private, public = generate_keypair()
    payload = {
        "epoch": 1,
        "safety": {
            "approval": {
                "control_file": str(approvals),
                "ttl_seconds": 120,
            },
            "tools": [
                {
                    "name": "external.json_corpus",
                    "mode": "guarded",
                    "match": {"type": "always"},
                    "target": [{"full_arguments": True}],
                }
            ],
        },
    }
    path = work / "trusted.json"
    path.write_text(sign_payload(payload, private), encoding="utf-8")
    return path, public


def response_outcome(response: dict | None) -> tuple[str, str]:
    if response is None:
        return "UNKNOWN", "no downstream response before timeout"
    if response.get("method") == "notifications/message":
        return "UNKNOWN", "downstream emitted a notification, not a request response"
    if "error" in response:
        return "REJECTS", json.dumps(response["error"], separators=(",", ":"))
    result = response.get("result")
    if isinstance(result, dict) and result.get("isError") is True:
        return "REJECTS", json.dumps(result, separators=(",", ":"))
    return "UNKNOWN", "server returned success; extraction comparison required"


def extraction_outcome(
    action: dict, observations: list[dict], forwarded_frame_sha256: str
) -> tuple[str, str, list[dict]]:
    matching = [
        observation
        for observation in observations
        if observation.get("wire_frame_sha256") == forwarded_frame_sha256
    ]
    if not matching:
        return (
            "UNKNOWN",
            "no server parse observation matched the exact forwarded frame SHA-256",
            [],
        )

    accepted = [
        observation for observation in matching if observation.get("accepted") is not False
    ]
    if not accepted:
        return (
            "REJECTS",
            "server parser rejected the exact forwarded frame: "
            + "; ".join(str(item.get("parse_error")) for item in matching),
            matching,
        )

    server_readings = [
        {
            "tool": observation.get("tool"),
            "arguments": observation.get("arguments"),
        }
        for observation in accepted
    ]
    if any(reading != server_readings[0] for reading in server_readings[1:]):
        return (
            "UNKNOWN",
            "parse layers produced internally inconsistent tool/argument readings",
            matching,
        )
    if action.get("class") != "Act":
        return "UNKNOWN", "Lean oracle did not return a CanonicalAction", matching

    lean_reading = {
        "tool": action.get("tool"),
        "arguments": action.get("arguments"),
    }
    server_reading = server_readings[0]
    if server_reading == lean_reading:
        return "AGREE", "same tool and arguments", matching
    return "DISAGREE", "different tool or arguments", matching


def evidence_safe(value):
    """Render lone UTF-16 code units as literal escape text in valid JSON."""
    if isinstance(value, str):
        return "".join(
            f"\\u{ord(char):04X}" if 0xD800 <= ord(char) <= 0xDFFF else char
            for char in value
        )
    if isinstance(value, list):
        return [evidence_safe(item) for item in value]
    if isinstance(value, dict):
        return {
            evidence_safe(key): evidence_safe(item) for key, item in value.items()
        }
    return value


def run_cell(server: Server, vector: str, judged: bytes, action: dict, base: Path) -> dict:
    work = base / re.sub(r"[^A-Za-z0-9_.-]", "_", server.name) / vector
    work.mkdir(parents=True)
    approvals = work / "approvals.ndjson"
    approvals.write_bytes(b"")
    trusted, public = config(work, approvals)
    receipts = work / "receipts"
    receipts.mkdir(mode=0o700)

    env = os.environ.copy()
    env.update(server.env)
    env["LD_LIBRARY_PATH"] = str(ROOT / ".lake/build/lib") + (
        os.pathsep + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else ""
    )
    command = [
        str(HOST),
        "--insecure-development-mode",
        "--config",
        str(trusted),
        "--pubkey",
        public,
        "--channel",
        "file",
        "--receipt-dir",
        str(receipts),
        "--",
        *server.command,
    ]
    proc = subprocess.Popen(
        command,
        cwd=ROOT,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
    forwarded_frame = judged + b"\n"
    record: dict = {
        "vector": vector,
        "server": server.name,
        "judged_sha256": hashlib.sha256(judged).hexdigest(),
        "forwarded_frame_sha256": hashlib.sha256(forwarded_frame).hexdigest(),
        "lean": action,
    }
    try:
        proc.stdin.write(INIT)
        proc.stdin.flush()
        init_response = read_line(proc.stdout, 30)
        if init_response is None:
            record.update(outcome="UNKNOWN", detail="server did not initialize")
            return record
        try:
            parsed_init = json.loads(init_response)
        except Exception:
            parsed_init = {
                "unparseable_response": init_response.decode("utf-8", "replace")
            }
        record["initialize_response"] = parsed_init
        if not (
            isinstance(parsed_init, dict)
            and parsed_init.get("id") == 0
            and isinstance(parsed_init.get("result"), dict)
        ):
            record.update(
                outcome="UNKNOWN",
                detail="server returned a non-initialize response to initialize",
            )
            return record
        proc.stdin.write(INITIALIZED)
        proc.stdin.flush()

        # First identical frame: obtain the target produced by Lean.
        proc.stdin.write(forwarded_frame)
        proc.stdin.flush()
        block_line = read_line(proc.stdout, 20)
        if block_line is None:
            record.update(outcome="UNKNOWN", detail="no Seal block response")
            return record
        block_text = block_line.decode("utf-8", "replace")
        target_match = re.search(r"approval required: ([0-9a-f]{64})", block_text)
        if target_match is None:
            # The depth-limit vector lands here. It is not sent around Seal.
            try:
                block_response = json.loads(block_line)
            except Exception:
                block_response = {"raw": block_text}
            record.update(
                outcome="REFUSED",
                detail="Seal refused before approval/forwarding",
                seal_response=block_response,
                downstream_exercised=False,
            )
            return record

        target = target_match.group(1)
        approvals.write_text(json.dumps({"target": target}, separators=(",", ":")) + "\n")

        # Second frame is byte-for-byte identical. A forward can only occur
        # after Lean accepts the target just emitted for this CanonicalAction.
        proc.stdin.write(forwarded_frame)
        proc.stdin.flush()
        response_line = read_line(proc.stdout, 20)
        response = None
        if response_line is not None:
            try:
                response = json.loads(response_line)
            except Exception:
                response = {"unparseable_response": response_line.decode("utf-8", "replace")}
        outcome, detail = response_outcome(response)
        record.update(
            outcome="UNKNOWN",
            detail="extraction comparison pending",
            approval_target=target,
            downstream_response=response,
            downstream_response_outcome=outcome,
            downstream_response_detail=detail,
            downstream_exercised=True,
        )
        return record
    finally:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        stderr = proc.stderr.read().decode("utf-8", "replace")
        observations = []
        for line in stderr.splitlines():
            if line.startswith("V31_SERVER_OBSERVATION "):
                try:
                    observations.append(json.loads(line.split(" ", 1)[1]))
                except Exception:
                    pass
        record["server_observations"] = observations
        if record.get("downstream_exercised"):
            outcome, detail, matching_observations = extraction_outcome(
                action, observations, record["forwarded_frame_sha256"]
            )
            accepted_observations = [
                observation
                for observation in matching_observations
                if observation.get("accepted") is not False
            ]
            record.update(
                outcome=outcome,
                detail=detail,
                server_reading=(
                    {
                        "tool": accepted_observations[0].get("tool"),
                        "arguments": accepted_observations[0].get("arguments"),
                    }
                    if accepted_observations
                    else None
                ),
            )
        record["stderr_tail"] = stderr.splitlines()[-20:]


def main() -> int:
    missing = [path for path in (CORPUS, HOST, LEAN_ORACLE) if not path.exists()]
    if missing:
        print("missing required artifact(s): " + ", ".join(map(str, missing)), file=sys.stderr)
        return 2

    results = []
    disagreements = []
    base = Path(tempfile.mkdtemp(prefix="seal-v31rest."))
    vault = base / "vault"
    vault.mkdir()
    (vault / ".obsidian").mkdir()
    database = base / "sandbox.sqlite"
    server_list = servers(vault, database)
    for vector in VECTORS + NEGATIVE_CONTROLS:
        corpus_bytes = (CORPUS / vector).read_bytes()
        judged = CALL_PREFIX + corpus_bytes + CALL_SUFFIX
        action_dir = base / "lean" / vector
        action_dir.mkdir(parents=True)
        action = lean_action(judged, action_dir)
        for server in server_list:
            try:
                result = run_cell(server, vector, judged, action, base)
            except Exception as exc:
                result = {
                    "vector": vector,
                    "server": server.name,
                    "lean": action,
                    "outcome": "UNKNOWN",
                    "detail": f"harness exception: {type(exc).__name__}: {exc}",
                    "downstream_exercised": False,
                }
            results.append(result)
            print(
                f"{vector}\t{server.name}\t{result['outcome']}\t{result['detail']}",
                file=sys.stderr,
                flush=True,
            )
            if result["outcome"] in ("DISAGREE", "REJECTS"):
                disagreements.append(
                    {
                        "vector": vector,
                        "server": server.name,
                        "detail": result["detail"],
                    }
                )

    classifications = []
    for vector in VECTORS:
        vector_results = [result for result in results if result["vector"] == vector]
        outcomes = [result["outcome"] for result in vector_results]
        if outcomes and all(outcome == "REFUSED" for outcome in outcomes):
            classification = "REFUSED by the guard"
        elif any(outcome in ("DISAGREE", "REJECTS") for outcome in outcomes):
            classification = "FORWARDED and observers DISAGREE"
        elif outcomes and all(outcome == "AGREE" for outcome in outcomes):
            classification = "FORWARDED and observers AGREE"
        else:
            classification = "UNACCOUNTED"
        classifications.append(
            {
                "vector": vector,
                "classification": classification,
                "observer_outcomes": outcomes,
            }
        )

    output = {
        "generated_at_unix_ms": int(time.time() * 1000),
        "evidence_dir": str(base),
        "corpus_dir": str(CORPUS),
        "host": str(HOST),
        "lean_oracle": str(LEAN_ORACLE),
        "vectors": VECTORS,
        "negative_controls": NEGATIVE_CONTROLS,
        "servers": [server.name for server in server_list],
        "results": results,
        "classifications": classifications,
        "negative_control_results": [
            result
            for result in results
            if result["vector"] in NEGATIVE_CONTROLS
        ],
        "disagreements": disagreements,
    }
    json.dump(evidence_safe(output), sys.stdout, indent=2, ensure_ascii=True)
    sys.stdout.write("\n")
    has_unknown = any(result["outcome"] == "UNKNOWN" for result in results)
    return 1 if disagreements or has_unknown else 0


if __name__ == "__main__":
    raise SystemExit(main())
