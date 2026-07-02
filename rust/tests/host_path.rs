// SPDX-License-Identifier: Apache-2.0
//! Full-host-path conformance oracle.
//!
//! Drives the REAL binary (stdio, Lean FFI, provider polling, A3, child
//! spawn) with `cat` as the guarded server, so every byte that reaches the
//! child is echoed back verbatim and every blocked call answers with the
//! kernel's response instead. The oracle property, at the transport level:
//!
//!   a line is echoed  ⇔  the kernel routed it (classify passthrough, or
//!                        step forward after an approval);
//!   a guarded call without a matching approval is answered with the
//!   kernel's `approval required` block AND never reaches the child;
//!   every obfuscation disguise of an approved call stays blocked —
//!   canonicalisation cannot be forged (the obfuscation_probe.mjs property);
//!   an approval is one-shot — replaying the approved call blocks again;
//!   a non-UTF-8 line is refused with the seam error and the session
//!   survives.
//!
//! The protocol is strictly lockstep (each input line produces exactly one
//! output line), so a forwarded line can never be mistaken for a block.

use seal_host_rs::route::SEAM_ERROR_RESPONSE;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

struct Oracle {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    dir: PathBuf,
}

impl Oracle {
    fn spawn(tag: &str) -> Oracle {
        let dir = std::env::temp_dir().join(format!(
            "seal-host-oracle-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let approvals = dir.join("approvals.ndjson");
        std::fs::write(&approvals, b"").unwrap();

        let pk = "test-pk";
        let payload = serde_json::json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": approvals.to_str().unwrap(),
                    "ttl_seconds": 120
                },
                "tools": [
                    {
                        "name": "db.execute",
                        "mode": "guarded",
                        "match": {"type": "contains_any_ci", "arg": "sql",
                                  "needles": ["drop", "delete", "truncate"]},
                        "target": [{"literal": "db"}, {"arg": "database"},
                                   {"literal": "write"}, {"arg": "sql"}]
                    },
                    {"name": "approve", "mode": "deny",
                     "match": {"type": "always"}, "target": []}
                ]
            }
        })
        .to_string();
        let envelope = serde_json::json!({
            "payload": payload,
            "signature": format!("stub-ed25519:{pk}:{payload}"),
        })
        .to_string();
        let config = dir.join("trusted.json");
        std::fs::write(&config, envelope).unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
            .args(["--config", config.to_str().unwrap(), "--pubkey", pk, "--", "/bin/cat"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn seal-host-rs");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Audit/A3 telemetry: drain so the host never blocks on stderr, and
        // surface it in the (captured) test output for post-mortems.
        std::thread::spawn(move || {
            let mut text = String::new();
            let mut r = BufReader::new(stderr);
            let _ = r.read_to_string(&mut text);
            if !text.is_empty() {
                eprintln!("[seal-host stderr]\n{text}");
            }
        });

        let (tx, lines) = channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        Oracle { child, stdin, lines, dir }
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).unwrap();
        self.stdin.flush().unwrap();
    }

    fn send(&mut self, line: &str) {
        self.send_bytes(format!("{line}\n").as_bytes());
    }

    /// One output line per input line (lockstep). `BufRead::lines` strips
    /// the terminator (and a trailing `\r`), so callers compare content.
    fn expect_line(&mut self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(20))
            .expect("host produced no output line in time")
    }

    fn approve(&mut self, target: u64) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("approvals.ndjson"))
            .unwrap();
        writeln!(f, "{{\"target\": {target}}}").unwrap();
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn guarded_call(id: u64, sql: &str) -> String {
    // "database" and "sql" both feed the policy's target derivation
    // ([db, arg:database, write, arg:sql]); without them the kernel
    // default-denies with "missing target field" (fail-closed, but not the
    // approval path this oracle exercises).
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"db.execute","arguments":{{"database":"prod","sql":{}}}}}}}"#,
        serde_json::to_string(sql).unwrap()
    )
}

fn is_block(line: &str) -> bool {
    line.contains("\"isError\":true") && line.contains("approval required: ")
}

fn block_target(line: &str) -> Option<u64> {
    let digits: String = line
        .split("approval required: ")
        .nth(1)?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

#[test]
fn mediation_obfuscation_and_one_shot_approval() {
    let mut o = Oracle::spawn("main");

    // Passthrough lines echo VERBATIM (the wire bytes, not a reconstruction).
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
    o.send(init);
    assert_eq!(o.expect_line(), init, "passthrough must echo verbatim");

    // CRLF-terminated passthrough: the child receives the original bytes
    // (lines() strips the terminator for comparison only).
    let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
    o.send_bytes(format!("{list}\r\n").as_bytes());
    assert_eq!(o.expect_line(), list, "CRLF passthrough must reach the child");

    // Canonical guarded call, no approval: kernel block, nothing at the child.
    let canonical = guarded_call(3, "drop table accounts");
    o.send(&canonical);
    let blocked = o.expect_line();
    assert!(is_block(&blocked), "unapproved guarded call must block: {blocked}");
    let target = block_target(&blocked).expect("block names its approval target");

    // The obfuscation corpus at the transport level: the same destructive
    // call in every disguise. All are guarded (contains_any_ci still sees
    // the needle) and none is approved — every one must block.
    let sql_disguises = [
        "drop table accounts\n",
        "drop table accounts ",
        " drop table accounts",
        "drop table accounts\t",
        "DROP TABLE ACCOUNTS",
        "DrOp TaBlE aCcOuNtS",
        "drop table accounts\r\n",
        "  drop table accounts  ",
    ];
    let mut id = 10;
    let mut disguise_targets = Vec::new();
    for sql in sql_disguises {
        let call = guarded_call(id, sql);
        o.send(&call);
        let resp = o.expect_line();
        assert!(is_block(&resp), "disguised call must block ({sql:?}): {resp}");
        disguise_targets.push(block_target(&resp).expect("disguise block names target"));
        id += 1;
    }
    // Canonicalisation makes every disguise a DIFFERENT target than the
    // canonical call — that is exactly why an approval cannot be forged.
    for (sql, t) in sql_disguises.iter().zip(&disguise_targets) {
        assert_ne!(*t, target, "disguise {sql:?} must not share the canonical target");
    }

    // Line-level disguises: whitespace/terminator noise around the whole
    // call. Still mediated, still blocked.
    for wire in [
        format!("  {canonical}  \n"),
        format!("\t{canonical}\n"),
        format!("{canonical}\r\n"),
    ] {
        o.send_bytes(wire.as_bytes());
        let resp = o.expect_line();
        assert!(is_block(&resp), "line-disguised call must block: {resp}");
    }

    // Method disguise: "TOOLS/CALL" is NOT a tools/call in the V1 routing
    // view (byte-exact method match) — Lean classifies it passthrough and it
    // reaches the child. The mediation contract covers requests the protocol
    // recognises; a lenient child parser is out of contract (A-strict-child,
    // RUST_BRIDGE.md).
    let shouted = canonical.replace("\"tools/call\"", "\"TOOLS/CALL\"");
    o.send(&shouted);
    assert_eq!(o.expect_line(), shouted, "non-tools/call method is passthrough");

    // Approve the canonical target, then fire a DISGUISE first: the approval
    // is in hand, bound to the canonical bytes — the disguise must still
    // block (and the ingested approval survives the deny; Registry.lean).
    o.approve(target);
    let disguised_again = guarded_call(30, "DROP TABLE ACCOUNTS");
    o.send(&disguised_again);
    let resp = o.expect_line();
    assert!(is_block(&resp), "approval for canonical must not unlock a disguise: {resp}");

    // The canonical call is now approved: it must FORWARD (echo verbatim).
    let approved = guarded_call(31, "drop table accounts");
    o.send(&approved);
    assert_eq!(o.expect_line(), approved, "approved canonical call must forward");

    // One-shot: the same call again must block — the approval was consumed.
    let replay = guarded_call(32, "drop table accounts");
    o.send(&replay);
    let resp = o.expect_line();
    assert!(is_block(&resp), "approval must be one-shot; replay blocked: {resp}");
}

#[test]
fn non_utf8_line_refused_and_session_survives() {
    let mut o = Oracle::spawn("utf8");

    // Not valid UTF-8: cannot be judged, must not be forwarded — the client
    // gets the host's static seam error and the session stays up.
    o.send_bytes(b"\xff\xfe\xfd{\"method\":\"tools/call\"}\n");
    assert_eq!(
        o.expect_line(),
        SEAM_ERROR_RESPONSE.trim_end(),
        "non-UTF-8 line must answer with the seam error"
    );

    // The session is alive and still mediating.
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
    o.send(init);
    assert_eq!(o.expect_line(), init, "session must survive a refused line");

    let call = guarded_call(2, "drop table accounts");
    o.send(&call);
    assert!(is_block(&o.expect_line()), "mediation must survive a refused line");
}
