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

use ed25519_dalek::{Signer, SigningKey};
use seal_host_rs::route::SEAM_ERROR_RESPONSE;
use sha2::Digest;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

struct Oracle {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    /// Same stdout stream as `lines`, but each frame is the RAW bytes up to
    /// and including the `\n` — the terminator is NOT stripped. Used by the
    /// T3 terminator test to observe the exact bytes the child echoed.
    raw: Receiver<Vec<u8>>,
    stderr_lines: Receiver<String>,
    dir: PathBuf,
    args: Vec<String>,
}

/// Deterministic approval signing key for the ed25519 channel tests. MUST
/// differ from the config key ([7u8;32]) — the host refuses a shared key.
fn approval_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

/// One signed NDJSON token line, exactly the shape sign_approval.py emits:
/// the signature covers the exact payload bytes.
fn signed_token(target: &str, issued_at: u64, nonce: &str, decision: Option<&str>) -> String {
    let sk = approval_signing_key();
    let payload = match decision {
        Some(d) => format!(
            r#"{{"target":"{target}","issuedAt":{issued_at},"nonce":"{nonce}","decision":"{d}"}}"#
        ),
        None => format!(r#"{{"target":"{target}","issuedAt":{issued_at},"nonce":"{nonce}"}}"#),
    };
    let sig = hex::encode(sk.sign(payload.as_bytes()).to_bytes());
    format!(
        r#"{{"payload":{},"signature":"{}"}}"#,
        serde_json::to_string(&payload).unwrap(),
        sig
    )
}

fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

impl Oracle {
    fn spawn(tag: &str) -> Oracle {
        Oracle::spawn_channel(tag, false)
    }

    /// Spawn on the PRODUCTION approval channel: ed25519 signed tokens with
    /// a sqlite replay store (required by the host for this channel).
    fn spawn_signed(tag: &str) -> Oracle {
        Oracle::spawn_channel(tag, true)
    }

    fn spawn_channel(tag: &str, signed: bool) -> Oracle {
        let dir =
            std::env::temp_dir().join(format!("seal-host-oracle-{}-{}", std::process::id(), tag));
        std::fs::create_dir_all(&dir).unwrap();
        let approvals = dir.join("approvals.ndjson");
        std::fs::write(&approvals, b"").unwrap();

        let config_sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(config_sk.verifying_key().to_bytes());
        let mut approval = serde_json::json!({
            "control_file": approvals.to_str().unwrap(),
            "ttl_seconds": 120
        });
        if signed {
            approval["replay_store"] = serde_json::json!({
                "sqlite_path": dir.join("replay.sqlite").to_str().unwrap()
            });
        }
        let payload = serde_json::json!({
            "epoch": 1,
            "safety": {
                "approval": approval,
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
        let sig = hex::encode(config_sk.sign(payload.as_bytes()).to_bytes());
        let envelope = serde_json::json!({
            "payload": payload,
            "signature": sig,
        })
        .to_string();
        let config = dir.join("trusted.json");
        std::fs::write(&config, envelope).unwrap();

        let mut args = vec![
            "--insecure-development-mode".to_string(),
            "--config".to_string(),
            config.to_str().unwrap().to_string(),
            "--pubkey".to_string(),
            pk,
        ];
        if signed {
            let token_file = dir.join("tokens.ndjson");
            std::fs::write(&token_file, b"").unwrap();
            let approval_pk = hex::encode(approval_signing_key().verifying_key().to_bytes());
            args.extend([
                "--channel".to_string(),
                "ed25519".to_string(),
                "--token-file".to_string(),
                token_file.to_str().unwrap().to_string(),
                "--approval-pubkey".to_string(),
                approval_pk,
            ]);
        }
        args.extend(["--".to_string(), "/bin/cat".to_string()]);

        let (child, stdin, lines, raw, stderr_lines) = Oracle::spawn_process(&args);
        Oracle {
            child,
            stdin,
            lines,
            raw,
            stderr_lines,
            dir,
            args,
        }
    }

    #[allow(clippy::type_complexity)]
    fn spawn_process(
        args: &[String],
    ) -> (
        Child,
        ChildStdin,
        Receiver<String>,
        Receiver<Vec<u8>>,
        Receiver<String>,
    ) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn seal-host-rs");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Audit/A3 telemetry: drain so the host never blocks on stderr.
        let (err_tx, stderr_lines) = channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if err_tx.send(line).is_err() {
                    break;
                }
            }
        });

        // One reader, teed to two channels: raw bytes (terminator preserved,
        // via read_until) and the stripped String the existing tests compare.
        let (tx, lines) = channel::<String>();
        let (raw_tx, raw) = channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut buf: Vec<u8> = Vec::new();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
                let mut s = String::from_utf8_lossy(&buf).into_owned();
                // Match BufRead::lines(): strip a trailing \n then \r.
                if s.ends_with('\n') {
                    s.pop();
                    if s.ends_with('\r') {
                        s.pop();
                    }
                }
                let raw_ok = raw_tx.send(buf).is_ok();
                let line_ok = tx.send(s).is_ok();
                if !raw_ok && !line_ok {
                    break;
                }
            }
        });

        (child, stdin, lines, raw, stderr_lines)
    }

    /// Kill the host and start a fresh process on the SAME state directory
    /// (same config, token file, and sqlite replay store) — a host restart.
    fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let (child, stdin, lines, raw, stderr_lines) = Oracle::spawn_process(&self.args);
        self.child = child;
        self.stdin = stdin;
        self.lines = lines;
        self.raw = raw;
        self.stderr_lines = stderr_lines;
    }

    fn append_token_line(&mut self, line: &str) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("tokens.ndjson"))
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).unwrap();
        self.stdin.flush().unwrap();
    }

    fn send(&mut self, line: &str) {
        self.send_bytes(format!("{line}\n").as_bytes());
    }

    fn receipt_dir(&self) -> PathBuf {
        self.dir.join("seal-receipts")
    }

    fn receipts(&self) -> Vec<serde_json::Value> {
        let mut paths: Vec<_> = std::fs::read_dir(self.receipt_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        paths.sort();
        paths
            .into_iter()
            .map(|path| serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
            .collect()
    }

    /// One output line per input line (lockstep). `BufRead::lines` strips
    /// the terminator (and a trailing `\r`), so callers compare content.
    fn expect_line(&mut self) -> String {
        match self.lines.recv_timeout(Duration::from_secs(20)) {
            Ok(line) => line,
            Err(e) => {
                let status = self.child.try_wait().ok().flatten();
                let stderr = self.drain_stderr(Duration::from_millis(50));
                panic!(
                    "host produced no output line in time: {e}; status={status:?}; stderr={stderr:?}"
                );
            }
        }
    }

    /// The exact bytes the child echoed for the next output frame, terminator
    /// included. Pairs with `expect_line` (the same frame, stripped).
    fn expect_raw(&mut self) -> Vec<u8> {
        match self.raw.recv_timeout(Duration::from_secs(20)) {
            Ok(bytes) => bytes,
            Err(e) => panic!("host produced no raw output frame in time: {e}"),
        }
    }

    fn approve(&mut self, target: &str) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("approvals.ndjson"))
            .unwrap();
        writeln!(f, "{{\"target\": \"{target}\"}}").unwrap();
    }

    fn append_approval_line(&mut self, line: &str) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("approvals.ndjson"))
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn drain_stderr(&mut self, quiet_for: Duration) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(line) = self.stderr_lines.recv_timeout(quiet_for) {
            lines.push(line);
        }
        lines
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

fn block_target(line: &str) -> Option<String> {
    let target: String = line
        .split("approval required: ")
        .nth(1)?
        .chars()
        .take(64)
        .collect();
    if target.len() == 64
        && target
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        Some(target)
    } else {
        None
    }
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
    assert_eq!(
        o.expect_line(),
        list,
        "CRLF passthrough must reach the child"
    );

    // Canonical guarded call, no approval: kernel block, nothing at the child.
    let canonical = guarded_call(3, "drop table accounts");
    o.send(&canonical);
    let blocked = o.expect_line();
    assert!(
        is_block(&blocked),
        "unapproved guarded call must block: {blocked}"
    );
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
    let mut disguise_targets = Vec::new();
    for (id, sql) in (10..).zip(sql_disguises) {
        let call = guarded_call(id, sql);
        o.send(&call);
        let resp = o.expect_line();
        assert!(
            is_block(&resp),
            "disguised call must block ({sql:?}): {resp}"
        );
        disguise_targets.push(block_target(&resp).expect("disguise block names target"));
    }
    // Canonicalisation makes every disguise a DIFFERENT target than the
    // canonical call — that is exactly why an approval cannot be forged.
    for (sql, t) in sql_disguises.iter().zip(&disguise_targets) {
        assert_ne!(
            t, &target,
            "disguise {sql:?} must not share the canonical target"
        );
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
    assert_eq!(
        o.expect_line(),
        shouted,
        "non-tools/call method is passthrough"
    );

    // Approve the canonical target, then fire a DISGUISE first: the approval
    // is in hand, bound to the canonical bytes — the disguise must still
    // block (and the ingested approval survives the deny; Registry.lean).
    o.approve(&target);
    let disguised_again = guarded_call(30, "DROP TABLE ACCOUNTS");
    o.send(&disguised_again);
    let resp = o.expect_line();
    assert!(
        is_block(&resp),
        "approval for canonical must not unlock a disguise: {resp}"
    );

    // The canonical call is now approved: it must FORWARD (echo verbatim).
    let approved = guarded_call(31, "drop table accounts");
    o.send(&approved);
    assert_eq!(
        o.expect_line(),
        approved,
        "approved canonical call must forward"
    );
    let receipts = o.receipts();
    let envelope: serde_json::Value =
        serde_json::from_slice(&std::fs::read(o.dir.join("trusted.json")).unwrap()).unwrap();
    let expected_payload = envelope["payload"].as_str().unwrap();
    let expected_signature = envelope["signature"].as_str().unwrap();
    let expected_pubkey = hex::encode(
        SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    for receipt in &receipts {
        assert_eq!(receipt["signed_config"]["payload"], expected_payload);
        assert_eq!(receipt["signed_config"]["signature"], expected_signature);
        assert_eq!(receipt["signed_config"]["pubkey"], expected_pubkey);
        assert_eq!(
            serde_json::to_string(&receipt["kernel_config"]).unwrap(),
            expected_payload,
            "preserve_order must keep kernel_config byte-identical to the signed payload"
        );
    }
    let allow = receipts
        .iter()
        .rev()
        .find(|receipt| receipt["verdict"] == "ALLOW")
        .expect("forwarded decision persisted an ALLOW receipt");
    assert_eq!(allow["seal_receipt"], "v2");
    let effect_view = &allow["effect_view"];
    assert_eq!(effect_view["schema"], "seal.effect-view/v0");
    assert_eq!(effect_view["authoritative"], false);
    assert_eq!(effect_view["effect"]["resource"], "db.execute");
    assert_eq!(effect_view["effect"]["action"], "call");
    assert_eq!(effect_view["effect"]["arguments"], allow["arguments"]);
    assert_eq!(effect_view["raw_preimage_sha256"], allow["request_sha256"]);
    assert_eq!(effect_view["policy_hash"], allow["approval"]["policy_hash"]);
    assert_eq!(effect_view["policy_version"], 1);
    assert_eq!(effect_view["policy_version_enforced"], false);
    assert!(effect_view["session"]
        .as_str()
        .unwrap()
        .starts_with("seal-host-rs/stdio:"));
    assert!(effect_view.get("principal").is_none());
    assert_eq!(allow["approval"]["approval_identity"]["channel"], "file");
    assert_eq!(allow["approval"]["policy_hash"].as_str().unwrap().len(), 64);
    assert_eq!(allow["host_identity"]["equivalence"], "not_proven");
    assert_eq!(
        allow["kernel_identity"]["wasm_sha256"],
        seal_host_rs::decision_receipt::VERIFIED_WASM_SHA256
    );

    // One-shot: the same call again must block — the approval was consumed.
    let replay = guarded_call(32, "drop table accounts");
    o.send(&replay);
    let resp = o.expect_line();
    assert!(
        is_block(&resp),
        "approval must be one-shot; replay blocked: {resp}"
    );
}

/// T3 TERMINATOR: the same request under `\n` and `\r\n` shares ONE kernel
/// commitment (`request_sha256` over the terminator-stripped `lean_view`)
/// while the child receives the ORIGINAL wire, terminator included — so the
/// two children see byte-different lines under one receipt. This is the T3
/// question in the RED corpus. The verdict pinned here is CHARACTERIZED, not
/// a defect: `lean_view` strips exactly the trailing terminator (≤1 `\n`,
/// then ≤1 `\r`; main.rs:334-341) and nothing interior, the stripped bytes
/// are semantically-inert JSON line framing, and the receipt names its
/// commitment as that stripped view (`request_sha256`). The test fails closed
/// if a future change either (a) forwards something OTHER than the client's
/// original wire, or (b) lets the two terminators produce DIFFERENT
/// commitments — i.e. it pins BOTH halves the corpus entry must claim, which
/// the pre-existing `main.rs` unit test (lean_view equality + one golden
/// hash) does not: that test never touches the child and so pins only the
/// benign half.
#[test]
fn terminator_shares_commitment_but_child_sees_original_bytes() {
    let mut o = Oracle::spawn("t3-terminator");

    // Read every frame RAW so the terminator is visible; parse the string
    // view from the same bytes (keeps the raw/lines channels aligned — this
    // test never calls expect_line).
    fn raw_str(bytes: &[u8]) -> String {
        let mut s = String::from_utf8_lossy(bytes).into_owned();
        if s.ends_with('\n') {
            s.pop();
            if s.ends_with('\r') {
                s.pop();
            }
        }
        s
    }

    // Learn the canonical approval target: an unapproved guarded call blocks
    // and names it. Terminator is irrelevant to the target (lean_view strips
    // it before the kernel derives the target).
    let call = guarded_call(1, "drop table accounts");
    o.send(&call);
    let blocked = raw_str(&o.expect_raw());
    let target = block_target(&blocked).expect("unapproved guarded call names its target");

    // (A) LF-terminated, approved → forwards. The child echoes the wire.
    o.approve(&target);
    o.send_bytes(format!("{call}\n").as_bytes());
    let lf_child = o.expect_raw();

    // (B) SAME call, CRLF-terminated. Approve again (one-shot consumed the
    // first grant), forward, capture the child echo.
    o.approve(&target);
    o.send_bytes(format!("{call}\r\n").as_bytes());
    let crlf_child = o.expect_raw();

    // -- HALF 1: the child received byte-DIFFERENT lines --
    assert_ne!(
        lf_child, crlf_child,
        "the child must receive the original wire, so the terminators differ"
    );
    assert!(
        lf_child.ends_with(b"}\n") && !lf_child.ends_with(b"}\r\n"),
        "LF call reaches the child terminated by a bare \\n: {lf_child:?}"
    );
    assert!(
        crlf_child.ends_with(b"}\r\n"),
        "CRLF call reaches the child terminated by \\r\\n: {crlf_child:?}"
    );
    // The delta is EXACTLY the carriage return, nothing interior.
    let mut crlf_stripped = crlf_child.clone();
    let n = crlf_stripped.len();
    crlf_stripped.remove(n - 2); // drop the \r before the trailing \n
    assert_eq!(
        crlf_stripped, lf_child,
        "the only difference the child sees is the terminator's \\r"
    );

    // -- HALF 2: both decisions share ONE kernel commitment --
    let allows: Vec<serde_json::Value> = o
        .receipts()
        .into_iter()
        .filter(|r| r["verdict"] == "ALLOW")
        .collect();
    assert_eq!(allows.len(), 2, "both forwards persisted an ALLOW receipt");
    let sha_a = allows[0]["request_sha256"].as_str().unwrap();
    let sha_b = allows[1]["request_sha256"].as_str().unwrap();
    assert_eq!(
        sha_a, sha_b,
        "terminator-stripped lean_view collapses \\n and \\r\\n to one commitment"
    );
    // And that single commitment is the hash of the terminator-free line —
    // the same value the pure lean_view/main.rs unit test pins.
    let expected = hex::encode(sha2::Sha256::digest(call.as_bytes()));
    assert_eq!(sha_a, expected, "commitment is sha256 of the stripped line");
}

/// BLUE: the PRODUCTION channel end to end — a signed ed25519 approval
/// unlocks exactly its target through the full host path (signature verify,
/// A3 nonce/replay via sqlite, Lean consume), and the approval is one-shot.
#[test]
fn ed25519_signed_approval_forwards_end_to_end() {
    let mut o = Oracle::spawn_signed("ed25519-blue");

    // Passthrough sanity on the signed channel.
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
    o.send(init);
    assert_eq!(o.expect_line(), init, "passthrough must echo verbatim");

    // Unapproved guarded call blocks and names its target.
    let call = guarded_call(2, "drop table accounts");
    o.send(&call);
    let blocked = o.expect_line();
    assert!(is_block(&blocked), "unapproved call must block: {blocked}");
    let target = block_target(&blocked).expect("block names its approval target");

    // Signed approval for the target: the call now forwards.
    o.append_token_line(&signed_token(&target, wall_now_ms(), "n-blue-1", None));
    let approved = guarded_call(3, "drop table accounts");
    o.send(&approved);
    assert_eq!(
        o.expect_line(),
        approved,
        "signed approval must forward the call"
    );

    // The ALLOW receipt names the production channel and the approval key.
    let allow = o
        .receipts()
        .into_iter()
        .rev()
        .find(|receipt| receipt["verdict"] == "ALLOW")
        .expect("forwarded decision persisted an ALLOW receipt");
    assert_eq!(allow["approval"]["approval_identity"]["channel"], "ed25519");
    assert!(allow["approval"]["approval_identity"]["key_id"].is_string());

    // One-shot: the same call blocks again.
    let replay = guarded_call(4, "drop table accounts");
    o.send(&replay);
    assert!(
        is_block(&o.expect_line()),
        "approval must be one-shot on the signed channel"
    );

    // Replaying the very same signed token is dead: the nonce is burned.
    o.append_token_line(&signed_token(&target, wall_now_ms(), "n-blue-1", None));
    let replay2 = guarded_call(5, "drop table accounts");
    o.send(&replay2);
    assert!(
        is_block(&o.expect_line()),
        "replayed token must not re-approve"
    );
    let stderr = o.drain_stderr(Duration::from_millis(100));
    assert!(
        stderr.iter().any(|l| l.contains("replayed_nonce")),
        "operator must see the replay drop: {stderr:?}"
    );
}

/// KNOWN DEFECT PIN — this test documents CURRENT WRONG BEHAVIOR, not a
/// desired property. Do not read it as the specification.
///
/// A valid signed approval whose ingesting step is denied by Lean for an
/// unrelated reason (here: a different call's missing approval) is retired
/// before the verdict exists: the nonce is committed inside `a3.filter` at
/// main.rs:634 (via a3.rs:167 → persist_nonce), eighteen lines before the
/// Lean verdict at main.rs:652, and `ReplayStore` has no un-consume. The
/// burn is DURABLE (sqlite) while the approval's ingestion into the Lean
/// registry is in-memory only — so across a host restart the approval is
/// gone, and resubmitting the very same signed token dies as
/// `replayed_nonce`. The approval is permanently retired without ever
/// having authorized anything. (Within one process the Lean registry
/// retains the ingested approval across the deny, which masks the defect
/// until a restart.)
///
/// Redesign options (NOT applied here): split validate from commit-nonce
/// and commit only on `route == Forward`, or give the replay store a
/// rollback path. Cross-reference: checkpoint ckpt-19caa937cca56524,
/// roadmap item P10.
#[test]
fn pinned_defect_denied_call_retires_valid_approval() {
    let mut o = Oracle::spawn_signed("ed25519-pin");

    // Learn target T of call C (the call the approval is FOR).
    let call_c = guarded_call(10, "drop table accounts");
    o.send(&call_c);
    let blocked = o.expect_line();
    assert!(is_block(&blocked));
    let target_t = block_target(&blocked).expect("block names target T");

    // A valid signed approval for T arrives, but the next mediated line is
    // an UNRELATED unapproved call D: the poll ingests the token during D's
    // step (nonce committed pre-verdict) and Lean denies D for its own
    // missing approval — a reason unrelated to T's approval.
    o.append_token_line(&signed_token(&target_t, wall_now_ms(), "n-pin-1", None));
    let call_d = guarded_call(11, "delete from users");
    o.send(&call_d);
    let resp_d = o.expect_line();
    assert!(
        is_block(&resp_d),
        "unrelated call D stays blocked: {resp_d}"
    );
    assert_ne!(
        block_target(&resp_d).expect("D names its own target"),
        target_t,
        "D's deny must be unrelated to T's approval"
    );

    let before_restart = o.drain_stderr(Duration::from_millis(200));
    let prior_record = before_restart
        .iter()
        .filter_map(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .filter(|value| value["seal_record"] == "v1")
        })
        .next_back()
        .expect("pre-restart audit record")
        .clone();

    // Host restarts (the sqlite replay store is the state that survives).
    o.restart();

    // Resubmit the SAME valid token. PINNED DEFECT: it is dead — the nonce
    // was durably burned by the denied step, so call C can never forward on
    // this approval even though it never authorized anything.
    o.append_token_line(&signed_token(&target_t, wall_now_ms(), "n-pin-1", None));
    let call_c2 = guarded_call(12, "drop table accounts");
    o.send(&call_c2);
    let resp = o.expect_line();
    assert!(
        is_block(&resp),
        "PINNED DEFECT: the retired approval cannot be resubmitted; \
         if this forwards, the defect was fixed — update this pin: {resp}"
    );
    let stderr = o.drain_stderr(Duration::from_millis(200));
    let restarted_record = stderr
        .iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["seal_record"] == "v1")
        .expect("post-restart audit record");
    assert_eq!(restarted_record["prev_head"], prior_record["head"]);
    assert_eq!(
        restarted_record["prior_session"], prior_record["session"],
        "first record after restart must cross-link the prior process session"
    );
    assert_ne!(restarted_record["session"], prior_record["session"]);
    assert!(
        stderr.iter().any(|l| l.contains("replayed_nonce")),
        "the resubmitted token dies as a nonce replay: {stderr:?}"
    );
}

#[test]
fn receipt_sink_failure_blocks_before_child_forward() {
    let mut o = Oracle::spawn("receipt-sink-failure");

    // READINESS BY ROUND-TRIP, not by stat. `ReceiptChain::new` calls
    // `create_dir_all` and only THEN probes the sink
    // (decision_receipt.rs:326-336), so "the receipt directory exists" goes
    // true BEFORE the host is past its probe. Sabotaging inside that window
    // makes the host fail the probe and exit 4 ("receipt sink rejected")
    // without ever answering -- a DIFFERENT failure than the one under test,
    // and the source of this test's flake. Only a completed round-trip proves
    // the probe is done and the host is serving. This call is guarded with no
    // approval on file, so it blocks: a deterministic answer.
    o.send(&guarded_call(69, "drop table accounts"));
    assert!(
        is_block(&o.expect_line()),
        "host must be serving (probe complete) before the sink is sabotaged"
    );

    let receipt_dir = o.receipt_dir();
    assert!(
        receipt_dir.is_dir(),
        "host did not initialize its receipt sink"
    );
    assert_eq!(
        std::fs::metadata(&receipt_dir).unwrap().mode() & 0o777,
        0o700,
        "receipt directory must be private"
    );
    for receipt in std::fs::read_dir(&receipt_dir).unwrap() {
        let metadata = receipt.unwrap().metadata().unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600, "receipt must be private");
    }
    // `remove_dir_all`, not `remove_dir`: the warm-up above has already written
    // a decision receipt, so the directory is NOT empty and `remove_dir` would
    // fail ENOTEMPTY. Contents are irrelevant -- the scenario only needs the
    // sink PATH to stop being a directory.
    std::fs::remove_dir_all(&receipt_dir).unwrap();
    std::fs::write(&receipt_dir, b"not a directory").unwrap();

    let call = guarded_call(70, "drop table accounts");
    o.send(&call);
    assert_eq!(
        o.expect_line(),
        SEAM_ERROR_RESPONSE.trim_end(),
        "receipt persistence failure must never reach the child"
    );
    let stderr = o.drain_stderr(Duration::from_millis(100));
    assert!(
        stderr.iter().any(|line| {
            line.contains("receipt persistence failure")
                || line.contains("audit head persistence failure")
        }),
        "operator must see the availability failure: {stderr:?}"
    );
}

#[test]
fn malformed_approval_record_denies_and_warns_once() {
    let mut o = Oracle::spawn("malformed-approval");
    let malformed = "not-json-approval-record";
    o.append_approval_line(malformed);

    let call = guarded_call(50, "drop table accounts");
    o.send(&call);
    let resp = o.expect_line();
    assert!(
        is_block(&resp),
        "malformed approval evidence must not unlock the call: {resp}"
    );

    let stderr = o.drain_stderr(Duration::from_millis(100));
    let warnings: Vec<serde_json::Value> = stderr
        .iter()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|v| v.get("approval_drop").is_some())
        .collect();
    assert_eq!(
        warnings.len(),
        1,
        "expected exactly one approval_drop warning, stderr={stderr:?}"
    );
    let warning = &warnings[0]["approval_drop"];
    assert_eq!(warning["source"], "control-file");
    assert_eq!(warning["reason"], "parse_error");
    assert_eq!(warning["counter"], 1);
    let record_id = warning["record_id"].as_str().unwrap_or_default();
    assert!(
        record_id.starts_with("sha256:") && record_id.len() == "sha256:".len() + 16,
        "record id must be a redacted hash prefix: {record_id}"
    );
    assert!(
        !warnings[0].to_string().contains(malformed),
        "raw malformed record leaked into warning: {}",
        warnings[0]
    );
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
    assert!(
        is_block(&o.expect_line()),
        "mediation must survive a refused line"
    );
}

/// The kernel is deliberately the more tolerant parser (the differential
/// corpus pins lines Lean mediates that serde rejects). The receipt layer
/// must therefore never veto a kernel verdict it cannot re-parse: an
/// allowed call forwards, a blocked call gets the KERNEL's response — and
/// the receipt records the raw line hash + parse error instead of the
/// structured request material it does not hold.
#[test]
fn receipt_layer_never_vetoes_kernel_verdicts() {
    let mut o = Oracle::spawn("receipt-deparse");

    // A guarded call whose arguments serde cannot parse (1e309 overflows
    // f64, the whole serde parse fails) but the kernel mediates fine.
    let divergent = r#"{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","x":1e309}}}"#;
    o.send(divergent);
    let blocked = o.expect_line();
    assert!(
        is_block(&blocked),
        "unapproved divergent call must get the KERNEL's block, not a seam error: {blocked}"
    );
    let target = block_target(&blocked).expect("kernel block names its approval target");

    // Approve and resend: the kernel allows — the receipt writer must not
    // stand in the way of the proven verdict.
    o.approve(&target);
    o.send(divergent);
    assert_eq!(
        o.expect_line(),
        divergent,
        "kernel-allowed call must forward even though serde cannot re-parse it"
    );

    // The ALLOW receipt carries the raw line identity in place of the
    // structured request material the producer does not hold.
    let receipts = o.receipts();
    let allow = receipts
        .iter()
        .rev()
        .find(|receipt| receipt["verdict"] == "ALLOW")
        .expect("forwarded decision persisted an ALLOW receipt");
    assert_eq!(
        allow["request_sha256"],
        hex::encode(sha2::Sha256::digest(divergent.as_bytes())),
        "receipt must hash the exact wire line"
    );
    assert!(
        allow["request_parse_error"].is_string(),
        "receipt must name the parse failure"
    );
    for absent in [
        "tool",
        "arguments",
        "args_hash",
        "canonical_request",
        "canonical_request_sha256",
        "effect_view",
    ] {
        assert!(
            allow.get(absent).is_none(),
            "field {absent} must be ABSENT (honesty rule), not fabricated"
        );
    }
    assert_eq!(allow["authorization"], "approval");

    // The kernel-attested request commitment inside emitted_bytes agrees
    // with the receipt's request_sha256 — for exactly this unparseable
    // class of line, the binding is now kernel-backed, not host-asserted.
    let emitted: serde_json::Value = serde_json::from_str(
        allow["emitted_bytes"]
            .as_str()
            .expect("emitted_bytes string"),
    )
    .expect("emitted bytes parse");
    let audit: serde_json::Value =
        serde_json::from_str(emitted["audit"].as_str().expect("audit string"))
            .expect("audit parses");
    assert_eq!(
        audit["request_sha256"], allow["request_sha256"],
        "kernel-attested hash must equal the receipt's request_sha256"
    );

    // Parseable receipts are unchanged AND now also carry request_sha256.
    let parseable = guarded_call(91, "drop table accounts");
    o.send(&parseable);
    let resp = o.expect_line();
    assert!(is_block(&resp));
    let receipts = o.receipts();
    let last = receipts.last().expect("block receipt persisted");
    assert_eq!(last["tool"], "db.execute");
    assert!(last["canonical_request_sha256"].is_string());
    assert_eq!(
        last["request_sha256"],
        hex::encode(sha2::Sha256::digest(parseable.as_bytes()))
    );
    assert!(last.get("request_parse_error").is_none());

    // The rest of the divergent corpus: shapes Lean's act parse admits but
    // request_parts rejects. Each must get the kernel's own block response
    // (here: no matching policy rule), never the seam error.
    let argless =
        r#"{"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"db.execute"}}"#;
    let non_object_args = r#"{"jsonrpc":"2.0","id":93,"method":"tools/call","params":{"name":"db.execute","arguments":"drop"}}"#;
    for line in [argless, non_object_args] {
        o.send(line);
        let resp = o.expect_line();
        assert!(
            is_block(&resp),
            "kernel-blocked divergent shape must get the kernel's response: {resp}"
        );
    }
}

/// BLUE for the kernel request commitment: a mediated call with multibyte
/// UTF-8 arguments crosses the serde-encode → Lean-JSON-decode seam and
/// comes back with the kernel's hash of the SAME bytes the host hashed.
/// Any divergence in the transport of the line (escaping, UTF-8 handling)
/// now trips the host's cross-check and fails closed as a SEAM error —
/// so this call completing as an ordinary kernel block, with matching
/// hashes in the persisted receipt, is an end-to-end proof of byte
/// identity across the FFI boundary.
#[test]
fn multibyte_request_commitment_survives_the_ffi_seam() {
    let mut o = Oracle::spawn("multibyte-commitment");
    let line = guarded_call(94, "drop table 日本語 ✓ naïve");
    o.send(&line);
    let resp = o.expect_line();
    assert!(
        is_block(&resp),
        "multibyte call must get the kernel's own block, never a seam error: {resp}"
    );
    assert_ne!(resp.trim_end(), SEAM_ERROR_RESPONSE.trim_end());
    let receipts = o.receipts();
    let receipt = receipts.last().expect("block receipt persisted");
    let expected = hex::encode(sha2::Sha256::digest(line.as_bytes()));
    assert_eq!(receipt["request_sha256"], expected);
    let emitted: serde_json::Value = serde_json::from_str(
        receipt["emitted_bytes"]
            .as_str()
            .expect("emitted_bytes string"),
    )
    .expect("emitted bytes parse");
    let audit: serde_json::Value =
        serde_json::from_str(emitted["audit"].as_str().expect("audit string"))
            .expect("audit parses");
    assert_eq!(
        audit["request_sha256"], expected,
        "kernel and host must hash the multibyte line identically"
    );
}

/// The kernel approval target is a pure function of the tool name and the
/// argument paths the policy names (`target: [db, arg:database, write, arg:sql]`);
/// it IGNORES any argument key the policy does not name. So an attacker cannot
/// change, dodge, or redirect an approval target by adding sibling keys — and,
/// dually, a human approval granted for the clean call also covers any variant
/// that only adds unnamed keys. This is the on-disk defence against the P0-2
/// on-path downgrade; the Track-1 form is proved in mcp-seal
/// `Seal.p0_2_policy_target_ignores_unnamed` (that lemma proves the invariance
/// modulo `atPath` agreement — this test supplies the last mile that `atPath`'s
/// `partial def` blocks in Lean, against the real kernel binary).
///
/// Exercised beyond one token: a scalar sibling (`x:1e309`, serde-hostile) AND a
/// structurally different nested object/array sibling must both leave the target
/// byte-identical to the clean call's.
#[test]
fn approval_target_ignores_keys_not_in_policy_target() {
    let mut o = Oracle::spawn("target-ignores-siblings");

    // Clean guarded call: {database:"prod", sql:"drop table accounts"}.
    let clean = guarded_call(90, "drop table accounts");
    o.send(&clean);
    let t_clean = block_target(&o.expect_line()).expect("clean call names its approval target");

    // Variant A — scalar serde-hostile sibling x:1e309 (raw string so the
    // overflow token survives; serde rejects it, the kernel mediates it).
    let scalar_sibling = r#"{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","x":1e309}}}"#;
    o.send(scalar_sibling);
    let t_scalar =
        block_target(&o.expect_line()).expect("scalar-sibling call names its approval target");

    // Variant B — a structurally different sibling: a nested object holding an
    // array and further nesting. Exercises the property past a single token.
    let nested_sibling = r#"{"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","meta":{"tags":["a","b"],"nested":{"deep":true,"n":7}}}}}"#;
    o.send(nested_sibling);
    let t_nested =
        block_target(&o.expect_line()).expect("nested-sibling call names its approval target");

    assert_eq!(
        t_clean, t_scalar,
        "a scalar sibling key (x:1e309) must not change the approval target"
    );
    assert_eq!(
        t_clean, t_nested,
        "a nested object/array sibling key must not change the approval target"
    );

    // Non-vacuous end-to-end: the approval a human grants for the CLEAN target
    // also authorises both unnamed-key variants — each forwards verbatim once
    // approved (one-shot, so re-grant per send).
    o.approve(&t_clean);
    o.send(scalar_sibling);
    assert_eq!(
        o.expect_line(),
        scalar_sibling,
        "clean-target approval must authorise the scalar-sibling variant"
    );
    o.approve(&t_clean);
    o.send(nested_sibling);
    assert_eq!(
        o.expect_line(),
        nested_sibling,
        "clean-target approval must authorise the nested-sibling variant"
    );
}

/// P2-c observability tap: a FORCED reduced-scope forward (an ALLOW whose wire
/// line serde cannot recover) must emit a distinct, structured stderr signal so
/// an operator can see and count forced downgrades — while the forward itself
/// stays byte-identical and the receipt is unchanged (passive tap). A normal
/// parseable ALLOW must stay silent. Drives the real binary end-to-end.
#[test]
fn reduced_scope_forward_emits_observability_signal() {
    let mut o = Oracle::spawn("reduced-scope-signal");

    // FORCED downgrade: the 1e309 serde-hostile sibling — kernel-mediated,
    // serde-unrecoverable (same class as receipt_layer_never_vetoes_kernel_verdicts).
    let divergent = r#"{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","x":1e309}}}"#;
    o.send(divergent);
    let target = block_target(&o.expect_line()).expect("kernel block names its approval target");
    o.approve(&target);
    o.send(divergent);

    // Passive-tap property #1: the child receives the wire VERBATIM — the forward
    // is byte-identical, the signal changed nothing about what was forwarded.
    assert_eq!(
        o.expect_line(),
        divergent,
        "forward must be byte-identical to the wire (signal is a passive tap)"
    );

    // The signal is on stderr, structured, and reports THIS forced downgrade.
    let signal = o
        .drain_stderr(Duration::from_millis(400))
        .into_iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
        .find(|v| v["event"] == "reduced_scope_forward")
        .expect("a forced reduced-scope forward must emit the observability signal");
    assert_eq!(
        signal["request_sha256"],
        hex::encode(sha2::Sha256::digest(divergent.as_bytes())),
        "signal must carry the exact wire-line hash"
    );
    assert!(
        signal["parse_error"].is_string(),
        "signal must name the parse failure"
    );
    assert_eq!(signal["count"], 1, "first forced downgrade is count 1");

    // Passive-tap property #2: the receipt is unchanged — still the reduced-scope
    // shape (raw hash + parse error, structured fields absent), not touched by the signal.
    let receipts = o.receipts();
    let allow = receipts
        .iter()
        .rev()
        .find(|r| r["verdict"] == "ALLOW")
        .expect("forwarded decision persisted an ALLOW receipt");
    assert_eq!(
        allow["request_sha256"],
        hex::encode(sha2::Sha256::digest(divergent.as_bytes()))
    );
    assert!(allow["request_parse_error"].is_string());
    for absent in [
        "tool",
        "arguments",
        "args_hash",
        "canonical_request",
        "canonical_request_sha256",
    ] {
        assert!(
            allow.get(absent).is_none(),
            "receipt field {absent} must stay absent"
        );
    }

    // A normal PARSEABLE ALLOW must NOT emit the signal (fires only on downgrade).
    let parseable = guarded_call(91, "drop table accounts");
    o.send(&parseable);
    let t2 = block_target(&o.expect_line()).expect("parseable guarded call blocks");
    o.approve(&t2);
    o.send(&parseable);
    assert_eq!(
        o.expect_line(),
        parseable,
        "parseable ALLOW forwards verbatim"
    );
    let no_signal = o
        .drain_stderr(Duration::from_millis(400))
        .into_iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
        .any(|v| v["event"] == "reduced_scope_forward");
    assert!(
        !no_signal,
        "a parseable ALLOW must not emit the reduced-scope signal"
    );
}
