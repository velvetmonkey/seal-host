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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use seal_host_rs::lean::LeanHost;
use seal_host_rs::providers::{
    approval_v2_signature_preimage, canonical_approval_v2_payload, ApprovalRecordV2Payload,
    ApprovalRenderer,
};
use seal_host_rs::release::{ReadableDurabilityClass, ReleaseStatus, ReleaseStore};
use seal_host_rs::replay_store::{ReplayStoreLineage, SqliteReplayStore};
use seal_host_rs::route::SEAM_ERROR_RESPONSE;
use sha2::Digest;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
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
    /// Extra environment for the spawned host (G2 crash-point injection).
    env: Vec<(String, String)>,
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

fn signed_v2_token(target: &str, framed_bytes: &[u8], shown_bytes: &[u8], nonce: &str) -> String {
    let sk = approval_signing_key();
    let authorized_at = wall_now_ms();
    let payload = ApprovalRecordV2Payload {
        approval_record_version: 2,
        target: target.to_string(),
        authorized_at,
        expiry: authorized_at + 120_000,
        nonce: nonce.to_string(),
        session: "host-path-approval-session".to_string(),
        subject_sha256: hex::encode(sha2::Sha256::digest(framed_bytes)),
        subject_length: framed_bytes.len() as u64,
        subject_scope: "mcp-jsonrpc-request-frame-including-delimiter".to_string(),
        subject_encoding: "bytes".to_string(),
        shown_sha256: hex::encode(sha2::Sha256::digest(shown_bytes)),
        shown_length: shown_bytes.len() as u64,
        shown_media_type: "text/plain".to_string(),
        shown_character_encoding: "utf-8".to_string(),
        renderer: ApprovalRenderer {
            name: "host-path-renderer".to_string(),
            version: "2.0.0".to_string(),
            manifest_sha256: hex::encode(sha2::Sha256::digest(b"host-path renderer manifest")),
        },
        approver: "host-path-human".to_string(),
        authorization_signer_key_id: hex::encode(sha2::Sha256::digest(
            sk.verifying_key().to_bytes(),
        )),
        authorization_signature_algorithm: "Ed25519".to_string(),
        authorization_domain: "seal.approval-record/v2".to_string(),
    };
    let signature = sk.sign(&approval_v2_signature_preimage(&payload).unwrap());
    serde_json::json!({
        "payload": String::from_utf8(canonical_approval_v2_payload(&payload).unwrap()).unwrap(),
        "signature_algorithm": "Ed25519",
        "signature_encoding": "base64url-nopad",
        "signer_key_id": payload.authorization_signer_key_id,
        "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
    .to_string()
}

fn wall_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

impl Oracle {
    fn spawn(tag: &str) -> Oracle {
        Oracle::spawn_channel(tag, false, false)
    }

    /// Spawn on the PRODUCTION approval channel: ed25519 signed tokens with
    /// a sqlite replay store (required by the host for this channel).
    fn spawn_signed(tag: &str) -> Oracle {
        Oracle::spawn_channel(tag, true, false)
    }

    /// Production channel plus extra environment — used by the G2 crash
    /// suite to arm SEAL_TEST_CRASH_POINT in the host process.
    fn spawn_signed_with_env(tag: &str, env: &[(&str, &str)]) -> Oracle {
        let mut o = Oracle::spawn_channel(tag, true, false);
        // Re-spawn with the env armed; the first process only set up state.
        o.restart_with_env(env);
        o
    }

    fn spawn_numeric_observer(tag: &str) -> Oracle {
        Oracle::spawn_channel(tag, false, true)
    }

    fn spawn_channel(tag: &str, signed: bool, numeric_observer: bool) -> Oracle {
        Oracle::spawn_channel_with(tag, signed, numeric_observer, None, false)
    }

    fn spawn_crash_recorder(tag: &str, crash_point: &str) -> Oracle {
        Oracle::spawn_channel_with(tag, true, false, Some(crash_point), true)
    }

    fn spawn_channel_with(
        tag: &str,
        signed: bool,
        numeric_observer: bool,
        crash_point: Option<&str>,
        durable_receiver: bool,
    ) -> Oracle {
        let dir =
            std::env::temp_dir().join(format!("seal-host-oracle-{}-{}", std::process::id(), tag));
        std::fs::create_dir_all(&dir).unwrap();
        if signed {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let approvals = dir.join("approvals.ndjson");
        std::fs::write(&approvals, b"").unwrap();
        if signed {
            std::fs::set_permissions(&approvals, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        let config_sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(config_sk.verifying_key().to_bytes());
        let mut approval = serde_json::json!({
            "control_file": approvals.to_str().unwrap(),
            "ttl_seconds": 120
        });
        if signed {
            approval["replay_store"] = serde_json::json!({
                "sqlite_path": dir.join("replay.sqlite").to_str().unwrap(),
                "schema_version": 2,
                "namespace_encoding_version": 1
            });
        }
        let mut tools = vec![
            serde_json::json!({
                "name": "db.execute",
                "mode": "guarded",
                "match": {"type": "contains_any_ci", "arg": "sql",
                          "needles": ["drop", "delete", "truncate"]},
                "target": [{"full_arguments": true}]
            }),
            serde_json::json!({
                "name": "approve",
                "mode": "deny",
                "match": {"type": "always"},
                "target": []
            }),
            serde_json::json!({
                "name": "m7.echo",
                "mode": "allow",
                "match": {"type": "always"},
                "target": []
            }),
        ];
        if numeric_observer {
            tools.push(serde_json::json!({
                "name": "numeric.observer",
                "mode": "allow",
                "match": {"type": "always"},
                "target": []
            }));
        }
        let payload = serde_json::json!({
            "epoch": 1,
            "safety": {
                "approval": approval,
                "tools": tools
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
        if signed {
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            SqliteReplayStore::initialize(dir.join("replay.sqlite"), ReplayStoreLineage::CURRENT)
                .unwrap();
        }

        let mut args = Vec::new();
        if !signed {
            args.push("--insecure-development-mode".to_string());
        }
        args.extend([
            "--config".to_string(),
            config.to_str().unwrap().to_string(),
            "--pubkey".to_string(),
            pk,
        ]);
        if signed {
            let token_file = dir.join("tokens.ndjson");
            std::fs::write(&token_file, b"").unwrap();
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
            let receipt_dir = dir.join("production-receipts");
            std::fs::create_dir(&receipt_dir).unwrap();
            std::fs::set_permissions(&receipt_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let approval_pk = hex::encode(approval_signing_key().verifying_key().to_bytes());
            args.extend([
                "--channel".to_string(),
                "ed25519".to_string(),
                "--token-file".to_string(),
                token_file.to_str().unwrap().to_string(),
                "--approval-pubkey".to_string(),
                approval_pk,
                "--receipt-dir".to_string(),
                receipt_dir.to_str().unwrap().to_string(),
            ]);
        }
        args.push("--".to_string());
        if durable_receiver {
            const DURABLE_RECEIVER: &str = r#"
import fcntl
import os
import sys
fd = os.open(sys.argv[1], os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
frame_open = False
try:
    while True:
        chunk = os.read(0, 1)
        if not chunk:
            break
        if not frame_open:
            fcntl.flock(fd, fcntl.LOCK_EX)
            frame_open = True
        os.write(fd, chunk)
        os.fsync(fd)
        if chunk == b"\n":
            fcntl.flock(fd, fcntl.LOCK_UN)
            frame_open = False
finally:
    if frame_open:
        fcntl.flock(fd, fcntl.LOCK_UN)
    os.close(fd)
"#;
            args.extend([
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                DURABLE_RECEIVER.to_string(),
                dir.join("receiver.bin").to_str().unwrap().to_string(),
            ]);
        } else if numeric_observer {
            const OBSERVER: &str = r#"
import json
import sys
for line in sys.stdin:
    raw = line.rstrip("\n")
    message = json.loads(raw)
    value = message["params"]["arguments"]["v"]
    response = {
        "jsonrpc": "2.0",
        "id": message["id"],
        "result": {
            "content": [{
                "type": "text",
                "text": f"observer received v={value}",
                "raw": raw,
                "value": value,
            }],
            "isError": False,
        },
    }
    print(json.dumps(response, separators=(",", ":")), flush=True)
"#;
            args.extend([
                "/usr/bin/python3".to_string(),
                "-c".to_string(),
                OBSERVER.to_string(),
            ]);
        } else {
            args.push("/bin/cat".to_string());
        }

        let env = crash_point
            .map(|point| {
                vec![(
                    seal_host_rs::crash_injection::CRASH_POINT_ENV.to_string(),
                    point.to_string(),
                )]
            })
            .unwrap_or_default();
        let (child, stdin, lines, raw, stderr_lines) = Oracle::spawn_process(&args, &env);
        Oracle {
            child,
            stdin,
            lines,
            raw,
            stderr_lines,
            dir,
            args,
            env,
        }
    }

    #[allow(clippy::type_complexity)]
    fn spawn_process(
        args: &[String],
        env: &[(String, String)],
    ) -> (
        Child,
        ChildStdin,
        Receiver<String>,
        Receiver<Vec<u8>>,
        Receiver<String>,
    ) {
        let mut command = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"));
        for (key, value) in env {
            command.env(key, value);
        }
        command
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("spawn seal-host-rs");
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
        let (child, stdin, lines, raw, stderr_lines) = Oracle::spawn_process(&self.args, &self.env);
        self.child = child;
        self.stdin = stdin;
        self.lines = lines;
        self.raw = raw;
        self.stderr_lines = stderr_lines;
    }

    /// Restart with a REPLACED extra environment (arm or disarm a crash
    /// point) on the same state directory.
    fn restart_with_env(&mut self, env: &[(&str, &str)]) {
        self.env = env
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.restart();
    }

    fn append_token_line(&mut self, line: &str) {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("tokens.ndjson"))
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn approve_v2(&mut self, target: &str, framed_bytes: &[u8], nonce: &str) {
        let token = signed_v2_token(target, framed_bytes, b"host-path test approval", nonce);
        self.append_token_line(&token);
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).unwrap();
        self.stdin.flush().unwrap();
    }

    fn send(&mut self, line: &str) {
        self.send_bytes(format!("{line}\n").as_bytes());
    }

    fn receipt_dir(&self) -> PathBuf {
        self.args
            .windows(2)
            .find(|pair| pair[0] == "--receipt-dir")
            .map(|pair| PathBuf::from(&pair[1]))
            .unwrap_or_else(|| self.dir.join("seal-receipts"))
    }

    fn receipts(&self) -> Vec<serde_json::Value> {
        let mut paths: Vec<_> = std::fs::read_dir(self.receipt_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("receipt-") && name.ends_with(".json"))
            })
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
    // The complete arguments object feeds the policy's target derivation.
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"db.execute","arguments":{{"database":"prod","sql":{}}}}}}}"#,
        serde_json::to_string(sql).unwrap()
    )
}

/// A mediated ALLOW forwards the exact authorized frame with one reserved,
/// receiver-visible top-level member appended. Removing that one member must
/// recover the byte-identical approved frame, including its delimiter.
fn assert_forwarded_with_operation_id(actual: &[u8], approved: &[u8]) -> String {
    fn split_terminator(frame: &[u8]) -> (&[u8], &[u8]) {
        if let Some(body) = frame.strip_suffix(b"\r\n") {
            (body, b"\r\n")
        } else if let Some(body) = frame.strip_suffix(b"\n") {
            (body, b"\n")
        } else {
            (frame, b"")
        }
    }

    let (actual_body, actual_terminator) = split_terminator(actual);
    let (approved_body, approved_terminator) = split_terminator(approved);
    assert_eq!(
        actual_terminator, approved_terminator,
        "operation-id forwarding must preserve the authorized delimiter"
    );
    let parsed: serde_json::Value = serde_json::from_slice(actual_body).unwrap();
    let operation_id = parsed["operation_id"]
        .as_str()
        .expect("mediated forward carries operation_id")
        .to_string();
    assert_eq!(operation_id.len(), 64);
    assert!(operation_id.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let suffix = format!(",\"operation_id\":\"{operation_id}\"}}");
    assert!(
        actual_body.ends_with(suffix.as_bytes()),
        "operation_id must be the only appended wire member"
    );
    let reconstructed_len = actual_body.len() - suffix.len();
    let mut reconstructed = actual_body[..reconstructed_len].to_vec();
    reconstructed.push(b'}');
    assert_eq!(reconstructed, approved_body);
    operation_id
}

fn assert_line_forwarded_with_operation_id(actual: &str, approved: &str) -> String {
    assert_forwarded_with_operation_id(actual.as_bytes(), approved.as_bytes())
}

fn m7_state_inventory(o: &Oracle) -> String {
    let mut receipt_entries: Vec<_> = std::fs::read_dir(o.receipt_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    receipt_entries.sort();
    let replay = rusqlite::Connection::open(o.dir.join("replay.sqlite")).unwrap();
    let replay_rows: i64 = replay
        .query_row("SELECT COUNT(*) FROM nonces", [], |row| row.get(0))
        .unwrap();
    let approvals_bytes = std::fs::read(o.dir.join("approvals.ndjson")).unwrap().len();
    let tokens_bytes = std::fs::read(o.dir.join("tokens.ndjson")).unwrap().len();
    format!(
        "receipt_dir_entries={receipt_entries:?} authorization_decisions={} audit_head_present={} approval_bytes={approvals_bytes} token_bytes={tokens_bytes} replay_rows={replay_rows}",
        receipt_entries
            .iter()
            .filter(|name| name.starts_with("receipt-") && name.ends_with(".json"))
            .count(),
        receipt_entries
            .iter()
            .any(|name| name == ".seal-audit-head.state"),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DurableReceiverState {
    Empty,
    Partial {
        hex: String,
    },
    Complete {
        frames: usize,
        operation_ids_match_signed_receipts: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DurableCutState {
    release_statuses: Vec<ReleaseStatus>,
    durability_classes: Vec<ReadableDurabilityClass>,
    operation_state_entries: usize,
    receiver: DurableReceiverState,
}

struct CrashCutSpec {
    name: &'static str,
    crash_point: &'static str,
    expected_before: DurableCutState,
    expected_after_kill: DurableCutState,
    expected_after_recovery: DurableCutState,
}

fn durable_cut_state(o: &Oracle) -> DurableCutState {
    let store = ReleaseStore::open(o.receipt_dir()).expect("open signed release store");
    let mut receipt_paths: Vec<_> = std::fs::read_dir(o.receipt_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("receipt-") && name.ends_with(".json"))
        })
        .collect();
    receipt_paths.sort();
    let releases: Vec<_> = receipt_paths
        .iter()
        .map(|path| {
            store
                .read_verified(path)
                .unwrap_or_else(|error| {
                    panic!("signed receipt {} did not verify: {error}", path.display())
                })
                .1
                .expect("crash-cut receipt is an ALLOW release")
        })
        .collect();
    let release_statuses = releases.iter().map(|release| release.status).collect();
    let durability_classes = releases
        .iter()
        .map(|release| release.durability_class)
        .collect();
    let mut signed_operation_ids: Vec<_> = releases
        .iter()
        .map(|release| release.operation_id.clone())
        .collect();
    signed_operation_ids.sort();
    let receiver_bytes = read_durable_receiver(o.dir.join("receiver.bin"));
    let receiver = if receiver_bytes.is_empty() {
        DurableReceiverState::Empty
    } else if !receiver_bytes.ends_with(b"\n") {
        DurableReceiverState::Partial {
            hex: hex::encode(receiver_bytes),
        }
    } else {
        let mut received_operation_ids = Vec::new();
        for line in receiver_bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let frame: serde_json::Value = serde_json::from_slice(line).unwrap_or_else(|error| {
                panic!("durable receiver has a bad complete frame: {error}")
            });
            received_operation_ids.push(
                frame["operation_id"]
                    .as_str()
                    .expect("forwarded frame carries operation_id")
                    .to_string(),
            );
        }
        received_operation_ids.sort();
        DurableReceiverState::Complete {
            frames: received_operation_ids.len(),
            operation_ids_match_signed_receipts: received_operation_ids == signed_operation_ids,
        }
    };
    DurableCutState {
        release_statuses,
        durability_classes,
        operation_state_entries: store.operation_count().expect("read operation state"),
        receiver,
    }
}

/// Snapshot only between receiver frames. The receiver intentionally fsyncs
/// each byte so cut (d) can prove a prefix survived an interrupted transport,
/// but an in-progress prefix is not yet an observable MCP frame. Its
/// frame-scoped exclusive lock is released at the newline, or at EOF for a
/// genuinely partial frame; this shared lock therefore distinguishes those
/// states without polling or a timing assumption.
fn read_durable_receiver(path: PathBuf) -> Vec<u8> {
    let Ok(mut file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let fd = file.as_raw_fd();
    assert_eq!(
        unsafe { libc::flock(fd, libc::LOCK_SH) },
        0,
        "lock durable receiver snapshot"
    );
    let mut bytes = Vec::new();
    let read_result = file.read_to_end(&mut bytes);
    let unlock_result = unsafe { libc::flock(fd, libc::LOCK_UN) };
    read_result.expect("read locked durable receiver snapshot");
    assert_eq!(unlock_result, 0, "unlock durable receiver snapshot");
    bytes
}

fn print_cut_state(label: &str, state: &DurableCutState) {
    println!("{label}: {state:?}");
}

/// Drive a named crash cut against the real host process. A case is entirely
/// described by its armed point and exact durable states before the trigger,
/// after the kill, and after a fresh process has booted over the same files.
/// Reaching the expected files is insufficient: the harness also requires an
/// intentional SIGABRT and the named marker from the dying process.
fn drive_crash_cut(spec: CrashCutSpec, trigger: impl FnOnce(&mut Oracle)) -> Oracle {
    let mut oracle = Oracle::spawn_crash_recorder(spec.name, spec.crash_point);

    let before = durable_cut_state(&oracle);
    print_cut_state("T1 durable state before kill", &before);
    assert_eq!(before, spec.expected_before);

    trigger(&mut oracle);
    let status = oracle.child.wait().expect("wait for crash-injected host");
    let crash_stderr = oracle.drain_stderr(Duration::from_millis(100));
    println!(
        "T1 process exit: status={status:?} signal={:?} crash_point={}",
        status.signal(),
        spec.crash_point
    );
    assert_eq!(
        status.signal(),
        Some(libc::SIGABRT),
        "a crash cut cannot pass unless the real host exited by SIGABRT"
    );
    assert!(
        crash_stderr.iter().any(|line| {
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|value| {
                    value["seal_test_crash_point"]
                        .as_str()
                        .map(|point| point == spec.crash_point)
                })
                .unwrap_or(false)
        }),
        "dying process did not evidence the armed crash point: {crash_stderr:?}"
    );

    // The receiver fsyncs each byte. Give the orphaned child time to consume
    // the pipe byte and observe EOF after the host's abort.
    let mut after_kill = durable_cut_state(&oracle);
    for _ in 0..200 {
        if after_kill == spec.expected_after_kill {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        after_kill = durable_cut_state(&oracle);
    }
    print_cut_state("T1 durable state after kill", &after_kill);
    assert_eq!(after_kill, spec.expected_after_kill);

    oracle.restart();
    // Prove the replacement process completed boot and is mediating input;
    // this malformed frame is refused locally and cannot alter either durable
    // state component measured by this cut.
    oracle.send_bytes(&[0xff, b'\n']);
    assert_eq!(oracle.expect_line(), SEAM_ERROR_RESPONSE.trim_end());
    // A startup retry is delivered to a different process asynchronously and
    // the receiver fsyncs every byte, so a positive recovery needs bounded
    // time to drain. Poll until the expected state appears...
    let mut after_recovery = durable_cut_state(&oracle);
    for _ in 0..200 {
        if after_recovery == spec.expected_after_recovery {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        after_recovery = durable_cut_state(&oracle);
    }
    print_cut_state("T1 durable state after recovery", &after_recovery);
    assert_eq!(after_recovery, spec.expected_after_recovery);
    // ...then hold and re-assert, so a forbidden late write (an unsafe replay
    // landing after a transient match) still turns the cut red instead of
    // slipping in behind a single early sample.
    std::thread::sleep(Duration::from_millis(150));
    let settled = durable_cut_state(&oracle);
    assert_eq!(
        settled, spec.expected_after_recovery,
        "durable state changed after the recovery snapshot settled"
    );
    oracle
}

fn empty_cut_state() -> DurableCutState {
    DurableCutState {
        release_statuses: Vec::new(),
        durability_classes: Vec::new(),
        operation_state_entries: 0,
        receiver: DurableReceiverState::Empty,
    }
}

fn recorded_cut_state(
    status: ReleaseStatus,
    operation_state_entries: usize,
    receiver: DurableReceiverState,
) -> DurableCutState {
    DurableCutState {
        release_statuses: vec![status],
        durability_classes: vec![ReadableDurabilityClass::AssertedLocalFsync],
        operation_state_entries,
        receiver,
    }
}

fn complete_receiver() -> DurableReceiverState {
    DurableReceiverState::Complete {
        frames: 1,
        operation_ids_match_signed_receipts: true,
    }
}

fn cut_request(cut: char) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 800,
        "method": "tools/call",
        "params": {
            "name": "m7.echo",
            "arguments": {"message": format!("cut-{cut}")},
        },
    })
    .to_string()
}

#[test]
fn g2_cut_b_recorded_receipt_redoes_state_and_releases_on_restart() {
    let oracle = drive_crash_cut(
        CrashCutSpec {
            name: "g2-cut-b",
            crash_point: "g2-b-after-recorded",
            expected_before: empty_cut_state(),
            expected_after_kill: recorded_cut_state(
                ReleaseStatus::Pending,
                0,
                DurableReceiverState::Empty,
            ),
            expected_after_recovery: recorded_cut_state(
                ReleaseStatus::Released,
                1,
                complete_receiver(),
            ),
        },
        |oracle| oracle.send(&cut_request('b')),
    );
    assert_eq!(
        oracle
            .receipts()
            .into_iter()
            .find(|record| record["record_type"] == "seal.authorization-decision")
            .expect("durable authorization decision")["record_version"],
        3
    );
}

#[test]
fn g2_cut_c_committed_state_resumes_release_once_on_restart() {
    drive_crash_cut(
        CrashCutSpec {
            name: "g2-cut-c",
            crash_point: "g2-c-after-state-commit",
            expected_before: empty_cut_state(),
            expected_after_kill: recorded_cut_state(
                ReleaseStatus::Pending,
                1,
                DurableReceiverState::Empty,
            ),
            expected_after_recovery: recorded_cut_state(
                ReleaseStatus::Released,
                1,
                complete_receiver(),
            ),
        },
        |oracle| oracle.send(&cut_request('c')),
    );
}

#[test]
fn g2_cut_d_partial_child_write_is_ambiguous_and_not_retried_on_restart() {
    let ambiguous = recorded_cut_state(
        ReleaseStatus::Unknown,
        1,
        DurableReceiverState::Partial {
            hex: "7b".to_string(),
        },
    );
    drive_crash_cut(
        CrashCutSpec {
            name: "g2-cut-d",
            crash_point: "g2-d-during-child-write",
            expected_before: empty_cut_state(),
            expected_after_kill: ambiguous.clone(),
            expected_after_recovery: ambiguous,
        },
        |oracle| oracle.send(&cut_request('d')),
    );
}

#[test]
fn g2_cut_e_released_operation_is_not_released_again_before_ack() {
    let released = recorded_cut_state(ReleaseStatus::Released, 1, complete_receiver());
    drive_crash_cut(
        CrashCutSpec {
            name: "g2-cut-e",
            crash_point: "g2-e-after-released",
            expected_before: empty_cut_state(),
            expected_after_kill: released.clone(),
            expected_after_recovery: released,
        },
        |oracle| oracle.send(&cut_request('e')),
    );
}

#[test]
fn m7_version_gate_precedes_authority_and_preserves_positive_control() {
    let mut o = Oracle::spawn_signed("m7-version-gate");
    let discover = r#"{"jsonrpc":"2.0","id":700,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    o.send(discover);
    assert_eq!(o.expect_line(), discover);

    let empty_state = m7_state_inventory(&o);
    println!("M7 STATE BEFORE {empty_state}");

    let malformed = r#"{"jsonrpc":"2.0","id":701,"method":"tools/call","params":{"name":"m7.echo","arguments":{"q":"malformed"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    println!("M7 MALFORMED WIRE UTF8={malformed}\\n");
    println!(
        "M7 MALFORMED WIRE HEX={}",
        hex::encode(format!("{malformed}\n"))
    );
    o.send(malformed);
    let malformed_response = o.expect_line();
    println!("M7 MALFORMED RESPONSE={malformed_response}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&malformed_response).unwrap()["error"]["code"],
        -32602
    );
    let after_malformed = m7_state_inventory(&o);
    println!("M7 STATE AFTER MALFORMED {after_malformed}");
    assert_eq!(after_malformed, empty_state);

    let unsupported = r#"{"jsonrpc":"2.0","id":702,"method":"tools/call","params":{"name":"m7.echo","arguments":{"q":"unsupported"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2099-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    o.send(unsupported);
    let unsupported_response = o.expect_line();
    println!("M7 UNSUPPORTED RESPONSE={unsupported_response}");
    let unsupported_json: serde_json::Value = serde_json::from_str(&unsupported_response).unwrap();
    assert_eq!(unsupported_json["error"]["code"], -32022);
    assert_eq!(
        unsupported_json["error"]["data"]["supportedVersions"],
        serde_json::json!(["2025-06-18", "2026-07-28"])
    );
    let after_unsupported = m7_state_inventory(&o);
    println!("M7 STATE AFTER UNSUPPORTED {after_unsupported}");
    assert_eq!(after_unsupported, empty_state);

    let legacy_after_modern = r#"{"jsonrpc":"2.0","id":703,"method":"tools/call","params":{"name":"m7.echo","arguments":{"q":"legacy-after-modern"}}}"#;
    o.send(legacy_after_modern);
    let era_response = o.expect_line();
    println!("M7 ERA CONSISTENCY selected=2026-07-28 later_request=legacy response={era_response}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&era_response).unwrap()["error"]["code"],
        -32602
    );
    let after_era_rejection = m7_state_inventory(&o);
    println!("M7 STATE AFTER ERA REJECTION {after_era_rejection}");
    assert_eq!(after_era_rejection, empty_state);

    let positive = r#"{"jsonrpc":"2.0","id":704,"method":"tools/call","params":{"name":"m7.echo","arguments":{"q":"positive"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    o.send(positive);
    let positive_response = o.expect_line();
    println!("M7 POSITIVE RESPONSE={positive_response}");
    assert_line_forwarded_with_operation_id(&positive_response, positive);
    println!("M7 STATE AFTER POSITIVE {}", m7_state_inventory(&o));
}

/// M.1 stage 3 live cross-layer control. The shipped Lean FFI supplies the
/// audit's raw request commitment; Rust supplies the reader-facing canonical
/// projection. A metadata-only mutation must move both identities, while the
/// identical twin must leave both byte strings unchanged.
#[test]
fn meta_identity_live_host_projection_and_kernel_commitment_agree() {
    let mut o = Oracle::spawn_numeric_observer("meta-host-kernel-agreement");
    let line_a = r#"{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"numeric.observer","arguments":{"v":1},"_meta":{"example.com/invocation":"a"}}}"#;
    let line_b = r#"{"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"numeric.observer","arguments":{"v":1},"_meta":{"example.com/invocation":"b"}}}"#;

    for line in [line_a, line_a, line_b] {
        o.send(line);
        let response: serde_json::Value = serde_json::from_str(&o.expect_line()).unwrap();
        let raw = response
            .pointer("/result/content/0/raw")
            .and_then(|value| value.as_str())
            .expect("observer reports exact received frame");
        assert_line_forwarded_with_operation_id(raw, line);
    }

    let receipts = o.receipts();
    assert_eq!(receipts.len(), 3, "one live receipt per metadata probe");
    let [receipt_a, receipt_a_twin, receipt_b] = receipts.as_slice() else {
        unreachable!("receipt count checked above")
    };

    assert_eq!(
        receipt_a["canonical_request"], receipt_a_twin["canonical_request"],
        "LIVE-POSITIVE-TWIN RED key=_meta: identical request projections differ"
    );
    assert_eq!(
        receipt_a["canonical_request_sha256"], receipt_a_twin["canonical_request_sha256"],
        "LIVE-POSITIVE-TWIN RED key=_meta: identical projection commitments differ"
    );
    assert_eq!(
        receipt_a["request_sha256"], receipt_a_twin["request_sha256"],
        "LIVE-POSITIVE-TWIN RED key=_meta: identical kernel request commitments differ"
    );

    let kernel_commitment = |receipt: &serde_json::Value| -> String {
        let step: serde_json::Value =
            serde_json::from_str(receipt["emitted_bytes"].as_str().unwrap()).unwrap();
        let audit: serde_json::Value =
            serde_json::from_str(step["audit"].as_str().unwrap()).unwrap();
        let kernel = audit["request_sha256"].as_str().unwrap();
        assert_eq!(
            Some(kernel),
            receipt["request_sha256"].as_str(),
            "LIVE-RAW-HASH-SEAM RED key=_meta: kernel audit and receipt disagree"
        );
        kernel.to_owned()
    };

    let kernel_a = kernel_commitment(receipt_a);
    let kernel_b = kernel_commitment(receipt_b);
    let host_changed =
        receipt_a["canonical_request_sha256"] != receipt_b["canonical_request_sha256"];
    let kernel_changed = kernel_a != kernel_b;
    assert!(
        host_changed,
        "LIVE-HOST-PROJECTION RED key=_meta: canonical projection ignored metadata mutation"
    );
    assert_eq!(
        host_changed, kernel_changed,
        "LIVE-HOST-KERNEL-AGREEMENT RED key=_meta: host projection and shipped kernel disagree about identity change"
    );
    assert_eq!(
        receipt_a["_meta"]["example.com/invocation"], "a",
        "LIVE-RECEIPT-VISIBILITY RED key=_meta: receipt omitted metadata A"
    );
    assert_eq!(
        receipt_b["_meta"]["example.com/invocation"], "b",
        "LIVE-RECEIPT-VISIBILITY RED key=_meta: receipt omitted metadata B"
    );
    println!(
        "LIVE-HOST-KERNEL-AGREEMENT GREEN key=_meta positive_twin=byte-identical-projections host_projection_changed={} kernel_request_commitment_changed={} kernel_sha_a={} kernel_sha_b={}",
        host_changed, kernel_changed, kernel_a, kernel_b
    );
}

/// Receipt follows envelope: every complete JSON `_meta` identity accepted
/// by the real kernel must survive a mediated ALLOW as complete evidence.
#[test]
fn non_object_metadata_allow_receipts_are_complete_and_distinct() {
    let mut o = Oracle::spawn_numeric_observer("receipt-follows-envelope");
    let cases = [
        ("absent", None),
        ("empty", Some("{}")),
        ("null", Some("null")),
        ("number", Some("42")),
        ("string", Some(r#""receipt""#)),
        ("array", Some(r#"[{"z":1,"a":2}]"#)),
    ];
    let expected_count = cases.len();
    let mut expected = Vec::new();
    for (index, (label, raw_metadata)) in cases.into_iter().enumerate() {
        let metadata_member = raw_metadata
            .map(|raw| format!(r#","_meta":{raw}"#))
            .unwrap_or_default();
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"numeric.observer","arguments":{{"v":1}}{metadata_member}}}}}"#,
            80 + index
        );
        o.send(&line);
        let response: serde_json::Value = serde_json::from_str(&o.expect_line()).unwrap();
        let raw = response
            .pointer("/result/content/0/raw")
            .and_then(serde_json::Value::as_str)
            .expect("observer reports exact received frame");
        assert_line_forwarded_with_operation_id(raw, &line);
        expected.push((label, raw_metadata, line));
    }

    let receipts = o.receipts();
    assert_eq!(receipts.len(), expected_count, "one receipt per ALLOW");
    let mut canonical_identities = std::collections::BTreeSet::new();
    for (receipt, (label, raw_metadata, line)) in receipts.iter().zip(&expected) {
        assert_eq!(receipt["verdict"], "ALLOW", "{label}: verdict");
        assert_eq!(receipt["tool"], "numeric.observer", "{label}: tool");
        assert_eq!(
            receipt["arguments"],
            serde_json::json!({"v": 1}),
            "{label}: arguments"
        );
        assert_eq!(
            receipt["effect_view"]["effect"]["arguments"], receipt["arguments"],
            "{label}: effect arguments"
        );
        match raw_metadata {
            None => {
                assert!(receipt.get("_meta").is_none(), "absent metadata was minted");
                assert!(
                    receipt["effect_view"]["effect"].get("_meta").is_none(),
                    "effect view minted absent metadata"
                );
            }
            Some(raw) => {
                let value: serde_json::Value = serde_json::from_str(raw).unwrap();
                assert_eq!(
                    receipt.get("_meta"),
                    Some(&value),
                    "{label}: receipt metadata"
                );
                assert_eq!(
                    receipt["effect_view"]["effect"].get("_meta"),
                    Some(&value),
                    "{label}: effect metadata"
                );
            }
        }
        assert!(receipt["effect_view"].is_object(), "{label}: effect_view");
        assert!(
            receipt.get("request_parse_error").is_none(),
            "{label}: parse error"
        );

        let canonical = receipt["canonical_request"]
            .as_str()
            .unwrap_or_else(|| panic!("{label}: canonical request missing"));
        let canonical_value: serde_json::Value = serde_json::from_str(canonical).unwrap();
        match raw_metadata {
            None => assert!(canonical_value["params"].get("_meta").is_none()),
            Some(raw) => assert_eq!(
                canonical_value["params"].get("_meta"),
                Some(&serde_json::from_str::<serde_json::Value>(raw).unwrap()),
                "{label}: canonical request metadata"
            ),
        }
        let canonical_hash = hex::encode(sha2::Sha256::digest(canonical.as_bytes()));
        assert_eq!(
            receipt["canonical_request_sha256"], canonical_hash,
            "{label}: canonical request hash"
        );
        assert!(
            canonical_identities.insert(canonical_hash),
            "{label}: canonical identity collapsed"
        );

        let emitted: serde_json::Value =
            serde_json::from_str(receipt["emitted_bytes"].as_str().unwrap()).unwrap();
        let audit: serde_json::Value =
            serde_json::from_str(emitted["audit"].as_str().unwrap()).unwrap();
        let raw_hash = hex::encode(sha2::Sha256::digest(line.as_bytes()));
        assert_eq!(
            audit["request_sha256"], raw_hash,
            "{label}: kernel raw hash"
        );
        assert_eq!(
            receipt["request_sha256"], raw_hash,
            "{label}: receipt raw hash"
        );
    }
    assert_eq!(canonical_identities.len(), expected_count);
    println!(
        "RECEIPT-FOLLOWS-ENVELOPE REAL-RECEIPT {}",
        serde_json::to_string(&receipts[3]).unwrap()
    );
}

/// M.4 stage 3 live host-versus-kernel agreement. The shipped kernel's exact
/// request commitment observes each complete MRTR value independently of the
/// Rust projection. Every field-specific discrimination has a byte-identical
/// positive twin before the negative pair is compared.
#[test]
fn mrtr_identity_live_host_projection_and_kernel_commitment_agree() {
    let mut o = Oracle::spawn_numeric_observer("mrtr-host-kernel-agreement");
    let request_state_a = r#"{"opaque":{"token":"state-a","nested":[1,null]},"sibling":"kept"}"#;
    let request_state_b = r#"{"opaque":{"token":"state-b","nested":[1,null]},"sibling":"kept"}"#;
    let responses_a = r#"{"confirm":{"action":"accept","content":true},"survey":{"score":5},"extension":["one","two"]}"#;
    let responses_b = r#"{"confirm":{"action":"decline","content":false},"survey":{"score":5},"extension":["one","two"]}"#;
    let line = |id: u64, field: &str, value: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"numeric.observer","arguments":{{"v":1}},"{field}":{value}}}}}"#
        )
    };
    let probes = [
        (
            "requestState",
            line(72, "requestState", request_state_a),
            line(72, "requestState", request_state_b),
        ),
        (
            "inputResponses",
            line(73, "inputResponses", responses_a),
            line(73, "inputResponses", responses_b),
        ),
    ];

    for (_, left, right) in &probes {
        for raw in [left, left, right] {
            o.send(raw);
            let response: serde_json::Value = serde_json::from_str(&o.expect_line()).unwrap();
            let observed = response
                .pointer("/result/content/0/raw")
                .and_then(|value| value.as_str())
                .expect("observer reports exact received frame");
            assert_line_forwarded_with_operation_id(observed, raw);
        }
    }

    let receipts = o.receipts();
    assert_eq!(receipts.len(), 6, "three live receipts per MRTR field");
    let kernel_commitment = |field: &str, receipt: &serde_json::Value| -> String {
        let step: serde_json::Value =
            serde_json::from_str(receipt["emitted_bytes"].as_str().unwrap()).unwrap();
        let audit: serde_json::Value =
            serde_json::from_str(step["audit"].as_str().unwrap()).unwrap();
        let kernel = audit["request_sha256"].as_str().unwrap();
        assert_eq!(
            Some(kernel),
            receipt["request_sha256"].as_str(),
            "LIVE-MRTR-RAW-HASH-SEAM RED field={field}: kernel audit and receipt disagree"
        );
        kernel.to_owned()
    };

    for (index, (field, _, _)) in probes.iter().enumerate() {
        let left = &receipts[index * 3];
        let twin = &receipts[index * 3 + 1];
        let right = &receipts[index * 3 + 2];
        assert_eq!(
            left["canonical_request"], twin["canonical_request"],
            "LIVE-MRTR-POSITIVE-TWIN RED field={field}: identical projections differ"
        );
        assert_eq!(
            left["canonical_request_sha256"], twin["canonical_request_sha256"],
            "LIVE-MRTR-POSITIVE-TWIN RED field={field}: identical projection commitments differ"
        );
        assert_eq!(
            left["request_sha256"], twin["request_sha256"],
            "LIVE-MRTR-POSITIVE-TWIN RED field={field}: identical kernel commitments differ"
        );
        println!(
            "LIVE-MRTR-POSITIVE-TWIN GREEN field={field} request=byte-identical host-projection=kernel-commitment=same"
        );

        let host_changed = left["canonical_request_sha256"] != right["canonical_request_sha256"];
        assert!(
            host_changed,
            "LIVE-HOST-PROJECTION RED field={field}: canonical projection ignored MRTR mutation"
        );
        let kernel_left = kernel_commitment(field, left);
        let kernel_right = kernel_commitment(field, right);
        let kernel_changed = kernel_left != kernel_right;
        assert_eq!(
            host_changed, kernel_changed,
            "LIVE-HOST-KERNEL-AGREEMENT RED field={field}: host projection and shipped kernel disagree about identity change"
        );
        assert!(
            left.get(field).is_some()
                && right.get(field).is_some()
                && left["effect_view"]["effect"].get(field) == left.get(field)
                && right["effect_view"]["effect"].get(field) == right.get(field),
            "LIVE-MRTR-RECEIPT-VISIBILITY RED field={field}: complete values not exposed"
        );
        println!(
            "LIVE-MRTR-HOST-KERNEL-AGREEMENT GREEN field={field} positive_twin=byte-identical host_projection_changed={host_changed} kernel_request_commitment_changed={kernel_changed}"
        );
    }
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

fn block_framed_subject(line: &str) -> Option<Vec<u8>> {
    let response: serde_json::Value = serde_json::from_str(line).ok()?;
    let subject = response.pointer("/result/framed_subject")?;
    if subject.get("encoding")?.as_str()? != "base64" {
        return None;
    }
    let framed_bytes = base64::engine::general_purpose::STANDARD
        .decode(subject.get("base64")?.as_str()?)
        .ok()?;
    if subject.get("length")?.as_u64()? != framed_bytes.len() as u64
        || subject.get("sha256")?.as_str()? != hex::encode(sha2::Sha256::digest(&framed_bytes))
    {
        return None;
    }
    Some(framed_bytes)
}

fn numeric_call(id: u64, literal: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"numeric.observer","arguments":{{"v":{literal}}}}}}}"#
    )
}

/// RUN: REPINNUM-WIRE-EVIDENCE
///
/// The real stdio host and a real downstream JSON observer establish
/// both halves of the agreement gate: disagreement is refused before child
/// ingress with the exact literal named, while agreed values are mediated,
/// receipt-bound by the kernel request hash, and forwarded byte-identically.
#[test]
fn numeric_agreement_refuses_at_wire_and_preserves_negative_control() {
    let mut o = Oracle::spawn_numeric_observer("numeric-agreement-wire");

    let fixture =
        include_str!("corpora/JSONTestSuite/test_parsing/i_number_neg_int_huge_exp.json").trim();
    let measured_literal = fixture
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .expect("measured JSONTestSuite vector is a one-element array");
    let measured = numeric_call(200, measured_literal);
    o.send(&measured);
    let measured_response = o.expect_line();
    println!("WIRE REFUSAL REQUEST: {measured}");
    println!("WIRE REFUSAL RESPONSE: {measured_response}");
    assert!(
        measured_response.contains("request refused")
            && measured_response.contains(measured_literal),
        "measured vector must be refused at the wire with its literal named: {measured_response}"
    );
    assert_ne!(
        measured_response, measured,
        "measured vector must not reach the echo observer"
    );

    let negative = numeric_call(201, "1e308");
    o.send(&negative);
    let negative_response = o.expect_line();
    println!("NEGATIVE CTRL REQUEST: {negative}");
    println!("NEGATIVE CTRL OBSERVER RESPONSE: {negative_response}");
    let observer: serde_json::Value =
        serde_json::from_str(&negative_response).expect("observer returned valid JSON");
    let observation = &observer["result"]["content"][0];
    let observer_value = observation["value"]
        .as_f64()
        .expect("downstream observer reads 1e308 as binary64");
    let observer_raw = observation["raw"]
        .as_str()
        .expect("downstream observer reports exact input line");
    let negative_receipt = o
        .receipts()
        .into_iter()
        .rev()
        .find(|receipt| receipt["verdict"] == "ALLOW")
        .expect("kernel-signed ALLOW receipt for 1e308");
    let expected_hash = hex::encode(sha2::Sha256::digest(negative.as_bytes()));
    println!(
        "NEGATIVE CTRL OBSERVER: raw={observer_raw} value={observer_value:e} kernel_request_sha256={}",
        negative_receipt["request_sha256"]
    );
    assert_line_forwarded_with_operation_id(observer_raw, &negative);
    assert_eq!(observer_value, 1e308);
    assert_eq!(
        negative_receipt["request_sha256"], expected_hash,
        "the kernel-signed request commitment must bind the bytes the observer read"
    );

    let safe_boundary = numeric_call(202, "9007199254740991");
    o.send(&safe_boundary);
    let safe_response = o.expect_line();
    let safe_observer: serde_json::Value =
        serde_json::from_str(&safe_response).expect("safe-boundary observer response parses");
    let safe_observation = &safe_observer["result"]["content"][0];
    println!("BOUNDARY SAFE REQUEST: {safe_boundary}");
    println!("BOUNDARY SAFE OBSERVER RESPONSE: {safe_response}");
    assert_line_forwarded_with_operation_id(
        safe_observation["raw"].as_str().unwrap(),
        &safe_boundary,
    );
    assert_eq!(safe_observation["value"].as_u64(), Some(9007199254740991));

    let unsafe_boundary = numeric_call(203, "9007199254740993");
    o.send(&unsafe_boundary);
    let unsafe_response = o.expect_line();
    let rounded = serde_json::from_str::<serde_json::Value>(&unsafe_boundary)
        .expect("serde parses the unsafe boundary")["params"]["arguments"]["v"]
        .as_f64()
        .expect("unsafe boundary has a binary64 reading");
    println!("BOUNDARY UNSAFE REQUEST: {unsafe_boundary}");
    println!("BOUNDARY UNSAFE BINARY64 READBACK: {rounded:.0}");
    println!("BOUNDARY UNSAFE RESPONSE: {unsafe_response}");
    assert_eq!(rounded, 9007199254740992.0);
    assert!(
        unsafe_response.contains("request refused") && unsafe_response.contains("9007199254740993"),
        "2^53 + 1 must be refused with the literal named: {unsafe_response}"
    );
    assert_ne!(
        unsafe_response, unsafe_boundary,
        "2^53 + 1 must not reach the echo observer"
    );
}

/// Stage-A guard rules must bind approvals to the complete canonical
/// arguments. Exercise the production config load path, not a parser helper:
/// the stale literal target must stop startup with the kernel's exact error,
/// while its otherwise-identical full-arguments twin starts successfully.
#[test]
fn guarded_non_full_arguments_target_is_rejected_on_startup() {
    let dir = std::env::temp_dir().join(format!(
        "seal-host-invalid-guard-target-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let approvals = dir.join("approvals.ndjson");
    std::fs::write(&approvals, b"").unwrap();

    let run = |tag: &str, target: serde_json::Value| {
        let config_sk = SigningKey::from_bytes(&[7u8; 32]);
        let payload = serde_json::json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": approvals.to_str().unwrap(),
                    "ttl_seconds": 120
                },
                "tools": [{
                    "name": "db.execute",
                    "mode": "guarded",
                    "match": {"type": "always"},
                    "target": target
                }]
            }
        })
        .to_string();
        let signature = hex::encode(config_sk.sign(payload.as_bytes()).to_bytes());
        let envelope = serde_json::json!({
            "payload": payload,
            "signature": signature
        });
        let config = dir.join(format!("{tag}.json"));
        std::fs::write(&config, envelope.to_string()).unwrap();

        Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
            .args([
                "--insecure-development-mode",
                "--config",
                config.to_str().unwrap(),
                "--pubkey",
                &hex::encode(config_sk.verifying_key().to_bytes()),
                "--",
                "/bin/cat",
            ])
            .output()
            .expect("run real host config load path")
    };

    let rejected = run("literal-target", serde_json::json!([{"literal": "db"}]));
    assert_eq!(
        rejected.status.code(),
        Some(3),
        "non-full guarded target unexpectedly loaded: stdout={} stderr={}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    let expected = r#"guard mode requires target [{"full_arguments": true}]"#;
    assert!(
        stderr.lines().any(|line| line.ends_with(expected)),
        "startup rejection must carry the exact kernel error; stderr={stderr}"
    );

    let accepted = run(
        "full-arguments-target",
        serde_json::json!([{"full_arguments": true}]),
    );
    assert!(
        accepted.status.success(),
        "full-arguments acceptance twin did not start: stderr={}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mediation_obfuscation_and_one_shot_approval() {
    let mut o = Oracle::spawn_signed("main");

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

    // Present an exact-subject v2 approval for the canonical call, then fire a
    // DISGUISE first: the subject mismatch must drop the token and block.
    let approved = guarded_call(31, "drop table accounts");
    let approved_frame = format!("{approved}\n");
    o.approve_v2(&target, approved_frame.as_bytes(), "n-main-wrong-subject");
    let disguised_again = guarded_call(30, "DROP TABLE ACCOUNTS");
    o.send(&disguised_again);
    let resp = o.expect_line();
    assert!(
        is_block(&resp),
        "approval for canonical must not unlock a disguise: {resp}"
    );

    // Re-establish the canonical challenge, issue a fresh exact-subject v2
    // token, and prove that the canonical call forwards.
    o.send(&approved);
    assert!(
        is_block(&o.expect_line()),
        "the mismatched v2 token must not survive for the canonical call"
    );
    o.approve_v2(&target, approved_frame.as_bytes(), "n-main-canonical");
    o.send(&approved);
    assert_line_forwarded_with_operation_id(&o.expect_line(), &approved);
    let mut receipts = o.receipts();
    for _ in 0..200 {
        if receipts
            .iter()
            .any(|receipt| receipt["verdict"] == "ALLOW" && receipt["release_status"] == "RELEASED")
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
        receipts = o.receipts();
    }
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
        .expect("forwarded decision persisted an ALLOW authorization decision");
    assert_eq!(allow["record_type"], "seal.authorization-decision");
    assert_eq!(allow["record_version"], 3);
    assert_eq!(allow["release_status"], "RELEASED");
    assert_eq!(allow["durability_class"], "asserted_local_fsync");
    assert_eq!(allow["operation_id"].as_str().unwrap().len(), 64);
    assert_eq!(allow["signature"]["domain"], "seal.object-b/v1");
    assert_eq!(allow["signature"]["algorithm"], "Ed25519");
    assert_ne!(
        allow["signature"]["public_key"], expected_pubkey,
        "per-install receipt signing key must remain role-split from config authority"
    );
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
    assert_eq!(allow["approval"]["approval_identity"]["channel"], "ed25519");
    assert_eq!(allow["approval"]["policy_hash"].as_str().unwrap().len(), 64);
    assert_eq!(allow["host_identity"]["equivalence"], "not_proven");
    assert_eq!(
        allow["kernel_identity"]["wasm_sha256"],
        seal_host_rs::authorization_decision::VERIFIED_WASM_SHA256
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
    let mut o = Oracle::spawn_signed("t3-terminator");

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
    let lf_frame = format!("{call}\n");
    o.approve_v2(&target, lf_frame.as_bytes(), "n-terminator-lf");
    o.send_bytes(lf_frame.as_bytes());
    let lf_child = o.expect_raw();

    // (B) SAME call, CRLF-terminated. First establish the distinct framed
    // challenge, then approve those exact bytes and capture the child echo.
    let crlf_frame = format!("{call}\r\n");
    o.send_bytes(crlf_frame.as_bytes());
    assert!(is_block(&raw_str(&o.expect_raw())));
    o.approve_v2(&target, crlf_frame.as_bytes(), "n-terminator-crlf");
    o.send_bytes(crlf_frame.as_bytes());
    let crlf_child = o.expect_raw();

    // -- HALF 1: removing each distinct operation id recovers the exact
    // authorized LF/CRLF frame. --
    assert_forwarded_with_operation_id(&lf_child, lf_frame.as_bytes());
    assert_forwarded_with_operation_id(&crlf_child, crlf_frame.as_bytes());
    assert_ne!(
        lf_child, crlf_child,
        "the child must receive distinct operation-bearing frames"
    );
    assert!(
        lf_child.ends_with(b"}\n") && !lf_child.ends_with(b"}\r\n"),
        "LF call reaches the child terminated by a bare \\n: {lf_child:?}"
    );
    assert!(
        crlf_child.ends_with(b"}\r\n"),
        "CRLF call reaches the child terminated by \\r\\n: {crlf_child:?}"
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

/// A validly signed v1 approval is explicitly refused on the production
/// channel and cannot unlock its guarded effect.
#[test]
fn ed25519_signed_approval_forwards_end_to_end() {
    let mut o = Oracle::spawn_signed("ed25519-blue");

    assert!(
        !o.args
            .iter()
            .any(|arg| arg == "--insecure-development-mode"),
        "production-path coverage must not opt out of production preflight: {:?}",
        o.args
    );
    assert!(o.args.windows(2).any(|pair| pair[0] == "--receipt-dir"));
    assert_eq!(std::fs::metadata(&o.dir).unwrap().mode() & 0o777, 0o700);
    for private_file in ["trusted.json", "tokens.ndjson", "approvals.ndjson"] {
        assert_eq!(
            std::fs::metadata(o.dir.join(private_file)).unwrap().mode() & 0o777,
            0o600,
            "{private_file} must be private"
        );
    }
    assert_eq!(
        std::fs::metadata(o.receipt_dir()).unwrap().mode() & 0o777,
        0o700
    );

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

    // A validly signed v1 approval for the target is refused and the effect
    // remains blocked.
    let token = signed_token(&target, wall_now_ms(), "n-blue-1", None);
    o.append_token_line(&token);
    o.send(&call);
    let refused_response = o.expect_line();
    println!("V1 REFUSAL RESPONSE: {refused_response}");
    assert!(
        is_block(&refused_response),
        "v1 approval must leave the guarded call blocked: {refused_response}"
    );
    assert_ne!(
        refused_response, call,
        "v1 approval must not forward the guarded call to the effect"
    );
    assert!(
        !o.receipts()
            .iter()
            .any(|receipt| receipt["verdict"] == "ALLOW"),
        "v1 refusal must not persist an ALLOW authorization decision"
    );
    let stderr = o.drain_stderr(Duration::from_millis(100));
    let refusal = stderr
        .iter()
        .find(|line| line.contains("approval_record_v1_not_supported"))
        .expect("operator must see the explicit v1 refusal");
    println!("V1 REFUSAL STDERR: {refusal}");
    for receipt in std::fs::read_dir(o.receipt_dir()).unwrap() {
        let receipt = receipt.unwrap();
        if receipt.path().extension().and_then(|value| value.to_str()) == Some("json") {
            assert_eq!(receipt.metadata().unwrap().mode() & 0o777, 0o600);
        }
    }

    // Restart on the same sqlite store: v1 stays refused independently of
    // in-memory provider state or replay tracking.
    o.restart();
    o.append_token_line(&token);
    o.send(&call);
    assert!(
        is_block(&o.expect_line()),
        "v1 token must not approve after restart"
    );
    let stderr = o.drain_stderr(Duration::from_millis(100));
    assert!(
        stderr
            .iter()
            .any(|l| l.contains("approval_record_v1_not_supported")),
        "operator must see the v1 refusal after restart: {stderr:?}"
    );

    // A permission regression is rejected by production preflight before the
    // guarded child starts.
    let _ = o.child.kill();
    let _ = o.child.wait();
    std::fs::set_permissions(
        o.dir.join("tokens.ndjson"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let refused = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
        .args(&o.args)
        .output()
        .expect("run production startup with unsafe token permissions");
    assert_eq!(refused.status.code(), Some(3));
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        refused_stderr.contains("production startup refused")
            && refused_stderr.contains("approval token file")
            && refused_stderr.contains("required 0600"),
        "unexpected production refusal: {refused_stderr}"
    );
}

#[test]
fn ed25519_approval_v2_forwards_the_exact_framed_subject() {
    let mut o = Oracle::spawn_signed("ed25519-v2-subject");
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
    o.send(init);
    assert_eq!(o.expect_line(), init);
    assert_eq!(o.expect_raw(), format!("{init}\n").as_bytes());

    let call = guarded_call(2, "drop table approval_v2_exact_bytes");
    o.send(&call);
    let blocked = o.expect_line();
    assert!(is_block(&blocked));
    let _blocked_raw = o.expect_raw();
    let target = block_target(&blocked).expect("block names its approval target");

    let framed_bytes =
        block_framed_subject(&blocked).expect("block emits its exact framed approval subject");
    assert_eq!(
        framed_bytes,
        format!("{call}\n").into_bytes(),
        "emitted approval subject must round-trip to the caller's exact frame"
    );
    let shown_bytes = b"Approve: drop table approval_v2_exact_bytes";
    let wrong_target = if target.starts_with('0') {
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    } else {
        "0000000000000000000000000000000000000000000000000000000000000000"
    };
    let wrong_target_token = signed_v2_token(
        wrong_target,
        &framed_bytes,
        shown_bytes,
        "n-v2-wrong-target",
    );
    o.append_token_line(&wrong_target_token);
    o.send(&call);
    let wrong_target_response = o.expect_line();
    assert!(
        is_block(&wrong_target_response),
        "exact subject with a different signed target must fail closed"
    );
    let _wrong_target_raw = o.expect_raw();

    let mut mutated_subject = framed_bytes.clone();
    mutated_subject[1] ^= 1;
    let wrong_subject_token = signed_v2_token(&target, &mutated_subject, shown_bytes, "n-v2-wrong");
    o.append_token_line(&wrong_subject_token);
    o.send(&call);
    let wrong_subject_response = o.expect_line();
    assert!(
        is_block(&wrong_subject_response),
        "valid signature over a different framed subject must fail closed"
    );
    let _wrong_subject_raw = o.expect_raw();

    let token = signed_v2_token(&target, &framed_bytes, shown_bytes, "n-v2-host-path");
    o.append_token_line(&token);
    o.send(&call);
    assert_forwarded_with_operation_id(&o.expect_raw(), &framed_bytes);
    assert_line_forwarded_with_operation_id(&o.expect_line(), &call);

    o.send(&call);
    assert!(
        is_block(&o.expect_line()),
        "v2 approval remains one-shot after exact-byte forward"
    );
}

/// V1 refusal happens at provider ingestion, before A3 can burn its nonce.
/// Resubmitting the same v1 token after restart remains an unsupported-v1
/// refusal, never a replay refusal, and cannot unlock the guarded effect.
#[test]
fn v1_refusal_happens_before_replay_admission() {
    let mut o = Oracle::spawn_signed("ed25519-pin");

    // Learn target T of call C (the call the approval is FOR).
    let call_c = guarded_call(10, "drop table accounts");
    o.send(&call_c);
    let blocked = o.expect_line();
    assert!(is_block(&blocked));
    let target_t = block_target(&blocked).expect("block names target T");

    let token = signed_token(&target_t, wall_now_ms(), "n-pin-1", None);
    o.append_token_line(&token);
    o.send(&call_c);
    let resp_d = o.expect_line();
    assert!(
        is_block(&resp_d),
        "v1 token must not unlock its guarded effect: {resp_d}"
    );

    let before_restart = o.drain_stderr(Duration::from_millis(200));
    assert!(before_restart
        .iter()
        .any(|line| line.contains("approval_record_v1_not_supported")));
    assert!(!before_restart
        .iter()
        .any(|line| line.contains("replayed_nonce")));
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

    // Resubmit the byte-identical token after restart. It is still refused as
    // v1, proving its nonce was never admitted into replay state.
    o.append_token_line(&token);
    let call_c2 = guarded_call(12, "drop table accounts");
    o.send(&call_c2);
    let resp = o.expect_line();
    assert!(
        is_block(&resp),
        "resubmitted v1 token must remain refused: {resp}"
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
        stderr
            .iter()
            .any(|l| l.contains("approval_record_v1_not_supported")),
        "the resubmitted token must be refused as unsupported v1: {stderr:?}"
    );
    assert!(
        !stderr.iter().any(|l| l.contains("replayed_nonce")),
        "v1 refusal must happen before replay admission: {stderr:?}"
    );
}

#[test]
fn authorization_decision_sink_failure_blocks_before_child_forward() {
    let mut o = Oracle::spawn("receipt-sink-failure");

    // READINESS BY ROUND-TRIP, not by stat. `ReceiptChain::new` calls
    // `create_dir_all` and only THEN probes the sink
    // (authorization_decision.rs:326-336), so "the authorization-decision directory exists" goes
    // true BEFORE the host is past its probe. Sabotaging inside that window
    // makes the host fail the probe and exit 4 ("authorization decision sink rejected")
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
        "host did not initialize its authorization decision sink"
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
    // an authorization decision, so the directory is NOT empty and `remove_dir` would
    // fail ENOTEMPTY. Contents are irrelevant -- the scenario only needs the
    // sink PATH to stop being a directory.
    std::fs::remove_dir_all(&receipt_dir).unwrap();
    std::fs::write(&receipt_dir, b"not a directory").unwrap();

    let call = guarded_call(70, "drop table accounts");
    o.send(&call);
    assert_eq!(
        o.expect_line(),
        SEAM_ERROR_RESPONSE.trim_end(),
        "authorization decision persistence failure must never reach the child"
    );
    let stderr = o.drain_stderr(Duration::from_millis(100));
    assert!(
        stderr.iter().any(|line| {
            line.contains("authorization decision persistence failure")
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

/// An overflow number must stay in the explicitly enumerated fail-closed
/// classifier set (refuse or mediate), never passthrough or a new value. The
/// observed outcome is printed so permitted drift remains visible.
///
/// Recut 2026-07-31 to the seven-guard boundary. The serde-unrecoverable,
/// kernel-mediated, approvable class this test used to drive end-to-end is
/// now EMPTY at the wire: lone surrogates and non-agreement numerics are
/// wire-refused by the pre-parse guards, and any nesting deep enough to
/// defeat serde (>128) is stopped far earlier by the host's own
/// `check_json_limits` depth bound (`MAX_JSON_DEPTH = 64`, `-32001`). This
/// test pins both closures, then keeps the still-reachable halves: parseable
/// receipts and the structural divergent shapes, which must always get the
/// KERNEL's response. The reduced-scope receipt writer itself keeps unit
/// coverage in `src/main.rs` — defense in depth, no longer wire-reachable.
#[test]
fn authorization_decision_layer_never_vetoes_kernel_verdicts() {
    let mut o = Oracle::spawn_signed("receipt-deparse");

    let overflow = r#"{"jsonrpc":"2.0","id":89,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","x":1e309}}}"#;
    let overflow_outcome = LeanHost::new()
        .classify(overflow)
        .expect("classify seam healthy in host-path test");
    println!(
        "overflow-number classifier outcome: {} ({overflow_outcome})",
        match overflow_outcome {
            1 => "mediate",
            2 => "refuse",
            _ => "unexpected",
        }
    );
    assert!(
        matches!(overflow_outcome, 1 | 2),
        "overflow-number classifier must fail closed (allowed: refuse=2, mediate=1; observed {overflow_outcome})"
    );

    // Recut 2026-07-31: the former divergent vector of this test — the
    // parser-boundary case `str-lone-high-surrogate` — is wire-refused by the
    // unpaired-surrogate-escape guard. Pin the new boundary: refused before
    // the kernel, never offered an approval target.
    let surrogate = r#"{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","x":"\ud800"}}}"#;
    assert_eq!(
        LeanHost::new()
            .classify(surrogate)
            .expect("classify seam healthy on the surrogate line"),
        2,
        "lone-surrogate line must wire-refuse under the seven-guard stack"
    );
    o.send(surrogate);
    let refused = o.expect_line();
    assert!(
        block_target(&refused).is_none(),
        "a wire-refused line must never be offered an approval target: {refused}"
    );

    // Closure pin 2: nesting past serde's recursion limit is still Lean-
    // mediated at the classify seam (the parser-boundary `nesting-125`
    // divergence lives), but the deployed host's byte-level depth bound
    // (`MAX_JSON_DEPTH = 64`) stops the line long before the kernel could
    // name an approval target: constant resource-limit response, nothing
    // forwarded. serde-unrecoverable ∧ host-admitted is therefore empty.
    let deep = format!("{}0{}", "[".repeat(125), "]".repeat(125));
    let divergent = format!(
        r#"{{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{{"name":"db.execute","arguments":{{"database":"prod","sql":"drop table accounts","x":{deep}}}}}}}"#
    );
    let divergent = divergent.as_str();
    assert_eq!(
        LeanHost::new()
            .classify(divergent)
            .expect("classify seam healthy on the deep-nesting line"),
        1,
        "deep-nesting divergent line is still kernel-mediated at the classify seam"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(divergent).is_err(),
        "deep-nesting divergent line must stay serde-unrecoverable"
    );
    o.send(divergent);
    let limited = o.expect_line();
    assert!(
        limited.contains("\"code\":-32001"),
        "over-deep line must get the constant resource-limit response: {limited}"
    );
    assert!(
        block_target(&limited).is_none(),
        "a resource-limited line must never be offered an approval target: {limited}"
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
    assert_eq!(
        last["framed_subject_sha256"],
        hex::encode(sha2::Sha256::digest(format!("{parseable}\n").as_bytes()))
    );
    assert_eq!(last["framed_subject_length"], parseable.len() + 1);
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

/// Stage A requires guarded approvals to bind the full canonical arguments.
/// Adding any sibling argument therefore changes the target, including nested
/// object/array values. This exercises that binding through the real host path
/// and confirms that each distinct argument set needs its own approval.
#[test]
fn approval_target_binds_every_argument_key() {
    let mut o = Oracle::spawn_signed("target-binds-siblings");

    // Clean guarded call: {database:"prod", sql:"drop table accounts"}.
    let clean = guarded_call(90, "drop table accounts");
    o.send(&clean);
    let t_clean = block_target(&o.expect_line()).expect("clean call names its approval target");

    // Variant A — a scalar sibling.
    let scalar_sibling = r#"{"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","x":7}}}"#;
    o.send(scalar_sibling);
    let t_scalar =
        block_target(&o.expect_line()).expect("scalar-sibling call names its approval target");

    // Variant B — a structurally different sibling: a nested object holding an
    // array and further nesting. Exercises the property past a single token.
    let nested_sibling = r#"{"jsonrpc":"2.0","id":92,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","meta":{"tags":["a","b"],"nested":{"deep":true,"n":7}}}}}"#;
    o.send(nested_sibling);
    let t_nested =
        block_target(&o.expect_line()).expect("nested-sibling call names its approval target");

    assert_ne!(
        t_clean, t_scalar,
        "a scalar sibling key must change the full-arguments approval target"
    );
    assert_ne!(
        t_clean, t_nested,
        "a nested object/array sibling key must change the full-arguments approval target"
    );
    assert_ne!(
        t_scalar, t_nested,
        "distinct sibling values must have distinct full-arguments targets"
    );

    // Non-vacuous end-to-end: an approval for the clean target does not
    // authorise the scalar variant.
    o.send(&clean);
    assert!(is_block(&o.expect_line()));
    o.approve_v2(&t_clean, format!("{clean}\n").as_bytes(), "n-target-clean");
    o.send(scalar_sibling);
    assert!(
        is_block(&o.expect_line()),
        "clean-target approval must not authorise a scalar-sibling variant"
    );

    // Each variant forwards only with its own target.
    o.approve_v2(
        &t_scalar,
        format!("{scalar_sibling}\n").as_bytes(),
        "n-target-scalar",
    );
    o.send(scalar_sibling);
    assert_line_forwarded_with_operation_id(&o.expect_line(), scalar_sibling);
    o.send(nested_sibling);
    assert!(is_block(&o.expect_line()));
    o.approve_v2(
        &t_nested,
        format!("{nested_sibling}\n").as_bytes(),
        "n-target-nested",
    );
    o.send(nested_sibling);
    assert_line_forwarded_with_operation_id(&o.expect_line(), nested_sibling);
}

/// P2-c observability tap, recut 2026-07-31 to the seven-guard boundary. The
/// forced reduced-scope forward (an ALLOW whose wire line serde cannot
/// recover) is no longer wire-reachable: lone surrogates wire-refuse
/// pre-parse, and any nesting deep enough to defeat serde is stopped by the
/// host's depth bound (`MAX_JSON_DEPTH = 64`) before mediation. This test
/// pins that BOTH closure responses stay signal-silent — the downgrade
/// counter must never tick for a line that was never forwarded — and that a
/// normal parseable ALLOW forwards verbatim, also silent. The signal
/// emitter itself keeps line-escape unit coverage in `src/main.rs`.
#[test]
fn reduced_scope_forward_attempt_emits_observability_signal() {
    let mut o = Oracle::spawn_signed("reduced-scope-signal");

    // Closed class 1: lone surrogate escape — wire-refused pre-parse.
    let surrogate = r#"{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","x":"\ud800"}}}"#;
    o.send(surrogate);
    let refused = o.expect_line();
    assert!(
        block_target(&refused).is_none(),
        "wire-refused line must not be offered an approval target: {refused}"
    );

    // Closed class 2: nesting past serde's limit — host resource-limited.
    let deep = format!("{}0{}", "[".repeat(125), "]".repeat(125));
    let divergent = format!(
        r#"{{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{{"name":"db.execute","arguments":{{"database":"prod","sql":"drop table accounts","x":{deep}}}}}}}"#
    );
    o.send(&divergent);
    let limited = o.expect_line();
    assert!(
        limited.contains("\"code\":-32001"),
        "over-deep line must get the constant resource-limit response: {limited}"
    );

    // Neither closure emits the downgrade signal: nothing was forwarded.
    let stray = o
        .drain_stderr(Duration::from_millis(400))
        .into_iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
        .any(|v| v["event"] == "reduced_scope_forward_attempt");
    assert!(
        !stray,
        "a refused or resource-limited line must not tick the downgrade counter"
    );

    // A normal PARSEABLE ALLOW must NOT emit the signal (fires only on downgrade).
    let parseable = guarded_call(91, "drop table accounts");
    o.send(&parseable);
    let t2 = block_target(&o.expect_line()).expect("parseable guarded call blocks");
    o.approve_v2(
        &t2,
        format!("{parseable}\n").as_bytes(),
        "n-reduced-parseable",
    );
    o.send(&parseable);
    assert_line_forwarded_with_operation_id(&o.expect_line(), &parseable);
    let no_signal = o
        .drain_stderr(Duration::from_millis(400))
        .into_iter()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(&l).ok())
        .any(|v| v["event"] == "reduced_scope_forward_attempt");
    assert!(
        !no_signal,
        "a parseable ALLOW must not emit the reduced-scope signal"
    );
}

// ---------------------------------------------------------------------------
// G2 cut (a) crash suite — two-phase approval burn (ruled by Ben 2026-08-06).
// The host process is genuinely killed (abort at an env-armed crash point),
// never "simulated" by calling recovery in-process.

/// Every `nonces` row as (nonce, committed_at): `None` = open hold (reserved,
/// not RECORDED), `Some(_)` = committed burn.
fn replay_rows(o: &Oracle) -> Vec<(String, Option<i64>)> {
    let conn = rusqlite::Connection::open(o.dir.join("replay.sqlite")).unwrap();
    let mut stmt = conn
        .prepare("SELECT nonce, committed_at FROM nonces ORDER BY nonce")
        .unwrap();
    let rows = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    rows
}

/// G2 T1 — crash between reserve and RECORDED. The host dies (SIGABRT) after
/// the kernel ALLOW but before the authorization decision persists. The
/// crashed window must leave NO receipt and a reclaimable hold; after a clean
/// restart the byte-identical token is usable again.
#[test]
fn g2_t1_crash_between_reserve_and_recorded_recovers_the_approval() {
    let mut o =
        Oracle::spawn_signed_with_env("g2-t1", &[("SEAL_TEST_CRASH_POINT", "g2-before-record")]);
    let call = guarded_call(211, "drop table g2_t1");
    o.send(&call);
    let blocked = o.expect_line();
    let _ = o.expect_raw();
    assert!(is_block(&blocked));
    let target = block_target(&blocked).expect("block names its approval target");
    let framed = block_framed_subject(&blocked).expect("block emits its framed subject");

    let decisions_before = o.receipts().len();
    o.approve_v2(&target, &framed, "n-g2-t1");
    println!(
        "T1 state before crash send: replay_rows={:?} decisions={decisions_before}",
        replay_rows(&o)
    );

    o.send(&call);
    let status = o.child.wait().unwrap();
    println!("T1 kill: host process exited {status:?} at crash point g2-before-record");
    assert!(
        !status.success(),
        "the host must actually die at the crash point"
    );

    let rows = replay_rows(&o);
    println!(
        "T1 state after crash: replay_rows={rows:?} decisions={}",
        o.receipts().len()
    );
    assert_eq!(
        rows,
        vec![("n-g2-t1".to_string(), None)],
        "the crash window holds a reservation, never a committed burn"
    );
    assert_eq!(
        o.receipts().len(),
        decisions_before,
        "no RECORDED receipt exists for the crashed ALLOW"
    );

    // Clean restart on the same state: startup recovery reclaims the hold.
    o.restart_with_env(&[]);
    o.send(&call);
    let challenged = o.expect_line();
    let _ = o.expect_raw();
    assert!(
        is_block(&challenged),
        "fresh approval challenge after restart"
    );
    assert_eq!(
        replay_rows(&o),
        vec![],
        "recovery reclaimed the unrecorded hold: state as if never presented"
    );

    // Byte-identical re-presentation of the SAME signed token (same nonce).
    // The recovered approval forwards; the mediated frame is the approved
    // bytes plus exactly the one reserved operation_id member.
    o.approve_v2(&target, &framed, "n-g2-t1");
    o.send(&call);
    let raw_id = assert_forwarded_with_operation_id(&o.expect_raw(), &framed);
    let line_id = assert_line_forwarded_with_operation_id(&o.expect_line(), &call);
    assert_eq!(raw_id, line_id);
    let rows = replay_rows(&o);
    println!(
        "T1 state after recovery + reuse: replay_rows={rows:?} decisions={}",
        o.receipts().len()
    );
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].1.is_some(),
        "this time the burn committed at RECORDED"
    );
}

/// G2 T2 — double-spend blocked while the reservation is OPEN. Two
/// byte-identical tokens enter the same poll: the first takes the durable
/// hold, the second drops as `replayed_nonce` in `a3.filter`, which runs
/// strictly BEFORE the kernel step and therefore before any commit — the
/// refusal comes from the open hold, not from a burn. (The pure-store shape
/// of the same property, with no commit ever, is
/// `a3::tests::second_presentation_fails_while_reservation_open`.)
#[test]
fn g2_t2_second_presentation_fails_while_reservation_open() {
    let mut o = Oracle::spawn_signed("g2-t2");
    let call = guarded_call(221, "drop table g2_t2");
    o.send(&call);
    let blocked = o.expect_line();
    let _ = o.expect_raw();
    assert!(is_block(&blocked));
    let target = block_target(&blocked).unwrap();
    let framed = block_framed_subject(&blocked).unwrap();

    o.approve_v2(&target, &framed, "n-g2-dup");
    o.approve_v2(&target, &framed, "n-g2-dup"); // identical second presentation
    o.send(&call);
    // Exactly one forward: the approved bytes plus the one operation_id member.
    let raw_id = assert_forwarded_with_operation_id(&o.expect_raw(), &framed);
    let line_id = assert_line_forwarded_with_operation_id(&o.expect_line(), &call);
    assert_eq!(raw_id, line_id);
    let stderr = o.drain_stderr(Duration::from_millis(300));
    assert!(
        stderr.iter().any(|l| l.contains("replayed_nonce")),
        "second presentation must drop while the first holds an open reservation: {stderr:?}"
    );
    let rows = replay_rows(&o);
    println!("T2 state after single forward: replay_rows={rows:?}");
    assert_eq!(rows.len(), 1, "one hold total, no second row");
    assert!(rows[0].1.is_some(), "the consumed approval committed");

    o.send(&call);
    assert!(
        is_block(&o.expect_line()),
        "the burned approval cannot fire a second forward"
    );
}

/// G2 T3 — crash AFTER RECORDED, before the child write. Receipt persisted,
/// burn committed, process killed. Recovery must NOT un-burn the used
/// approval (that would be a worse defect than the one this lane fixes);
/// the receipt must survive; re-presenting the token is a replay.
#[test]
fn g2_t3_crash_after_recorded_keeps_burn_and_receipt() {
    let mut o =
        Oracle::spawn_signed_with_env("g2-t3", &[("SEAL_TEST_CRASH_POINT", "g2-after-burn")]);
    let call = guarded_call(231, "drop table g2_t3");
    o.send(&call);
    let blocked = o.expect_line();
    let _ = o.expect_raw();
    assert!(is_block(&blocked));
    let target = block_target(&blocked).unwrap();
    let framed = block_framed_subject(&blocked).unwrap();

    let decisions_before = o.receipts().len();
    o.approve_v2(&target, &framed, "n-g2-t3");
    o.send(&call);
    let status = o.child.wait().unwrap();
    println!("T3 kill: host process exited {status:?} at crash point g2-after-burn");
    assert!(!status.success());
    assert!(
        o.lines.recv_timeout(Duration::from_secs(2)).is_err(),
        "no forward escaped before the crash"
    );

    let rows = replay_rows(&o);
    println!(
        "T3 state after crash: replay_rows={rows:?} decisions={}",
        o.receipts().len()
    );
    assert_eq!(rows.len(), 1);
    assert!(rows[0].1.is_some(), "the burn committed at RECORDED");
    assert_eq!(
        o.receipts().len(),
        decisions_before + 1,
        "the RECORDED receipt survives the crash"
    );

    o.restart_with_env(&[]);
    // The crash landed after RECORDED: the durable receipt is fresh PENDING
    // release authority, so startup recovery resumes the release exactly once
    // and it must be the approved bytes plus the one operation_id member —
    // the reservation is FINISHED from the receipt, never re-spent.
    let recovered_line = o.expect_line();
    let recovered_raw = o.expect_raw();
    let raw_id = assert_forwarded_with_operation_id(&recovered_raw, &framed);
    let line_id = assert_line_forwarded_with_operation_id(&recovered_line, &call);
    assert_eq!(raw_id, line_id);
    o.send(&call);
    let challenged = o.expect_line();
    let _ = o.expect_raw();
    assert!(is_block(&challenged));
    let rows = replay_rows(&o);
    assert_eq!(rows.len(), 1, "recovery must not un-burn a committed nonce");
    assert!(rows[0].1.is_some());

    o.approve_v2(&target, &framed, "n-g2-t3"); // byte-identical re-presentation
    o.send(&call);
    assert!(
        is_block(&o.expect_line()),
        "a burned approval stays burned across restart"
    );
    let stderr = o.drain_stderr(Duration::from_millis(300));
    assert!(
        stderr.iter().any(|l| l.contains("replayed_nonce")),
        "the re-presented token must be refused as a replay: {stderr:?}"
    );
    println!(
        "T3 state after restart + replay attempt: replay_rows={:?} decisions={}",
        replay_rows(&o),
        o.receipts().len()
    );
}

/// G2 residual — a real process crash after RECORDED and before nonce commit.
#[test]
fn g2_crash_after_recorded_before_commit_reconciles_burn() {
    let mut o = Oracle::spawn_signed_with_env(
        "g2-after-record",
        &[("SEAL_TEST_CRASH_POINT", "g2-after-record")],
    );
    let call = guarded_call(241, "drop table g2_after_record");
    o.send(&call);
    let blocked = o.expect_line();
    let _ = o.expect_raw();
    assert!(is_block(&blocked));
    let target = block_target(&blocked).unwrap();
    let framed = block_framed_subject(&blocked).unwrap();

    let decisions_before = o.receipts().len();
    o.approve_v2(&target, &framed, "n-g2-after-record");
    o.send(&call);
    let status = o.child.wait().unwrap();
    println!("G2 after-record kill: host process exited {status:?} at crash point g2-after-record");
    assert!(!status.success());

    let rows = replay_rows(&o);
    println!(
        "G2 after-record state after crash: replay_rows={rows:?} decisions={}",
        o.receipts().len()
    );
    assert_eq!(
        rows,
        vec![("n-g2-after-record".to_string(), None)],
        "the receipt exists but the reserved hold must still be open"
    );
    assert_eq!(
        o.receipts().len(),
        decisions_before + 1,
        "the RECORDED receipt survives the crash"
    );

    o.restart_with_env(&[]);
    let recovered_line = o.expect_line();
    let recovered_raw = o.expect_raw();
    let raw_id = assert_forwarded_with_operation_id(&recovered_raw, &framed);
    let line_id = assert_line_forwarded_with_operation_id(&recovered_line, &call);
    assert_eq!(raw_id, line_id);
    let rows = replay_rows(&o);
    println!(
        "G2 after-record state after restart: replay_rows={rows:?} decisions={}",
        o.receipts().len()
    );
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].1.is_some(),
        "recovery must commit the receipt-backed hold"
    );

    o.send(&call);
    let challenged = o.expect_line();
    let _ = o.expect_raw();
    assert!(is_block(&challenged));
    o.approve_v2(&target, &framed, "n-g2-after-record");
    o.send(&call);
    assert!(
        is_block(&o.expect_line()),
        "the approval must remain burned after restart"
    );
    let stderr = o.drain_stderr(Duration::from_millis(300));
    assert!(
        stderr.iter().any(|l| l.contains("replayed_nonce")),
        "the re-presented approval must be refused as a replay: {stderr:?}"
    );
    println!(
        "G2 after-record state after replay attempt: replay_rows={:?} decisions={} stderr_has_replayed_nonce=true",
        replay_rows(&o),
        o.receipts().len()
    );
}
