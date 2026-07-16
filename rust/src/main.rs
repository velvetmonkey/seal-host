// SPDX-License-Identifier: Apache-2.0
//! seal-host-rs — the Rust transport host around the Lean verified core.
//!
//! Owns: stdio MITM, child server process, approval back-channel providers,
//! A3 freshness, evidence file reads, the wall clock. Does NOT own any
//! decision: every line is classified and decided by the Lean exports
//! (`seal_host_step`), and this host only routes bytes accordingly.
//!
//! # Path inventory (source → sink → mediated?)
//!
//! | # | Source                    | Sink                                   | Mediated? |
//! |---|---------------------------|----------------------------------------|-----------|
//! | P1| stdin line (hostile)      | `child_in.write_all` (classify path)   | YES — `seal_host_classify == 0`, literal-only mapping (`route_of_classify`); Lean panic exits the process (never a routable default) |
//! | P2| stdin line                | `child_in.write_all` (step path)       | YES — `seal_host_step` route `forward`, exact parse (`route_of_step_output`) |
//! | P3| stdin line                | `child_in.write_all` (interactive retry)| YES — second `seal_host_step == forward` after a human-minted approval |
//! | P4| operator argv             | `Command::new(...).spawn()`            | N/A — operator-trusted setup; the child IS the guarded resource |
//! | P5| kernel block response     | client stdout                          | YES — kernel-authored bytes |
//! | P6| child stdout              | client stdout (relay thread)           | NO — response egress is unmediated BY DESIGN (requests are mediated, responses are not; see RUST_BRIDGE.md) |
//! | P7| audit / A3 drops / errors | stderr                                 | telemetry only, no effect |
//! | P8| approval evidence         | (feeds Lean via A3 only)               | parse failure drops the record ⇒ deny |
//! | P9| votes/grants/forecasts    | (raw text to Lean)                     | Lean parses; grants cursor line-split is drop-only |
//!
//! Enforced invariant: bytes reach the child ⇔ the Lean kernel returned
//! classify == 0 or step route == forward for the
//! byte-identical line. Every seam error, panic, or ambiguity refuses the
//! line and answers the client with `SEAM_ERROR_RESPONSE` — the only
//! host-authored egress bytes.
//!
//! The wire bytes the client sent are forwarded VERBATIM on allow — the host
//! never reconstructs, re-encodes, or trims what the child receives.

use seal_host_rs::a3;
use seal_host_rs::decision_receipt::{
    request_parts, sha256_hex, ApprovalIdentity, DecisionInput, ReceiptWriter, SignedConfig,
};
use seal_host_rs::lean;
use seal_host_rs::providers::{self, ApprovalProvider};
use seal_host_rs::receipt::ReceiptChain;
use seal_host_rs::replay_store::SqliteReplayStore;
use seal_host_rs::route::{
    route_of_classify, route_of_step_output, ClassifyRoute, Route, SEAM_ERROR_RESPONSE,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The active back-channel. Enum (not a trait object) so the transport can
/// reach the interactive provider's queue without downcasting.
enum Channel {
    File(providers::ControlFileProvider),
    Ed(providers::Ed25519TokenProvider),
    Tty(providers::InteractiveProvider<std::io::BufReader<std::fs::File>, std::io::Stderr>),
}

impl Channel {
    fn poll(&mut self) -> providers::ApprovalPoll {
        match self {
            Channel::File(p) => p.poll(),
            Channel::Ed(p) => p.poll(),
            Channel::Tty(p) => p.poll(),
        }
    }

    fn queue_interactive(&mut self, target: String) -> bool {
        if let Channel::Tty(p) = self {
            p.queue(target);
            true
        } else {
            false
        }
    }
}
use std::io::{BufRead, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

struct Args {
    config: String,
    pubkey: String,
    channel: String,
    token_file: Option<String>,
    approval_pubkey: Option<String>,
    receipt_dir: Option<String>,
    cmd: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut config = None;
    let mut pubkey = None;
    let mut channel = "file".to_string();
    let mut token_file = None;
    let mut approval_pubkey = None;
    let mut receipt_dir = None;
    let mut cmd = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--config" => {
                config = argv.get(i + 1).cloned();
                i += 2
            }
            "--pubkey" => {
                pubkey = argv.get(i + 1).cloned();
                i += 2
            }
            "--channel" => {
                channel = argv.get(i + 1).cloned().unwrap_or_default();
                i += 2
            }
            "--token-file" => {
                token_file = argv.get(i + 1).cloned();
                i += 2
            }
            "--approval-pubkey" => {
                approval_pubkey = argv.get(i + 1).cloned();
                i += 2
            }
            "--receipt-dir" => {
                receipt_dir = argv.get(i + 1).cloned();
                i += 2
            }
            "--" => {
                cmd = argv[i + 1..].to_vec();
                break;
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        config: config.ok_or("--config required")?,
        pubkey: pubkey.ok_or("--pubkey required")?,
        channel,
        token_file,
        approval_pubkey,
        receipt_dir,
        cmd: if cmd.is_empty() {
            return Err("server command required after --".into());
        } else {
            cmd
        },
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn extract_target_hex(s: &str) -> Option<String> {
    let target: String = s.chars().take(64).collect();
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

fn read_or_empty(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        std::fs::read_to_string(path).unwrap_or_default()
    }
}

fn same_ed25519_key_hex(left: &str, right: &str) -> bool {
    match (hex::decode(left), hex::decode(right)) {
        (Ok(left), Ok(right)) => left.len() == 32 && right.len() == 32 && left == right,
        _ => false,
    }
}

fn approval_key_id(public_key_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(public_key_hex).map_err(|e| format!("bad approval public key: {e}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn signed_config_from_envelope(
    envelope: &str,
    pubkey: &str,
) -> Result<(Value, SignedConfig), String> {
    let envelope_json: Value =
        serde_json::from_str(envelope).map_err(|e| format!("bad envelope JSON: {e}"))?;
    let payload = envelope_json
        .get("payload")
        .and_then(Value::as_str)
        .ok_or("missing string payload")?;
    let signature = envelope_json
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("missing string signature")?;
    let kernel_config =
        serde_json::from_str(payload).map_err(|e| format!("bad payload JSON: {e}"))?;
    Ok((
        kernel_config,
        SignedConfig {
            payload: payload.to_owned(),
            signature: signature.to_owned(),
            pubkey: pubkey.to_owned(),
        },
    ))
}

fn default_receipt_dir(config_path: &str) -> std::path::PathBuf {
    std::path::Path::new(config_path)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("seal-receipts")
}

fn persist_decision(
    writer: &mut ReceiptWriter,
    input: DecisionInput<'_>,
) -> Result<Option<String>, ()> {
    match writer.persist(input) {
        Ok(receipt) => {
            eprintln!("{}", json!({"decision_receipt": receipt.path}));
            Ok(receipt.consumed_target)
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({"error": "receipt persistence failure", "detail": error})
            );
            Err(())
        }
    }
}

fn consume_pending_approval(records: &mut Vec<providers::ApprovalRecord>, target: Option<String>) {
    if let Some(target) = target {
        if let Some(index) = records.iter().position(|record| record.target == target) {
            records.remove(index);
        }
    }
}

fn replay_store_path_from_envelope(envelope: &str) -> Result<Option<String>, String> {
    let envelope_json: Value =
        serde_json::from_str(envelope).map_err(|e| format!("bad envelope JSON: {e}"))?;
    let payload_text = envelope_json
        .get("payload")
        .and_then(Value::as_str)
        .ok_or("missing string payload")?;
    let payload_json: Value =
        serde_json::from_str(payload_text).map_err(|e| format!("bad payload JSON: {e}"))?;
    let Some(replay_store) = payload_json.pointer("/safety/approval/replay_store") else {
        return Ok(None);
    };
    if replay_store.is_null() {
        return Ok(None);
    }
    let obj = replay_store
        .as_object()
        .ok_or("safety.approval.replay_store must be an object")?;
    let path = obj
        .get("sqlite_path")
        .and_then(Value::as_str)
        .ok_or("safety.approval.replay_store.sqlite_path must be a string")?;
    if path.is_empty() {
        return Err("safety.approval.replay_store.sqlite_path must be non-empty".to_string());
    }
    Ok(Some(path.to_string()))
}

struct GrantsCursor {
    path: String,
    seen: usize,
}

impl GrantsCursor {
    /// Fresh grant lines since the last poll (Lean ingests grants
    /// unconditionally, so each line must cross the seam exactly once).
    fn fresh(&mut self) -> String {
        if self.path.is_empty() {
            return String::new();
        }
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return String::new();
        };
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let fresh = lines[self.seen.min(lines.len())..].join("\n");
        self.seen = lines.len();
        fresh
    }
}

fn write_locked(lock: &Mutex<()>, line: &str) {
    let _g = lock.lock().unwrap();
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

fn emit_audit(receipts: &mut ReceiptChain, audit: &str) {
    eprintln!("{audit}");
    eprintln!("{}", receipts.observe(audit).to_json_line());
}

/// Render one dropped-approval warning as a single audit line. The reason holds
/// up to 64 ATTACKER-CHOSEN chars from an unauthenticated control-file channel;
/// `json!()` string-escaping is the ONLY control that stops those bytes forging a
/// second audit line (quote-breaking, newline injection, ANSI smuggling). Kept as
/// a named fn so a regression test can pin the escaping — swapping this for a
/// `format!()` would silently kill it, and T4's whole point is that it must not.
fn approval_drop_line(w: &providers::ApprovalDropWarning) -> String {
    json!({
        "approval_drop": {
            "source": w.source,
            "reason": w.reason,
            "record_id": w.record_id,
            "counter": w.counter
        }
    })
    .to_string()
}

fn emit_approval_drop_warnings(warnings: &[providers::ApprovalDropWarning]) {
    for w in warnings {
        eprintln!("{}", approval_drop_line(w));
    }
}

/// The P2-c observability signal for a FORCED reduced-scope forward: an ALLOW
/// whose wire line `request_parts` cannot recover (whole-line serde failure — the
/// `1e309` / argless / non-object-args class). Returns `None` for a normal
/// parseable ALLOW, so the signal fires ONLY on the reduced-scope condition; the
/// reduced-scope test hook is `request_parts` itself, the SAME function the
/// receipt writer uses, so the signal's condition is identical to the receipt's
/// by construction. `count` is the running total of forced downgrades this
/// session (burst visibility).
///
/// `parse_error` and `tool_hint` can carry ATTACKER-CHOSEN bytes from the wire;
/// `json!()` string-escaping is the ONLY control that stops them forging a second
/// stderr line (quote-breaking, newline injection, ANSI smuggling). Kept as a
/// named fn so a regression test pins the escaping — swapping this for `format!()`
/// would silently kill it. Passive tap: reads only `line`, never `wire`, the
/// receipt, or the verdict.
fn reduced_scope_forward_line(line: &str, count: u64) -> Option<String> {
    let parse_error = match request_parts(line) {
        Ok(_) => return None,
        Err(error) => error,
    };
    // Best-effort tool hint: present only when the line is valid JSON carrying a
    // string `params.name` (the argless / non-object-args class); `null` when the
    // whole line is unparseable (the `1e309` class). Never fails the signal.
    let tool_hint = serde_json::from_str::<Value>(line.trim())
        .ok()
        .and_then(|value| {
            value
                .pointer("/params/name")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    Some(
        json!({
            "event": "reduced_scope_forward",
            "request_sha256": sha256_hex(line.as_bytes()),
            "parse_error": parse_error,
            "tool_hint": tool_hint,
            "count": count,
        })
        .to_string(),
    )
}

/// The Lean routing view of one wire line: the line terminator (`\n` or
/// `\r\n`) stripped. This framing strip is the ONLY transformation between
/// the client's bytes and what Lean judges; the bytes forwarded to the child
/// on allow are the client's original, terminator included.
fn lean_view(wire: &[u8]) -> &[u8] {
    let s = wire.strip_suffix(b"\n").unwrap_or(wire);
    s.strip_suffix(b"\r").unwrap_or(s)
}

fn main() {
    // Fail-closed panic policy, armed before the runtime exists and before
    // any thread spawns: a Lean panic must terminate the process, never
    // return a type default that could route (classify's default is 0 =
    // passthrough — a fail-open without this). Belt: env var (runtime
    // abort_on_panic). Braces: lean_set_exit_on_panic in LeanHost::new.
    std::env::set_var("LEAN_ABORT_ON_PANIC", "1");

    // Hidden probes for tests/panic_probe.rs: verify empirically that a Lean
    // panic kills the process under the production guard (and demonstrates
    // the fail-open default without it). Never used in normal operation.
    match std::env::args().nth(1).as_deref() {
        Some("--panic-probe") => {
            let host = lean::LeanHost::new();
            let v = host.force_panic_probe();
            // Reaching this line means the guard FAILED to kill the process.
            println!("SURVIVED {v}");
            std::process::exit(42);
        }
        Some("--panic-probe-unguarded") => {
            std::env::remove_var("LEAN_ABORT_ON_PANIC");
            let host = lean::LeanHost::new_with_panic_guard(false);
            let v = host.force_panic_probe();
            println!("SURVIVED {v}");
            std::process::exit(0);
        }
        _ => {}
    }

    std::process::exit(run());
}

fn run() -> i32 {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "usage: seal-host-rs --config <trusted.json> --pubkey <config-pubkey-hex> \
                [--channel file|ed25519|interactive] [--token-file <path>] \
                [--approval-pubkey <hex>] [--receipt-dir <path>] \
                -- <server-cmd> <args...>\nerror: {e}"
            );
            return 2;
        }
    };

    let host = lean::LeanHost::new();

    // Fail-closed: a rejected config aborts before any stdio is mediated.
    let envelope = match std::fs::read_to_string(&args.config) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("trusted config rejected: cannot read {}: {e}", args.config);
            return 3;
        }
    };
    let init_out = match host.init(&envelope, &args.pubkey) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("trusted config rejected: init seam failure: {e}");
            return 3;
        }
    };
    let summary: Value = match serde_json::from_str(&init_out) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("trusted config rejected: bad init response: {e}");
            return 3;
        }
    };
    if summary["ok"] != json!(true) {
        eprintln!(
            "trusted config rejected: {}",
            summary["error"].as_str().unwrap_or("unknown")
        );
        return 3;
    }
    let (kernel_config, signed_config) = match signed_config_from_envelope(&envelope, &args.pubkey)
    {
        Ok(value) => value,
        Err(e) => {
            eprintln!("trusted config rejected: {e}");
            return 3;
        }
    };
    let ttl_ms = summary["approval_ttl_ms"].as_u64().unwrap_or(0);
    let approval_file = summary["approval_file"].as_str().unwrap_or("").to_string();
    let votes_file = summary["votes_file"].as_str().unwrap_or("").to_string();
    let forecasts_file = summary["forecasts_file"].as_str().unwrap_or("").to_string();
    let replay_store_path = match replay_store_path_from_envelope(&envelope) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("trusted config rejected: replay store config: {e}");
            return 3;
        }
    };
    let mut grants = GrantsCursor {
        path: summary["grants_file"].as_str().unwrap_or("").to_string(),
        seen: 0,
    };

    let mut provider: Channel = match args.channel.as_str() {
        "file" => Channel::File(providers::ControlFileProvider::new(&approval_file)),
        "ed25519" => {
            let (Some(tf), Some(pk)) = (&args.token_file, &args.approval_pubkey) else {
                eprintln!("--channel ed25519 needs --token-file and --approval-pubkey");
                return 2;
            };
            if same_ed25519_key_hex(&args.pubkey, pk) {
                eprintln!(
                    "trusted config rejected: config signing key must differ from approval signing key"
                );
                return 3;
            }
            match providers::Ed25519TokenProvider::new(tf, pk) {
                Ok(p) => Channel::Ed(p),
                Err(e) => {
                    eprintln!("ed25519 channel: {e}");
                    return 2;
                }
            }
        }
        "interactive" => Channel::Tty(providers::InteractiveProvider::new(
            std::io::BufReader::new(std::fs::File::open("/dev/tty").unwrap_or_else(|e| {
                eprintln!("interactive channel needs a tty: {e}");
                std::process::exit(2);
            })),
            std::io::stderr(),
        )),
        other => {
            eprintln!("unknown channel: {other}");
            return 2;
        }
    };
    let approval_identity = ApprovalIdentity {
        channel: match args.channel.as_str() {
            "file" => "file",
            "interactive" => "interactive",
            "ed25519" => "ed25519",
            _ => unreachable!(),
        }
        .to_string(),
        key_id: if args.channel == "ed25519" {
            match approval_key_id(
                args.approval_pubkey
                    .as_deref()
                    .expect("validated approval key"),
            ) {
                Ok(key_id) => Some(key_id),
                Err(e) => {
                    eprintln!("ed25519 channel: {e}");
                    return 2;
                }
            }
        } else {
            None
        },
    };
    let receipt_dir = args
        .receipt_dir
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| default_receipt_dir(&args.config));
    let mut decision_receipts = match ReceiptWriter::new(&receipt_dir) {
        Ok(writer) => writer,
        Err(e) => {
            eprintln!("receipt sink rejected: {e}");
            return 4;
        }
    };
    let mut a3 = if args.channel == "ed25519" {
        let Some(path) = replay_store_path else {
            eprintln!(
                "trusted config rejected: ed25519 channel requires \
                safety.approval.replay_store.sqlite_path"
            );
            return 3;
        };
        let store = match SqliteReplayStore::open(&path) {
            Ok(store) => store,
            Err(e) => {
                eprintln!("trusted config rejected: cannot open replay store: {e}");
                return 3;
            }
        };
        match a3::A3Filter::with_store(ttl_ms, Box::new(store), now_ms()) {
            Ok(a3) => a3,
            Err(e) => {
                eprintln!("trusted config rejected: cannot load replay store: {e}");
                return 3;
            }
        }
    } else {
        a3::A3Filter::new(ttl_ms)
    };
    let mut receipts = ReceiptChain::new();
    let mut pending_approvals: Vec<providers::ApprovalRecord> = Vec::new();
    let interactive = args.channel == "interactive";

    let mut child = match Command::new(&args.cmd[0])
        .args(&args.cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot spawn server: {e}");
            return 2;
        }
    };
    let mut child_in = child.stdin.take().expect("child stdin");
    let mut child_out = child.stdout.take().expect("child stdout");

    let stdout_lock = Arc::new(Mutex::new(()));
    let relay_lock = stdout_lock.clone();
    let relay = std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            match child_out.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _g = relay_lock.lock().unwrap();
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(&buf[..n]);
                    let _ = out.flush();
                }
            }
        }
    });

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut wire: Vec<u8> = Vec::new();
    // P2-c observability: monotonic count of forced reduced-scope forwards, so a
    // BURST (the griefing pattern) is distinguishable from an occasional
    // legitimate unparseable call. Passive — never gates the forward.
    let mut reduced_scope_forwards: u64 = 0;
    loop {
        wire.clear();
        match reader.read_until(b'\n', &mut wire) {
            Ok(0) => break, // EOF: session over
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}", json!({"error": format!("stdin read error: {e}")}));
                break; // transport dead: stop mediating, kill child
            }
        }

        // The Lean view must be valid UTF-8 (Lean strings are UTF-8). A
        // non-UTF-8 line cannot be judged, so it cannot be forwarded:
        // refuse it and keep the session alive.
        let Ok(line) = std::str::from_utf8(lean_view(&wire)) else {
            eprintln!("{}", json!({"error": "non-utf8 line refused"}));
            write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
            continue;
        };
        let now = now_ms();

        // Pass non-mediated lines (initialize, tools/list, notifications)
        // straight through WITHOUT polling the approval channel. V1 reads the
        // control file only for tools/call; polling on passthrough lines would
        // advance the provider's seen-counter and consume an approval before
        // the mediated call that needs it ever sees it.
        //
        // `line` (the string judged here) is byte-identical to the "line"
        // field handed to `step` below — one binding, no rewrites.
        match route_of_classify(host.classify(line)) {
            ClassifyRoute::Passthrough => {
                let _ = child_in.write_all(&wire);
                let _ = child_in.flush();
                continue;
            }
            ClassifyRoute::Mediate => {}
            ClassifyRoute::Refuse => {
                eprintln!(
                    "{}",
                    json!({"error": "classify seam failure; line refused"})
                );
                write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
                continue;
            }
        }

        let poll = provider.poll();
        let mut warnings = poll.warnings;
        let (records, a3_warnings) = a3.filter(poll.records, now);
        pending_approvals.extend(records.iter().cloned());
        warnings.extend(a3_warnings);
        emit_approval_drop_warnings(&warnings);
        let declines = poll.declines;
        let approvals: Vec<Value> = records
            .iter()
            .map(|r| json!({"target": r.target, "issuedAt": r.issued_at}))
            .collect();

        let input = json!({
            "line": line,
            "now": now,
            "approvals": approvals,
            "votes": read_or_empty(&votes_file),
            "grants": grants.fresh(),
            "forecasts": read_or_empty(&forecasts_file),
        });
        let step_output = match host.step(&input.to_string()) {
            Ok(output) => output,
            Err(error) => {
                eprintln!("{}", json!({"error": format!("seam error: {error}")}));
                write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
                continue;
            }
        };
        match route_of_step_output(Ok(step_output.clone())) {
            Route::Forward { audit } => {
                if let Some(a) = audit {
                    emit_audit(&mut receipts, &a);
                }
                let consumed = match persist_decision(
                    &mut decision_receipts,
                    DecisionInput {
                        line,
                        now,
                        emitted_bytes: &step_output,
                        kernel_config: &kernel_config,
                        signed_config: &signed_config,
                        approvals: &pending_approvals,
                        approval_identity: &approval_identity,
                        approval_ttl_ms: ttl_ms,
                    },
                ) {
                    Ok(consumed) => consumed,
                    Err(()) => {
                        write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
                        continue;
                    }
                };
                consume_pending_approval(&mut pending_approvals, consumed);
                // P2-c passive observability tap: an ALLOW forwarded with an
                // UNRECOVERABLE request (reduced-scope receipt) is a forced
                // downgrade an operator must be able to see and count. Emitted
                // BEFORE the forward but reads only `line` — it never touches
                // `wire`, the receipt, or the verdict, so the forward stays
                // byte-identical with or without it.
                if let Some(signal) = reduced_scope_forward_line(line, reduced_scope_forwards + 1) {
                    reduced_scope_forwards += 1;
                    eprintln!("{signal}");
                }
                let _ = child_in.write_all(&wire);
                let _ = child_in.flush();
            }
            Route::Block {
                mut response,
                audit,
            } => {
                if let Some(a) = audit {
                    emit_audit(&mut receipts, &a);
                }
                if persist_decision(
                    &mut decision_receipts,
                    DecisionInput {
                        line,
                        now,
                        emitted_bytes: &step_output,
                        kernel_config: &kernel_config,
                        signed_config: &signed_config,
                        approvals: &pending_approvals,
                        approval_identity: &approval_identity,
                        approval_ttl_ms: ttl_ms,
                    },
                )
                .is_err()
                {
                    write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
                    continue;
                }

                // Explicit signed decline short-circuit (first-class deny):
                // if a decline for the target (from this poll) is present on
                // an approval-required block, emit "refused" (not "timed out"
                // or plain deny) + host audit label. The decline itself is
                // host-layer (not a Lean Event). This is the signed origin
                // path; see docs for TCB and "what this proves".
                if let Some(target) = response
                    .split("approval required: ")
                    .nth(1)
                    .and_then(extract_target_hex)
                {
                    if declines.iter().any(|d| d.target == target) {
                        let refused_audit =
                            format!("approval refused: {} (explicit signed decline)", target);
                        emit_audit(&mut receipts, &refused_audit);
                        let refused = format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":-32000,\"message\":\"seal-host: approval refused (signed decline for target {})\"}}}}\n",
                            target
                        );
                        write_locked(&stdout_lock, &refused);
                        continue;
                    }
                }

                // Interactive channel: a missing-approval deny queues a human
                // question; a "y" mints the approval and the call retries once.
                // The target is parsed from the KERNEL's response text (never
                // from raw input); a failed parse means no retry — the line
                // stays blocked.
                if interactive {
                    if let Some(target) = response
                        .split("approval required: ")
                        .nth(1)
                        .and_then(extract_target_hex)
                    {
                        provider.queue_interactive(target);
                        let poll = provider.poll();
                        let mut warnings = poll.warnings;
                        // Fresh clock: the interactive poll blocks on the TTY, so the
                        // approval's issued_at is answer-time. Filtering with the `now`
                        // captured at line arrival dropped any approval minted >5s
                        // (MAX_FUTURE_SKEW_MS) after the line arrived as future_issued_at.
                        let (records, a3_warnings) = a3.filter(poll.records, now_ms());
                        pending_approvals.extend(records.iter().cloned());
                        warnings.extend(a3_warnings);
                        emit_approval_drop_warnings(&warnings);
                        if !records.is_empty() {
                            let approvals: Vec<Value> = records
                                .iter()
                                .map(|r| json!({"target": r.target, "issuedAt": r.issued_at}))
                                .collect();
                            let retry = json!({
                                "line": line, "now": now_ms(), "approvals": approvals,
                                "votes": read_or_empty(&votes_file),
                                "grants": grants.fresh(),
                                "forecasts": read_or_empty(&forecasts_file),
                            });
                            let retry_now = retry["now"].as_u64().unwrap_or(0);
                            let retry_output = match host.step(&retry.to_string()) {
                                Ok(output) => output,
                                Err(error) => {
                                    eprintln!(
                                        "{}",
                                        json!({"error": format!("seam error: {error}")})
                                    );
                                    write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
                                    continue;
                                }
                            };
                            match route_of_step_output(Ok(retry_output.clone())) {
                                Route::Forward { audit } => {
                                    if let Some(a) = audit {
                                        emit_audit(&mut receipts, &a);
                                    }
                                    let consumed = match persist_decision(
                                        &mut decision_receipts,
                                        DecisionInput {
                                            line,
                                            now: retry_now,
                                            emitted_bytes: &retry_output,
                                            kernel_config: &kernel_config,
                                            signed_config: &signed_config,
                                            approvals: &pending_approvals,
                                            approval_identity: &approval_identity,
                                            approval_ttl_ms: ttl_ms,
                                        },
                                    ) {
                                        Ok(consumed) => consumed,
                                        Err(()) => {
                                            write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
                                            continue;
                                        }
                                    };
                                    consume_pending_approval(&mut pending_approvals, consumed);
                                    let _ = child_in.write_all(&wire);
                                    let _ = child_in.flush();
                                    continue;
                                }
                                Route::Block {
                                    response: r2,
                                    audit,
                                } => {
                                    if let Some(a) = audit {
                                        emit_audit(&mut receipts, &a);
                                    }
                                    if persist_decision(
                                        &mut decision_receipts,
                                        DecisionInput {
                                            line,
                                            now: retry_now,
                                            emitted_bytes: &retry_output,
                                            kernel_config: &kernel_config,
                                            signed_config: &signed_config,
                                            approvals: &pending_approvals,
                                            approval_identity: &approval_identity,
                                            approval_ttl_ms: ttl_ms,
                                        },
                                    )
                                    .is_err()
                                    {
                                        write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
                                        continue;
                                    }
                                    response = r2;
                                }
                                Route::SeamFailure { reason } => {
                                    eprintln!("{}", json!({"error": reason}));
                                    response = SEAM_ERROR_RESPONSE.to_string();
                                }
                            }
                        }
                    }
                }
                write_locked(&stdout_lock, &response);
            }
            Route::SeamFailure { reason } => {
                eprintln!("{}", json!({"error": reason}));
                write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
            }
        }
    }

    let _ = child.kill();
    let code = child.wait().map(|s| s.code().unwrap_or(0)).unwrap_or(0);
    let _ = relay.join();
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    /// T4 (audit-stream injection): a dropped-approval warning carries up to 64
    /// attacker-chosen chars from an unauthenticated channel. `json!()` escaping
    /// at the emission site is the ONLY control that stops those bytes forging a
    /// second audit line. This pins that control: a reason packed with the exact
    /// smuggling payloads (quote-break, CR/LF newline forge, ANSI escape, NUL)
    /// must render as a SINGLE line that round-trips as JSON with the reason
    /// intact. Swap `json!()` for `format!()` in `approval_drop_line` and this
    /// goes RED — which is the whole point (the escaping cannot die silently).
    #[test]
    fn approval_drop_line_escapes_hostile_reason_no_second_audit_line() {
        // Everything an attacker would use to break out of the reason field.
        let hostile =
            "\"}\n{\"approval_drop\":{\"reason\":\"FORGED\"}}\r\n\u{1b}[31mred\u{1b}[0m\u{0000}end";
        let w = providers::ApprovalDropWarning {
            source: "control_file",
            reason: format!("unknown_decision:{hostile}"),
            record_id: "sha256:deadbeef".into(),
            counter: 1,
        };
        let line = approval_drop_line(&w);

        // 1. Exactly one physical line — no raw newline forged a second record.
        assert_eq!(
            line.lines().count(),
            1,
            "hostile reason forged a newline: {line:?}"
        );
        assert!(
            !line.contains('\n') && !line.contains('\r'),
            "raw CR/LF survived escaping: {line:?}"
        );

        // 2. It is valid JSON and the reason round-trips byte-for-byte (escaping
        //    is lossless, not truncating/stripping).
        let parsed: serde_json::Value =
            serde_json::from_str(&line).expect("escaped line must parse as JSON");
        assert_eq!(
            parsed["approval_drop"]["reason"].as_str().unwrap(),
            w.reason,
            "reason did not round-trip through escaping"
        );

        // 3. The injected inner object is inert text inside the reason string, not
        //    a structural sibling — there is exactly one approval_drop object.
        assert!(parsed["approval_drop"]["source"] == "control_file");
        assert!(parsed.get("approval_drop").is_some() && parsed.as_object().unwrap().len() == 1);
    }

    /// P2-c signal, unit half: `reduced_scope_forward_line` fires EXACTLY on the
    /// unrecoverable-request condition and is silent on a normal parseable ALLOW.
    #[test]
    fn reduced_scope_forward_line_fires_only_on_unrecoverable_request() {
        // Parseable guarded call → no signal (a normal ALLOW must stay silent).
        let parseable = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table t"}}}"#;
        assert!(
            reduced_scope_forward_line(parseable, 1).is_none(),
            "a parseable ALLOW must not emit the reduced-scope signal"
        );

        // Whole-line serde failure (the 1e309 class) → signal fires, tool_hint
        // is null (the line is not parseable JSON), request_sha256 matches.
        let overflow = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table t","x":1e309}}}"#;
        let signal =
            reduced_scope_forward_line(overflow, 7).expect("unrecoverable line must signal");
        let parsed: serde_json::Value = serde_json::from_str(&signal).unwrap();
        assert_eq!(parsed["event"], "reduced_scope_forward");
        assert_eq!(parsed["request_sha256"], sha256_hex(overflow.as_bytes()));
        assert!(parsed["parse_error"].is_string());
        assert!(
            parsed["tool_hint"].is_null(),
            "unparseable line has no tool hint"
        );
        assert_eq!(parsed["count"], 7);
    }

    /// P2-c signal, escaping half (the T4 discipline for this stream): the
    /// `tool_hint` can carry an ATTACKER-CHOSEN `params.name` (the non-object-
    /// arguments reduced-scope class is valid JSON, so the name flows into the
    /// signal). `json!()` escaping is the ONLY control that stops those bytes
    /// forging a second stderr line. Swap it for `format!()` and this goes RED.
    #[test]
    fn reduced_scope_forward_line_escapes_hostile_tool_hint_no_second_line() {
        // Quote-break, CR/LF newline forge, ANSI escape, NUL — the smuggling kit.
        let hostile =
            "\"}\n{\"event\":\"reduced_scope_forward\",\"tool_hint\":\"FORGED\"}\r\n\u{1b}[31mx\u{1b}[0m\u{0000}end";
        // Valid JSON with a string params.name but a NON-OBJECT arguments →
        // request_parts fails on "lacks object params.arguments", so the signal
        // fires AND carries the hostile name as tool_hint.
        let wire = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": hostile, "arguments": "drop"}
        })
        .to_string();
        let signal =
            reduced_scope_forward_line(&wire, 1).expect("non-object-args line must signal");

        // Exactly one physical line — no raw newline forged a second record.
        assert_eq!(
            signal.lines().count(),
            1,
            "hostile tool_hint forged a newline: {signal:?}"
        );
        assert!(
            !signal.contains('\n') && !signal.contains('\r'),
            "raw CR/LF survived escaping: {signal:?}"
        );
        // Valid JSON; the hostile name round-trips intact inside tool_hint, inert.
        let parsed: serde_json::Value =
            serde_json::from_str(&signal).expect("escaped signal must parse as JSON");
        assert_eq!(parsed["tool_hint"].as_str().unwrap(), hostile);
        assert_eq!(parsed["event"], "reduced_scope_forward");
        assert_eq!(
            parsed.as_object().unwrap().len(),
            5,
            "exactly one signal object"
        );
    }

    /// PURE, HOST-SIDE half of T3: `lean_view` collapses the three terminator
    /// forms (`\r\n`, `\n`, none) to one committed string, and the host's OWN
    /// commitment fn (`decision_receipt::sha256_hex`, the same call the host
    /// makes at `decision_receipt.rs`) over that string yields the golden
    /// vector. A change to either the strip or the host hash RED-fires here.
    ///
    /// This pin does NOT exercise the kernel seam or the child — it must not
    /// claim to. The full property (both sides commit to the SAME stripped
    /// bytes AND the child receives the original wire, terminator included, so
    /// two terminators share one commitment while the child sees byte-different
    /// lines) is pinned by the integration test
    /// `terminator_shares_commitment_but_child_sees_original_bytes` in
    /// `tests/host_path.rs`, which drives the real binary and observes the
    /// child. Lean twin: Host/Audit.lean golden vector v1 (sha256("x")).
    #[test]
    fn request_commitment_is_over_the_terminator_stripped_lean_view() {
        for wire in [&b"x\r\n"[..], b"x\n", b"x"] {
            assert_eq!(lean_view(wire), b"x");
        }
        // Commit the golden with the PRODUCTION host fn, not a raw digest, so a
        // change to the host's commitment hashing cannot pass this pin silently.
        assert_eq!(
            seal_host_rs::decision_receipt::sha256_hex(lean_view(b"x\r\n")),
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
        );
    }

    fn envelope(payload: Value) -> String {
        let payload = payload.to_string();
        json!({"payload": payload, "signature": "00"}).to_string()
    }

    #[test]
    fn replay_store_path_reads_signed_payload_field() {
        let env = envelope(json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": "/tmp/approvals.ndjson",
                    "ttl_seconds": 120,
                    "replay_store": {"sqlite_path": "/tmp/replay.sqlite"}
                },
                "tools": []
            }
        }));
        assert_eq!(
            replay_store_path_from_envelope(&env).unwrap(),
            Some("/tmp/replay.sqlite".to_string())
        );
    }

    #[test]
    fn replay_store_path_absent_is_none() {
        let env = envelope(json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": "/tmp/approvals.ndjson",
                    "ttl_seconds": 120
                },
                "tools": []
            }
        }));
        assert_eq!(replay_store_path_from_envelope(&env).unwrap(), None);
    }

    #[test]
    fn replay_store_path_rejects_malformed_field() {
        let env = envelope(json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": "/tmp/approvals.ndjson",
                    "ttl_seconds": 120,
                    "replay_store": {"sqlite_path": ""}
                },
                "tools": []
            }
        }));
        assert!(replay_store_path_from_envelope(&env).is_err());
    }
}
