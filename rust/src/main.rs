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
//! | P1| stdin line (hostile)      | `child_in.write_all` (classify path)   | YES — numeric-agreement scan accepts, then `seal_host_classify == 0`, literal-only mapping (`route_of_classify`); Lean panic exits the process (never a routable default) |
//! | P2| stdin line                | `child_in.write_all` (step path)       | YES — `seal_host_step` route `forward`, exact parse (`route_of_step_output`) |
//! | P3| stdin line                | `child_in.write_all` (interactive retry)| YES — second `seal_host_step == forward` after a human-minted approval |
//! | P4| operator argv             | `Command::new(...).spawn()`            | N/A — operator-trusted setup; the child IS the guarded resource |
//! | P5| kernel block response     | client stdout                          | YES — kernel-authored response plus host-owned exact framed-subject metadata on approval refusals |
//! | P6| child stdout              | client stdout (relay thread)           | NO — response egress is unmediated BY DESIGN (requests are mediated, responses are not; see RUST_BRIDGE.md) |
//! | P7| audit / A3 drops / errors | stderr                                 | telemetry only, no effect |
//! | P8| approval evidence         | (feeds Lean via A3 only)               | parse failure drops the record ⇒ deny |
//! | P9| votes/grants/forecasts    | (raw text to Lean)                     | Lean parses; grants cursor line-split is drop-only |
//! | P10| authenticated health HTTP| fixed health/readiness response         | N/A — operational status only; no MCP or mutation surface |
//!
//! Enforced invariant: bytes reach the child ⇔ the Lean numeric-agreement
//! scan accepted and the kernel then returned classify == 0 or step route ==
//! forward for the byte-identical JUDGED line. For a plain line the judged
//! line is the terminator-stripped wire
//! and the child receives the original wire verbatim. For a V2.1 principal
//! envelope (strict `envelope_view` predicate) the judged line is the EXACT
//! inner request string and the child receives exactly those bytes plus one
//! host-authored `\n` — the inner string is verifiably newline-free, so the
//! child line and the kernel's `request_sha256` commitment differ only by
//! that canonical terminator. Every seam error, panic, malformed envelope,
//! or ambiguity refuses the line and answers the client with
//! `SEAM_ERROR_RESPONSE`. Numeric disagreement instead returns a host-authored
//! invalid-request response naming the kernel-reported offending literal.
//!
//! The wire bytes the client sent are forwarded VERBATIM on allow (enveloped
//! lines: the inner bytes verbatim + `\n`) — the host never reconstructs,
//! re-encodes, or trims what the child receives.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use seal_host_rs::a3;
use seal_host_rs::adapter_revision::McpRevisionSession;
use seal_host_rs::authorization_decision::{
    request_parts, sha256_hex, ApprovalIdentity, AuthorizationDecisionWriter, DecisionInput,
    SignedConfig,
};
use seal_host_rs::envelope_v23::{
    self, EnvelopeV23, HostContext as EnvelopeHostContext, VerifiedEnvelope,
};
use seal_host_rs::health::HealthServer;
use seal_host_rs::lean;
use seal_host_rs::limits::{
    check_json_limits, read_bounded_frame, read_file_bounded, FrameStatus,
    MAX_AUXILIARY_FILE_BYTES, MAX_PENDING_APPROVALS, MAX_WIRE_MESSAGE_BYTES,
};
use seal_host_rs::output::{OutputQueue, OutputSender};
use seal_host_rs::providers::{self, ApprovalProvider};
use seal_host_rs::receipt::ReceiptChain;
use seal_host_rs::replay_store::SqliteReplayStore;
use seal_host_rs::route::{
    numeric_agreement_refusal_response, route_of_classify, route_of_step_output,
    route_of_version_gate, ClassifyRoute, Route, VersionGateRoute, RESOURCE_LIMIT_RESPONSE,
    SEAM_ERROR_RESPONSE,
};
use seal_host_rs::secure_fs;
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
use std::io::{BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

struct Args {
    config: String,
    pubkey: String,
    channel: String,
    token_file: Option<String>,
    approval_pubkey: Option<String>,
    receipt_dir: Option<String>,
    production: bool,
    envelope_v23: bool,
    health: bool,
    health_listen: String,
    health_token_file: Option<String>,
    cmd: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    parse_args_from(argv)
}

fn parse_args_from(argv: Vec<String>) -> Result<Args, String> {
    let mut config = None;
    let mut pubkey = None;
    let mut channel = "file".to_string();
    let mut token_file = None;
    let mut approval_pubkey = None;
    let mut receipt_dir = None;
    let mut production = true;
    let mut production_requested = false;
    let mut insecure_development_mode = false;
    let mut envelope_v23 = false;
    let mut health = false;
    let mut health_listen = "127.0.0.1:9464".to_string();
    let mut health_token_file = None;
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
            "--production" => {
                production_requested = true;
                production = true;
                i += 1
            }
            "--insecure-development-mode" => {
                insecure_development_mode = true;
                production = false;
                i += 1
            }
            "--envelope-v23" => {
                envelope_v23 = true;
                i += 1
            }
            "--health" => {
                health = true;
                i += 1
            }
            "--health-listen" => {
                health = true;
                health_listen = argv.get(i + 1).cloned().unwrap_or_default();
                i += 2
            }
            "--health-token-file" => {
                health_token_file = argv.get(i + 1).cloned();
                i += 2
            }
            "--" => {
                cmd = argv[i + 1..].to_vec();
                break;
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    if production_requested && insecure_development_mode {
        return Err("--production conflicts with --insecure-development-mode".into());
    }
    Ok(Args {
        config: config.ok_or("--config required")?,
        pubkey: pubkey.ok_or("--pubkey required")?,
        channel,
        token_file,
        approval_pubkey,
        receipt_dir,
        production,
        envelope_v23,
        health,
        health_listen,
        health_token_file,
        cmd: if cmd.is_empty() {
            return Err("server command required after --".into());
        } else {
            cmd
        },
    })
}

const INSECURE_MODE_WARNING: &str =
    "WARNING: INSECURE DEVELOPMENT MODE ENABLED; production preflight is disabled";

fn startup_mode_warning(args: &Args) -> Option<&'static str> {
    (!args.production).then_some(INSECURE_MODE_WARNING)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Receipt-only identity for this stdio mediation session. It is recorded as
/// runtime context and never crosses into Lean, signature verification, or A3.
fn receipt_session_id(started_at_ms: u64) -> String {
    format!("seal-host-rs/stdio:{}:{started_at_ms}", std::process::id())
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

/// Add the exact delimiter-bearing approval subject to an approval-required
/// refusal. The kernel-authored target text is retained byte-for-byte as a
/// JSON string value; this host-owned sibling is transport metadata only and
/// is never fed back into target derivation, Lean, or approval verification.
fn refusal_with_framed_subject(
    response: &str,
    framed_subject: &[u8],
    framed_subject_sha256: &str,
) -> Result<String, String> {
    if response
        .split("approval required: ")
        .nth(1)
        .and_then(extract_target_hex)
        .is_none()
    {
        return Ok(response.to_owned());
    }

    let mut refusal: Value = serde_json::from_str(response)
        .map_err(|error| format!("cannot add framed subject to refusal: {error}"))?;
    let result = refusal
        .get_mut("result")
        .and_then(Value::as_object_mut)
        .ok_or("cannot add framed subject to refusal: result is not an object")?;
    result.insert(
        "framed_subject".into(),
        json!({
            "encoding": "base64",
            "length": framed_subject.len(),
            "sha256": framed_subject_sha256,
            "base64": STANDARD.encode(framed_subject),
        }),
    );
    serde_json::to_string(&refusal)
        .map(|text| text + "\n")
        .map_err(|error| format!("cannot serialize framed-subject refusal: {error}"))
}

fn read_or_empty(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        read_file_bounded(std::path::Path::new(path), MAX_AUXILIARY_FILE_BYTES)
            .ok()
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_default()
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

fn production_preflight(args: &Args, replay_store_path: Option<&str>) -> Result<(), String> {
    if !args.production {
        return Ok(());
    }
    if args.channel != "ed25519" {
        return Err("production mode requires --channel ed25519".into());
    }
    let token_file = args
        .token_file
        .as_deref()
        .ok_or("production mode requires --token-file")?;
    let approval_pubkey = args
        .approval_pubkey
        .as_deref()
        .ok_or("production mode requires --approval-pubkey")?;
    if same_ed25519_key_hex(&args.pubkey, approval_pubkey) {
        return Err("production mode requires separate config and approval keys".into());
    }
    let receipt_dir = args
        .receipt_dir
        .as_deref()
        .filter(|path| !path.is_empty())
        .ok_or("production mode requires explicit --receipt-dir")?;
    let replay_path = replay_store_path
        .filter(|path| !path.is_empty())
        .ok_or("production mode requires a durable replay store")?;

    secure_fs::validate_private_file(std::path::Path::new(&args.config), "trusted config")?;
    secure_fs::validate_private_file(std::path::Path::new(token_file), "approval token file")?;
    secure_fs::ensure_private_dir(
        std::path::Path::new(receipt_dir),
        "authorization decision directory",
    )?;
    secure_fs::validate_private_parent(
        std::path::Path::new(replay_path),
        "replay database directory",
    )?;
    if std::path::Path::new(replay_path).exists() {
        secure_fs::validate_private_file(std::path::Path::new(replay_path), "replay database")?;
    }
    Ok(())
}

fn persist_decision(
    writer: &mut AuthorizationDecisionWriter,
    input: DecisionInput<'_>,
) -> Result<Option<String>, ()> {
    match writer.persist(input) {
        Ok(decision) => {
            eprintln!("{}", json!({"authorization_decision": decision.path}));
            Ok(decision.consumed_target)
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({"error": "authorization decision persistence failure", "detail": error})
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
        let Ok(bytes) =
            read_file_bounded(std::path::Path::new(&self.path), MAX_AUXILIARY_FILE_BYTES)
        else {
            return String::new();
        };
        let Ok(text) = String::from_utf8(bytes) else {
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

fn write_frame(output: &OutputSender, line: &str) -> Result<(), ()> {
    output.send_frame(line.as_bytes()).map_err(|error| {
        eprintln!("{}", json!({"error": error}));
    })
}

fn write_child(child: &mut impl Write, bytes: &[u8], ready: &AtomicBool) -> Result<(), ()> {
    child
        .write_all(bytes)
        .and_then(|_| child.flush())
        .map_err(|error| {
            ready.store(false, Ordering::Release);
            eprintln!(
                "{}",
                json!({"error": format!("downstream child transport failed: {error}")})
            );
        })
}

fn emit_audit(receipts: &mut ReceiptChain, audit: &str) -> Result<(), ()> {
    eprintln!("{audit}");
    match receipts.observe(audit) {
        Ok(record) => {
            eprintln!("{}", record.to_json_line());
            Ok(())
        }
        Err(error) => {
            eprintln!(
                "{}",
                json!({"error": "audit head persistence failure", "detail": error})
            );
            Err(())
        }
    }
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

fn emit_resource_limit(limit: &str, maximum: usize) {
    eprintln!(
        "{}",
        json!({
            "seal_host_event": "resource_limit_refusal",
            "limit": limit,
            "maximum": maximum,
        })
    );
}

fn admit_pending_approvals(
    pending: &mut Vec<providers::ApprovalRecord>,
    records: &[providers::ApprovalRecord],
    now: u64,
    ttl_ms: u64,
) -> bool {
    pending.retain(|record| {
        record
            .issued_at
            .map(|issued| issued.saturating_add(ttl_ms) >= now)
            .unwrap_or(true)
    });
    if records.len() > MAX_PENDING_APPROVALS.saturating_sub(pending.len()) {
        emit_resource_limit("pending_approval_records", MAX_PENDING_APPROVALS);
        return false;
    }
    pending.extend(records.iter().cloned());
    true
}

/// The P2-c observability signal for a FORCED reduced-scope forward attempt: an ALLOW
/// whose wire line `request_parts` cannot recover (whole-line serde failure — the
/// `1e309` / argless / non-object-args class). Returns `None` for a normal
/// parseable ALLOW, so the signal fires ONLY on the reduced-scope condition; the
/// reduced-scope test hook is `request_parts` itself, the SAME function the
/// authorization-decision writer uses, so the signal's condition is identical
/// to the authorization decision's by construction. `count` is the running
/// total of forced downgrades this
/// session (burst visibility).
///
/// `parse_error` and `tool_hint` can carry ATTACKER-CHOSEN bytes from the wire;
/// `json!()` string-escaping is the ONLY control that stops them forging a second
/// stderr line (quote-breaking, newline injection, ANSI smuggling). Kept as a
/// named fn so a regression test pins the escaping — swapping this for `format!()`
/// would silently kill it. Passive tap: reads only `line`, never `wire`, the
/// authorization decision, or the verdict.
fn reduced_scope_forward_attempt_line(line: &str, count: u64) -> Option<String> {
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
            "event": "reduced_scope_forward_attempt",
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
///
/// V2.1 exception, deliberately narrow: a line that IS a well-formed
/// principal envelope (`envelope_view` returns `Enveloped`) is judged and
/// forwarded as its INNER request string — see `envelope_view` for the
/// strict predicate and the terminator-canonicalization story.
fn lean_view(wire: &[u8]) -> &[u8] {
    let s = wire.strip_suffix(b"\n").unwrap_or(wire);
    s.strip_suffix(b"\r").unwrap_or(s)
}

/// Raw V2.1 principal-envelope fields as extracted off the wire — passed to
/// Lean UNINTERPRETED (never a principal string): `Host.verifyEnvelope`
/// verifies the Ed25519 signature against the signed config's registry over
/// the exact judged line, inside the kernel.
#[derive(Clone, Debug, PartialEq)]
struct EnvFields {
    key_id: String,
    sig: String,
    nonce: String,
    issued_at: u64,
}

/// The currently pinned V2.2 envelope, or the staged V2.3 host-side shape.
/// V2.3 is selected explicitly at boot and remains fail-closed until the Lean
/// adapter is reviewed and repinned in a separate, authorized change.
#[derive(Clone, Debug, PartialEq)]
enum PrincipalEnvelope {
    V22(EnvFields),
    V23(Box<EnvelopeV23>),
}

impl PrincipalEnvelope {
    fn nonce_and_issued_at(&self) -> (&str, u64) {
        match self {
            Self::V22(envelope) => (&envelope.nonce, envelope.issued_at),
            Self::V23(envelope) => (&envelope.nonce, envelope.issued_at),
        }
    }

    fn lean_value(&self) -> Value {
        match self {
            Self::V22(envelope) => json!({
                "key_id": envelope.key_id,
                "sig": envelope.sig,
                "nonce": envelope.nonce,
                "issued_at": envelope.issued_at,
            }),
            Self::V23(envelope) => {
                // The pinned Lean FFI sees the familiar four fields and
                // therefore rejects the V2.3 signature. The remaining fields
                // stage the full future adapter input; the host principal
                // cross-check below prevents any pre-repin forward.
                serde_json::to_value(envelope).expect("V2.3 envelope is serializable")
            }
        }
    }
}

/// One wire line, classified for the V2.1 principal envelope.
#[derive(Debug, PartialEq)]
enum EnvelopeView {
    /// No top-level `seal_env` key (or not a JSON object at all): the line
    /// is judged and forwarded byte-identically to the pre-V2.1 host.
    Plain,
    /// A well-formed envelope: `request` is the exact inner judged line.
    Enveloped { request: String, env: EnvFields },
    /// The line CLAIMS to be an envelope (top-level `seal_env` present) but
    /// fails the strict predicate — an ambiguity channel, refused outright.
    Malformed(String),
}

/// STRICT envelope predicate, fail-closed. `Enveloped` requires EXACTLY:
/// top-level keys `{seal_env, request}`; `seal_env` an object with exactly
/// `{key_id: string, sig: string, nonce: string, issued_at: u64}`; `request`
/// a non-empty string free of `\n`, `\r` and NUL. The newline-freedom rule
/// closes line smuggling (one Lean allow must never forward two protocol
/// lines), and makes the enveloped path CANONICALIZE the terminator: the
/// child receives exactly `request + "\n"` whatever terminator the wrapper
/// arrived with. A nested `seal_env` inside a normal call's arguments never
/// triggers (top-level key only).
fn envelope_view(line: &str) -> EnvelopeView {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return EnvelopeView::Plain;
    };
    let Some(obj) = v.as_object() else {
        return EnvelopeView::Plain;
    };
    if !obj.contains_key("seal_env") {
        return EnvelopeView::Plain;
    }
    if obj.len() != 2 || !obj.contains_key("request") {
        return EnvelopeView::Malformed("envelope must carry exactly {seal_env, request}".into());
    }
    let Some(env) = obj["seal_env"].as_object() else {
        return EnvelopeView::Malformed("seal_env must be an object".into());
    };
    if env.len() != 4 {
        return EnvelopeView::Malformed(
            "seal_env must carry exactly {key_id, sig, nonce, issued_at}".into(),
        );
    }
    let (Some(key_id), Some(sig), Some(nonce), Some(issued_at)) = (
        env.get("key_id").and_then(Value::as_str),
        env.get("sig").and_then(Value::as_str),
        env.get("nonce").and_then(Value::as_str),
        env.get("issued_at").and_then(Value::as_u64),
    ) else {
        return EnvelopeView::Malformed(
            "seal_env fields must be {key_id: str, sig: str, nonce: str, issued_at: u64}".into(),
        );
    };
    let Some(request) = obj["request"].as_str() else {
        return EnvelopeView::Malformed("request must be a string".into());
    };
    if request.is_empty() {
        return EnvelopeView::Malformed("request must be non-empty".into());
    }
    if request.contains('\n') || request.contains('\r') || request.contains('\0') {
        return EnvelopeView::Malformed(
            "request must not contain newline, CR, or NUL (line smuggling refused)".into(),
        );
    }
    EnvelopeView::Enveloped {
        request: request.to_owned(),
        env: EnvFields {
            key_id: key_id.to_owned(),
            sig: sig.to_owned(),
            nonce: nonce.to_owned(),
            issued_at,
        },
    }
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
        Some("schema") => {
            std::process::exit(run_schema());
        }
        Some("validate") => {
            let files: Vec<String> = std::env::args().skip(2).collect();
            std::process::exit(run_validate(&files));
        }
        _ => {}
    }

    std::process::exit(run());
}

/// `seal-host-rs schema` — print the policy-bundle JSON Schema straight from
/// the Lean authority (the schema projection of the SAME codec the init path
/// parses with). The anti-drift gate byte-compares this output against the
/// artifact checked into the pinned authority
/// (`.lake/packages/mcp-seal/docs/policy-bundle.schema.json`).
fn run_schema() -> i32 {
    let host = lean::LeanHost::new();
    match host.policy_schema() {
        Ok(s) => {
            println!("{s}");
            0
        }
        Err(e) => {
            eprintln!("schema export failed: {e}");
            3
        }
    }
}

/// `seal-host-rs validate <payload.json>...` — one invocation, BOTH legs:
/// the Lean parser chain (number guard → JSON → parsePolicyBundle →
/// ofBundle) via FFI, and the emitted-schema validator (jsonschema crate)
/// against the schema projection of the same codec. Envelope files
/// (`{"payload": "...", "signature": ...}`) are unwrapped to their signed
/// payload bytes first — NOTHING is stripped from signed policy bytes.
///
/// Exit is nonzero iff any file shows `schema_rejects_parsed_policy` (the
/// schema rejecting what the Lean parser accepts — real drift) or a seam
/// error. The converse disagreement (`parser_refinement`: Lean rejects,
/// schema accepts) is expected for parser-only refinements (server
/// conflict, calibration delta bound, number guard, host-layer
/// duplicate-cap) and is reported per file for the gate script to assert.
fn run_validate(files: &[String]) -> i32 {
    if files.is_empty() {
        eprintln!("usage: seal-host-rs validate <payload-or-envelope.json>...");
        return 2;
    }
    let host = lean::LeanHost::new();
    let schema_text = match host.policy_schema() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("schema export failed: {e}");
            return 3;
        }
    };
    let schema_json: serde_json::Value = match serde_json::from_str(&schema_text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("emitted schema is not JSON: {e}");
            return 3;
        }
    };
    let validator = match jsonschema::validator_for(&schema_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("emitted schema failed to compile: {e}");
            return 3;
        }
    };

    let mut hard_failures = 0i32;
    for path in files {
        let raw = match read_file_bounded(std::path::Path::new(path), MAX_WIRE_MESSAGE_BYTES) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) => {
                    eprintln!("{path}: cannot read: input is not UTF-8: {error}");
                    hard_failures += 1;
                    continue;
                }
            },
            Err(e) => {
                eprintln!("{path}: cannot read: {e}");
                hard_failures += 1;
                continue;
            }
        };
        // Envelope unwrap: validate the exact signed payload bytes.
        let (payload_text, from_envelope) = match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) => match v.get("payload").and_then(|p| p.as_str()) {
                Some(p) if v.get("signature").is_some() => (p.to_string(), true),
                _ => (raw.clone(), false),
            },
            Err(_) => (raw.clone(), false),
        };

        let lean_verdict: serde_json::Value = match host.policy_validate(&payload_text) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(
                |e| serde_json::json!({"ok": false, "stage": "seam", "error": format!("unparseable verdict: {e}")}),
            ),
            Err(e) => {
                eprintln!("{path}: ffi seam error: {e}");
                hard_failures += 1;
                continue;
            }
        };
        let lean_ok = lean_verdict
            .get("ok")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let lean_stage = lean_verdict
            .get("stage")
            .and_then(|s| s.as_str())
            .unwrap_or("ok");

        let (schema_ok, schema_error) =
            match serde_json::from_str::<serde_json::Value>(&payload_text) {
                Ok(instance) => match validator.validate(&instance) {
                    Ok(()) => (true, serde_json::Value::Null),
                    Err(e) => (false, serde_json::Value::String(e.to_string())),
                },
                Err(e) => (false, serde_json::Value::String(format!("not JSON: {e}"))),
            };

        let agreement = match (lean_ok, schema_ok) {
            (true, true) => "agree_accept",
            (false, false) => "agree_reject",
            (false, true) => "parser_refinement",
            (true, false) => "schema_rejects_parsed_policy",
        };
        if agreement == "schema_rejects_parsed_policy" {
            hard_failures += 1;
        }
        let line = serde_json::json!({
            "file": path,
            "envelope": from_envelope,
            "lean": lean_verdict,
            "schema_ok": schema_ok,
            "schema_error": schema_error,
            "agreement": agreement,
            "lean_stage": lean_stage,
        });
        println!("{line}");
    }
    if hard_failures > 0 {
        eprintln!("validate: {hard_failures} hard failure(s) — schema/parser drift or seam error");
        1
    } else {
        0
    }
}

fn run() -> i32 {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "usage: seal-host-rs --config <trusted.json> --pubkey <config-pubkey-hex> \
                [--channel file|ed25519|interactive] [--token-file <path>] \
                [--approval-pubkey <hex>] [--receipt-dir <path>] \
                [--production|--insecure-development-mode] [--envelope-v23] \
                [--health [--health-listen 127.0.0.1:9464] --health-token-file <path>] \
                -- <server-cmd> <args...>\nerror: {e}"
            );
            return 2;
        }
    };
    if let Some(warning) = startup_mode_warning(&args) {
        eprintln!("{warning}");
    }

    let host = lean::LeanHost::new();

    // Fail-closed: a rejected config aborts before any stdio is mediated.
    let envelope =
        match read_file_bounded(std::path::Path::new(&args.config), MAX_WIRE_MESSAGE_BYTES) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => {
                    eprintln!("trusted config rejected: config is not UTF-8");
                    return 3;
                }
            },
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
    let v23_session = if args.envelope_v23 {
        match envelope_v23::issue_session_id() {
            Ok(session) => Some(session),
            Err(error) => {
                eprintln!("V2.3 startup refused: {error}");
                return 3;
            }
        }
    } else {
        None
    };
    let receipt_session = receipt_session_id(now_ms());
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
    if let Err(error) = production_preflight(&args, replay_store_path.as_deref()) {
        eprintln!("production startup refused: {error}");
        return 3;
    }
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
    let mut authorization_decisions = match AuthorizationDecisionWriter::new(&receipt_dir) {
        Ok(writer) => writer,
        Err(e) => {
            eprintln!("authorization decision sink rejected: {e}");
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
    // V2.1 envelope freshness: a SECOND A3 instance for request-envelope
    // nonces — the same TTL/skew/replay machinery, a separate namespace so
    // envelope nonces and approval nonces can never pre-burn each other.
    // MVP: in-memory store (session-scoped replay protection; a host restart
    // forgets envelope nonces within the TTL window — named in the TCB, a
    // sqlite twin of the approval store is the production follow-up). TTL
    // reuses the approval TTL from the signed config.
    let mut a3_env = a3::A3Filter::new(ttl_ms);
    let mut envelope_drops: u64 = 0;
    let mut receipts = match ReceiptChain::open(&receipt_dir, &receipt_session) {
        Ok(chain) => chain,
        Err(error) => {
            eprintln!("audit state rejected: {error}");
            return 4;
        }
    };
    let mut pending_approvals: Vec<providers::ApprovalRecord> = Vec::new();
    let mut approval_context_drop_counter: u64 = 0;
    // M.2/M.2a: select the transparent MCP era from the received entry-call
    // shape. There is intentionally no legacy default; a V2.3 mediated call
    // before selection (or after conflicting entry calls) refuses below.
    let mut mcp_revision_session = McpRevisionSession::default();
    // ApprovalRecord v2 is admitted only while an exact-frame challenge for
    // its target is outstanding. One slot is enough for this lockstep stdio
    // protocol; a later block replaces it and a forward clears it.
    let mut pending_approval_challenge: Option<(String, usize, String)> = None;
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
    let readiness = Arc::new(AtomicBool::new(false));
    let _health_server = if args.health {
        let Some(token_file) = args.health_token_file.as_deref() else {
            eprintln!("health listener refused: --health-token-file is required");
            let _ = child.kill();
            let _ = child.wait();
            return 2;
        };
        match HealthServer::start(
            &args.health_listen,
            std::path::Path::new(token_file),
            readiness.clone(),
        ) {
            Ok(server) => {
                eprintln!(
                    "{}",
                    json!({"health_listener": server.local_addr().to_string(), "authenticated": true})
                );
                Some(server)
            }
            Err(error) => {
                eprintln!("health listener refused: {error}");
                let _ = child.kill();
                let _ = child.wait();
                return 2;
            }
        }
    } else {
        None
    };
    let mut child_in = child.stdin.take().expect("child stdin");
    let child_out = child.stdout.take().expect("child stdout");

    let output_queue = OutputQueue::stdout();
    let output = output_queue.sender();
    // V2.3 clients must learn the boot-stable SESSION PLANE before they can
    // sign a call. Publish it before the relay thread starts, so no child
    // frame can race ahead of this issuance frame. This is deliberately not
    // the authorization-decision-only PID session.
    if let Some(session) = &v23_session {
        let notification = format!(
            "{}\n",
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/seal/session",
                "params": {
                    "schema": "seal.session/v1",
                    "envelope": "seal.effect/v2",
                    "session": session,
                }
            })
        );
        if let Err(error) = output.send_frame(notification.as_bytes()) {
            eprintln!("V2.3 startup refused: cannot publish session: {error}");
            let _ = child.kill();
            let _ = child.wait();
            output_queue.shutdown();
            return 2;
        }
    }
    let relay_output = output.clone();
    let downstream_dead = Arc::new(AtomicBool::new(false));
    let relay_dead = downstream_dead.clone();
    let relay_ready = readiness.clone();
    let relay = std::thread::spawn(move || {
        let mut reader = BufReader::new(child_out);
        let mut frame = Vec::new();
        loop {
            match read_bounded_frame(&mut reader, &mut frame, MAX_WIRE_MESSAGE_BYTES) {
                Ok(FrameStatus::Complete) => {
                    if let Err(error) = relay_output.send_frame(&frame) {
                        eprintln!("{}", json!({"error": error}));
                        relay_dead.store(true, Ordering::Release);
                        relay_ready.store(false, Ordering::Release);
                        break;
                    }
                }
                Ok(FrameStatus::Eof) => {
                    relay_dead.store(true, Ordering::Release);
                    relay_ready.store(false, Ordering::Release);
                    break;
                }
                Ok(FrameStatus::Unterminated) => {
                    eprintln!(
                        "{}",
                        json!({"error": "downstream child emitted an unterminated frame"})
                    );
                    relay_dead.store(true, Ordering::Release);
                    relay_ready.store(false, Ordering::Release);
                    break;
                }
                Ok(FrameStatus::Oversized) => {
                    emit_resource_limit("downstream_wire_message_bytes", MAX_WIRE_MESSAGE_BYTES);
                    relay_dead.store(true, Ordering::Release);
                    relay_ready.store(false, Ordering::Release);
                    break;
                }
                Err(error) => {
                    eprintln!(
                        "{}",
                        json!({"error": format!("downstream child read failed: {error}")})
                    );
                    relay_dead.store(true, Ordering::Release);
                    relay_ready.store(false, Ordering::Release);
                    break;
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
    let mut reduced_scope_forward_attempts: u64 = 0;
    readiness.store(true, Ordering::Release);
    loop {
        wire.clear();
        match read_bounded_frame(&mut reader, &mut wire, MAX_WIRE_MESSAGE_BYTES) {
            Ok(FrameStatus::Eof) => break,
            Ok(FrameStatus::Complete | FrameStatus::Unterminated) => {}
            Ok(FrameStatus::Oversized) => {
                emit_resource_limit("wire_message_bytes", MAX_WIRE_MESSAGE_BYTES);
                if write_frame(&output, RESOURCE_LIMIT_RESPONSE).is_err() {
                    break;
                }
                continue;
            }
            Err(e) => {
                eprintln!("{}", json!({"error": format!("stdin read error: {e}")}));
                break; // transport dead: stop mediating, kill child
            }
        }

        if output.has_failed() {
            readiness.store(false, Ordering::Release);
            break;
        }
        if downstream_dead.load(Ordering::Acquire) {
            let _ = write_frame(&output, SEAM_ERROR_RESPONSE);
            readiness.store(false, Ordering::Release);
            break;
        }

        // The Lean view must be valid UTF-8 (Lean strings are UTF-8). A
        // non-UTF-8 line cannot be judged, so it cannot be forwarded:
        // refuse it and keep the session alive.
        let Ok(line) = std::str::from_utf8(lean_view(&wire)) else {
            eprintln!("{}", json!({"error": "non-utf8 line refused"}));
            if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                break;
            }
            continue;
        };
        if let Err(limit) = check_json_limits(line.as_bytes()) {
            emit_resource_limit(limit.name(), limit.maximum());
            if write_frame(&output, RESOURCE_LIMIT_RESPONSE).is_err() {
                break;
            }
            continue;
        }
        // V2.1 envelope extraction — ONCE, BEFORE classify (a wrapper line
        // is not a tools/call, so classifying the wrapper would passthrough
        // the wrapper bytes unjudged). From here on `line` is the JUDGED
        // line: the inner request string for a well-formed envelope, the
        // wire view otherwise — one binding, no rewrites, exactly as before.
        // A malformed envelope (has `seal_env` but fails the strict
        // predicate) is an ambiguity channel and refuses outright.
        let parsed_envelope: Result<(Option<String>, Option<PrincipalEnvelope>), String> =
            if args.envelope_v23 {
                match envelope_v23::wire_view(line) {
                    envelope_v23::WireView::Plain => Ok((None, None)),
                    envelope_v23::WireView::Enveloped { request, envelope } => {
                        Ok((Some(request), Some(PrincipalEnvelope::V23(envelope))))
                    }
                    envelope_v23::WireView::Malformed(reason) => Err(reason),
                }
            } else {
                match envelope_view(line) {
                    EnvelopeView::Plain => Ok((None, None)),
                    EnvelopeView::Enveloped { request, env } => {
                        Ok((Some(request), Some(PrincipalEnvelope::V22(env))))
                    }
                    EnvelopeView::Malformed(reason) => Err(reason),
                }
            };
        let (inner, envelope) = match parsed_envelope {
            Ok(parsed) => parsed,
            Err(reason) => {
                eprintln!(
                    "{}",
                    json!({"error": format!("malformed principal envelope refused: {reason}")})
                );
                if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                    break;
                }
                continue;
            }
        };
        let line: &str = inner.as_deref().unwrap_or(line);
        if inner.is_some() {
            if let Err(limit) = check_json_limits(line.as_bytes()) {
                emit_resource_limit(limit.name(), limit.maximum());
                if write_frame(&output, RESOURCE_LIMIT_RESPONSE).is_err() {
                    break;
                }
                continue;
            }
        }
        // Numeric agreement is independent of the parse-cost guard already
        // inside `seal_host_classify`: ask the pinned Lean kernel for the
        // exact first literal BEFORE the classify fast path can admit this
        // judged line to either passthrough or mediation. The returned
        // literal is used only in a host-authored refusal; it is never parsed
        // or forwarded.
        match host.first_agreement_unsafe_number(line) {
            Ok(Some(literal)) => {
                eprintln!(
                    "{}",
                    json!({
                        "error": "numeric agreement refusal",
                        "offending_literal": literal
                    })
                );
                let response = numeric_agreement_refusal_response(&literal);
                if write_frame(&output, &response).is_err() {
                    break;
                }
                continue;
            }
            Ok(None) => {}
            Err(error) => {
                eprintln!(
                    "{}",
                    json!({
                        "error": format!(
                            "numeric agreement seam failure; line refused: {error}"
                        )
                    })
                );
                if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                    break;
                }
                continue;
            }
        }
        // M.7 kernel gate: before entry observation, classify, provider/replay
        // work, audit, approval consumption, or decision persistence.
        match route_of_version_gate(
            host.mcp_version_gate(line, mcp_revision_session.version_gate_input()),
        ) {
            VersionGateRoute::Continue => {}
            VersionGateRoute::Reject { response } => {
                eprintln!(
                    "{}",
                    json!({"seal_host_event": "mcp_version_gate_rejected"})
                );
                if write_frame(&output, &response).is_err() {
                    break;
                }
                continue;
            }
            VersionGateRoute::SeamFailure { reason } => {
                eprintln!("{}", json!({"error": reason}));
                if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                    break;
                }
                continue;
            }
        }
        // M.2 observation feeds the next kernel gate and signed adapter claim.
        mcp_revision_session.observe_received_call(line);
        // Bytes the child receives on allow: the original wire verbatim for
        // a plain line; for an enveloped line, exactly the judged inner
        // string plus ONE host-authored `\n` (the inner string is verifiably
        // newline-free, so child line and judged commitment differ only by
        // that canonical terminator — the sharpened T3 story).
        let forward: Vec<u8> = match &inner {
            Some(request) => {
                let mut bytes = request.clone().into_bytes();
                bytes.push(b'\n');
                bytes
            }
            None => wire.clone(),
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
                // For an enveloped non-mediated line the envelope is inert
                // framing: no verification, no nonce burn (freshness gates
                // decisions; passthrough lines carry none) — the INNER bytes
                // flow to the child.
                if write_child(&mut child_in, &forward, &readiness).is_err() {
                    let _ = write_frame(&output, SEAM_ERROR_RESPONSE);
                    break;
                }
                continue;
            }
            ClassifyRoute::Mediate => {}
            ClassifyRoute::Refuse => {
                eprintln!(
                    "{}",
                    json!({"error": "classify seam failure; line refused"})
                );
                if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                    break;
                }
                continue;
            }
        }

        // V2.3 independently reconstructs and verifies the full tuple in
        // Rust, including equality to host-owned adapter/session/effect
        // facts. This is additive defense at the future Lean adapter seam,
        // never an authorization oracle: Lean must still return the same
        // authenticated principal before any route can be enacted.
        let mut verified_v23: Option<VerifiedEnvelope> = match &envelope {
            Some(PrincipalEnvelope::V23(envelope)) => {
                let Some(session) = v23_session.as_deref() else {
                    eprintln!("{}", json!({"error": "V2.3 session was not issued"}));
                    if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                        break;
                    }
                    continue;
                };
                let actual_revision = match mcp_revision_session.actual_revision() {
                    Ok(revision) => revision,
                    Err(reason) => {
                        eprintln!(
                            "{}",
                            json!({"error": format!("V2.3 envelope refused: {reason}")})
                        );
                        if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                            break;
                        }
                        continue;
                    }
                };
                let actual_adapter = actual_revision.adapter_claim();
                match envelope_v23::verify(
                    envelope,
                    line,
                    &EnvelopeHostContext {
                        authority_hex: &args.pubkey,
                        session,
                        adapter: &actual_adapter,
                        kernel_config: &kernel_config,
                    },
                ) {
                    Ok(verified) => Some(verified),
                    Err(error) => {
                        eprintln!(
                            "{}",
                            json!({"error": format!("V2.3 envelope refused: {error}")})
                        );
                        if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                            break;
                        }
                        continue;
                    }
                }
            }
            _ => None,
        };

        let poll = provider.poll();
        let mut warnings = poll.warnings;
        let framed_sha256 = sha256_hex(&wire);
        let expected_approval_target = pending_approval_challenge
            .as_ref()
            .filter(|(digest, length, _)| digest == &framed_sha256 && *length == wire.len())
            .map(|(_, _, target)| target.as_str());
        let (context_bound_records, context_warnings) = providers::filter_approval_context(
            poll.records,
            &wire,
            expected_approval_target,
            &mut approval_context_drop_counter,
        );
        if context_bound_records
            .iter()
            .any(|record| record.v2().is_some())
        {
            pending_approval_challenge = None;
        }
        warnings.extend(context_warnings);
        let (records, a3_warnings) = a3.filter(context_bound_records, now);
        if !admit_pending_approvals(&mut pending_approvals, &records, now, ttl_ms) {
            warnings.extend(a3_warnings);
            emit_approval_drop_warnings(&warnings);
            if write_frame(&output, RESOURCE_LIMIT_RESPONSE).is_err() {
                break;
            }
            continue;
        }
        warnings.extend(a3_warnings);
        emit_approval_drop_warnings(&warnings);
        let declines = poll.declines;
        let approvals: Vec<Value> = records
            .iter()
            .map(|r| json!({"target": r.target, "issuedAt": r.issued_at}))
            .collect();

        // V2.1 envelope freshness (second A3 instance): the nonce is checked
        // ONCE per wire arrival; a dropped (replayed/stale/future) envelope
        // downgrades to no-envelope — fail-closed deny for principal-gated
        // tools, and a passive stderr counter so an operator can see a
        // downgrade burst (the reduced-scope observability idiom).
        let envelope = match envelope {
            Some(env) => {
                let (nonce, issued_at) = env.nonce_and_issued_at();
                let rec = providers::ApprovalRecord::legacy(
                    sha256_hex(line.as_bytes()),
                    Some(issued_at),
                    Some(nonce.to_owned()),
                );
                let (ok, env_warnings) = a3_env.filter(vec![rec], now);
                emit_approval_drop_warnings(&env_warnings);
                if ok.is_empty() {
                    envelope_drops += 1;
                    eprintln!(
                        "{}",
                        json!({
                            "seal_host_event": "principal_envelope_dropped",
                            "count": envelope_drops,
                        })
                    );
                    verified_v23 = None;
                    None
                } else {
                    Some(env)
                }
            }
            None => None,
        };

        let mut input = json!({
            "line": line,
            "now": now,
            "approvals": approvals,
            "votes": read_or_empty(&votes_file),
            "grants": grants.fresh(),
            "forecasts": read_or_empty(&forecasts_file),
        });
        if let Some(env) = &envelope {
            // RAW fields only — Rust never passes a principal string; the
            // kernel verifies and derives the principal in its parse path.
            input["envelope"] = env.lean_value();
        }
        let step_output = match host.step(&input.to_string()) {
            Ok(output) => output,
            Err(error) => {
                eprintln!("{}", json!({"error": format!("seam error: {error}")}));
                if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                    break;
                }
                continue;
            }
        };
        if let Some(verified) = &verified_v23 {
            if let Err(error) = envelope_v23::verify_kernel_principal(&step_output, verified) {
                eprintln!(
                    "{}",
                    json!({"error": format!("V2.3 kernel cross-check refused: {error}")})
                );
                if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                    break;
                }
                continue;
            }
        }
        match route_of_step_output(Ok(step_output.clone())) {
            Route::Forward { audit } => {
                pending_approval_challenge = None;
                if let Some(a) = audit {
                    if emit_audit(&mut receipts, &a).is_err() {
                        if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                            break;
                        }
                        continue;
                    }
                }
                let consumed = match persist_decision(
                    &mut authorization_decisions,
                    DecisionInput {
                        line,
                        framed_subject: &wire,
                        session: &receipt_session,
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
                        if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                            break;
                        }
                        continue;
                    }
                };
                consume_pending_approval(&mut pending_approvals, consumed);
                // P2-c passive observability tap: an ALLOW about to be forwarded
                // with an UNRECOVERABLE request (reduced-scope authorization
                // decision) is a forced downgrade an operator must be able to
                // see and count. Emitted BEFORE the forward attempt but reads
                // only `line` — it never touches `wire`, the authorization
                // decision, or the verdict, so the forwarded bytes stay
                // byte-identical with or without it.
                if let Some(signal) =
                    reduced_scope_forward_attempt_line(line, reduced_scope_forward_attempts + 1)
                {
                    reduced_scope_forward_attempts += 1;
                    eprintln!("{signal}");
                }
                if write_child(&mut child_in, &forward, &readiness).is_err() {
                    let _ = write_frame(&output, SEAM_ERROR_RESPONSE);
                    break;
                }
            }
            Route::Block {
                mut response,
                audit,
            } => {
                if let Some(a) = audit {
                    if emit_audit(&mut receipts, &a).is_err() {
                        if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                            break;
                        }
                        continue;
                    }
                }
                if persist_decision(
                    &mut authorization_decisions,
                    DecisionInput {
                        line,
                        framed_subject: &wire,
                        session: &receipt_session,
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
                    if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                        break;
                    }
                    continue;
                }

                pending_approval_challenge = response
                    .split("approval required: ")
                    .nth(1)
                    .and_then(extract_target_hex)
                    .map(|target| (framed_sha256.clone(), wire.len(), target));

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
                        if emit_audit(&mut receipts, &refused_audit).is_err() {
                            if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                                break;
                            }
                            continue;
                        }
                        let refused = format!(
                            "{{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{{\"code\":-32000,\"message\":\"seal-host: approval refused (signed decline for target {})\"}}}}\n",
                            target
                        );
                        if write_frame(&output, &refused).is_err() {
                            break;
                        }
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
                        if !admit_pending_approvals(
                            &mut pending_approvals,
                            &records,
                            now_ms(),
                            ttl_ms,
                        ) {
                            warnings.extend(a3_warnings);
                            emit_approval_drop_warnings(&warnings);
                            if write_frame(&output, RESOURCE_LIMIT_RESPONSE).is_err() {
                                break;
                            }
                            continue;
                        }
                        warnings.extend(a3_warnings);
                        emit_approval_drop_warnings(&warnings);
                        if !records.is_empty() {
                            let approvals: Vec<Value> = records
                                .iter()
                                .map(|r| json!({"target": r.target, "issuedAt": r.issued_at}))
                                .collect();
                            let mut retry = json!({
                                "line": line, "now": now_ms(), "approvals": approvals,
                                "votes": read_or_empty(&votes_file),
                                "grants": grants.fresh(),
                                "forecasts": read_or_empty(&forecasts_file),
                            });
                            // Same wire arrival, same envelope: the nonce was
                            // consumed once above and is NOT re-filtered —
                            // freshness is per wire line, not per step call.
                            if let Some(env) = &envelope {
                                retry["envelope"] = env.lean_value();
                            }
                            let retry_now = retry["now"].as_u64().unwrap_or(0);
                            let retry_output = match host.step(&retry.to_string()) {
                                Ok(output) => output,
                                Err(error) => {
                                    eprintln!(
                                        "{}",
                                        json!({"error": format!("seam error: {error}")})
                                    );
                                    if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                                        break;
                                    }
                                    continue;
                                }
                            };
                            if let Some(verified) = &verified_v23 {
                                if let Err(error) =
                                    envelope_v23::verify_kernel_principal(&retry_output, verified)
                                {
                                    eprintln!(
                                        "{}",
                                        json!({"error": format!(
                                            "V2.3 kernel cross-check refused: {error}"
                                        )})
                                    );
                                    if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                                        break;
                                    }
                                    continue;
                                }
                            }
                            match route_of_step_output(Ok(retry_output.clone())) {
                                Route::Forward { audit } => {
                                    pending_approval_challenge = None;
                                    if let Some(a) = audit {
                                        if emit_audit(&mut receipts, &a).is_err() {
                                            if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                                                break;
                                            }
                                            continue;
                                        }
                                    }
                                    let consumed = match persist_decision(
                                        &mut authorization_decisions,
                                        DecisionInput {
                                            line,
                                            framed_subject: &wire,
                                            session: &receipt_session,
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
                                            if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                                                break;
                                            }
                                            continue;
                                        }
                                    };
                                    consume_pending_approval(&mut pending_approvals, consumed);
                                    if write_child(&mut child_in, &forward, &readiness).is_err() {
                                        let _ = write_frame(&output, SEAM_ERROR_RESPONSE);
                                        break;
                                    }
                                    continue;
                                }
                                Route::Block {
                                    response: r2,
                                    audit,
                                } => {
                                    if let Some(a) = audit {
                                        if emit_audit(&mut receipts, &a).is_err() {
                                            if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                                                break;
                                            }
                                            continue;
                                        }
                                    }
                                    if persist_decision(
                                        &mut authorization_decisions,
                                        DecisionInput {
                                            line,
                                            framed_subject: &wire,
                                            session: &receipt_session,
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
                                        if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                                            break;
                                        }
                                        continue;
                                    }
                                    pending_approval_challenge = r2
                                        .split("approval required: ")
                                        .nth(1)
                                        .and_then(extract_target_hex)
                                        .map(|target| (framed_sha256.clone(), wire.len(), target));
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
                response = match refusal_with_framed_subject(&response, &wire, &framed_sha256) {
                    Ok(response) => response,
                    Err(error) => {
                        eprintln!("{}", json!({"error": error}));
                        SEAM_ERROR_RESPONSE.to_string()
                    }
                };
                if write_frame(&output, &response).is_err() {
                    break;
                }
            }
            Route::SeamFailure { reason } => {
                eprintln!("{}", json!({"error": reason}));
                if write_frame(&output, SEAM_ERROR_RESPONSE).is_err() {
                    break;
                }
            }
        }
    }

    readiness.store(false, Ordering::Release);
    let _ = child.kill();
    let code = child.wait().map(|s| s.code().unwrap_or(0)).unwrap_or(0);
    let _ = relay.join();
    output_queue.shutdown();
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn approval_refusal_emits_exact_framed_subject_with_explicit_identity() {
        let frame = b"{\"jsonrpc\":\"2.0\",\"id\":1}\r\n";
        let digest = sha256_hex(frame);
        let response = concat!(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",",
            "\"text\":\"approval required: ",
            "58309503cc30803da92ad66ba02f9b3e182d6513fad532dea18d37d3f25eb39d",
            "\"}],\"isError\":true}}\n"
        );
        let enriched =
            refusal_with_framed_subject(response, frame, &digest).expect("enrich refusal");
        let parsed: Value = serde_json::from_str(&enriched).expect("enriched refusal parses");
        let subject = &parsed["result"]["framed_subject"];
        assert_eq!(subject["encoding"], "base64");
        assert_eq!(subject["length"], frame.len());
        assert_eq!(subject["sha256"], digest);
        assert_eq!(
            STANDARD
                .decode(subject["base64"].as_str().expect("base64 string"))
                .expect("base64 decodes"),
            frame
        );
        assert_eq!(
            parsed["result"]["content"][0]["text"],
            concat!(
                "approval required: ",
                "58309503cc30803da92ad66ba02f9b3e182d6513fad532dea18d37d3f25eb39d"
            )
        );
    }

    #[test]
    fn production_preflight_requires_complete_private_state() {
        let root =
            std::env::temp_dir().join(format!("seal-production-preflight-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        secure_fs::ensure_private_dir(&root, "test root").unwrap();
        let config = root.join("trusted.json");
        let token = root.join("tokens.ndjson");
        let receipts = root.join("receipts");
        secure_fs::ensure_private_file(&config, "test config").unwrap();
        secure_fs::ensure_private_file(&token, "test token").unwrap();

        let args = Args {
            config: config.to_string_lossy().into_owned(),
            pubkey: "00".repeat(32),
            channel: "ed25519".into(),
            token_file: Some(token.to_string_lossy().into_owned()),
            approval_pubkey: Some("11".repeat(32)),
            receipt_dir: Some(receipts.to_string_lossy().into_owned()),
            production: true,
            envelope_v23: false,
            health: false,
            health_listen: "127.0.0.1:9464".into(),
            health_token_file: None,
            cmd: vec!["/bin/cat".into()],
        };
        let replay = root.join("replay.sqlite");
        assert!(production_preflight(&args, replay.to_str()).is_ok());

        std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(production_preflight(&args, replay.to_str())
            .unwrap_err()
            .contains("required 0600"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn validate_refuses_oversized_input_file() {
        let path =
            std::env::temp_dir().join(format!("seal-validate-oversized-{}", std::process::id()));
        std::fs::write(&path, vec![b' '; MAX_WIRE_MESSAGE_BYTES + 1]).unwrap();
        let result = run_validate(&[path.to_string_lossy().into_owned()]);
        std::fs::remove_file(path).unwrap();
        assert_ne!(result, 0);
    }

    fn mode_args(extra: &[&str]) -> Vec<String> {
        [
            vec![
                "--config".to_string(),
                "config.json".to_string(),
                "--pubkey".to_string(),
                "00".repeat(32),
            ],
            extra.iter().map(|value| (*value).to_string()).collect(),
            vec!["--".to_string(), "/bin/cat".to_string()],
        ]
        .concat()
    }

    #[test]
    fn production_preflight_is_the_default_mode() {
        let args = parse_args_from(mode_args(&[])).unwrap();
        assert!(args.production);
        assert_eq!(startup_mode_warning(&args), None);
    }

    #[test]
    fn insecure_development_mode_requires_explicit_opt_out() {
        let args = parse_args_from(mode_args(&["--insecure-development-mode"])).unwrap();
        assert!(!args.production);
        assert_eq!(startup_mode_warning(&args), Some(INSECURE_MODE_WARNING));
        assert!(INSECURE_MODE_WARNING.contains("WARNING: INSECURE DEVELOPMENT MODE ENABLED"));
    }

    #[test]
    fn envelope_v23_flag_does_not_weaken_production_default() {
        let args = parse_args_from(mode_args(&["--envelope-v23"])).unwrap();
        assert!(args.envelope_v23);
        assert!(args.production);
        assert_eq!(startup_mode_warning(&args), None);
    }

    /// V2.1 envelope extractor: plain lines are BYTE-UNTOUCHED (any JSON
    /// without a top-level `seal_env`, non-objects, non-JSON), every
    /// malformed-envelope shape refuses, the line-smuggling rule holds, and
    /// a nested `seal_env` inside a normal call's arguments is inert.
    #[test]
    fn envelope_view_strict_predicate() {
        // plain: non-JSON, non-object, and objects without seal_env
        for plain in [
            "not json at all",
            "[1,2,3]",
            "42",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"t","arguments":{"seal_env":{"key_id":"a","sig":"b","nonce":"c","issued_at":1}}}}"#,
        ] {
            assert_eq!(envelope_view(plain), EnvelopeView::Plain, "{plain}");
        }
        // well-formed
        let good = r#"{"seal_env":{"key_id":"alice","sig":"aa","nonce":"bb","issued_at":5},"request":"{\"m\":1}"}"#;
        match envelope_view(good) {
            EnvelopeView::Enveloped { request, env } => {
                assert_eq!(request, "{\"m\":1}");
                assert_eq!(env.key_id, "alice");
                assert_eq!(env.issued_at, 5);
            }
            other => panic!("expected Enveloped, got {other:?}"),
        }
        // every malformed shape refuses
        for bad in [
            // extra top-level key
            r#"{"seal_env":{"key_id":"a","sig":"b","nonce":"c","issued_at":1},"request":"r","x":1}"#,
            // missing request
            r#"{"seal_env":{"key_id":"a","sig":"b","nonce":"c","issued_at":1}}"#,
            // seal_env not an object
            r#"{"seal_env":"x","request":"r"}"#,
            // missing / extra seal_env field
            r#"{"seal_env":{"key_id":"a","sig":"b","nonce":"c"},"request":"r"}"#,
            r#"{"seal_env":{"key_id":"a","sig":"b","nonce":"c","issued_at":1,"z":2},"request":"r"}"#,
            // wrong field types
            r#"{"seal_env":{"key_id":1,"sig":"b","nonce":"c","issued_at":1},"request":"r"}"#,
            r#"{"seal_env":{"key_id":"a","sig":"b","nonce":"c","issued_at":"1"},"request":"r"}"#,
            // request not a string / empty
            r#"{"seal_env":{"key_id":"a","sig":"b","nonce":"c","issued_at":1},"request":{}}"#,
            r#"{"seal_env":{"key_id":"a","sig":"b","nonce":"c","issued_at":1},"request":""}"#,
            // line smuggling: escaped newline / CR / NUL inside the string
            "{\"seal_env\":{\"key_id\":\"a\",\"sig\":\"b\",\"nonce\":\"c\",\"issued_at\":1},\"request\":\"one\\ntwo\"}",
            "{\"seal_env\":{\"key_id\":\"a\",\"sig\":\"b\",\"nonce\":\"c\",\"issued_at\":1},\"request\":\"one\\rtwo\"}",
            "{\"seal_env\":{\"key_id\":\"a\",\"sig\":\"b\",\"nonce\":\"c\",\"issued_at\":1},\"request\":\"one\\u0000two\"}",
        ] {
            assert!(
                matches!(envelope_view(bad), EnvelopeView::Malformed(_)),
                "should refuse: {bad}"
            );
        }
    }

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

    /// P2-c signal, unit half: `reduced_scope_forward_attempt_line` fires EXACTLY on the
    /// unrecoverable-request condition and is silent on a normal parseable ALLOW.
    #[test]
    fn reduced_scope_forward_attempt_line_fires_only_on_unrecoverable_request() {
        // Parseable guarded call → no signal (a normal ALLOW must stay silent).
        let parseable = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table t"}}}"#;
        assert!(
            reduced_scope_forward_attempt_line(parseable, 1).is_none(),
            "a parseable ALLOW must not emit the reduced-scope signal"
        );

        // Whole-line serde failure (the 1e309 class) → signal fires, tool_hint
        // is null (the line is not parseable JSON), request_sha256 matches.
        let overflow = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table t","x":1e309}}}"#;
        let signal = reduced_scope_forward_attempt_line(overflow, 7)
            .expect("unrecoverable line must signal");
        let parsed: serde_json::Value = serde_json::from_str(&signal).unwrap();
        assert_eq!(parsed["event"], "reduced_scope_forward_attempt");
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
    fn reduced_scope_forward_attempt_line_escapes_hostile_tool_hint_no_second_line() {
        // Quote-break, CR/LF newline forge, ANSI escape, NUL — the smuggling kit.
        let hostile =
            "\"}\n{\"event\":\"reduced_scope_forward_attempt\",\"tool_hint\":\"FORGED\"}\r\n\u{1b}[31mx\u{1b}[0m\u{0000}end";
        // Valid JSON with a string params.name but a NON-OBJECT arguments →
        // request_parts fails on "lacks object params.arguments", so the signal
        // fires AND carries the hostile name as tool_hint.
        let wire = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": hostile, "arguments": "drop"}
        })
        .to_string();
        let signal =
            reduced_scope_forward_attempt_line(&wire, 1).expect("non-object-args line must signal");

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
        assert_eq!(parsed["event"], "reduced_scope_forward_attempt");
        assert_eq!(
            parsed.as_object().unwrap().len(),
            5,
            "exactly one signal object"
        );
    }

    /// PURE, HOST-SIDE half of T3: `lean_view` collapses the three terminator
    /// forms (`\r\n`, `\n`, none) to one committed string, and the host's OWN
    /// commitment fn (`authorization_decision::sha256_hex`, the same call the host
    /// makes at `authorization_decision.rs`) over that string yields the golden
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
            seal_host_rs::authorization_decision::sha256_hex(lean_view(b"x\r\n")),
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
