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
//! | P2| stdin line                | `child_in.write_all` (step path)       | YES — `seal_host_step` route `forward`/`passthrough`, exact parse (`route_of_step_output`) |
//! | P3| stdin line                | `child_in.write_all` (interactive retry)| YES — second `seal_host_step == forward` after a human-minted approval |
//! | P4| operator argv             | `Command::new(...).spawn()`            | N/A — operator-trusted setup; the child IS the guarded resource |
//! | P5| kernel block response     | client stdout                          | YES — kernel-authored bytes |
//! | P6| child stdout              | client stdout (relay thread)           | NO — response egress is unmediated BY DESIGN (requests are mediated, responses are not; see RUST_BRIDGE.md) |
//! | P7| audit / A3 drops / errors | stderr                                 | telemetry only, no effect |
//! | P8| approval evidence         | (feeds Lean via A3 only)               | parse failure drops the record ⇒ deny |
//! | P9| votes/grants/forecasts    | (raw text to Lean)                     | Lean parses; grants cursor line-split is drop-only |
//!
//! Enforced invariant: bytes reach the child ⇔ the Lean kernel returned
//! classify == 0 or step route ∈ {forward, passthrough} for the
//! byte-identical line. Every seam error, panic, or ambiguity refuses the
//! line and answers the client with `SEAM_ERROR_RESPONSE` — the only
//! host-authored egress bytes.
//!
//! The wire bytes the client sent are forwarded VERBATIM on allow — the host
//! never reconstructs, re-encodes, or trims what the child receives.

use seal_host_rs::a3;
use seal_host_rs::lean;
use seal_host_rs::providers::{self, ApprovalProvider};
use seal_host_rs::receipt::ReceiptChain;
use seal_host_rs::route::{
    route_of_classify, route_of_step_output, ClassifyRoute, Route, SEAM_ERROR_RESPONSE,
};
use serde_json::{json, Value};

/// The active back-channel. Enum (not a trait object) so the transport can
/// reach the interactive provider's queue without downcasting.
enum Channel {
    File(providers::ControlFileProvider),
    Ed(providers::Ed25519TokenProvider),
    Tty(providers::InteractiveProvider<std::io::BufReader<std::fs::File>, std::io::Stderr>),
}

impl Channel {
    fn poll(&mut self) -> Vec<providers::ApprovalRecord> {
        match self {
            Channel::File(p) => p.poll(),
            Channel::Ed(p) => p.poll(),
            Channel::Tty(p) => p.poll(),
        }
    }

    fn queue_interactive(&mut self, target: u64) -> bool {
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
    cmd: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut config = None;
    let mut pubkey = None;
    let mut channel = "file".to_string();
    let mut token_file = None;
    let mut approval_pubkey = None;
    let mut cmd = Vec::new();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--config" => { config = argv.get(i + 1).cloned(); i += 2 }
            "--pubkey" => { pubkey = argv.get(i + 1).cloned(); i += 2 }
            "--channel" => { channel = argv.get(i + 1).cloned().unwrap_or_default(); i += 2 }
            "--token-file" => { token_file = argv.get(i + 1).cloned(); i += 2 }
            "--approval-pubkey" => { approval_pubkey = argv.get(i + 1).cloned(); i += 2 }
            "--" => { cmd = argv[i + 1..].to_vec(); break }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(Args {
        config: config.ok_or("--config required")?,
        pubkey: pubkey.ok_or("--pubkey required")?,
        channel,
        token_file,
        approval_pubkey,
        cmd: if cmd.is_empty() { return Err("server command required after --".into()) } else { cmd },
    })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn read_or_empty(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        std::fs::read_to_string(path).unwrap_or_default()
    }
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
        let lines: Vec<&str> =
            text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
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
            eprintln!("usage: seal-host-rs --config <trusted.json> --pubkey <key> \
                [--channel file|ed25519|interactive] [--token-file <path>] \
                [--approval-pubkey <hex>] -- <server-cmd> <args...>\nerror: {e}");
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
        eprintln!("trusted config rejected: {}", summary["error"].as_str().unwrap_or("unknown"));
        return 3;
    }
    let ttl_ms = summary["approval_ttl_ms"].as_u64().unwrap_or(0);
    let approval_file = summary["approval_file"].as_str().unwrap_or("").to_string();
    let votes_file = summary["votes_file"].as_str().unwrap_or("").to_string();
    let forecasts_file = summary["forecasts_file"].as_str().unwrap_or("").to_string();
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
    let mut a3 = a3::A3Filter::new(ttl_ms);
    let mut receipts = ReceiptChain::new();
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
    loop {
        wire.clear();
        match reader.read_until(b'\n', &mut wire) {
            Ok(0) => break,          // EOF: session over
            Ok(_) => {}
            Err(e) => {
                eprintln!("{}", json!({"error": format!("stdin read error: {e}")}));
                break;               // transport dead: stop mediating, kill child
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
                eprintln!("{}", json!({"error": "classify seam failure; line refused"}));
                write_locked(&stdout_lock, SEAM_ERROR_RESPONSE);
                continue;
            }
        }

        let (records, dropped) = a3.filter(provider.poll(), now);
        for reason in &dropped {
            eprintln!("{}", json!({"a3": reason}).to_string());
        }
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
        match route_of_step_output(host.step(&input.to_string())) {
            Route::Forward { audit } => {
                if let Some(a) = audit {
                    emit_audit(&mut receipts, &a);
                }
                let _ = child_in.write_all(&wire);
                let _ = child_in.flush();
            }
            Route::Block { mut response, audit } => {
                if let Some(a) = audit {
                    emit_audit(&mut receipts, &a);
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
                        .and_then(|s| {
                            let digits: String =
                                s.chars().take_while(|c| c.is_ascii_digit()).collect();
                            digits.parse::<u64>().ok()
                        })
                    {
                        provider.queue_interactive(target);
                        let (records, _) = a3.filter(provider.poll(), now);
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
                            match route_of_step_output(host.step(&retry.to_string())) {
                                Route::Forward { audit } => {
                                    if let Some(a) = audit {
                                        emit_audit(&mut receipts, &a);
                                    }
                                    let _ = child_in.write_all(&wire);
                                    let _ = child_in.flush();
                                    continue;
                                }
                                Route::Block { response: r2, audit } => {
                                    if let Some(a) = audit {
                                        emit_audit(&mut receipts, &a);
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
