// SPDX-License-Identifier: Apache-2.0
//! seal-host-rs — the Rust transport host around the Lean verified core.
//!
//! Owns: stdio MITM, child server process, approval back-channel providers,
//! A3 freshness, evidence file reads, the wall clock. Does NOT own any
//! decision: every line is classified and decided by the Lean exports
//! (`seal_host_step`), and this host only routes bytes accordingly.

mod a3;
mod lean;
mod providers;

use providers::ApprovalProvider;
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

fn main() {
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
    let summary: Value = match serde_json::from_str(&host.init(&envelope, &args.pubkey)) {
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
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let wire = format!("{line}\n");
        let now = now_ms();

        // Pass non-mediated lines (initialize, tools/list, notifications)
        // straight through WITHOUT polling the approval channel. V1 reads the
        // control file only for tools/call; polling on passthrough lines would
        // advance the provider's seen-counter and consume an approval before
        // the mediated call that needs it ever sees it.
        if host.classify(&line) == 0 {
            let _ = child_in.write_all(wire.as_bytes());
            let _ = child_in.flush();
            continue;
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
        let out: Value = match serde_json::from_str(&host.step(&input.to_string())) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{}", json!({"error": format!("step output unparseable: {e}")}));
                continue; // fail-closed: never forward on a broken seam
            }
        };
        if let Some(audit) = out["audit"].as_str() {
            eprintln!("{audit}");
        }
        match out["route"].as_str() {
            Some("passthrough") | Some("forward") => {
                let _ = child_in.write_all(wire.as_bytes());
                let _ = child_in.flush();
            }
            Some("block") => {
                let mut response = out["response"].as_str().unwrap_or("").to_string();
                // Interactive channel: a missing-approval deny queues a human
                // question; a "y" mints the approval and the call retries once.
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
                            if let Ok(v) = serde_json::from_str::<Value>(&host.step(&retry.to_string())) {
                                if let Some(a) = v["audit"].as_str() {
                                    eprintln!("{a}");
                                }
                                if v["route"] == json!("forward") {
                                    let _ = child_in.write_all(wire.as_bytes());
                                    let _ = child_in.flush();
                                    continue;
                                }
                                if let Some(r) = v["response"].as_str() {
                                    response = r.to_string();
                                }
                            }
                        }
                    }
                }
                write_locked(&stdout_lock, &response);
            }
            _ => {
                eprintln!("{}", json!({"error": "missing route; not forwarding"}));
            }
        }
    }

    let _ = child.kill();
    let code = child.wait().map(|s| s.code().unwrap_or(0)).unwrap_or(0);
    let _ = relay.join();
    code
}
