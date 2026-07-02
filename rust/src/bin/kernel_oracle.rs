// SPDX-License-Identifier: Apache-2.0
//! Conformance-bridge NATIVE oracle.
//!
//! Calls the SAME `seal_host_init` / `seal_host_step` the deployed
//! `seal-host-rs` binary calls, through `LeanHost` (which links
//! `libsealffi.so` — the Lean decision core compiled Lean → C → native). This
//! is the COMPILED-artifact side of the differential; the model side is the
//! Lean interpreter (`scripts/model_oracle.lean`). Feeding both the same
//! step-input JSONs and diffing the output bytes tests that codegen preserves
//! the proven decisions and audit certificates on the corpus.
//!
//! Usage:
//!   kernel_oracle <envelope-file> <pubkey>
//!   # step-input JSON objects on stdin, one per line; one output JSON per line.

use seal_host_rs::lean::LeanHost;
use std::io::{BufRead, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: kernel_oracle <envelope-file> <pubkey>  (step inputs on stdin)");
        std::process::exit(2);
    }
    let envelope = match std::fs::read_to_string(&args[1]) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("kernel_oracle: cannot read envelope {}: {e}", args[1]);
            std::process::exit(2);
        }
    };
    let pk = &args[2];

    let host = LeanHost::new();
    match host.init(&envelope, pk) {
        Ok(out) => {
            if !out.contains("\"ok\":true") {
                eprintln!("kernel_oracle: init failed: {out}");
                std::process::exit(3);
            }
        }
        Err(e) => {
            eprintln!("kernel_oracle: init seam error: {e}");
            std::process::exit(3);
        }
    }

    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        // Any seam error resolves to a diagnostic line (never a routable
        // default) — the bridge treats it as a divergence.
        match host.step(t) {
            Ok(o) => {
                let _ = writeln!(out, "{o}");
            }
            Err(e) => {
                let _ = writeln!(out, "{{\"seam_error\":\"{e}\"}}");
            }
        }
        let _ = out.flush();
    }
}
