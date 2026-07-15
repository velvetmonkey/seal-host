// SPDX-License-Identifier: Apache-2.0
//! A1 — the 32-topology capability matrix, generated and asserted against
//! the deployed binary.
//!
//! `Ffi.registryFor_kernels` (FfiSpec.lean) already PROVES the registry
//! registers exactly `activeKernels s.config` — Safety and Temporal always,
//! consensus/convergence/calibration/linear/budget iff the config selects
//! them, calibration double-gated. This suite does NOT re-assert registry
//! construction; it asserts the layer the theorem cannot reach: the shipped
//! `seal-host-rs` process, at each of the 32 deployable configs, actually
//! ENFORCES what that registry implies.
//!
//! For every config (5-bit mask over {C,V,K,L,B}; S+T unconditional):
//!
//!   - every ACTIVE kernel is shown DENYING a real call through the real
//!     host, with a persisted receipt naming it in `deny_kernel`;
//!   - every INACTIVE kernel is shown NOT gating — its deny-input forwards
//!     verbatim and no cert from it appears in any receipt — while Safety
//!     and Temporal still deny at that same config (absence is fail-open
//!     for that kernel ONLY, never overall);
//!   - the cert set of every receipt equals the mask-derived gating set
//!     exactly, so a kernel silently dropping out of (or leaking into) a
//!     permutation fails the run;
//!   - calibration's configured-but-disabled state (`enabled: false`, with
//!     the damning forecasts file still crossing the FFI seam every step)
//!     is exercised separately from the absent state, and the two must be
//!     behaviourally identical.
//!
//! Expectations derive from the mask literal alone, never from the code
//! under test. The child is `/bin/cat` and the protocol is lockstep, so a
//! forwarded line can never be mistaken for a block; receipts are persisted
//! before any forward, so they are read only after all response lines
//! arrive. There is no skip path: the binary is forced by
//! `CARGO_BIN_EXE_seal-host-rs` and a missing `libsealffi.so` is a link
//! failure.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

const BIT_CONSENSUS: u8 = 1;
const BIT_CONVERGENCE: u8 = 2;
const BIT_CALIBRATION: u8 = 4;
const BIT_LINEAR: u8 = 8;
const BIT_BUDGET: u8 = 16;

/// The five optional kernels in registry order, each with its dedicated
/// probe tool and the reason substring its deny cert must carry. Probe tools
/// are pairwise disjoint and disjoint from the safety/temporal probes, so at
/// most one optional kernel gates any call and `deny_kernel` is unambiguous.
const PROBES: [(u8, &str, &str, &str); 5] = [
    (
        BIT_CONSENSUS,
        "consensus",
        "payments.send",
        "quorum missing",
    ),
    (
        BIT_CONVERGENCE,
        "convergence",
        "store.update",
        "proven-convergent",
    ),
    (
        BIT_CALIBRATION,
        "calibration",
        "model.act",
        "forecaster uncalibrated",
    ),
    (BIT_LINEAR, "linear", "key.use", "capability exhausted"),
    (BIT_BUDGET, "budget", "notes.add", "over budget"),
];

/// Calibration's three config states. `Disabled` is the double gate's
/// distinct middle state: the section is present (its records file is
/// exported to the host and read every step) but `enabled: false` keeps the
/// kernel out of the registry.
#[derive(Clone, Copy, PartialEq)]
enum CalVariant {
    Active,
    Disabled,
    Absent,
}

/// Behavioural fingerprint of one mediated call, for cross-variant equality.
#[derive(Debug, Clone, PartialEq)]
struct Outcome {
    verdict: String,
    deny_kernel: Option<String>,
    certs: BTreeSet<String>,
}

fn probe_args(tool: &str) -> Value {
    match tool {
        "payments.send" => json!({"amount": 1}),
        "store.update" => json!({"op": "assign"}),
        "model.act" => json!({"claim": "x"}),
        "key.use" => json!({"key": "k1"}),
        "notes.add" => json!({"note": "x"}),
        "db.execute" => json!({"database": "prod", "sql": "drop table accounts"}),
        _ => json!({}),
    }
}

fn call_line(id: u64, tool: &str) -> String {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": tool, "arguments": probe_args(tool)},
    }))
    .unwrap()
}

/// Signed config envelope for one topology. Every section a set mask bit
/// selects is emitted; expectations elsewhere derive from the same mask
/// independently, so a section the parser silently ignored would surface as
/// an active-deny assertion failure.
fn write_config(mask: u8, cal: CalVariant, dir: &Path) -> (PathBuf, String) {
    std::fs::create_dir_all(dir).unwrap();
    let approvals = dir.join("approvals.ndjson");
    std::fs::write(&approvals, b"").unwrap();
    let votes = dir.join("votes.ndjson");
    std::fs::write(&votes, b"").unwrap();
    let grants = dir.join("grants.ndjson");
    std::fs::write(&grants, b"").unwrap();
    // Overconfident forecast evidence exists at EVERY topology (outcome is a
    // JSON number: booleans are silently dropped by the record parser), so
    // an inactive calibration kernel is shown not gating against present,
    // damning evidence rather than against an empty file.
    let forecasts = dir.join("forecasts.ndjson");
    let record = "{\"confidence\": 0.9, \"outcome\": 0}\n".repeat(20);
    std::fs::write(&forecasts, record).unwrap();

    let mut tools = vec![json!({
        "name": "db.execute",
        "mode": "guarded",
        "match": {"type": "contains_any_ci", "arg": "sql",
                  "needles": ["drop", "delete", "truncate"]},
        "target": [{"literal": "db"}, {"arg": "database"},
                   {"literal": "write"}, {"arg": "sql"}]
    })];
    // Unlisted tools are safety-denied ("no matching policy rule"), so every
    // probe tool carries an explicit allow rule; allow-mode ALLOWs persist
    // without an approval record ("explicit policy allow").
    for tool in [
        "session.revoke",
        "audit.read",
        "payments.send",
        "store.update",
        "model.act",
        "key.use",
        "notes.add",
    ] {
        tools.push(json!({
            "name": tool,
            "mode": "allow",
            "match": {"type": "always"},
            "target": []
        }));
    }

    let mut payload = json!({
        "epoch": 1,
        "safety": {
            "approval": {
                "control_file": approvals.to_str().unwrap(),
                "ttl_seconds": 120
            },
            "tools": tools
        },
        "temporal": {
            "policies": [{
                "name": "no-audit-after-revoke",
                "type": "no_after",
                "trigger": ["session.revoke"],
                "forbidden": ["audit.read"]
            }]
        }
    });
    let obj = payload.as_object_mut().unwrap();
    if mask & BIT_CONSENSUS != 0 {
        obj.insert(
            "consensus".into(),
            json!({
                "roster": [1, 2, 3],
                "votes_file": votes.to_str().unwrap(),
                "high_stakes": ["payments.send"]
            }),
        );
    }
    if mask & BIT_CONVERGENCE != 0 {
        obj.insert(
            "convergence".into(),
            json!({"tools": [{"tool": "store.update", "op_arg": "op"}]}),
        );
    }
    // The calibration section appears iff the variant says so; the mask's K
    // bit is set only for the Active variant, and both inactive variants run
    // exclusively on K-clear masks.
    let cal_section = match cal {
        CalVariant::Active => Some(true),
        CalVariant::Disabled => Some(false),
        CalVariant::Absent => None,
    };
    if let Some(enabled) = cal_section {
        obj.insert(
            "calibration".into(),
            json!({
                "enabled": enabled,
                "delta_num": 1,
                "delta_den": 20,
                "min_samples": 20,
                "records_file": forecasts.to_str().unwrap(),
                "gated_tools": ["model.act"]
            }),
        );
    }
    if mask & BIT_LINEAR != 0 {
        obj.insert(
            "linear".into(),
            json!({
                "grants_file": grants.to_str().unwrap(),
                "tools": [{"tool": "key.use", "cap_arg": "key"}]
            }),
        );
    }
    if mask & BIT_BUDGET != 0 {
        obj.insert(
            "budget".into(),
            json!({"budgets": [{"name": "notes", "cap": 0, "tools": ["notes.add"]}]}),
        );
    }

    let config_sk = SigningKey::from_bytes(&[7u8; 32]);
    let payload_text = payload.to_string();
    let signature = hex::encode(config_sk.sign(payload_text.as_bytes()).to_bytes());
    let envelope = json!({"payload": payload_text, "signature": signature}).to_string();
    let config = dir.join("trusted.json");
    std::fs::write(&config, envelope).unwrap();
    (config, hex::encode(config_sk.verifying_key().to_bytes()))
}

struct Topo {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    stderr_lines: Receiver<String>,
    dir: PathBuf,
}

impl Topo {
    fn spawn(mask: u8, cal: CalVariant, tag: &str) -> Topo {
        let dir =
            std::env::temp_dir().join(format!("seal-topo-{}-{mask:02}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (config, pubkey) = write_config(mask, cal, &dir);
        let mut child = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
            .args([
                "--config",
                config.to_str().unwrap(),
                "--pubkey",
                &pubkey,
                "--",
                "/bin/cat",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn seal-host-rs");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        let (err_tx, stderr_lines) = channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                let Ok(line) = line else { break };
                if err_tx.send(line).is_err() {
                    break;
                }
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

        Topo {
            child,
            stdin,
            lines,
            stderr_lines,
            dir,
        }
    }

    fn send(&mut self, line: &str) {
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .unwrap();
        self.stdin.flush().unwrap();
    }

    /// Lockstep: one output line per input line. Loud on silence — child
    /// status and stderr in the panic, no skip path.
    fn expect_line(&mut self, context: &str) -> String {
        match self.lines.recv_timeout(Duration::from_secs(20)) {
            Ok(line) => line,
            Err(e) => {
                let status = self.child.try_wait().ok().flatten();
                let mut stderr = Vec::new();
                while let Ok(line) = self.stderr_lines.recv_timeout(Duration::from_millis(50)) {
                    stderr.push(line);
                }
                panic!("no output line for {context}: {e}; status={status:?}; stderr={stderr:?}");
            }
        }
    }

    /// Receipts in decision order (filenames embed the entry counter).
    fn receipts(&self) -> Vec<Value> {
        let mut paths: Vec<_> = std::fs::read_dir(self.dir.join("seal-receipts"))
            .expect("receipt dir must exist after mediated calls")
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("json"))
            .collect();
        paths.sort();
        paths
            .into_iter()
            .map(|path| serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap())
            .collect()
    }
}

impl Drop for Topo {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn cert_kernels(receipt: &Value) -> BTreeSet<String> {
    receipt["certs"]
        .as_array()
        .unwrap_or_else(|| panic!("receipt lacks certs: {receipt}"))
        .iter()
        .map(|c| c["kernel"].as_str().unwrap().to_owned())
        .collect()
}

fn cert_of<'a>(receipt: &'a Value, kernel: &str) -> &'a Value {
    receipt["certs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["kernel"].as_str() == Some(kernel))
        .unwrap_or_else(|| panic!("no {kernel} cert in receipt: {receipt}"))
}

fn outcome_of(receipt: &Value) -> Outcome {
    Outcome {
        verdict: receipt["verdict"].as_str().unwrap().to_owned(),
        deny_kernel: receipt["deny_kernel"].as_str().map(str::to_owned),
        certs: cert_kernels(receipt),
    }
}

/// Drive one config through the full call sequence and assert every
/// expectation derived from the mask. Returns the behavioural fingerprint
/// for cross-variant comparison.
fn run_config(mask: u8, cal: CalVariant, tag: &str) -> Vec<Outcome> {
    let mut host = Topo::spawn(mask, cal, tag);
    let ctx = format!("mask={mask:#07b} tag={tag}");

    // Liveness: passthrough echoes verbatim and produces no receipt.
    let init = r#"{"jsonrpc":"2.0","id":0,"method":"initialize"}"#;
    host.send(init);
    assert_eq!(host.expect_line(&ctx), init, "[{ctx}] passthrough echo");

    // Calls 1..5: one probe per optional kernel, registry order. 6: safety
    // deny. 7: temporal trigger (forwarded — the only state-advancing call,
    // so it precedes only the call that needs it). 8: temporal deny.
    let sequence: Vec<(&str, bool)> = PROBES
        .iter()
        .map(|&(bit, _, tool, _)| (tool, mask & bit != 0))
        .chain([
            ("db.execute", true),
            ("session.revoke", false),
            ("audit.read", true),
        ])
        .collect();

    let mut responses = Vec::new();
    for (i, &(tool, blocked)) in sequence.iter().enumerate() {
        let line = call_line(i as u64 + 1, tool);
        host.send(&line);
        let response = host.expect_line(&format!("{ctx} call {tool}"));
        if blocked {
            assert!(
                response.contains("\"isError\":true"),
                "[{ctx}] {tool} must block, got: {response}"
            );
        } else {
            assert_eq!(response, line, "[{ctx}] {tool} must forward verbatim");
        }
        responses.push(response);
    }

    // Every receipt is persisted before its response line, so after eight
    // responses the eight receipts are on disk.
    let receipts = host.receipts();
    assert_eq!(receipts.len(), 8, "[{ctx}] one receipt per mediated call");

    let st: BTreeSet<String> = ["safety", "temporal"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    for (receipt, &(bit, kernel, tool, deny_reason)) in receipts.iter().zip(PROBES.iter()) {
        let active = mask & bit != 0;
        assert_eq!(
            receipt["seal_receipt"], "v2",
            "[{ctx}] {tool} receipt schema"
        );
        assert_eq!(receipt["tool"], tool, "[{ctx}] receipt order");
        let mut expected = st.clone();
        if active {
            expected.insert(kernel.to_owned());
        }
        // Exact gating-set equality: an inactive kernel emitting any cert,
        // or an active one emitting none, fails here.
        assert_eq!(
            cert_kernels(receipt),
            expected,
            "[{ctx}] {tool} certs must equal the mask-derived gating set"
        );
        assert_eq!(
            cert_of(receipt, "safety")["reason"],
            "explicit policy allow",
            "[{ctx}] {tool} safety cert"
        );
        assert_eq!(
            cert_of(receipt, "temporal")["verdict"],
            "allow",
            "[{ctx}] {tool} temporal cert"
        );
        if active {
            assert_eq!(receipt["verdict"], "BLOCK", "[{ctx}] {tool} verdict");
            assert_eq!(receipt["deny_kernel"], kernel, "[{ctx}] {tool} deny_kernel");
            let cert = cert_of(receipt, kernel);
            assert_eq!(cert["verdict"], "deny", "[{ctx}] {tool} cert verdict");
            let reason = cert["reason"].as_str().unwrap();
            assert!(
                reason.contains(deny_reason),
                "[{ctx}] {tool} deny reason {reason:?} lacks {deny_reason:?}"
            );
        } else {
            assert_eq!(receipt["verdict"], "ALLOW", "[{ctx}] {tool} verdict");
            assert_eq!(receipt["deny_kernel"], Value::Null, "[{ctx}] {tool}");
            assert_eq!(
                receipt["authorization"], "explicit_policy_allow",
                "[{ctx}] {tool} authorization"
            );
        }
    }

    // Safety and Temporal shown DENYING at every topology — their presence
    // is a theorem; their teeth are what these three receipts pin.
    let safety = &receipts[5];
    assert_eq!(safety["verdict"], "BLOCK", "[{ctx}] safety probe");
    assert_eq!(safety["deny_kernel"], "safety", "[{ctx}] safety probe");
    assert_eq!(cert_kernels(safety), st, "[{ctx}] safety probe certs");
    let target = cert_of(safety, "safety")["reason"].as_str().unwrap();
    assert!(
        target.len() == 64 && target.bytes().all(|b| b.is_ascii_hexdigit()),
        "[{ctx}] guarded deny reason must be the 64-hex target, got {target:?}"
    );

    let trigger = &receipts[6];
    assert_eq!(trigger["verdict"], "ALLOW", "[{ctx}] trigger forwards");
    assert_eq!(cert_kernels(trigger), st, "[{ctx}] trigger certs");

    let temporal = &receipts[7];
    assert_eq!(temporal["verdict"], "BLOCK", "[{ctx}] temporal probe");
    assert_eq!(
        temporal["deny_kernel"], "temporal",
        "[{ctx}] temporal probe"
    );
    assert_eq!(cert_kernels(temporal), st, "[{ctx}] temporal probe certs");
    let reason = cert_of(temporal, "temporal")["reason"].as_str().unwrap();
    assert!(
        reason.contains("temporal policy violated"),
        "[{ctx}] temporal deny reason: {reason:?}"
    );

    receipts.iter().map(outcome_of).collect()
}

/// The generated mask space partitions exactly: 16 calibration-active + 16
/// calibration-inactive = the 32 deployable topologies, disjoint. Pure
/// arithmetic pin for the two spawning tests below.
#[test]
fn topology_masks_partition() {
    let k_set: Vec<u8> = (0u8..32).filter(|m| m & BIT_CALIBRATION != 0).collect();
    let k_clear: Vec<u8> = (0u8..32).filter(|m| m & BIT_CALIBRATION == 0).collect();
    assert_eq!(k_set.len(), 16);
    assert_eq!(k_clear.len(), 16);
    let union: BTreeSet<u8> = k_set.iter().chain(k_clear.iter()).copied().collect();
    assert_eq!(union, (0u8..32).collect::<BTreeSet<u8>>());
}

/// The 16 topologies with calibration active.
#[test]
fn topology_matrix_calibration_enabled() {
    let masks: Vec<u8> = (0u8..32).filter(|m| m & BIT_CALIBRATION != 0).collect();
    assert_eq!(masks.len(), 16);
    for mask in masks {
        run_config(mask, CalVariant::Active, "act");
    }
}

/// The 16 topologies with calibration inactive, each run TWICE: section
/// absent, and section present with `enabled: false`. Both must be inactive
/// and neither may weaken any other kernel — the two runs must be
/// behaviourally identical, call for call.
#[test]
fn topology_matrix_calibration_absent_vs_disabled() {
    let masks: Vec<u8> = (0u8..32).filter(|m| m & BIT_CALIBRATION == 0).collect();
    assert_eq!(masks.len(), 16);
    for mask in masks {
        let absent = run_config(mask, CalVariant::Absent, "abs");
        let disabled = run_config(mask, CalVariant::Disabled, "dis");
        assert_eq!(
            absent, disabled,
            "mask={mask:#07b}: configured-but-disabled calibration must be \
             behaviourally identical to absent"
        );
    }
}
