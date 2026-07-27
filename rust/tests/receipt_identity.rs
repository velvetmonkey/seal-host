// SPDX-License-Identifier: Apache-2.0
//! D3 authority-frontier differential: the receipt's `approval_identity` is
//! a boot-scoped constant of the approval TRUST ROOT (channel flag + SHA-256
//! fingerprint of the configured approval verifying key) and is INDEPENDENT
//! of the mediated request bytes — including any self-asserted
//! `caller_id`/`agent`/`program_origin` field an adversary plants in the
//! arguments. This is the operational discharge of the R-IDENT seam named in
//! `Host/ReceiptIdentity.lean`: the same key/fingerprint pair is pinned there
//! by compiled evaluation (`keyFingerprint`), and here against a receipt
//! written by the REAL binary.
//!
//! What would fail this test: the finish-line checklist's D3 as written —
//! copying a `caller.caller_id` out of the request into the receipt. The
//! mutation drill in the D3 report plants exactly that and watches
//! `approval_identity_ignores_self_asserted_caller` refuse it.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use seal_host_rs::providers::{
    approval_v2_signature_preimage, canonical_approval_v2_payload, ApprovalRecordV2Payload,
    ApprovalRenderer,
};
use sha2::Digest;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

/// The approval signing key the host_path oracle uses (seed [9u8;32]). Its
/// verifying key and fingerprint are ALSO pinned in Host/ReceiptIdentity.lean
/// (`keyFingerprint` conformance #guard_msgs) — one pair, two languages.
const PINNED_APPROVAL_PUBKEY_HEX: &str =
    "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618";
const PINNED_KEY_ID: &str = "dbc298251c51321b7266e78d1c151c2b62aff8cb95b293096d3463018544face";

struct Host {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    dir: PathBuf,
}

impl Host {
    /// Spawn the real binary on the PRODUCTION channel (ed25519 signed
    /// tokens + sqlite replay store), with `cat` as the guarded server and
    /// the given approval signing key seed.
    fn spawn_signed(tag: &str, approval_seed: [u8; 32]) -> Host {
        let dir = std::env::temp_dir().join(format!(
            "seal-receipt-identity-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let approvals = dir.join("approvals.ndjson");
        std::fs::write(&approvals, b"").unwrap();
        let token_file = dir.join("tokens.ndjson");
        std::fs::write(&token_file, b"").unwrap();

        let config_sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = hex::encode(config_sk.verifying_key().to_bytes());
        let payload = serde_json::json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": approvals.to_str().unwrap(),
                    "ttl_seconds": 120,
                    "replay_store": {
                        "sqlite_path": dir.join("replay.sqlite").to_str().unwrap()
                    }
                },
                "tools": [
                    {
                        "name": "db.execute",
                        "mode": "guarded",
                        "match": {"type": "contains_any_ci", "arg": "sql",
                                  "needles": ["drop", "delete", "truncate"]},
                        "target": [{"full_arguments": true}]
                    }
                ]
            }
        })
        .to_string();
        let sig = hex::encode(config_sk.sign(payload.as_bytes()).to_bytes());
        let envelope = serde_json::json!({"payload": payload, "signature": sig}).to_string();
        let config = dir.join("trusted.json");
        std::fs::write(&config, envelope).unwrap();

        let approval_pk = hex::encode(
            SigningKey::from_bytes(&approval_seed)
                .verifying_key()
                .to_bytes(),
        );
        let args = vec![
            "--insecure-development-mode".to_string(),
            "--config".to_string(),
            config.to_str().unwrap().to_string(),
            "--pubkey".to_string(),
            pk,
            "--channel".to_string(),
            "ed25519".to_string(),
            "--token-file".to_string(),
            token_file.to_str().unwrap().to_string(),
            "--approval-pubkey".to_string(),
            approval_pk,
            "--".to_string(),
            "/bin/cat".to_string(),
        ];

        let mut child = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn seal-host-rs");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();

        // Drain stderr so the host never blocks on telemetry.
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                if line.is_err() {
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

        Host {
            child,
            stdin,
            lines,
            dir,
        }
    }

    fn send(&mut self, line: &str) {
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .unwrap();
        self.stdin.flush().unwrap();
    }

    fn expect_line(&mut self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(20))
            .expect("host produced no output line in time")
    }

    fn append_token_line(&mut self, line: &str) {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.dir.join("tokens.ndjson"))
            .unwrap();
        writeln!(f, "{line}").unwrap();
    }

    fn receipts(&self) -> Vec<serde_json::Value> {
        let mut paths: Vec<_> = std::fs::read_dir(self.dir.join("seal-receipts"))
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
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn signed_v2_token(seed: [u8; 32], target: &str, call: &str, nonce: &str) -> String {
    let sk = SigningKey::from_bytes(&seed);
    let authorized_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let framed_bytes = format!("{call}\n").into_bytes();
    let payload = ApprovalRecordV2Payload {
        approval_record_version: 2,
        target: target.to_string(),
        authorized_at,
        expiry: authorized_at + 120_000,
        nonce: nonce.to_string(),
        session: "receipt-identity-test-session".to_string(),
        subject_sha256: hex::encode(sha2::Sha256::digest(&framed_bytes)),
        subject_length: framed_bytes.len() as u64,
        subject_scope: "mcp-jsonrpc-request-frame-including-delimiter".to_string(),
        subject_encoding: "bytes".to_string(),
        shown_sha256: hex::encode(sha2::Sha256::digest(call.as_bytes())),
        shown_length: call.len() as u64,
        shown_media_type: "text/plain".to_string(),
        shown_character_encoding: "utf-8".to_string(),
        renderer: ApprovalRenderer {
            name: "receipt-identity-test-renderer".to_string(),
            version: "2.0.0".to_string(),
            manifest_sha256: hex::encode(sha2::Sha256::digest(b"receipt-identity-test-renderer")),
        },
        approver: "receipt-identity-test-human".to_string(),
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

fn is_block(line: &str) -> bool {
    line.contains("\"isError\":true") && line.contains("approval required: ")
}

fn block_target(line: &str) -> String {
    let target: String = line
        .split("approval required: ")
        .nth(1)
        .expect("block names its approval target")
        .chars()
        .take(64)
        .collect();
    assert!(
        target.len() == 64
            && target
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "target is 64 lowercase hex: {target}"
    );
    target
}

/// Drive one guarded call through block → signed approval → forward, and
/// return the ALLOW receipt the host persisted for it.
fn allow_receipt_for(
    host: &mut Host,
    seed: [u8; 32],
    call: &str,
    nonce: &str,
) -> serde_json::Value {
    host.send(call);
    let blocked = host.expect_line();
    assert!(is_block(&blocked), "unapproved call must block: {blocked}");
    let target = block_target(&blocked);
    host.append_token_line(&signed_v2_token(seed, &target, call, nonce));
    host.send(call);
    assert_eq!(
        host.expect_line(),
        call,
        "signed approval must forward the call"
    );
    host.receipts()
        .into_iter()
        .rev()
        .find(|receipt| receipt["verdict"] == "ALLOW")
        .expect("forwarded decision persisted an ALLOW receipt")
}

/// Every object key in the receipt OUTSIDE the descriptive `arguments` echo.
/// String VALUES are not keys (`canonical_request` legitimately embeds the
/// argument text); identity-shaped KEYS are what a false D3 would add.
fn keys_outside_arguments(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                out.push(key.clone());
                if key != "arguments" {
                    keys_outside_arguments(inner, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for inner in items {
                keys_outside_arguments(inner, out);
            }
        }
        _ => {}
    }
}

/// The receipt's `approval_identity` names the approval trust root — the
/// channel flag and the SHA-256 fingerprint of the CONFIGURED verifying key
/// — byte-identically across two requests that differ arbitrarily, including
/// a planted self-asserted caller identity. The adversary owns every request
/// byte; the identity must not move.
#[test]
fn approval_identity_ignores_self_asserted_caller() {
    let seed = [9u8; 32];
    let mut host = Host::spawn_signed("self-asserted", seed);

    // Cross-language pin: this test's trust root IS the pair pinned in
    // Host/ReceiptIdentity.lean (keyFingerprint conformance evaluation).
    let approval_pk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    assert_eq!(hex::encode(approval_pk), PINNED_APPROVAL_PUBKEY_HEX);
    let expected_key_id = hex::encode(sha2::Sha256::digest(approval_pk));
    assert_eq!(expected_key_id, PINNED_KEY_ID);

    // Request 1: a plain guarded call.
    let call_plain = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts"}}}"#;
    let receipt_plain = allow_receipt_for(&mut host, seed, call_plain, "n-ident-1");

    // Request 2: different id, different sql, and a planted self-asserted
    // identity — the exact field the D3 checklist would have copied.
    let call_hostile = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"delete from users","caller_id":"root","agent":"mallory","program_origin":"trusted-deploy-bot"}}}"#;
    let receipt_hostile = allow_receipt_for(&mut host, seed, call_hostile, "n-ident-2");

    // The identity is the boot constant of the trust root, on BOTH receipts.
    let expected_identity = serde_json::json!({
        "channel": "ed25519",
        "key_id": expected_key_id,
    });
    assert_eq!(
        receipt_plain["approval"]["approval_identity"], expected_identity,
        "identity must be the configured trust root, not request material"
    );
    assert_eq!(
        receipt_plain["approval"]["approval_identity"],
        receipt_hostile["approval"]["approval_identity"],
        "identity must not move when the request bytes move"
    );

    // The planted identity is echoed ONLY as descriptive argument material —
    // no identity-shaped KEY exists anywhere else in either receipt.
    for receipt in [&receipt_plain, &receipt_hostile] {
        let mut keys = Vec::new();
        keys_outside_arguments(receipt, &mut keys);
        for forbidden in ["caller_id", "program_origin", "agent", "caller"] {
            assert!(
                !keys.iter().any(|k| k == forbidden),
                "receipt must not mint a caller-identity key {forbidden:?}: {keys:?}"
            );
        }
    }

    // And the hostile receipt still binds the REQUEST faithfully (the echo
    // lives in the descriptive plane, hashed and kernel-attested).
    assert_eq!(
        receipt_hostile["request_sha256"],
        serde_json::Value::String(hex::encode(sha2::Sha256::digest(call_hostile.as_bytes()))),
        "request commitment is the hash of the exact wire line"
    );
}

/// The identity moves with the TRUST ROOT and only with it: same request
/// bytes, different configured approval key ⇒ different `key_id`, equal to
/// the new key's fingerprint.
#[test]
fn approval_identity_tracks_trust_root_not_request() {
    let call = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts"}}}"#;

    let seed_a = [9u8; 32];
    let mut host_a = Host::spawn_signed("root-a", seed_a);
    let receipt_a = allow_receipt_for(&mut host_a, seed_a, call, "n-root-a");

    let seed_b = [11u8; 32];
    let mut host_b = Host::spawn_signed("root-b", seed_b);
    let receipt_b = allow_receipt_for(&mut host_b, seed_b, call, "n-root-b");

    let fingerprint = |seed: [u8; 32]| {
        hex::encode(sha2::Sha256::digest(
            SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
        ))
    };
    assert_eq!(
        receipt_a["approval"]["approval_identity"]["key_id"],
        serde_json::Value::String(fingerprint(seed_a))
    );
    assert_eq!(
        receipt_b["approval"]["approval_identity"]["key_id"],
        serde_json::Value::String(fingerprint(seed_b))
    );
    assert_ne!(
        receipt_a["approval"]["approval_identity"]["key_id"],
        receipt_b["approval"]["approval_identity"]["key_id"],
        "same request bytes, different trust root ⇒ different identity"
    );
    // Same request commitment on both — the request did not choose the key.
    assert_eq!(receipt_a["request_sha256"], receipt_b["request_sha256"]);
}
