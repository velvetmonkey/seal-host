// SPDX-License-Identifier: Apache-2.0
//! Host-side contract tests for the gated V2.3 effect envelope. These are
//! tested Rust obligations, not claims that the currently pinned Lean wasm
//! contains Fable's V2.3 proof package.

use ed25519_dalek::{Signer, SigningKey};
use seal_host_rs::envelope_v23::{
    effect_message, verify, verify_kernel_principal, wire_view, AdapterClaim, DelegationSeats,
    EffectClaim, EnvelopeV23, HostContext, PrincipalClaim, VerifiedEnvelope, WireView,
};
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

const PRINCIPAL_SEED: [u8; 32] = [1; 32];

fn proof_golden_envelope() -> EnvelopeV23 {
    EnvelopeV23 {
        key_id: "alice".into(),
        sig: String::new(),
        nonce: hex::encode((0u8..32).collect::<Vec<_>>()),
        issued_at: 1234,
        adapter: AdapterClaim {
            kind: "mcp".into(),
            version: "2025-06-18".into(),
        },
        principal: PrincipalClaim {
            session: "sess-1".into(),
        },
        effect: Some(EffectClaim {
            resource: "db.execute".into(),
            action: "call".into(),
            args: r#"{"q":1}"#.into(),
        }),
        idempotency_key: "idem-1".into(),
        policy_version: String::new(),
        delegation: DelegationSeats::default(),
        revocation_subject: String::new(),
        audience: String::new(),
        causality_token: String::new(),
        expires_at: 0,
    }
}

#[test]
fn byte_twin_matches_fable_golden_vector() {
    let authority: [u8; 32] = std::array::from_fn(|index| 0xa0 + index as u8);
    let actual =
        hex::encode(effect_message(&authority, &proof_golden_envelope(), r#"{"m":1}"#).unwrap());
    let expected = "7365616c2e6566666563742f763100a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000005616c696365000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000004d200000000000000077b226d223a317d00000000000000036d6370000000000000000a323032352d30362d31380000000000000006736573732d31000000000000000a64622e65786563757465000000000000000463616c6c00000000000000077b2271223a317d00000000000000066964656d2d310000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(actual, expected);
}

fn fixture() -> (EnvelopeV23, String, String, serde_json::Value) {
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","action":"call","arguments":{"q":1}}}"#.to_string();
    let authority: [u8; 32] = std::array::from_fn(|index| 0xa0 + index as u8);
    let signing_key = SigningKey::from_bytes(&PRINCIPAL_SEED);
    let kernel_config = json!({
        "epoch": 1,
        "principals": {"keys": [{
            "id": "alice",
            "pubkey": hex::encode(signing_key.verifying_key().to_bytes())
        }]}
    });
    let mut envelope = EnvelopeV23 {
        key_id: "alice".into(),
        sig: String::new(),
        nonce: "11".repeat(32),
        issued_at: 1234,
        adapter: AdapterClaim::deployed_mcp(),
        principal: PrincipalClaim {
            session: "seal-session-v1:test".into(),
        },
        effect: Some(EffectClaim {
            resource: "db.execute".into(),
            action: "call".into(),
            args: r#"{"q":1}"#.into(),
        }),
        idempotency_key: "idem-1".into(),
        // Deliberately differs from config epoch: F5 is a signed seat, not a gate.
        policy_version: "999".into(),
        delegation: DelegationSeats::default(),
        revocation_subject: String::new(),
        audience: String::new(),
        causality_token: String::new(),
        expires_at: 0,
    };
    envelope.sig = hex::encode(
        signing_key
            .sign(&effect_message(&authority, &envelope, &line).unwrap())
            .to_bytes(),
    );
    (envelope, line, hex::encode(authority), kernel_config)
}

fn resign(envelope: &mut EnvelopeV23, line: &str, authority_hex: &str) {
    let authority: [u8; 32] = hex::decode(authority_hex).unwrap().try_into().unwrap();
    envelope.sig = hex::encode(
        SigningKey::from_bytes(&PRINCIPAL_SEED)
            .sign(&effect_message(&authority, envelope, line).unwrap())
            .to_bytes(),
    );
}

fn verify_fixture(
    envelope: &EnvelopeV23,
    line: &str,
    authority_hex: &str,
    kernel_config: &serde_json::Value,
) -> Result<VerifiedEnvelope, String> {
    let adapter = AdapterClaim::deployed_mcp();
    verify(
        envelope,
        line,
        &HostContext {
            authority_hex,
            session: "seal-session-v1:test",
            adapter: &adapter,
            kernel_config,
        },
    )
}

#[test]
fn empty_seats_and_epoch_mismatch_are_accepted() {
    let (envelope, line, authority, config) = fixture();
    assert_eq!(envelope.policy_version, "999");
    assert_eq!(config["epoch"], 1);
    assert_eq!(
        verify_fixture(&envelope, &line, &authority, &config)
            .unwrap()
            .principal,
        "alice"
    );
}

#[test]
fn confused_deputy_effect_mismatch_fails_closed_even_when_signed() {
    let (mut envelope, line, authority, config) = fixture();
    envelope.effect.as_mut().unwrap().resource = "prod.root".into();
    resign(&mut envelope, &line, &authority);
    let error = verify_fixture(&envelope, &line, &authority, &config).unwrap_err();
    assert!(error.contains("effect claim"), "{error}");
}

#[test]
fn session_mismatch_fails_closed_even_when_signed() {
    let (mut envelope, line, authority, config) = fixture();
    envelope.principal.session = "seal-session-v1:other".into();
    resign(&mut envelope, &line, &authority);
    let error = verify_fixture(&envelope, &line, &authority, &config).unwrap_err();
    assert!(error.contains("issued session"), "{error}");
}

#[test]
fn kernel_principal_is_cross_checked() {
    let verified = VerifiedEnvelope {
        principal: "alice".into(),
    };
    assert!(
        verify_kernel_principal(r#"{"route":"forward","principal":"alice"}"#, &verified).is_ok()
    );
    assert!(
        verify_kernel_principal(r#"{"route":"forward","principal":"bob"}"#, &verified).is_err()
    );
    assert!(verify_kernel_principal(r#"{"route":"forward"}"#, &verified).is_err());
}

#[test]
fn strict_wire_shape_accepts_omitted_empty_seats() {
    let (envelope, line, _, _) = fixture();
    let mut env = serde_json::to_value(envelope).unwrap();
    for key in [
        "policy_version",
        "delegation",
        "revocation_subject",
        "audience",
        "causality_token",
        "expires_at",
    ] {
        env.as_object_mut().unwrap().remove(key);
    }
    let wrapper = json!({"seal_env": env, "request": line}).to_string();
    match wire_view(&wrapper) {
        WireView::Enveloped { envelope, .. } => {
            assert!(envelope.policy_version.is_empty());
            assert_eq!(envelope.expires_at, 0);
            assert_eq!(envelope.delegation, DelegationSeats::default());
        }
        other => panic!("unexpected wire view: {other:?}"),
    }
}

struct RunningHost {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    directory: std::path::PathBuf,
}

impl RunningHost {
    fn send(&mut self, line: &str) {
        writeln!(self.stdin, "{line}").unwrap();
        self.stdin.flush().unwrap();
    }

    fn receive(&self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(20))
            .expect("host produced no output frame")
    }
}

impl Drop for RunningHost {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn spawn_v23_host() -> (RunningHost, SigningKey, serde_json::Value) {
    let directory = std::env::temp_dir().join(format!(
        "seal-v23-host-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let approvals = directory.join("approvals.ndjson");
    std::fs::write(&approvals, b"").unwrap();

    let authority_key = SigningKey::from_bytes(&[7; 32]);
    let principal_key = SigningKey::from_bytes(&PRINCIPAL_SEED);
    let payload = json!({
        "epoch": 1,
        "safety": {
            "approval": {
                "control_file": approvals.to_str().unwrap(),
                "ttl_seconds": 120
            },
            "tools": [{"name": "db.execute", "mode": "allow"}]
        },
        "principals": {
            "keys": [{
                "id": "alice",
                "pubkey": hex::encode(principal_key.verifying_key().to_bytes())
            }],
            "budgets": [{"name": "db-budget", "cap": 2, "tools": ["db.execute"]}]
        }
    });
    let payload_text = payload.to_string();
    let trusted = json!({
        "payload": payload_text,
        "signature": hex::encode(authority_key.sign(payload_text.as_bytes()).to_bytes())
    });
    let config = directory.join("trusted.json");
    std::fs::write(&config, trusted.to_string()).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--pubkey",
            &hex::encode(authority_key.verifying_key().to_bytes()),
            "--channel",
            "file",
            "--envelope-v23",
            "--",
            "/bin/cat",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            if line.is_err() {
                break;
            }
        }
    });
    let (sender, lines) = channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    (
        RunningHost {
            child,
            stdin,
            lines,
            directory,
        },
        authority_key,
        payload,
    )
}

#[test]
fn runtime_issues_session_first_and_has_no_pre_repin_forward_path() {
    let (mut host, authority_key, kernel_config) = spawn_v23_host();
    let issuance: serde_json::Value = serde_json::from_str(&host.receive()).unwrap();
    assert_eq!(issuance["method"], "notifications/seal/session");
    assert_eq!(issuance["params"]["schema"], "seal.session/v1");
    assert_eq!(issuance["params"]["envelope"], "seal.effect/v1");
    let session = issuance["params"]["session"].as_str().unwrap();
    assert!(session.starts_with("seal-session-v1:"));
    assert!(!session.starts_with("seal-host-rs/stdio:"));

    let initialize = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}"#;
    host.send(initialize);
    assert_eq!(host.receive(), initialize);

    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","action":"call","arguments":{"q":1}}}"#;
    let principal_key = SigningKey::from_bytes(&PRINCIPAL_SEED);
    let authority = authority_key.verifying_key().to_bytes();
    let mut envelope = EnvelopeV23 {
        key_id: "alice".into(),
        sig: String::new(),
        nonce: "22".repeat(32),
        issued_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        adapter: AdapterClaim::deployed_mcp(),
        principal: PrincipalClaim {
            session: session.into(),
        },
        effect: Some(EffectClaim {
            resource: "db.execute".into(),
            action: "call".into(),
            args: r#"{"q":1}"#.into(),
        }),
        idempotency_key: "idem-runtime-1".into(),
        policy_version: "different-from-epoch".into(),
        delegation: DelegationSeats::default(),
        revocation_subject: String::new(),
        audience: String::new(),
        causality_token: String::new(),
        expires_at: 0,
    };
    envelope.sig = hex::encode(
        principal_key
            .sign(&effect_message(&authority, &envelope, line).unwrap())
            .to_bytes(),
    );
    // Prove the Rust side accepts this exact tuple before exercising the
    // runtime's independent-kernel-principal cross-check.
    assert!(verify(
        &envelope,
        line,
        &HostContext {
            authority_hex: &hex::encode(authority),
            session,
            adapter: &AdapterClaim::deployed_mcp(),
            kernel_config: &kernel_config,
        }
    )
    .is_ok());
    host.send(&json!({"seal_env": envelope, "request": line}).to_string());
    assert_eq!(
        host.receive(),
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"seal-host: mediation seam failure; request blocked"}}"#
    );

    // A blocked staged call does not kill or desynchronize the stdio session.
    let initialize_again = r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{}}"#;
    host.send(initialize_again);
    assert_eq!(host.receive(), initialize_again);
}
