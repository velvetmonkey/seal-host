// SPDX-License-Identifier: Apache-2.0
//! Host-side contract tests for the gated Stage B (`seal.effect/v2`) effect
//! envelope. These are tested Rust obligations, not claims that the currently
//! pinned Lean wasm contains Fable's V2.3 proof package.
//!
//! The killed-field and cross-version cases below are the Stage B NEGATIVE
//! CONTROLS: reverting the strip (re-adding a killed field to `EnvelopeV23`)
//! or reverting the domain-tag bump makes them fail.

use ed25519_dalek::{Signer, SigningKey};
use seal_host_rs::envelope_v23::{
    effect_message, verify, verify_kernel_principal, wire_view, AdapterClaim, EffectClaim,
    EnvelopeV23, HostContext, PrincipalClaim, VerifiedEnvelope, WireView, DOMAIN_TAG,
};
use serde_json::json;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

const PRINCIPAL_SEED: [u8; 32] = [1; 32];

/// The RETIRED `seal.effect/v1` domain tag — test-local on purpose: the
/// production module must not export the dead tag.
const DOMAIN_TAG_V1_RETIRED: &[u8] = b"seal.effect/v1\0";

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
        revocation_subject: String::new(),
    }
}

#[test]
fn byte_twin_matches_fable_golden_vector() {
    let authority: [u8; 32] = std::array::from_fn(|index| 0xa0 + index as u8);
    let actual =
        hex::encode(effect_message(&authority, &proof_golden_envelope(), r#"{"m":1}"#).unwrap());
    let expected = "7365616c2e6566666563742f763200a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000005616c696365000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000004d200000000000000077b226d223a317d00000000000000036d6370000000000000000a323032352d30362d31380000000000000006736573732d31000000000000000a64622e65786563757465000000000000000463616c6c00000000000000077b2271223a317d0000000000000000";
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
        revocation_subject: String::new(),
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
fn stripped_envelope_verifies() {
    let (envelope, line, authority, config) = fixture();
    assert_eq!(
        verify_fixture(&envelope, &line, &authority, &config)
            .unwrap()
            .principal,
        "alice"
    );
}

/// NEGATIVE CONTROL (strip): a wire envelope carrying ANY E1★ killed field
/// must fail closed at parse. Re-adding a killed field to `EnvelopeV23`
/// makes the corresponding case here pass parsing and this test fail.
#[test]
fn killed_field_in_wire_envelope_fails_closed() {
    let (envelope, line, _, _) = fixture();
    let killed: [(&str, serde_json::Value); 7] = [
        ("idempotency_key", json!("idem-1")),
        ("policy_version", json!("policy-7")),
        ("on_behalf_of", json!("orch:alpha")),
        ("parent_capability_ref", json!("cap:parent/9")),
        ("audience", json!("aud:fleet-1")),
        ("causality_token", json!("ct:42")),
        ("expires_at", json!(1234567890123u64)),
    ];
    for (key, value) in killed {
        let mut env = serde_json::to_value(&envelope).unwrap();
        env.as_object_mut().unwrap().insert(key.into(), value);
        let wrapper = json!({"seal_env": env, "request": line}).to_string();
        match wire_view(&wrapper) {
            WireView::Malformed(reason) => assert!(
                reason.contains("invalid seal_env"),
                "killed field {key}: unexpected reason {reason}"
            ),
            other => panic!("killed field {key} was accepted: {other:?}"),
        }
    }
    // Same for the retired F6 delegation OBJECT shape.
    let mut env = serde_json::to_value(&envelope).unwrap();
    env.as_object_mut().unwrap().insert(
        "delegation".into(),
        json!({"on_behalf_of": "", "parent_capability_ref": ""}),
    );
    let wrapper = json!({"seal_env": env, "request": line}).to_string();
    assert!(
        matches!(wire_view(&wrapper), WireView::Malformed(_)),
        "delegation object was accepted"
    );
}

/// The RETIRED `seal.effect/v1` message layout, reconstructed test-locally:
/// old tag, then the same bound prefix, then the killed seat frames and the
/// trailing `u64be(expires_at)`. Seats are encoded at their v1 "unset" wire
/// values (empty frames / zero), which is exactly the closest v1 receipt to
/// a stripped v2 one.
fn legacy_v1_effect_message(authority: &[u8; 32], envelope: &EnvelopeV23, line: &str) -> Vec<u8> {
    fn frame(message: &mut Vec<u8>, bytes: &[u8]) {
        message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        message.extend_from_slice(bytes);
    }
    let nonce: [u8; 32] = hex::decode(&envelope.nonce).unwrap().try_into().unwrap();
    let effect = envelope.effect.clone().unwrap_or(EffectClaim {
        resource: String::new(),
        action: String::new(),
        args: String::new(),
    });
    let mut message = Vec::new();
    message.extend_from_slice(DOMAIN_TAG_V1_RETIRED);
    message.extend_from_slice(authority);
    frame(&mut message, envelope.key_id.as_bytes());
    message.extend_from_slice(&nonce);
    message.extend_from_slice(&envelope.issued_at.to_be_bytes());
    frame(&mut message, line.as_bytes());
    frame(&mut message, envelope.adapter.kind.as_bytes());
    frame(&mut message, envelope.adapter.version.as_bytes());
    frame(&mut message, envelope.principal.session.as_bytes());
    frame(&mut message, effect.resource.as_bytes());
    frame(&mut message, effect.action.as_bytes());
    frame(&mut message, effect.args.as_bytes());
    for _ in 0..7 {
        // idempotency_key, policy_version, on_behalf_of, parent_capability_ref,
        // revocation_subject, audience, causality_token — all unset (len 0).
        frame(&mut message, b"");
    }
    message.extend_from_slice(&0u64.to_be_bytes()); // expires_at = 0
    message
}

/// NEGATIVE CONTROL (cross-version): a receipt signed under the retired
/// `seal.effect/v1` layout must NOT verify under the v2 verifier — the Rust
/// executable face of the Lean theorem `effect_cross_version_v1_separated`.
/// Reverting the domain-tag bump makes the v1 and v2 messages coincide on
/// this fixture and this test fail.
#[test]
fn v1_tagged_receipt_fails_closed_under_v2() {
    let (mut envelope, line, authority_hex, config) = fixture();
    let authority: [u8; 32] = hex::decode(&authority_hex).unwrap().try_into().unwrap();
    let v1_message = legacy_v1_effect_message(&authority, &envelope, &line);
    let v2_message = effect_message(&authority, &envelope, &line).unwrap();
    assert_ne!(
        v1_message, v2_message,
        "v1 and v2 messages must differ (tag bump)"
    );
    assert_eq!(&v2_message[..DOMAIN_TAG.len()], DOMAIN_TAG);
    assert_eq!(
        &v1_message[..DOMAIN_TAG_V1_RETIRED.len()],
        DOMAIN_TAG_V1_RETIRED
    );
    // A signature over the v1 bytes rides the envelope: fail closed.
    envelope.sig = hex::encode(
        SigningKey::from_bytes(&PRINCIPAL_SEED)
            .sign(&v1_message)
            .to_bytes(),
    );
    let error = verify_fixture(&envelope, &line, &authority_hex, &config).unwrap_err();
    assert!(error.contains("signature verification failed"), "{error}");
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
fn strict_wire_shape_accepts_omitted_revocation_subject() {
    let (envelope, line, _, _) = fixture();
    let mut env = serde_json::to_value(envelope).unwrap();
    env.as_object_mut().unwrap().remove("revocation_subject");
    let wrapper = json!({"seal_env": env, "request": line}).to_string();
    match wire_view(&wrapper) {
        WireView::Enveloped { envelope, .. } => {
            assert!(envelope.revocation_subject.is_empty());
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
            "--insecure-development-mode",
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
    assert_eq!(issuance["params"]["envelope"], "seal.effect/v2");
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
        revocation_subject: String::new(),
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
