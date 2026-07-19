// SPDX-License-Identifier: Apache-2.0
//! R-PRINC differential: the receipt's `principal` field is the id of the
//! signed-config registry key whose Ed25519 envelope VERIFIED in the Lean
//! parse path over the exact judged line — and NOTHING an adversary plants
//! in the request bytes can move it. This is the operational discharge of
//! the R-PRINC seam named in `Ffi.PrincipalFaithful` (Ffi.lean): the Lean
//! model half is `Ffi.receipt_principal_authenticated`; this file pins the
//! Rust assembler half against receipts written by the REAL binary.
//!
//! Also pinned here: the cross-language V2.2 signed-message contract
//! (`Host.envelopeMessage` golden vector, byte-twinned — tag ‖ authority(32)
//! ‖ u64be(|key_id|) ‖ key_id ‖ nonce(32) ‖ u64be(issued_at) ‖ line; the
//! authority is the config-signing pubkey, so the transplant and relabel
//! drills below are the operational half of council C1), the V2.1 T3 story
//! (an enveloped allow forwards EXACTLY the inner judged bytes + one
//! canonical `\n`; wrapper bytes never reach the child; line smuggling
//! refuses), envelope nonce replay (second A3 instance), and per-principal
//! budget isolation end to end (alice's exhaustion never starves bob).
//!
//! What would fail this test: copying a request-supplied `principal` /
//! `caller_id` into the receipt (the proxy trap in miniature), forwarding
//! wrapper bytes, or minting a principal for a tampered/unknown/replayed
//! envelope.

use ed25519_dalek::{Signer, SigningKey};
use sha2::Digest;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::Duration;

const ALICE_SEED: [u8; 32] = [1u8; 32];
const BOB_SEED: [u8; 32] = [2u8; 32];
/// The config-signing key seed — its PUBKEY is the V2.2 envelope authority.
const CONFIG_SEED: [u8; 32] = [7u8; 32];

const SEAM_ERROR_LINE: &str = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"seal-host: mediation seam failure; request blocked\"}}";

fn pubkey_hex(seed: [u8; 32]) -> String {
    hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The raw 32-byte config authority pubkey the V2.2 message commits to.
fn config_authority() -> [u8; 32] {
    SigningKey::from_bytes(&CONFIG_SEED).verifying_key().to_bytes()
}

/// The canonical V2.2 signed message — MUST byte-match `Host.envelopeMessage`
/// (Host/Principal.lean):
///   tag ‖ authority(32) ‖ u64be(|key_id|) ‖ key_id ‖ nonce(32)
///       ‖ u64be(issued_at) ‖ line bytes.
/// `authority` is the raw config-signing pubkey (the trust root); `key_id`
/// is the wire-claimed registry id, length-prefixed. The bind is what makes
/// a signature non-transplantable (across config authorities) and
/// non-relabelable (across registry ids).
fn envelope_message(
    authority: &[u8; 32],
    key_id: &str,
    nonce: &[u8; 32],
    issued_at: u64,
    line: &str,
) -> Vec<u8> {
    let mut m = b"seal/v2.2/principal-envelope\0".to_vec();
    m.extend_from_slice(authority);
    m.extend_from_slice(&(key_id.len() as u64).to_be_bytes());
    m.extend_from_slice(key_id.as_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(&issued_at.to_be_bytes());
    m.extend_from_slice(line.as_bytes());
    m
}

/// Wrap `request` in a signed principal envelope wire line (the client-side
/// signer this MVP asks callers to run), bound to `authority`.
fn signed_envelope_for_authority(
    authority: &[u8; 32],
    seed: [u8; 32],
    key_id: &str,
    request: &str,
    nonce: &[u8; 32],
    issued_at: u64,
) -> String {
    let sk = SigningKey::from_bytes(&seed);
    let sig = hex::encode(
        sk.sign(&envelope_message(authority, key_id, nonce, issued_at, request))
            .to_bytes(),
    );
    serde_json::json!({
        "seal_env": {
            "key_id": key_id,
            "sig": sig,
            "nonce": hex::encode(nonce),
            "issued_at": issued_at,
        },
        "request": request,
    })
    .to_string()
}

/// The common case: an envelope bound to the REAL config authority.
fn signed_envelope(
    seed: [u8; 32],
    key_id: &str,
    request: &str,
    nonce: &[u8; 32],
    issued_at: u64,
) -> String {
    signed_envelope_for_authority(&config_authority(), seed, key_id, request, nonce, issued_at)
}

struct Host {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    dir: PathBuf,
}

impl Host {
    /// Spawn the real binary (file approval channel — approvals play no role
    /// here) with `cat` as the guarded server and a signed config carrying
    /// the V2.1 `principals` section: alice + bob registered, one
    /// per-principal budget `pnotes` (cap 2) over `notes.add`.
    fn spawn(tag: &str) -> Host {
        let dir = std::env::temp_dir().join(format!(
            "seal-principal-identity-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let approvals = dir.join("approvals.ndjson");
        std::fs::write(&approvals, b"").unwrap();

        let config_sk = SigningKey::from_bytes(&CONFIG_SEED);
        let pk = hex::encode(config_sk.verifying_key().to_bytes());
        let payload = serde_json::json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": approvals.to_str().unwrap(),
                    "ttl_seconds": 120
                },
                "tools": [
                    {"name": "notes.add", "mode": "allow"}
                ]
            },
            "principals": {
                // "alice-admin" shares alice's PUBKEY under a different id —
                // legal registry, here so the V2.2 relabel drill can show a
                // signature names ONE id even when two ids share a key.
                "keys": [
                    {"id": "alice", "pubkey": pubkey_hex(ALICE_SEED)},
                    {"id": "alice-admin", "pubkey": pubkey_hex(ALICE_SEED)},
                    {"id": "bob", "pubkey": pubkey_hex(BOB_SEED)}
                ],
                "budgets": [
                    {"name": "pnotes", "cap": 2, "tools": ["notes.add"]}
                ]
            }
        })
        .to_string();
        let sig = hex::encode(config_sk.sign(payload.as_bytes()).to_bytes());
        let envelope = serde_json::json!({"payload": payload, "signature": sig}).to_string();
        let config = dir.join("trusted.json");
        std::fs::write(&config, envelope).unwrap();

        let args = vec![
            "--config".to_string(),
            config.to_str().unwrap().to_string(),
            "--pubkey".to_string(),
            pk,
            "--channel".to_string(),
            "file".to_string(),
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
        self.send_raw(&format!("{line}\n"));
    }

    fn send_raw(&mut self, bytes: &str) {
        self.stdin.write_all(bytes.as_bytes()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn expect_line(&mut self) -> String {
        self.lines
            .recv_timeout(Duration::from_secs(20))
            .expect("host produced no output line in time")
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

    fn last_receipt(&self) -> serde_json::Value {
        self.receipts().pop().expect("a receipt was persisted")
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Every object key OUTSIDE the descriptive `arguments` echo (the
/// receipt_identity.rs discipline: identity-shaped KEYS are what a false
/// binding would add).
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

fn assert_no_principal_key(receipt: &serde_json::Value, label: &str) {
    let mut keys = Vec::new();
    keys_outside_arguments(receipt, &mut keys);
    assert!(
        !keys.iter().any(|k| k == "principal"),
        "{label}: receipt must not carry a principal key: {keys:?}"
    );
}

const PLAIN_CALL: &str = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.add","arguments":{"text":"hello"}}}"#;

/// The cross-language V2.2 signed-message contract, byte-for-byte: the Lean
/// `#guard_msgs` golden vector in Host/Principal.lean pins the SAME hex
/// (authority 0xa0..0xbf, key_id "alice", nonce 0x00..0x1f, issued_at 1234).
#[test]
fn envelope_message_golden_vector_matches_lean() {
    let mut authority = [0u8; 32];
    for (i, b) in authority.iter_mut().enumerate() {
        *b = 0xa0 + i as u8;
    }
    let mut nonce = [0u8; 32];
    for (i, b) in nonce.iter_mut().enumerate() {
        *b = i as u8;
    }
    assert_eq!(
        hex::encode(envelope_message(&authority, "alice", &nonce, 1234, "{\"m\":1}")),
        "7365616c2f76322e322f7072696e636970616c2d656e76656c6f706500\
         a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\
         0000000000000005\
         616c696365\
         000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
         00000000000004d2\
         7b226d223a317d"
            .replace(char::is_whitespace, "")
    );
}

/// THE MUTATION DRILL. (a) A gated tool with no envelope is denied
/// fail-closed and the receipt carries NO principal. (b) An alice-signed
/// envelope whose request body plants `principal`/`caller_id` strings
/// forwards with receipt principal == "alice" — the registry id of the
/// verifying KEY, immovable by request material. (c) The child receives
/// exactly the inner judged bytes (never the wrapper), and `request_sha256`
/// commits to the inner line.
#[test]
fn principal_binds_registry_key_and_ignores_planted_identity() {
    let mut host = Host::spawn("drill");

    // (a) mixed-mode fail-closed
    host.send(PLAIN_CALL);
    let blocked = host.expect_line();
    assert!(
        blocked.contains("principal envelope required"),
        "unenveloped call on a principal-gated tool must deny: {blocked}"
    );
    let r = host.last_receipt();
    assert_eq!(r["verdict"], "BLOCK", "{r}");
    assert_no_principal_key(&r, "unenveloped");

    // (b) + (c)
    let hostile_inner = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"notes.add","arguments":{"text":"x","principal":"root","caller_id":"mallory","program_origin":"trusted-deploy-bot"}}}"#;
    let wire = signed_envelope(ALICE_SEED, "alice", hostile_inner, &[0xa1; 32], now_ms());
    host.send(&wire);
    let echoed = host.expect_line();
    assert_eq!(
        echoed, hostile_inner,
        "the child must receive EXACTLY the inner judged line — never wrapper bytes"
    );
    let r = host.last_receipt();
    assert_eq!(r["verdict"], "ALLOW", "{r}");
    assert_eq!(
        r["principal"],
        serde_json::Value::String("alice".into()),
        "the principal is the registry id of the VERIFYING KEY, not any planted string: {r}"
    );
    assert_eq!(
        r["request_sha256"],
        serde_json::Value::String(hex::encode(sha2::Sha256::digest(hostile_inner.as_bytes()))),
        "the request commitment is over the exact inner judged line"
    );
    // The planted identity strings live ONLY in the descriptive arguments echo.
    let mut keys = Vec::new();
    keys_outside_arguments(&r, &mut keys);
    for forbidden in ["caller_id", "program_origin", "agent", "caller"] {
        assert!(
            !keys.iter().any(|k| k == forbidden),
            "receipt must not mint an identity key {forbidden:?}: {keys:?}"
        );
    }
}

/// Fail-closed spectrum: tampered signature, unregistered key, a valid
/// envelope presented with a DIFFERENT line (signature binds the exact
/// judged bytes), and a REPLAYED nonce (second A3 instance) — all deny on
/// the gated tool, none mints a principal.
#[test]
fn tampered_unknown_wrongline_and_replayed_envelopes_fail_closed() {
    let mut host = Host::spawn("fail-closed");
    let iss = now_ms();

    // tampered signature: flip the first sig byte
    let good = signed_envelope(ALICE_SEED, "alice", PLAIN_CALL, &[0x11; 32], iss);
    let mut v: serde_json::Value = serde_json::from_str(&good).unwrap();
    let sig = v["seal_env"]["sig"].as_str().unwrap();
    let flipped = if let Some(rest) = sig.strip_prefix("00") {
        format!("ff{rest}")
    } else {
        format!("00{}", &sig[2..])
    };
    v["seal_env"]["sig"] = serde_json::Value::String(flipped);
    host.send(&v.to_string());
    let out = host.expect_line();
    assert!(out.contains("principal envelope required"), "{out}");
    assert_no_principal_key(&host.last_receipt(), "tampered sig");

    // unregistered key id (carol signs with her own key — not in the registry)
    let carol = signed_envelope([3u8; 32], "carol", PLAIN_CALL, &[0x22; 32], iss);
    host.send(&carol);
    let out = host.expect_line();
    assert!(out.contains("principal envelope required"), "{out}");
    assert_no_principal_key(&host.last_receipt(), "unknown key");

    // valid alice envelope, different inner line: the signature covers the
    // exact judged bytes, so swapping the request breaks verification.
    let other_inner = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"notes.add","arguments":{"text":"other"}}}"#;
    let mut swapped: serde_json::Value = serde_json::from_str(&signed_envelope(
        ALICE_SEED,
        "alice",
        PLAIN_CALL,
        &[0x33; 32],
        iss,
    ))
    .unwrap();
    swapped["request"] = serde_json::Value::String(other_inner.into());
    host.send(&swapped.to_string());
    let out = host.expect_line();
    assert!(out.contains("principal envelope required"), "{out}");
    assert_no_principal_key(&host.last_receipt(), "wrong line");

    // V2.2 TRANSPLANT drill: alice's GENUINE key, but the message is bound
    // to an attacker authority (a self-signed config's pubkey, 0x42*32).
    // Presented to the host — whose session pins the REAL trust root — the
    // recomputed message differs, Ed25519 rejects, fail-closed deny.
    let transplanted = signed_envelope_for_authority(
        &[0x42; 32],
        ALICE_SEED,
        "alice",
        PLAIN_CALL,
        &[0x55; 32],
        iss,
    );
    host.send(&transplanted);
    let out = host.expect_line();
    assert!(
        out.contains("principal envelope required"),
        "an envelope bound to a foreign authority must deny: {out}"
    );
    assert_no_principal_key(&host.last_receipt(), "transplanted authority");

    // V2.2 RELABEL drill: a genuine alice signature (bound to key_id
    // "alice") presented as "alice-admin" — an id registered with the SAME
    // pubkey. The message commits to the claimed key_id, so verification
    // fails: one signature names ONE registry id.
    let mut relabeled: serde_json::Value = serde_json::from_str(&signed_envelope(
        ALICE_SEED,
        "alice",
        PLAIN_CALL,
        &[0x66; 32],
        iss,
    ))
    .unwrap();
    relabeled["seal_env"]["key_id"] = serde_json::Value::String("alice-admin".into());
    host.send(&relabeled.to_string());
    let out = host.expect_line();
    assert!(
        out.contains("principal envelope required"),
        "a relabeled key_id must deny even when the pubkey matches: {out}"
    );
    assert_no_principal_key(&host.last_receipt(), "relabeled key_id");

    // replayed nonce: first use forwards, byte-identical resend is dropped by
    // the envelope A3 filter and downgrades to no-envelope ⇒ deny.
    let once = signed_envelope(ALICE_SEED, "alice", PLAIN_CALL, &[0x44; 32], now_ms());
    host.send(&once);
    assert_eq!(host.expect_line(), PLAIN_CALL, "fresh nonce must forward");
    host.send(&once);
    let out = host.expect_line();
    assert!(
        out.contains("principal envelope required"),
        "replayed nonce must downgrade to no-envelope and deny: {out}"
    );
    assert_no_principal_key(&host.last_receipt(), "replayed nonce");
}

/// PER-PRINCIPAL ISOLATION, end to end: alice exhausts her cap-2 budget and
/// is denied on the third call — with the deny receipt still NAMING alice —
/// while bob's counter is untouched and his call flows. The operational twin
/// of `Kernels.principal_budget_isolation` /
/// `Host.principal_budget_trace_isolation`.
#[test]
fn per_principal_budgets_debit_independently() {
    let mut host = Host::spawn("isolation");

    for (i, nonce) in [[0x51u8; 32], [0x52; 32]].iter().enumerate() {
        let wire = signed_envelope(ALICE_SEED, "alice", PLAIN_CALL, nonce, now_ms());
        host.send(&wire);
        assert_eq!(
            host.expect_line(),
            PLAIN_CALL,
            "alice call {} within cap must forward",
            i + 1
        );
        assert_eq!(host.last_receipt()["principal"], "alice");
    }

    let third = signed_envelope(ALICE_SEED, "alice", PLAIN_CALL, &[0x53; 32], now_ms());
    host.send(&third);
    let out = host.expect_line();
    assert!(
        out.contains("over principal budget"),
        "alice's third call must exceed her cap: {out}"
    );
    let r = host.last_receipt();
    assert_eq!(r["verdict"], "BLOCK");
    assert_eq!(
        r["principal"], "alice",
        "the deny receipt still names who was denied: {r}"
    );

    // bob is isolated: alice's exhaustion moved nothing of his.
    let bobs = signed_envelope(BOB_SEED, "bob", PLAIN_CALL, &[0x54; 32], now_ms());
    host.send(&bobs);
    assert_eq!(
        host.expect_line(),
        PLAIN_CALL,
        "bob must be unaffected by alice's exhaustion"
    );
    assert_eq!(host.last_receipt()["principal"], "bob");
}

/// The V2.1 T3 story: (a) `\n`- and `\r\n`-terminated wrappers yield
/// byte-identical child lines and identical request commitments (the
/// enveloped path CANONICALIZES the terminator); (b) an inner string with an
/// escaped newline is refused outright — zero bytes reach the child (line
/// smuggling closed).
#[test]
fn terminator_canonicalization_and_line_smuggling() {
    let mut host = Host::spawn("t3");

    let w1 = signed_envelope(ALICE_SEED, "alice", PLAIN_CALL, &[0x61; 32], now_ms());
    host.send_raw(&format!("{w1}\n"));
    assert_eq!(host.expect_line(), PLAIN_CALL);
    let r1 = host.last_receipt();

    let w2 = signed_envelope(ALICE_SEED, "alice", PLAIN_CALL, &[0x62; 32], now_ms());
    host.send_raw(&format!("{w2}\r\n"));
    assert_eq!(
        host.expect_line(),
        PLAIN_CALL,
        "CRLF-terminated wrapper must yield the same child line"
    );
    let r2 = host.last_receipt();
    assert_eq!(
        r1["request_sha256"], r2["request_sha256"],
        "one commitment, whatever the wrapper terminator"
    );

    // line smuggling: an inner string decoding to two protocol lines refuses
    // before Lean, before the child — the strict extractor's newline rule.
    let smuggle = format!(
        "{{\"seal_env\":{{\"key_id\":\"alice\",\"sig\":\"00\",\"nonce\":\"00\",\"issued_at\":1}},\"request\":{}}}",
        serde_json::to_string(&format!("{PLAIN_CALL}\n{PLAIN_CALL}")).unwrap()
    );
    host.send(&smuggle);
    assert_eq!(
        host.expect_line(),
        SEAM_ERROR_LINE,
        "an embedded newline in the inner request must refuse at the seam"
    );
    // and nothing reached the child: the next legitimate call's echo is the
    // very next child output line. (Bob's — alice already spent her cap of 2
    // on w1/w2 above.)
    let probe = signed_envelope(BOB_SEED, "bob", PLAIN_CALL, &[0x63; 32], now_ms());
    host.send(&probe);
    assert_eq!(
        host.expect_line(),
        PLAIN_CALL,
        "no smuggled bytes may precede the probe's echo"
    );
}
