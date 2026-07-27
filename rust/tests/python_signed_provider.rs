// SPDX-License-Identifier: Apache-2.0
//! Cross-language consumer test: the REAL `Ed25519TokenProvider` consuming
//! NDJSON signed by the PYTHON signer (`test/tools/sign_approval.py`).
//!
//! Closes the provider-unit gap flagged by classifier 0011268d: the in-module
//! unit test (`ed25519_provider_accepts_signed_decline_and_allow`) self-signs
//! inside Rust, so Python-signed bytes had never reached the provider at unit
//! level. This test takes a Python-signed file and asserts the provider's
//! full contract on it: one allow record, one decline, zero warnings.
//!
//! Driven by `test/integration/test_approval_consumer.py` (Step A'), which
//! generates the keypair, signs one allow + one decline line with the real
//! Python signer, and hands the file + pubkey over via env vars. When the
//! env vars are absent (a bare `cargo test` run), the test skips with an
//! explicit message rather than fabricating inputs.

use seal_host_rs::providers::{ApprovalProvider, Ed25519TokenProvider};

#[test]
fn ed25519_provider_accepts_python_signed_ndjson() {
    let (path, vk_hex, target, decline_nonce) = match (
        std::env::var("SEAL_PY_SIGNED_NDJSON"),
        std::env::var("SEAL_PY_SIGNED_PUBKEY"),
        std::env::var("SEAL_PY_SIGNED_TARGET"),
        std::env::var("SEAL_PY_SIGNED_DECLINE_NONCE"),
    ) {
        (Ok(p), Ok(k), Ok(t), Ok(n)) => (p, k, t, n),
        _ => {
            eprintln!(
                "SKIP: SEAL_PY_SIGNED_* env not set — run via \
                 test/integration/test_approval_consumer.py (Step A')"
            );
            return;
        }
    };

    let mut provider = Ed25519TokenProvider::new(&path, &vk_hex)
        .expect("provider must construct from the python-signed channel inputs");
    let poll = provider.poll();

    assert!(
        poll.warnings.is_empty(),
        "python-signed allow+decline must produce zero warnings, got: {:?}",
        poll.warnings
    );
    assert_eq!(poll.records.len(), 1, "exactly one allow record expected");
    assert_eq!(poll.records[0].target, target, "allow record target-bound");
    assert_eq!(poll.declines.len(), 1, "exactly one decline expected");
    assert_eq!(poll.declines[0].target, target, "decline target-bound");
    assert_eq!(
        poll.declines[0].nonce.as_deref(),
        Some(decline_nonce.as_str()),
        "decline nonce round-trips"
    );
    println!(
        "python-signed NDJSON accepted by real Ed25519TokenProvider: \
         1 record, 1 decline, 0 warnings (target {target})"
    );
}

#[test]
fn ed25519_provider_accepts_python_signed_approval_v2() {
    let (path, vk_hex, target, session) = match (
        std::env::var("SEAL_PY_SIGNED_V2_NDJSON"),
        std::env::var("SEAL_PY_SIGNED_PUBKEY"),
        std::env::var("SEAL_PY_SIGNED_V2_TARGET"),
        std::env::var("SEAL_PY_SIGNED_V2_SESSION"),
    ) {
        (Ok(p), Ok(k), Ok(t), Ok(s)) => (p, k, t, s),
        _ => {
            eprintln!(
                "SKIP: SEAL_PY_SIGNED_V2_* env not set — run via \
                 test/integration/test_approval_consumer.py (Step A')"
            );
            return;
        }
    };

    let mut provider = Ed25519TokenProvider::new(&path, &vk_hex)
        .expect("provider must construct from the Python-signed v2 inputs");
    let poll = provider.poll();
    assert!(
        poll.warnings.is_empty(),
        "Python-signed v2 token must produce zero warnings: {:?}",
        poll.warnings
    );
    assert_eq!(poll.records.len(), 1);
    let record = poll.records[0]
        .v2()
        .expect("Python v2 token must retain exact-byte evidence");
    assert_eq!(record.approval_record_version, 2);
    assert_eq!(record.target, target);
    assert_eq!(record.session, session);
    assert_eq!(record.authorization_domain, "seal.approval-record/v2");
    assert_eq!(record.authorization_signature_algorithm, "Ed25519");
    println!(
        "Python-signed ApprovalRecord v2 accepted: subject={} shown={} token_bytes={}",
        record.subject_sha256, record.shown_sha256, record.authorization_token.decoded_length
    );
}
