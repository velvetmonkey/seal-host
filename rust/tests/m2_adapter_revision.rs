// SPDX-License-Identifier: Apache-2.0
//! M.2/M.2a physical controls for scalar actual-revision binding.

use ed25519_dalek::{Signer, SigningKey};
use seal_host_rs::adapter_revision::{
    McpAdapterRevision, McpMixedVersionPolicy, McpRevisionSession,
    MCP_DISCOVERY_SUPPORTED_REVISIONS, MCP_MIXED_VERSION_POLICY,
};
use seal_host_rs::envelope_v23::{
    effect_message, verify, AdapterClaim, EffectClaim, EnvelopeV23, HostContext, PrincipalClaim,
};
use seal_host_rs::lean::LeanHost;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

fn host() -> &'static LeanHost {
    static HOST: OnceLock<LeanHost> = OnceLock::new();
    HOST.get_or_init(LeanHost::new)
}

const PRINCIPAL_SEED: [u8; 32] = [41; 32];
const AUTHORITY: [u8; 32] = [83; 32];
const CALL: &str = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"db.execute","action":"call","arguments":{"q":1}}}"#;
const INITIALIZE: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#;
const DISCOVER: &str = r#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

fn selected(entry: &str) -> McpAdapterRevision {
    let mut session = McpRevisionSession::default();
    session.observe_received_call(host(), entry).unwrap();
    session.actual_revision().unwrap()
}

fn signed(
    revision: McpAdapterRevision,
) -> (AdapterClaim, Vec<u8>, ed25519_dalek::Signature, EnvelopeV23) {
    let signing_key = SigningKey::from_bytes(&PRINCIPAL_SEED);
    let adapter = revision.adapter_claim();
    let mut envelope = EnvelopeV23 {
        key_id: "alice".into(),
        sig: String::new(),
        nonce: "33".repeat(32),
        issued_at: 1_800_000_000,
        expires_at: 1_800_000_600,
        adapter: adapter.clone(),
        principal: PrincipalClaim {
            session: "seal-session-v1:m2-control".into(),
        },
        policy_version: "policy-m2".into(),
        effect: Some(EffectClaim {
            resource: "db.execute".into(),
            action: "call".into(),
            args: r#"{"q":1}"#.into(),
        }),
    };
    let message = effect_message(&AUTHORITY, &envelope, CALL).unwrap();
    let signature = signing_key.sign(&message);
    envelope.sig = hex::encode(signature.to_bytes());

    let kernel_config = json!({
        "principals": {"keys": [{
            "id": "alice",
            "pubkey": hex::encode(signing_key.verifying_key().to_bytes())
        }]}
    });
    verify(
        &envelope,
        CALL,
        &HostContext {
            authority_hex: &hex::encode(AUTHORITY),
            session: "seal-session-v1:m2-control",
            adapter: &adapter,
            kernel_config: &kernel_config,
        },
    )
    .unwrap();
    (adapter, message, signature, envelope)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
fn discovery_capability_is_a_two_revision_set_and_policy_is_transparent() {
    let revisions: BTreeSet<_> = MCP_DISCOVERY_SUPPORTED_REVISIONS.into_iter().collect();
    assert_eq!(
        revisions.len(),
        MCP_DISCOVERY_SUPPORTED_REVISIONS.len(),
        "M2 RED: discovery supportedVersions contains a duplicate, so it is not a set"
    );
    assert_eq!(
        revisions,
        BTreeSet::from(["2025-06-18", "2026-07-28"]),
        "M2 RED: discovery supportedVersions is not the ruled dual-era set"
    );
    assert_eq!(
        MCP_MIXED_VERSION_POLICY,
        McpMixedVersionPolicy::TransparentDualEra,
        "M2a RED: mixed-version policy is not transparent dual-era mediation"
    );
}

#[test]
fn missing_or_conflicting_entry_shape_has_no_hidden_default() {
    let mut unselected = McpRevisionSession::default();
    unselected.observe_received_call(host(), CALL).unwrap();
    let empty = unselected.actual_revision().unwrap_err();
    assert!(empty.contains("undetermined"), "{empty}");

    let mut conflict = McpRevisionSession::default();
    conflict.observe_received_call(host(), INITIALIZE).unwrap();
    conflict.observe_received_call(host(), DISCOVER).unwrap();
    let error = conflict.actual_revision().unwrap_err();
    assert!(error.contains("ambiguous"), "{error}");
}

#[test]
fn different_received_eras_sign_different_scalar_claims_and_commitments() {
    let legacy = signed(selected(INITIALIZE));
    let current = signed(selected(DISCOVER));

    println!(
        "M2 LEGACY entry=initialize adapterVersion={} commitment_sha256={} signature={}",
        legacy.0.version,
        sha256(&legacy.1),
        hex::encode(legacy.2.to_bytes())
    );
    println!(
        "M2 CURRENT entry=server/discover adapterVersion={} commitment_sha256={} signature={}",
        current.0.version,
        sha256(&current.1),
        hex::encode(current.2.to_bytes())
    );

    assert_ne!(
        legacy.0.version, current.0.version,
        "M2 RED: different received MCP entry eras collapsed to the same signed adapterVersion"
    );
    assert_ne!(
        legacy.1, current.1,
        "M2 RED: different received MCP entry eras collapsed to the same signed commitment"
    );
}

#[test]
fn byte_identical_same_era_calls_have_identical_claim_commitment_and_signature() {
    let first = signed(selected(INITIALIZE));
    let second = signed(selected(INITIALIZE));
    assert_eq!(first.0, second.0, "M2 TWIN RED: adapter claims differ");
    assert_eq!(first.1, second.1, "M2 TWIN RED: commitments differ");
    assert_eq!(first.2, second.2, "M2 TWIN RED: signatures differ");
    println!(
        "M2 POSITIVE TWIN GREEN era=initialize adapterVersion={} commitment_sha256={} signature={}",
        first.0.version,
        sha256(&first.1),
        hex::encode(first.2.to_bytes())
    );
}
