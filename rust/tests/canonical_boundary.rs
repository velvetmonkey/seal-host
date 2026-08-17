// SPDX-License-Identifier: Apache-2.0
//! Full-domain containment tests for the Rust/Lean signed-effect byte seam.
//!
//! The production accepted space is not represented by this corpus: it is
//! defined by `canonical_effect_agreement`, which compares every byte-bearing
//! field returned by the actual pinned Lean derivation with Rust's actual
//! derivation.  These tests exhaust the complete C0 alphabet, cover every
//! compared field, and watch the known divergences reappear when that gate is
//! deliberately bypassed.

use seal_host_rs::envelope_v23::{
    canonical_effect_agreement, canonical_json, derive_mcp_effect, effect_message_for_signing,
    AdapterClaim, CanonicalAgreementError, EnvelopeV23, PrincipalClaim,
};
use seal_host_rs::lean::LeanHost;
use serde_json::Value;
use std::sync::OnceLock;

fn host() -> &'static LeanHost {
    static HOST: OnceLock<LeanHost> = OnceLock::new();
    HOST.get_or_init(LeanHost::new)
}

fn observation(line: &str) -> String {
    host().canonical_effect(line).expect("Lean oracle seam")
}

fn request(field: &str, value: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"db.execute","action":"call","arguments":{{"q":"ok"}},"{field}":{value}}}}}"#
    )
}

fn argument_request(arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"db.execute","action":"call","arguments":{arguments}}}}}"#
    )
}

/// SealV2's canonical raw-wire spelling for one C0 scalar.  These literals
/// are hand-derived from SealV2/Escape.lean's documented grammar; they are
/// input construction, never expected output from either serializer.
fn c0_escape(value: u8) -> String {
    match value {
        0x08 => r#"\b"#.into(),
        0x09 => r#"\t"#.into(),
        0x0a => r#"\n"#.into(),
        0x0c => r#"\f"#.into(),
        0x0d => r#"\r"#.into(),
        _ => format!(r#"\u{value:04x}"#),
    }
}

fn quoted_c0(value: u8) -> String {
    format!(r#""{}""#, c0_escape(value))
}

#[test]
fn complete_c0_alphabet_is_measured_at_every_reachable_seat() {
    // RFC 8785 section 3.2.2.2 plus the measured Lean.Json.compress table:
    // these and only these C0 scalars differ from serde_json.
    const COMPRESS_DISAGREEMENTS: [u8; 3] = [0x08, 0x09, 0x0c];

    for scalar in 0u8..=0x1f {
        let quoted = quoted_c0(scalar);
        for field in ["_meta", "requestState", "inputResponses"] {
            let value = if field == "_meta" {
                format!(r#"{{"v":{quoted}}}"#)
            } else {
                quoted.clone()
            };
            let line = request(field, &value);
            let result = canonical_effect_agreement(&line, &observation(&line));
            if COMPRESS_DISAGREEMENTS.contains(&scalar) {
                assert_eq!(
                    result.unwrap_err(),
                    CanonicalAgreementError::ByteMismatch { field },
                    "C0 U+{scalar:04X} must be rejected at {field}"
                );
            } else {
                result.unwrap_or_else(|error| {
                    panic!("C0 U+{scalar:04X} unexpectedly rejected at {field}: {error}")
                });
            }
        }

        // Arguments use SealV2.escapeString rather than Lean.Json.compress;
        // all 32 C0 spellings match serde_json there.
        let line = argument_request(&format!(r#"{{"v":{quoted}}}"#));
        canonical_effect_agreement(&line, &observation(&line)).unwrap_or_else(|error| {
            panic!("argument C0 U+{scalar:04X} unexpectedly rejected: {error}")
        });
    }
}

#[test]
fn tab_backspace_and_formfeed_in_meta_are_typed_rejections() {
    for (name, escape) in [
        ("tab", r#"\t"#),
        ("backspace", r#"\b"#),
        ("formfeed", r#"\f"#),
    ] {
        let line = request("_meta", &format!(r#"{{"v":"{escape}"}}"#));
        assert_eq!(
            canonical_effect_agreement(&line, &observation(&line)).unwrap_err(),
            CanonicalAgreementError::ByteMismatch { field: "_meta" },
            "{name} must fail closed before signing"
        );

        let effect = derive_mcp_effect(&line).unwrap();
        let envelope = EnvelopeV23 {
            key_id: "alice".into(),
            sig: String::new(),
            nonce: "00".repeat(32),
            issued_at: 1,
            expires_at: 2,
            adapter: AdapterClaim::deployed_mcp(),
            principal: PrincipalClaim {
                session: "seal-session-v1:containment-test".into(),
            },
            policy_version: "containment-test".into(),
            effect: Some(effect),
        };
        assert_eq!(
            effect_message_for_signing(&[0; 32], &envelope, &line, None).unwrap_err(),
            CanonicalAgreementError::MissingAgreement,
            "{name} must not yield bytes to the signing API"
        );
    }
}

#[test]
fn reachable_number_and_ordering_classes_are_contained_precisely() {
    // Hand calculation: 0.0000001 is the mathematical value 1e-7. Rust's
    // binary64 shortest renderer emits exponent notation; Lean JsonNumber
    // emits fixed notation. The pre-existing value-agreement gate accepts
    // the value, while this byte gate rejects its rendering mismatch.
    let number = request("requestState", "0.0000001");
    assert_eq!(
        canonical_effect_agreement(&number, &observation(&number)).unwrap_err(),
        CanonicalAgreementError::ByteMismatch {
            field: "requestState"
        }
    );

    // RFC 8785 would put U+10000 before U+FFFE by UTF-16 code units. Both
    // implementations instead sort Unicode scalar values and therefore put
    // U+FFFE first. This is reachable and non-JCS, but it is not a cross-side
    // mismatch, so containment correctly admits it unchanged.
    let ordering = request("requestState", r#"{"\ufffe":1,"\ud800\udc00":2}"#);
    canonical_effect_agreement(&ordering, &observation(&ordering)).unwrap();

    // Arguments use the separate SealV2 AST serializer. In this build both
    // sides preserve parsed member order, so each ordering is reachable and
    // agrees byte-for-byte (neither claim is JCS property sorting).
    for arguments in [r#"{"z":1,"a":2}"#, r#"{"a":2,"z":1}"#] {
        let line = argument_request(arguments);
        canonical_effect_agreement(&line, &observation(&line)).unwrap();
    }

    // The same arguments serializer escapes DEL/non-ASCII while Rust emits
    // valid Unicode scalars literally. This separate reachable class is also
    // rejected by the byte predicate.
    for value in [r#"\u007f"#, r#"\u00e9"#, r#"\ud83d\ude00"#] {
        let line = argument_request(&format!(r#"{{"v":"{value}"}}"#));
        assert_eq!(
            canonical_effect_agreement(&line, &observation(&line)).unwrap_err(),
            CanonicalAgreementError::ByteMismatch { field: "arguments" }
        );
    }
}

#[test]
fn unknown_malformed_and_unclassifiable_observations_fail_closed() {
    let line = argument_request(r#"{"q":1}"#);
    assert!(canonical_effect_agreement(&line, "not-json").is_err());
    assert!(
        canonical_effect_agreement(&line, r#"{"ok":false,"error":"unknown canonical form"}"#)
            .is_err()
    );

    let actionless = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"q":1}}}"#;
    assert!(matches!(
        canonical_effect_agreement(actionless, &observation(actionless)),
        Err(CanonicalAgreementError::RustUnclassifiable(_))
            | Err(CanonicalAgreementError::LeanUnclassifiable(_))
    ));
}

#[test]
fn negative_control_disabling_boundary_reveals_real_byte_divergence() {
    let line = request("_meta", r#"{"v":"\t"}"#);
    let rust_effect = derive_mcp_effect(&line).unwrap();
    let rust = canonical_json(rust_effect.metadata.as_ref().unwrap()).unwrap();
    let lean: Value = serde_json::from_str(&observation(&line)).unwrap();
    let lean = lean["metadata"]["bytes"].as_str().unwrap();

    // This is the deliberately disabled-gate path: observe both production
    // canonicalizers but do not call canonical_effect_agreement. The known
    // mismatch is visible again. The gate assertion immediately afterwards
    // proves production rejects the same request.
    assert_ne!(rust.as_bytes(), lean.as_bytes());
    println!(
        "CANONICAL-BOUNDARY NEGATIVE CONTROL RED gate=disabled field=_meta rust_hex={} lean_hex={}",
        hex::encode(rust.as_bytes()),
        hex::encode(lean.as_bytes())
    );
    assert_eq!(
        canonical_effect_agreement(&line, &observation(&line)).unwrap_err(),
        CanonicalAgreementError::ByteMismatch { field: "_meta" }
    );
}
