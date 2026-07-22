// SPDX-License-Identifier: Apache-2.0
//! Byte-twin guard for the Stage B (`seal.effect/v2`) effect envelope
//! encoding.
//!
//! Shared corpus: `tests/vectors/envelope_v23_twin_corpus.json` — consumed by
//! this file (Rust `effect_message`) and by
//! `scripts/envelope_v23_twin_lane.lean` (the REAL Lean spec encoder
//! `SealV2.Effect.effectMessage` from mcp-seal-dev).
//!
//! Two layers, honestly separated:
//!
//! 1. `rust_encoder_matches_lean_generated_expectation`: the Rust encoder
//!    must reproduce `tests/vectors/envelope_v23_twin_expected.hex`
//!    byte-for-byte — a fast, hermetic guard against Rust encoder drift.
//! 2. `live_lean_diff_over_shared_corpus` (LIVE, runs by default since
//!    Stage B — Ben, 2026-07-22 18:07): runs the Lean lane NOW against the
//!    manifest-pinned `mcp-seal` package (advanced to `4f39f20`, the Stage
//!    B2 reconciliation, whose build carries `SealV2.EffectEnvelope`) and diffs
//!    both encoders over the corpus with no frozen middleman. THIS test is
//!    the kernel-to-host binding; layer 1 alone only proves Rust matches a
//!    snapshot. Spec resolution: `SEAL_V23_SPEC_LEAN_PATH` (+ optional
//!    `SEAL_V23_LEAN_BIN`) overrides for out-of-graph spec checkouts;
//!    otherwise `lake env lean` resolves the pinned package graph.
//!
//! Expectation provenance: generated 2026-07-22 by
//! `lean --run scripts/envelope_v23_twin_lane.lean rust/tests/vectors/envelope_v23_twin_corpus.json`
//! against mcp-seal-dev `4f39f20` built oleans (toolchain v4.28.0) — the
//! Stage B2 reconciliation commit, the same rev the manifest pins. The `golden-fable`
//! line is additionally pinned below to the exact hex that mcp-seal-dev's
//! `SealV2/EffectEnvelope.lean` freezes under `#guard_msgs`, so the frozen
//! file cannot silently drift from the spec repo's own pin.

use seal_host_rs::envelope_v23::{
    effect_message, AdapterClaim, EffectClaim, EnvelopeV23, PrincipalClaim,
};
use serde_json::Value;
use std::process::Command;

/// The exact hex `mcp-seal-dev/SealV2/EffectEnvelope.lean` pins with
/// `#guard_msgs` at `4f39f20` (and `rust/tests/envelope_v23.rs` pins as the
/// golden vector). Anchor: the expectation FILE must agree with the spec
/// repo's own frozen literal on this vector.
const LEAN_GUARD_MSGS_GOLDEN_HEX: &str = "7365616c2e6566666563742f763200a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000005616c696365000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00000000000004d2000000000000162e00000000000000077b226d223a317d00000000000000036d6370000000000000000a323032352d30362d31380000000000000006736573732d310000000000000005706f6c2d3101000000000000000a64622e65786563757465000000000000000463616c6c00000000000000077b2271223a317d";

fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/envelope_v23_twin_corpus.json")
}

fn expected_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/envelope_v23_twin_expected.hex")
}

fn field(v: &Value, key: &str) -> String {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("corpus field {key} must be a string"))
        .to_string()
}

/// (name, line, authority, envelope) for every corpus vector, in file order.
/// A vector still carrying a killed field — or missing a rescued mandatory
/// one — fails loudly here.
fn corpus_vectors() -> Vec<(String, String, [u8; 32], EnvelopeV23)> {
    const KILLED: [&str; 7] = [
        "idempotency_key",
        "on_behalf_of",
        "parent_capability_ref",
        "delegation",
        "audience",
        "causality_token",
        "revocation_subject",
    ];
    let text = std::fs::read_to_string(corpus_path()).expect("read corpus");
    let doc: Value = serde_json::from_str(&text).expect("corpus is JSON");
    doc["vectors"]
        .as_array()
        .expect("corpus has vectors array")
        .iter()
        .map(|v| {
            let e = &v["envelope"];
            for key in KILLED {
                assert!(
                    e.get(key).is_none(),
                    "corpus vector {} carries killed field {key}",
                    v["name"]
                );
            }
            assert!(
                e.get("expires_at").is_some() && e.get("policy_version").is_some(),
                "corpus vector {} is missing a rescued mandatory field",
                v["name"]
            );
            let effect = if e["effect"].is_null() {
                None
            } else {
                Some(EffectClaim {
                    resource: field(&e["effect"], "resource"),
                    action: field(&e["effect"], "action"),
                    args: field(&e["effect"], "args"),
                })
            };
            let envelope = EnvelopeV23 {
                key_id: field(e, "key_id"),
                sig: String::new(),
                nonce: field(e, "nonce_hex"),
                issued_at: e["issued_at"].as_u64().expect("issued_at u64"),
                expires_at: e["expires_at"].as_u64().expect("expires_at u64"),
                adapter: AdapterClaim {
                    kind: field(&e["adapter"], "type"),
                    version: field(&e["adapter"], "version"),
                },
                principal: PrincipalClaim {
                    session: field(e, "session"),
                },
                policy_version: field(e, "policy_version"),
                effect,
            };
            let authority: [u8; 32] = hex::decode(field(v, "authority_hex"))
                .expect("authority hex")
                .try_into()
                .expect("authority is 32 bytes");
            (field(v, "name"), field(v, "line"), authority, envelope)
        })
        .collect()
}

fn rust_hex_lines() -> Vec<(String, String)> {
    corpus_vectors()
        .iter()
        .map(|(name, line, authority, envelope)| {
            (
                name.clone(),
                hex::encode(effect_message(authority, envelope, line).unwrap()),
            )
        })
        .collect()
}

#[test]
fn rust_encoder_matches_lean_generated_expectation() {
    let expected: Vec<String> = std::fs::read_to_string(expected_path())
        .expect("read expected hex")
        .lines()
        .map(str::to_string)
        .collect();
    let actual = rust_hex_lines();
    assert_eq!(
        expected.len(),
        actual.len(),
        "expectation file and corpus disagree on vector count"
    );
    for ((name, rust_hex), lean_hex) in actual.iter().zip(&expected) {
        assert_eq!(
            rust_hex, lean_hex,
            "byte-twin break on vector {name}: Rust encoding differs from the \
             Lean-spec-generated expectation"
        );
    }
}

/// WHAT THIS CAN AND CANNOT SEE. Corrected 2026-07-25: the name and the old
/// failure message both oversold it.
///
/// Both sides of this comparison are frozen artifacts living in THIS repo.
/// `expected_path()` is a checked-in file; `LEAN_GUARD_MSGS_GOLDEN_HEX` is a
/// `const` declared above. Nothing here opens the spec repo. So it catches
/// exactly one thing: regenerating the expectation file without updating the
/// const, or the reverse.
///
/// It CANNOT see the spec itself changing. On 2026-07-25 the spec had already
/// moved the domain tag from `seal.effect/v1` to `seal.effect/v2` (mcp-seal-dev
/// `81e73dc`, reconciled by `ae9fadc`) and this test stayed green, because the
/// two frozen artifacts still agreed with each other about a layout the spec
/// no longer used. Only `live_lean_diff_over_shared_corpus` can catch that, and
/// it is `#[ignore]`d, so nothing was actually watching.
///
/// FALSIFIES: make this read the spec repo's `#guard_msgs` literal at test time
/// (needs the spec checkout reachable from CI), or un-ignore the live diff.
/// Until one lands, this test's green is evidence about two local files only.
#[test]
fn golden_anchor_ties_expectation_to_lean_guard_msgs_pin() {
    let expected = std::fs::read_to_string(expected_path()).expect("read expected hex");
    let golden_index = corpus_vectors()
        .iter()
        .position(|(name, ..)| name == "golden-fable")
        .expect("corpus carries the golden-fable vector");
    assert_eq!(
        expected.lines().nth(golden_index).unwrap(),
        LEAN_GUARD_MSGS_GOLDEN_HEX,
        "the expectation file and the in-repo golden const disagree. NOTE: this \
         compares two frozen LOCAL artifacts, never the spec repo (see docstring)"
    );
}

/// Live dual-encoder diff, no frozen middleman — the kernel-to-host binding.
/// Default: `lake env lean` against the manifest-pinned `mcp-seal` package
/// (`81e73dc`, Stage B). Override with `SEAL_V23_SPEC_LEAN_PATH` (+ optional
/// `SEAL_V23_LEAN_BIN`) to diff against an out-of-graph spec checkout.
#[test]
fn live_lean_diff_over_shared_corpus() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let lane_args = [
        "--run",
        "scripts/envelope_v23_twin_lane.lean",
        "rust/tests/vectors/envelope_v23_twin_corpus.json",
    ];
    let output = match std::env::var("SEAL_V23_SPEC_LEAN_PATH") {
        Ok(lean_path) => {
            let lean_bin = std::env::var("SEAL_V23_LEAN_BIN").unwrap_or_else(|_| "lean".into());
            Command::new(lean_bin)
                .args(lane_args)
                .env("LEAN_PATH", lean_path)
                .current_dir(root)
                .output()
                .expect("spawn lean")
        }
        Err(_) => Command::new("lake")
            .args(["env", "lean"])
            .args(lane_args)
            .current_dir(root)
            .output()
            .expect("spawn lake env lean"),
    };
    assert!(
        output.status.success(),
        "lean lane failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lean_lines: Vec<&str> = std::str::from_utf8(&output.stdout)
        .expect("lean lane emits UTF-8")
        .lines()
        .collect();
    let rust_lines = rust_hex_lines();
    assert_eq!(lean_lines.len(), rust_lines.len(), "vector count mismatch");
    for ((name, rust_hex), lean_hex) in rust_lines.iter().zip(&lean_lines) {
        assert_eq!(rust_hex, lean_hex, "LIVE byte-twin break on vector {name}");
    }
}
