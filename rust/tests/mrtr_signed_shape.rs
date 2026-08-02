// SPDX-License-Identifier: Apache-2.0
//! Live Phase-M signed effect-shape correspondence. Expected bytes are never
//! checked in: Rust and the actual Lean encoder run over the same named
//! observations and are compared directly.

use seal_host_rs::envelope_v23::{
    derive_mcp_effect, effect_message, AdapterClaim, EnvelopeV23, PrincipalClaim,
};
use std::collections::BTreeMap;
use std::process::Command;

fn request(
    metadata: Option<&str>,
    request_state: Option<&str>,
    input_responses: Option<&str>,
) -> String {
    let mut raw = String::from(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell_exec","action":"run","arguments":{"command":"echo controlled"}"#,
    );
    if let Some(value) = metadata {
        raw.push_str(",\"_meta\":");
        raw.push_str(value);
    }
    if let Some(value) = request_state {
        raw.push_str(",\"requestState\":");
        raw.push_str(value);
    }
    if let Some(value) = input_responses {
        raw.push_str(",\"inputResponses\":");
        raw.push_str(value);
    }
    raw.push_str("}}");
    raw
}

fn rust_observations() -> BTreeMap<String, String> {
    let state_left =
        r#"{"opaque":{"token":"state-a","ignoredSemantics":[1,null,false]},"sibling":"retained"}"#;
    let state_right =
        r#"{"opaque":{"token":"state-b","ignoredSemantics":[1,null,false]},"sibling":"retained"}"#;
    let responses_left = r#"{"confirm":{"action":"accept","content":true},"survey":{"score":5},"extension":["one","two"]}"#;
    let responses_right = r#"{"confirm":{"action":"decline","content":false},"survey":{"score":5},"extension":["one","two"]}"#;
    let cases = [
        ("requestState.left", request(None, Some(state_left), None)),
        ("requestState.right", request(None, Some(state_right), None)),
        (
            "inputResponses.left",
            request(None, None, Some(responses_left)),
        ),
        (
            "inputResponses.right",
            request(None, None, Some(responses_right)),
        ),
        (
            "metadata.left",
            request(Some(r#"{"trace":"meta-a","attempt":1}"#), None, None),
        ),
        (
            "metadata.right",
            request(Some(r#"{"trace":"meta-b","attempt":1}"#), None, None),
        ),
        ("metadata.absent", request(None, None, None)),
        ("metadata.present-empty", request(Some("{}"), None, None)),
        (
            "metadata.with-requestState",
            request(
                Some(r#"{"trace":"co-present"}"#),
                Some(r#"{"opaque":"state"}"#),
                None,
            ),
        ),
        ("requestState.absent", request(None, None, None)),
        (
            "requestState.present-empty",
            request(None, Some("{}"), None),
        ),
        (
            "requestState.present-null",
            request(None, Some("null"), None),
        ),
        ("inputResponses.absent", request(None, None, None)),
        (
            "inputResponses.present-empty",
            request(None, None, Some("{}")),
        ),
        (
            "inputResponses.present-null",
            request(None, None, Some("null")),
        ),
        (
            "both.present",
            request(
                None,
                Some(r#"{"opaque":"state"}"#),
                Some(r#"{"confirm":{"action":"accept"},"extension":{"retained":true}}"#),
            ),
        ),
    ];
    let authority: [u8; 32] = std::array::from_fn(|index| 160 + index as u8);
    let mut observations = BTreeMap::new();
    for (label, raw) in cases {
        let claim = derive_mcp_effect(&raw)
            .unwrap_or_else(|error| panic!("{label}: Phase-M derivation failed: {error}"));
        let envelope = EnvelopeV23 {
            key_id: "mrtr-control".into(),
            sig: String::new(),
            nonce: hex::encode((0u8..32).collect::<Vec<_>>()),
            issued_at: 10,
            expires_at: 120,
            adapter: AdapterClaim {
                kind: "mcp".into(),
                version: "2026-07-28".into(),
            },
            principal: PrincipalClaim {
                session: "mrtr-control".into(),
            },
            policy_version: "mrtr-control-policy".into(),
            effect: Some(claim),
        };
        let first = effect_message(&authority, &envelope, "{}").unwrap();
        let twin = effect_message(&authority, &envelope, "{}").unwrap();
        assert_eq!(
            first, twin,
            "SIGNED-SHAPE-POSITIVE-TWIN RED field={label}: byte-identical claims differed"
        );
        println!(
            "SIGNED-SHAPE-POSITIVE-TWIN GREEN field={label} claim=byte-identical message=same"
        );
        observations.insert(label.into(), hex::encode(first));
    }

    for field in ["requestState", "inputResponses"] {
        assert_ne!(
            observations[&format!("{field}.left")],
            observations[&format!("{field}.right")],
            "SIGNED-SHAPE-DISCRIMINATION RED field={field}: complete values collided"
        );
        let absent = &observations[&format!("{field}.absent")];
        let empty = &observations[&format!("{field}.present-empty")];
        let null = &observations[&format!("{field}.present-null")];
        assert!(
            absent != empty && absent != null && empty != null,
            "SIGNED-SHAPE-ABSENCE RED field={field}: absent/empty/null collapsed"
        );
        println!(
            "SIGNED-SHAPE-DISCRIMINATION GREEN field={field} complete-values=different absent/empty/null=three-distinct"
        );
    }
    assert_ne!(
        observations["metadata.left"], observations["metadata.right"],
        "SIGNED-SHAPE-DISCRIMINATION RED field=metadata: complete values collided"
    );
    assert_ne!(
        observations["metadata.absent"], observations["metadata.present-empty"],
        "SIGNED-SHAPE-ABSENCE RED field=metadata: absent/present-empty collapsed"
    );
    println!(
        "SIGNED-SHAPE-DISCRIMINATION GREEN field=metadata complete-values=different absent/present-empty=distinct"
    );
    observations
}

#[test]
fn live_phase_m_rust_lean_signed_shape_agreement() {
    let rust = rust_observations();
    let host_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let spec_root = std::env::var_os("SEAL_PHASE_M_SPEC_ROOT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let sibling = host_root.parent().unwrap().join("mcp-seal-dev");
            if sibling.is_dir() {
                sibling
            } else {
                host_root.clone()
            }
        });

    // Before Ben's repin, a checkout without the sibling Phase-M spec has no
    // compatible Lean type to compile this lane against. Keep ordinary CI
    // green without pretending the old pin is evidence; the required local
    // run supplies `81b2114` (or an explicit override).
    if spec_root == host_root {
        let pinned = host_root.join(".lake/packages/mcp-seal/SealV2/EffectEnvelope.lean");
        let source = std::fs::read_to_string(&pinned).expect("read manifest-pinned effect spec");
        if !source.contains("def optMrtr") {
            eprintln!(
                "SIGNED-SHAPE UNVERIFIED: manifest pin predates Phase M and no SEAL_PHASE_M_SPEC_ROOT/sibling checkout is available"
            );
            return;
        }
    }

    let lane = host_root.join("scripts/mrtr_signed_shape_lane.lean");
    let output = Command::new("lake")
        .args(["env", "lean", "--run"])
        .arg(&lane)
        .current_dir(&spec_root)
        .output()
        .expect("spawn live Phase-M Lean lane");
    assert!(
        output.status.success(),
        "Phase-M Lean lane failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lean: BTreeMap<String, String> = std::str::from_utf8(&output.stdout)
        .expect("Lean lane emits UTF-8")
        .lines()
        .map(|line| {
            let (label, hex) = line
                .split_once(' ')
                .unwrap_or_else(|| panic!("malformed Lean observation: {line:?}"));
            (label.into(), hex.into())
        })
        .collect();
    assert_eq!(
        rust.keys().collect::<Vec<_>>(),
        lean.keys().collect::<Vec<_>>()
    );
    for (label, rust_hex) in &rust {
        assert_eq!(
            Some(rust_hex),
            lean.get(label),
            "RUST-LEAN-SIGNED-SHAPE RED field={label}: encoders disagree"
        );
    }
    println!(
        "RUST-LEAN-SIGNED-SHAPE GREEN fields=metadata,requestState,inputResponses modes=absent,metadata,state,responses,co-present complete-values=byte-identical"
    );
}
