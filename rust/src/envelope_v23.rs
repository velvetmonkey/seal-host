// SPDX-License-Identifier: Apache-2.0
//! Rust byte twin and host-side gates for the gated V2.3 effect envelope
//! (`seal.effect/v2`, Stage B strip).
//!
//! This module independently reconstructs the manifest-pinned
//! `SealV2.Effect.effectMessage` byte contract and checks the transport facts
//! Rust owns at the active verification boundary.
//!
//! Stage B (E1★ ballot, Ben 2026-07-22) stripped the killed seats; Stage B2
//! (field-warrant reconciliation, same unshipped tag) adjusts the shape:
//! `expires_at` and `policy_version` are RESCUED and MANDATORY (their gates
//! were proven kernel-side), `revocation_subject` is STRIPPED (SEAT — a
//! request field cannot shrink trust), and the F3 effect claim is
//! Option-encoded with a SIGNED presence byte (0x00 absent / 0x01 present):
//! absence is declared, never inferred from empty strings, and the retired
//! ("","","") sentinel is an ordinary checked claim. Killed and refused at
//! parse (`deny_unknown_fields`): `idempotency_key`, `on_behalf_of`,
//! `parent_capability_ref`, `audience`, `causality_token`,
//! `revocation_subject`; the domain-tag bump to `seal.effect/v2` makes a
//! signature over the old seated layout fail closed at verify.

use crate::ed25519::{self, VerificationError};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;

/// Stage B domain tag. The v1→v2 bump IS the strip: `seal.effect/v1` signed
/// seven fields this layout no longer carries (Lean twin:
/// `SealV2.Effect.effectTag`, cross-version separation proven there as
/// `effect_cross_version_v1_separated`).
pub const DOMAIN_TAG: &[u8] = b"seal.effect/v2\0";
pub const MCP_ADAPTER_TYPE: &str = "mcp";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterClaim {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrincipalClaim {
    pub session: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EffectClaim {
    pub resource: String,
    pub action: String,
    /// Kernel-defined `SealV2.serializeAstValue` bytes for MCP
    /// `params.arguments` (not an RFC 8785/JCS claim).
    pub args: String,
    /// Complete `_meta` value. The signed bytes use the pinned kernel rule;
    /// `None` is structural absence;
    /// every present value, including `null`, remains distinct.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_json"
    )]
    pub metadata: Option<Value>,
    /// Complete opaque JSON value. Structural absence, `{}`, and `null` are
    /// distinct: a present JSON null deserializes as `Some(Value::Null)`.
    #[serde(
        rename = "requestState",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_json"
    )]
    pub request_state: Option<Value>,
    /// Complete JSON value; kernel-rule rendering retains every member.
    #[serde(
        rename = "inputResponses",
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_json"
    )]
    pub input_responses: Option<Value>,
}

fn deserialize_present_json<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

/// The stripped Stage B envelope: every field both authenticated AND
/// interpreted. The E1★ killed seats are gone from the struct, so
/// `deny_unknown_fields` rejects any wire envelope still carrying one —
/// the parse-level negative control.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeV23 {
    pub key_id: String,
    pub sig: String,
    pub nonce: String,
    pub issued_at: u64,
    /// MANDATORY nonzero signer-declared deadline (Stage B2; kernel
    /// `expiryGate`). A missing key fails parse; zero fails `verify`.
    pub expires_at: u64,
    pub adapter: AdapterClaim,
    pub principal: PrincipalClaim,
    /// MANDATORY nonempty anti-downgrade pin (Stage B2; kernel
    /// `policyVersionGate` holds the equality against trusted state).
    pub policy_version: String,
    /// F3 advisory claim — INTERPRETED (equality gate below); under a
    /// separate flagged strip decision, deliberately retained. `None` is
    /// DECLARED absence (signed presence byte 0x00), not an empty-string
    /// sentinel; an absent JSON key parses as `None`.
    #[serde(default)]
    pub effect: Option<EffectClaim>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireView {
    Plain,
    Enveloped {
        request: String,
        envelope: Box<EnvelopeV23>,
    },
    Malformed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEnvelope {
    pub principal: String,
}

#[derive(Clone, Debug)]
pub struct HostContext<'a> {
    pub authority_hex: &'a str,
    pub session: &'a str,
    pub adapter: &'a AdapterClaim,
    pub kernel_config: &'a Value,
}

/// Proof-carrying result of the host-boundary byte-agreement check.  Its
/// fields are private: callers can obtain one only after the actual pinned
/// Lean derivation and the independent Rust derivation matched in every
/// signed effect seat.
#[derive(Clone, Debug)]
pub struct CanonicalAgreement {
    line: String,
    effect: EffectClaim,
}

/// Typed fail-closed outcomes of canonical byte classification.  None is a
/// signing/verification verdict; every variant means that no canonical
/// preimage may be used for this request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonicalAgreementError {
    RustUnclassifiable(String),
    LeanSeam(String),
    LeanUnclassifiable(String),
    MalformedLeanObservation(String),
    ByteMismatch { field: &'static str },
    WrongRequest,
    MissingAgreement,
    EffectClaimMismatch,
    PreimageEncoding(String),
}

impl std::fmt::Display for CanonicalAgreementError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RustUnclassifiable(reason) => {
                write!(formatter, "Rust could not classify signed effect: {reason}")
            }
            Self::LeanSeam(reason) => write!(formatter, "Lean canonical oracle failed: {reason}"),
            Self::LeanUnclassifiable(reason) => {
                write!(formatter, "Lean could not classify signed effect: {reason}")
            }
            Self::MalformedLeanObservation(reason) => {
                write!(
                    formatter,
                    "Lean canonical oracle returned malformed data: {reason}"
                )
            }
            Self::ByteMismatch { field } => {
                write!(formatter, "Rust and Lean canonical bytes differ at {field}")
            }
            Self::WrongRequest => formatter
                .write_str("canonical agreement witness belongs to a different judged request"),
            Self::MissingAgreement => formatter
                .write_str("present signed effect lacks a canonical byte agreement witness"),
            Self::EffectClaimMismatch => {
                formatter.write_str("signed effect claim does not match the agreement witness")
            }
            Self::PreimageEncoding(reason) => {
                write!(formatter, "cannot encode signed effect preimage: {reason}")
            }
        }
    }
}

impl std::error::Error for CanonicalAgreementError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalSeatObservation {
    present: bool,
    #[serde(default)]
    bytes: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalEffectObservation {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    args: Option<String>,
    #[serde(default)]
    metadata: Option<CanonicalSeatObservation>,
    #[serde(rename = "requestState", default)]
    request_state: Option<CanonicalSeatObservation>,
    #[serde(rename = "inputResponses", default)]
    input_responses: Option<CanonicalSeatObservation>,
}

/// Parse the strict V2.3 wrapper. Only the F3 `effect` claim may be
/// omitted (declared absence); unknown fields — every killed field,
/// `revocation_subject` included — are refused.
pub fn wire_view(line: &str) -> WireView {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return WireView::Plain;
    };
    let Some(object) = value.as_object() else {
        return WireView::Plain;
    };
    if !object.contains_key("seal_env") {
        return WireView::Plain;
    }
    if object.len() != 2 || !object.contains_key("request") {
        return WireView::Malformed("envelope must carry exactly {seal_env, request}".into());
    }
    let Some(request) = object.get("request").and_then(Value::as_str) else {
        return WireView::Malformed("request must be a string".into());
    };
    if request.is_empty() {
        return WireView::Malformed("request must be non-empty".into());
    }
    if request.contains(['\n', '\r', '\0']) {
        return WireView::Malformed(
            "request must not contain newline, CR, or NUL (line smuggling refused)".into(),
        );
    }
    let envelope = match serde_json::from_value::<EnvelopeV23>(object["seal_env"].clone()) {
        Ok(envelope) => envelope,
        Err(error) => return WireView::Malformed(format!("invalid seal_env: {error}")),
    };
    WireView::Enveloped {
        request: request.into(),
        envelope: Box::new(envelope),
    }
}

fn frame(message: &mut Vec<u8>, bytes: &[u8]) {
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(bytes);
}

/// Render one complete JSON value through recursively scalar-sorted object
/// members using serde_json. Arrays retain order; no member is selected or
/// interpreted. This is compared with `Lean.Json.compress` by the boundary
/// gate and is not an RFC 8785/JCS claim.
pub fn canonical_json(value: &Value) -> Result<String, String> {
    fn normalized(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut entries: Vec<_> = object.iter().collect();
                entries.sort_by_key(|(key, _)| *key);
                let mut canonical = serde_json::Map::new();
                for (key, value) in entries {
                    canonical.insert(key.clone(), normalized(value));
                }
                Value::Object(canonical)
            }
            Value::Array(values) => Value::Array(values.iter().map(normalized).collect()),
            _ => value.clone(),
        }
    }

    serde_json::to_string(&normalized(value))
        .map_err(|error| format!("cannot canonicalize complete JSON value: {error}"))
}

/// Derive the complete MCP claim from the judged line. `requestState`
/// is fetched exactly once from top-level `params` and then treated opaquely;
/// `inputResponses` is cloned whole.
pub fn derive_mcp_effect(line: &str) -> Result<EffectClaim, String> {
    let request: Value = serde_json::from_str(line)
        .map_err(|error| format!("cannot parse judged MCP line: {error}"))?;
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Err("judged line is not an MCP tools/call".into());
    }
    let params = request
        .get("params")
        .and_then(Value::as_object)
        .ok_or("judged MCP line lacks object params")?;
    let resource = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or("judged MCP line lacks string params.name")?;
    let action = params
        .get("action")
        .and_then(Value::as_str)
        .ok_or("judged MCP line lacks string params.action")?;
    let arguments = params
        .get("arguments")
        .ok_or("judged MCP line lacks params.arguments")?;
    let metadata = params.get("_meta").cloned();
    Ok(EffectClaim {
        resource: resource.into(),
        action: action.into(),
        args: serde_json::to_string(arguments)
            .map_err(|error| format!("cannot serialize MCP arguments: {error}"))?,
        metadata,
        request_state: params.get("requestState").cloned(),
        input_responses: params.get("inputResponses").cloned(),
    })
}

fn observed_seat(
    name: &'static str,
    observation: Option<CanonicalSeatObservation>,
) -> Result<Option<String>, CanonicalAgreementError> {
    let observation = observation.ok_or_else(|| {
        CanonicalAgreementError::MalformedLeanObservation(format!(
            "successful response omitted {name}"
        ))
    })?;
    match (observation.present, observation.bytes) {
        (false, None) => Ok(None),
        (true, Some(bytes)) => Ok(Some(bytes)),
        (false, Some(_)) => Err(CanonicalAgreementError::MalformedLeanObservation(format!(
            "absent {name} carried bytes"
        ))),
        (true, None) => Err(CanonicalAgreementError::MalformedLeanObservation(format!(
            "present {name} omitted bytes"
        ))),
    }
}

fn rust_seat(value: &Option<Value>) -> Result<Option<String>, CanonicalAgreementError> {
    value
        .as_ref()
        .map(canonical_json)
        .transpose()
        .map_err(CanonicalAgreementError::RustUnclassifiable)
}

/// Compare the actual Rust signed-effect derivation with the exact field
/// bytes observed from `seal_host_canonical_effect`.  This predicate is the
/// containment boundary: its accepted space is the complete set of inputs
/// for which both implementations returned the same signed tuple, rather
/// than a hand-picked character or number allowlist.
pub fn canonical_effect_agreement(
    line: &str,
    lean_observation: &str,
) -> Result<CanonicalAgreement, CanonicalAgreementError> {
    let rust = derive_mcp_effect(line).map_err(CanonicalAgreementError::RustUnclassifiable)?;
    let lean: CanonicalEffectObservation = serde_json::from_str(lean_observation)
        .map_err(|error| CanonicalAgreementError::MalformedLeanObservation(error.to_string()))?;
    if !lean.ok {
        return Err(CanonicalAgreementError::LeanUnclassifiable(
            lean.error
                .unwrap_or_else(|| "oracle returned ok=false without an error".into()),
        ));
    }
    if lean.error.is_some() {
        return Err(CanonicalAgreementError::MalformedLeanObservation(
            "successful response also carried an error".into(),
        ));
    }

    let lean_resource = lean.resource.ok_or_else(|| {
        CanonicalAgreementError::MalformedLeanObservation(
            "successful response omitted resource".into(),
        )
    })?;
    let lean_action = lean.action.ok_or_else(|| {
        CanonicalAgreementError::MalformedLeanObservation(
            "successful response omitted action".into(),
        )
    })?;
    let lean_args = lean.args.ok_or_else(|| {
        CanonicalAgreementError::MalformedLeanObservation("successful response omitted args".into())
    })?;
    let lean_metadata = observed_seat("metadata", lean.metadata)?;
    let lean_request_state = observed_seat("requestState", lean.request_state)?;
    let lean_input_responses = observed_seat("inputResponses", lean.input_responses)?;

    let comparisons = [
        ("resource", rust.resource.as_str(), lean_resource.as_str()),
        ("action", rust.action.as_str(), lean_action.as_str()),
        ("arguments", rust.args.as_str(), lean_args.as_str()),
    ];
    for (field, rust_bytes, lean_bytes) in comparisons {
        if rust_bytes.as_bytes() != lean_bytes.as_bytes() {
            return Err(CanonicalAgreementError::ByteMismatch { field });
        }
    }
    for (field, rust_bytes, lean_bytes) in [
        ("_meta", rust_seat(&rust.metadata)?, lean_metadata),
        (
            "requestState",
            rust_seat(&rust.request_state)?,
            lean_request_state,
        ),
        (
            "inputResponses",
            rust_seat(&rust.input_responses)?,
            lean_input_responses,
        ),
    ] {
        if rust_bytes != lean_bytes {
            return Err(CanonicalAgreementError::ByteMismatch { field });
        }
    }

    Ok(CanonicalAgreement {
        line: line.to_owned(),
        effect: rust,
    })
}

/// Exact byte twin of the manifest-pinned Phase-M
/// `SealV2.Effect.effectMessage`:
///
/// ```text
/// tag ‖ authority(32) ‖ frame(key_id) ‖ nonce(32)
///     ‖ u64be(issued_at) ‖ u64be(expires_at)
///     ‖ frame(line)
///     ‖ frame(adapter.type) ‖ frame(adapter.version)
///     ‖ frame(principal.session) ‖ frame(policy_version)
///     ‖ opt_effect(effect)
/// ```
///
/// where `opt_effect(None) = 0x00` and `opt_effect(Some c) =
/// `0x01 ‖ frame(c.resource) ‖ frame(c.action) ‖ frame(c.args)
///  ‖ opt_meta(c.metadata) ‖ opt_mrtr(c.request_state,c.input_responses)`.
/// Metadata uses an explicit `0x00`/`0x01` presence byte. The all-absent
/// MRTR block is empty; its other three structural modes start with
/// `0x01`/`0x02`/`0x03` and frame complete kernel-rule JSON values.
pub fn effect_message(
    authority: &[u8; 32],
    envelope: &EnvelopeV23,
    line: &str,
) -> Result<Vec<u8>, String> {
    let nonce = decode_array::<32>(&envelope.nonce, "nonce")?;
    let mut message = Vec::new();
    message.extend_from_slice(DOMAIN_TAG);
    message.extend_from_slice(authority);
    frame(&mut message, envelope.key_id.as_bytes());
    message.extend_from_slice(&nonce);
    message.extend_from_slice(&envelope.issued_at.to_be_bytes());
    message.extend_from_slice(&envelope.expires_at.to_be_bytes());
    frame(&mut message, line.as_bytes());
    frame(&mut message, envelope.adapter.kind.as_bytes());
    frame(&mut message, envelope.adapter.version.as_bytes());
    frame(&mut message, envelope.principal.session.as_bytes());
    frame(&mut message, envelope.policy_version.as_bytes());
    match &envelope.effect {
        None => message.push(0x00),
        Some(effect) => {
            message.push(0x01);
            frame(&mut message, effect.resource.as_bytes());
            frame(&mut message, effect.action.as_bytes());
            frame(&mut message, effect.args.as_bytes());

            match &effect.metadata {
                None => message.push(0x00),
                Some(metadata) => {
                    message.push(0x01);
                    let canonical = canonical_json(metadata)?;
                    frame(&mut message, canonical.as_bytes());
                }
            }

            match (&effect.request_state, &effect.input_responses) {
                (None, None) => {}
                (Some(state), None) => {
                    message.push(0x01);
                    let canonical = canonical_json(state)?;
                    frame(&mut message, canonical.as_bytes());
                }
                (None, Some(responses)) => {
                    message.push(0x02);
                    let canonical = canonical_json(responses)?;
                    frame(&mut message, canonical.as_bytes());
                }
                (Some(state), Some(responses)) => {
                    message.push(0x03);
                    let canonical_state = canonical_json(state)?;
                    let canonical_responses = canonical_json(responses)?;
                    frame(&mut message, canonical_state.as_bytes());
                    frame(&mut message, canonical_responses.as_bytes());
                }
            }
        }
    }
    Ok(message)
}

fn require_agreement<'a>(
    envelope: &EnvelopeV23,
    line: &str,
    agreement: Option<&'a CanonicalAgreement>,
) -> Result<Option<&'a CanonicalAgreement>, CanonicalAgreementError> {
    let Some(effect) = &envelope.effect else {
        return Ok(None);
    };
    let agreement = agreement.ok_or(CanonicalAgreementError::MissingAgreement)?;
    if agreement.line != line {
        return Err(CanonicalAgreementError::WrongRequest);
    }
    if *effect != agreement.effect {
        return Err(CanonicalAgreementError::EffectClaimMismatch);
    }
    Ok(Some(agreement))
}

/// Produce bytes suitable for signing only after the full-domain Lean/Rust
/// boundary check.  The raw `effect_message` remains exposed as the verifier
/// twin and vector oracle; in-repository signers use this witness-requiring
/// entry point so divergent input is rejected before Ed25519 is invoked.
pub fn effect_message_for_signing(
    authority: &[u8; 32],
    envelope: &EnvelopeV23,
    line: &str,
    agreement: Option<&CanonicalAgreement>,
) -> Result<Vec<u8>, CanonicalAgreementError> {
    require_agreement(envelope, line, agreement)?;
    effect_message(authority, envelope, line).map_err(CanonicalAgreementError::PreimageEncoding)
}

/// Verify every host-owned equality gate and the Ed25519 signature over the
/// reconstructed full tuple.
pub fn verify(
    envelope: &EnvelopeV23,
    line: &str,
    context: &HostContext<'_>,
    agreement: Option<&CanonicalAgreement>,
) -> Result<VerifiedEnvelope, String> {
    if envelope.adapter != *context.adapter {
        return Err("V2.3 adapter claim does not match the deployed mediator".into());
    }
    if envelope.principal.session.is_empty() || envelope.principal.session != context.session {
        return Err("V2.3 principal session does not match the issued session".into());
    }
    if envelope.expires_at == 0 {
        return Err("V2.3 expires_at is mandatory and must be nonzero".into());
    }
    if envelope.policy_version.is_empty() {
        return Err("V2.3 policy_version is mandatory and must be nonempty".into());
    }
    if let Some(effect) = &envelope.effect {
        let agreement = match require_agreement(envelope, line, agreement)
            .map_err(|error| error.to_string())?
        {
            Some(agreement) => agreement,
            None => return Err(CanonicalAgreementError::MissingAgreement.to_string()),
        };
        // A PRESENT claim is checked unconditionally — the retired
        // all-empty sentinel is a claim like any other (Stage B2).
        if context.adapter.kind != MCP_ADAPTER_TYPE {
            return Err("non-MCP adapter carried an MCP effect claim".into());
        }
        debug_assert_eq!(effect, &agreement.effect);
    }

    let authority = decode_array::<32>(context.authority_hex, "config authority")?;
    let keys = context
        .kernel_config
        .pointer("/principals/keys")
        .and_then(Value::as_array)
        .ok_or("signed config has no principal registry")?;
    let key = keys
        .iter()
        .find(|key| key.get("id").and_then(Value::as_str) == Some(envelope.key_id.as_str()))
        .ok_or("V2.3 key_id is not registered")?;
    let pubkey_hex = key
        .get("pubkey")
        .and_then(Value::as_str)
        .ok_or("registered principal has no string pubkey")?;
    let pubkey = decode_array::<32>(pubkey_hex, "principal pubkey")?;
    let signature = decode_array::<64>(&envelope.sig, "signature")?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey)
        .map_err(|error| format!("invalid principal pubkey: {error}"))?;
    ed25519::verify(
        &verifying_key,
        &effect_message(&authority, envelope, line)?,
        &Signature::from_bytes(&signature),
    )
    .map_err(|error| match error {
        VerificationError::NonCanonicalScalar => {
            "V2.3 signature is malformed: RFC 8032 requires scalar S < L".to_string()
        }
        VerificationError::Mismatch => "V2.3 signature verification failed".to_string(),
    })?;
    Ok(VerifiedEnvelope {
        principal: envelope.key_id.clone(),
    })
}

/// Host-side cross-check at the future Lean adapter boundary. Rust may enact
/// a V2.3 result only when Lean reports the same authenticated registry id.
pub fn verify_kernel_principal(
    step_output: &str,
    verified: &VerifiedEnvelope,
) -> Result<(), String> {
    let output: Value = serde_json::from_str(step_output)
        .map_err(|error| format!("bad kernel step output: {error}"))?;
    match output.get("principal").and_then(Value::as_str) {
        Some(principal) if principal == verified.principal => Ok(()),
        Some(_) => Err("kernel principal disagrees with the host-verified V2.3 key".into()),
        None => Err("kernel omitted the host-verified V2.3 principal".into()),
    }
}

/// A boot-stable, client-visible session id. Entropy failure is a startup
/// failure: silently falling back to the authorization-decision PID string would cross the
/// locked session-plane boundary.
pub fn issue_session_id() -> Result<String, String> {
    let mut random = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .map_err(|error| format!("cannot issue V2.3 session: {error}"))?;
    Ok(format!("seal-session-v1:{}", hex::encode(random)))
}

fn decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|error| format!("bad {label} hex: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{label} must be exactly {N} bytes"))
}
