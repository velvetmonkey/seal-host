// SPDX-License-Identifier: Apache-2.0
//! Rust byte twin and host-side gates for the gated V2.3 effect envelope.
//!
//! This module deliberately does not alter or replace the pinned Lean kernel.
//! It stages the exact `SealV2.Effect.effectMessage` byte contract and the
//! transport facts Rust must independently check before the future repin.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;

pub const DOMAIN_TAG: &[u8] = b"seal.effect/v1\0";
pub const MCP_ADAPTER_TYPE: &str = "mcp";
pub const MCP_ADAPTER_VERSION: &str = "2025-06-18";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdapterClaim {
    #[serde(rename = "type")]
    pub kind: String,
    pub version: String,
}

impl AdapterClaim {
    pub fn deployed_mcp() -> Self {
        Self {
            kind: MCP_ADAPTER_TYPE.into(),
            version: MCP_ADAPTER_VERSION.into(),
        }
    }
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
    /// Canonical JSON serialization of the MCP `params.arguments` value.
    pub args: String,
}

impl EffectClaim {
    fn empty() -> Self {
        Self {
            resource: String::new(),
            action: String::new(),
            args: String::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.resource.is_empty() && self.action.is_empty() && self.args.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DelegationSeats {
    #[serde(default)]
    pub on_behalf_of: String,
    #[serde(default)]
    pub parent_capability_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeV23 {
    pub key_id: String,
    pub sig: String,
    pub nonce: String,
    pub issued_at: u64,
    pub adapter: AdapterClaim,
    pub principal: PrincipalClaim,
    #[serde(default)]
    pub effect: Option<EffectClaim>,
    pub idempotency_key: String,
    #[serde(default)]
    pub policy_version: String,
    #[serde(default)]
    pub delegation: DelegationSeats,
    #[serde(default)]
    pub revocation_subject: String,
    #[serde(default)]
    pub audience: String,
    #[serde(default)]
    pub causality_token: String,
    #[serde(default)]
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WireView {
    Plain,
    Enveloped {
        request: String,
        envelope: EnvelopeV23,
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

/// Parse the strict V2.3 wrapper. Optional seats may be omitted and therefore
/// become their zero-length/zero wire values; unknown fields are refused.
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
        envelope,
    }
}

fn frame(message: &mut Vec<u8>, bytes: &[u8]) {
    message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(bytes);
}

/// Exact byte twin of `SealV2.Effect.effectMessage` on Fable's proof branch.
pub fn effect_message(
    authority: &[u8; 32],
    envelope: &EnvelopeV23,
    line: &str,
) -> Result<Vec<u8>, String> {
    let nonce = decode_array::<32>(&envelope.nonce, "nonce")?;
    let effect = envelope.effect.clone().unwrap_or_else(EffectClaim::empty);
    let mut message = Vec::new();
    message.extend_from_slice(DOMAIN_TAG);
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
    frame(&mut message, envelope.idempotency_key.as_bytes());
    frame(&mut message, envelope.policy_version.as_bytes());
    frame(&mut message, envelope.delegation.on_behalf_of.as_bytes());
    frame(
        &mut message,
        envelope.delegation.parent_capability_ref.as_bytes(),
    );
    frame(&mut message, envelope.revocation_subject.as_bytes());
    frame(&mut message, envelope.audience.as_bytes());
    frame(&mut message, envelope.causality_token.as_bytes());
    message.extend_from_slice(&envelope.expires_at.to_be_bytes());
    Ok(message)
}

/// The host's independent MCP projection. `args` is serialized in the same
/// object order as the exact judged line; it remains advisory and never
/// replaces `line` as the decision input.
pub fn derive_mcp_effect(line: &str) -> Result<EffectClaim, String> {
    let request: Value = serde_json::from_str(line)
        .map_err(|error| format!("cannot parse judged MCP line: {error}"))?;
    if request.get("method").and_then(Value::as_str) != Some("tools/call") {
        return Err("judged line is not an MCP tools/call".into());
    }
    let resource = request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .ok_or("judged MCP line lacks string params.name")?;
    let action = request
        .pointer("/params/action")
        .and_then(Value::as_str)
        .ok_or("judged MCP line lacks string params.action")?;
    let args = request
        .pointer("/params/arguments")
        .ok_or("judged MCP line lacks params.arguments")?;
    Ok(EffectClaim {
        resource: resource.into(),
        action: action.into(),
        args: serde_json::to_string(args)
            .map_err(|error| format!("cannot serialize MCP arguments: {error}"))?,
    })
}

/// Verify every host-owned equality gate and the Ed25519 signature over the
/// reconstructed full tuple. Seated fields are signed but deliberately not
/// consulted by any host gate.
pub fn verify(
    envelope: &EnvelopeV23,
    line: &str,
    context: &HostContext<'_>,
) -> Result<VerifiedEnvelope, String> {
    if envelope.adapter != *context.adapter {
        return Err("V2.3 adapter claim does not match the deployed mediator".into());
    }
    if envelope.principal.session.is_empty() || envelope.principal.session != context.session {
        return Err("V2.3 principal session does not match the issued session".into());
    }
    if let Some(effect) = &envelope.effect {
        if !effect.is_empty() {
            if context.adapter.kind != MCP_ADAPTER_TYPE {
                return Err("non-MCP adapter carried a non-empty MCP effect claim".into());
            }
            let expected = derive_mcp_effect(line)?;
            if *effect != expected {
                return Err("V2.3 effect claim does not match the judged line".into());
            }
        }
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
    verifying_key
        .verify(
            &effect_message(&authority, envelope, line)?,
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| "V2.3 signature verification failed".to_string())?;
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
/// failure: silently falling back to the receipt PID string would cross the
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
