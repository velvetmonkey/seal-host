// SPDX-License-Identifier: Apache-2.0
//! The extensible approval back-channel: trait-based providers that mint
//! approval records without touching the proven core. The host polls the
//! active provider before each mediated call; records then pass A3
//! (nonce/replay/TTL) before reaching Lean.

use crate::ed25519::{self, VerificationError};
use crate::limits::{
    check_json_limits, read_bounded_frame, read_file_bounded, FrameStatus, MAX_APPROVAL_LINE_BYTES,
    MAX_TOKEN_FILE_BYTES,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::BufRead;

pub const APPROVAL_RECORD_V2_DOMAIN: &str = "seal.approval-record/v2";
const APPROVAL_RECORD_V2_DOMAIN_PREFIX: &[u8] = b"seal.approval-record/v2\0";
const V1_APPROVAL_REFUSAL_REASON: &str = "approval_record_v1_not_supported";
const MAX_CANONICAL_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const SUBJECT_SCOPE: &str = "mcp-jsonrpc-request-frame-including-delimiter";

fn is_target_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Accept exactly the deployed target commitment format: lowercase 64-hex SHA-256.
fn target_hex<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    use serde::de::Error;
    match serde_json::Value::deserialize(d)? {
        serde_json::Value::String(s) if is_target_hex(&s) => Ok(s),
        serde_json::Value::String(_) => Err(D::Error::custom("target must be lowercase 64-hex")),
        _ => Err(D::Error::custom("target must be a lowercase 64-hex string")),
    }
}

fn opt_u64_str_or_num<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    use serde::de::Error;
    match Option::<serde_json::Value>::deserialize(d)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| D::Error::custom("not u64")),
        Some(serde_json::Value::String(s)) => s.parse().map(Some).map_err(D::Error::custom),
        _ => Err(D::Error::custom("issuedAt must be a number or string")),
    }
}

#[derive(Debug, Clone, Deserialize)]
struct LegacyApprovalRecord {
    #[serde(deserialize_with = "target_hex")]
    target: String,
    #[serde(rename = "issuedAt", default, deserialize_with = "opt_u64_str_or_num")]
    issued_at: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRenderer {
    pub name: String,
    pub version: String,
    pub manifest_sha256: String,
}

/// The exact payload covered by an ApprovalRecord v2 signature.
///
/// Field names and values follow AUTHORIZATION-RECORD.md §2.4. The token
/// signature and retained token bytes are deliberately outside this payload:
/// a signature cannot include the token bytes that contain that signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRecordV2Payload {
    pub approval_record_version: u64,
    #[serde(deserialize_with = "target_hex")]
    pub target: String,
    pub authorized_at: u64,
    pub expiry: u64,
    pub nonce: String,
    pub session: String,
    pub subject_sha256: String,
    pub subject_length: u64,
    pub subject_scope: String,
    pub subject_encoding: String,
    pub shown_sha256: String,
    pub shown_length: u64,
    pub shown_media_type: String,
    pub shown_character_encoding: String,
    pub renderer: ApprovalRenderer,
    pub approver: String,
    pub authorization_signer_key_id: String,
    pub authorization_signature_algorithm: String,
    pub authorization_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationToken {
    pub encoding: String,
    pub decoded_length: u64,
    pub sha256: String,
    pub bytes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalRecordV2 {
    pub approval_record_version: u64,
    pub target: String,
    pub authorized_at: u64,
    pub expiry: u64,
    pub nonce: String,
    pub session: String,
    pub subject_sha256: String,
    pub subject_length: u64,
    pub subject_scope: String,
    pub subject_encoding: String,
    pub shown_sha256: String,
    pub shown_length: u64,
    pub shown_media_type: String,
    pub shown_character_encoding: String,
    pub renderer: ApprovalRenderer,
    pub approver: String,
    pub authorization_signer_key_id: String,
    pub authorization_signature_algorithm: String,
    pub authorization_domain: String,
    pub authorization_token: AuthorizationToken,
}

impl ApprovalRecordV2 {
    fn from_verified_payload(
        payload: ApprovalRecordV2Payload,
        original_token_bytes: &[u8],
    ) -> Self {
        Self {
            approval_record_version: payload.approval_record_version,
            target: payload.target,
            authorized_at: payload.authorized_at,
            expiry: payload.expiry,
            nonce: payload.nonce,
            session: payload.session,
            subject_sha256: payload.subject_sha256,
            subject_length: payload.subject_length,
            subject_scope: payload.subject_scope,
            subject_encoding: payload.subject_encoding,
            shown_sha256: payload.shown_sha256,
            shown_length: payload.shown_length,
            shown_media_type: payload.shown_media_type,
            shown_character_encoding: payload.shown_character_encoding,
            renderer: payload.renderer,
            approver: payload.approver,
            authorization_signer_key_id: payload.authorization_signer_key_id,
            authorization_signature_algorithm: payload.authorization_signature_algorithm,
            authorization_domain: payload.authorization_domain,
            authorization_token: AuthorizationToken {
                encoding: "base64url-nopad".to_string(),
                decoded_length: original_token_bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(original_token_bytes)),
                bytes: URL_SAFE_NO_PAD.encode(original_token_bytes),
            },
        }
    }

    pub fn payload(&self) -> ApprovalRecordV2Payload {
        ApprovalRecordV2Payload {
            approval_record_version: self.approval_record_version,
            target: self.target.clone(),
            authorized_at: self.authorized_at,
            expiry: self.expiry,
            nonce: self.nonce.clone(),
            session: self.session.clone(),
            subject_sha256: self.subject_sha256.clone(),
            subject_length: self.subject_length,
            subject_scope: self.subject_scope.clone(),
            subject_encoding: self.subject_encoding.clone(),
            shown_sha256: self.shown_sha256.clone(),
            shown_length: self.shown_length,
            shown_media_type: self.shown_media_type.clone(),
            shown_character_encoding: self.shown_character_encoding.clone(),
            renderer: self.renderer.clone(),
            approver: self.approver.clone(),
            authorization_signer_key_id: self.authorization_signer_key_id.clone(),
            authorization_signature_algorithm: self.authorization_signature_algorithm.clone(),
            authorization_domain: self.authorization_domain.clone(),
        }
    }

    pub fn matches_framed_subject(&self, framed_bytes: &[u8]) -> bool {
        self.subject_scope == SUBJECT_SCOPE
            && self.subject_encoding == "bytes"
            && self.subject_length == framed_bytes.len() as u64
            && self.subject_sha256 == hex::encode(Sha256::digest(framed_bytes))
    }
}

#[derive(Debug, Clone)]
enum ApprovalEvidence {
    Legacy,
    V2(Box<ApprovalRecordV2>),
}

#[derive(Debug, Clone)]
pub struct ApprovalRecord {
    pub target: String,
    pub issued_at: Option<u64>,
    pub nonce: Option<String>,
    evidence: ApprovalEvidence,
}

impl ApprovalRecord {
    pub fn legacy(target: String, issued_at: Option<u64>, nonce: Option<String>) -> Self {
        Self {
            target,
            issued_at,
            nonce,
            evidence: ApprovalEvidence::Legacy,
        }
    }

    fn from_v2(record: ApprovalRecordV2) -> Self {
        Self {
            target: record.target.clone(),
            issued_at: Some(record.authorized_at),
            nonce: Some(record.nonce.clone()),
            evidence: ApprovalEvidence::V2(Box::new(record)),
        }
    }

    /// `None` is the fail-closed evidence classification for an internal
    /// legacy record. Ingest providers refuse v1 approvals; legacy records
    /// remain for non-admission checks such as principal-envelope replay.
    pub fn v2(&self) -> Option<&ApprovalRecordV2> {
        match &self.evidence {
            ApprovalEvidence::Legacy => None,
            ApprovalEvidence::V2(record) => Some(record),
        }
    }

    pub fn authorizes_framed_subject(&self, framed_bytes: &[u8]) -> bool {
        match &self.evidence {
            ApprovalEvidence::Legacy => true,
            ApprovalEvidence::V2(record) => record.matches_framed_subject(framed_bytes),
        }
    }
}

fn write_canonical_json_string(value: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in value.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br#"\\"#),
            '\u{0000}'..='\u{001f}' => {
                let byte = ch as u8;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[(byte >> 4) as usize]);
                out.push(HEX[(byte & 0x0f) as usize]);
            }
            _ => {
                let mut encoded = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
            }
        }
    }
    out.push(b'"');
}

fn write_canonical_json(value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => {
            let integer = number
                .as_u64()
                .ok_or("approval payload numbers must be unsigned integers")?;
            if integer > MAX_CANONICAL_JSON_INTEGER {
                return Err("approval payload integer exceeds canonical JSON range".to_string());
            }
            out.extend_from_slice(integer.to_string().as_bytes());
        }
        Value::String(string) => write_canonical_json_string(string, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(object) => {
            out.push(b'{');
            let mut members: Vec<(&String, &Value)> = object.iter().collect();
            members.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            for (index, (name, member)) in members.into_iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_canonical_json_string(name, out);
                out.push(b':');
                write_canonical_json(member, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

pub fn canonical_approval_v2_payload(payload: &ApprovalRecordV2Payload) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(payload)
        .map_err(|error| format!("cannot encode approval v2 payload: {error}"))?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes)?;
    Ok(bytes)
}

pub fn approval_v2_signature_preimage(
    payload: &ApprovalRecordV2Payload,
) -> Result<Vec<u8>, String> {
    let canonical = canonical_approval_v2_payload(payload)?;
    let mut preimage = Vec::with_capacity(APPROVAL_RECORD_V2_DOMAIN_PREFIX.len() + canonical.len());
    preimage.extend_from_slice(APPROVAL_RECORD_V2_DOMAIN_PREFIX);
    preimage.extend_from_slice(&canonical);
    Ok(preimage)
}

fn require_nonempty(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        Err(format!("{name} must be non-empty"))
    } else {
        Ok(())
    }
}

fn validate_approval_v2_payload(payload: &ApprovalRecordV2Payload) -> Result<(), String> {
    if payload.approval_record_version != 2 {
        return Err("unsupported_approval_record_version".to_string());
    }
    for (name, number) in [
        ("authorized_at", payload.authorized_at),
        ("expiry", payload.expiry),
        ("subject_length", payload.subject_length),
        ("shown_length", payload.shown_length),
    ] {
        if number > MAX_CANONICAL_JSON_INTEGER {
            return Err(format!("{name} exceeds canonical JSON range"));
        }
    }
    if payload.expiry < payload.authorized_at {
        return Err("expiry precedes authorized_at".to_string());
    }
    for (name, digest) in [
        ("target", payload.target.as_str()),
        ("subject_sha256", payload.subject_sha256.as_str()),
        ("shown_sha256", payload.shown_sha256.as_str()),
        (
            "renderer.manifest_sha256",
            payload.renderer.manifest_sha256.as_str(),
        ),
    ] {
        if !is_target_hex(digest) {
            return Err(format!("{name} must be lowercase 64-hex"));
        }
    }
    for (name, value) in [
        ("nonce", payload.nonce.as_str()),
        ("session", payload.session.as_str()),
        ("approver", payload.approver.as_str()),
        (
            "authorization_signer_key_id",
            payload.authorization_signer_key_id.as_str(),
        ),
        ("renderer.name", payload.renderer.name.as_str()),
        ("renderer.version", payload.renderer.version.as_str()),
    ] {
        require_nonempty(name, value)?;
    }
    if payload.subject_scope != SUBJECT_SCOPE {
        return Err("unsupported subject_scope".to_string());
    }
    if payload.subject_encoding != "bytes" {
        return Err("unsupported subject_encoding".to_string());
    }
    if payload.shown_media_type != "text/plain" {
        return Err("unsupported shown_media_type".to_string());
    }
    if payload.shown_character_encoding != "utf-8" {
        return Err("unsupported shown_character_encoding".to_string());
    }
    if payload.authorization_signature_algorithm != "Ed25519" {
        return Err("unsupported authorization_signature_algorithm".to_string());
    }
    if payload.authorization_domain != APPROVAL_RECORD_V2_DOMAIN {
        return Err("unsupported authorization_domain".to_string());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDropWarning {
    pub source: &'static str,
    pub reason: String,
    pub record_id: String,
    pub counter: u64,
}

impl ApprovalDropWarning {
    pub fn new(
        counter: &mut u64,
        source: &'static str,
        reason: impl Into<String>,
        redaction_material: impl AsRef<[u8]>,
    ) -> Self {
        *counter += 1;
        Self {
            source,
            reason: reason.into(),
            record_id: redacted_record_id(redaction_material.as_ref()),
            counter: *counter,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeclineRecord {
    #[serde(deserialize_with = "target_hex")]
    pub target: String,
    #[serde(rename = "issuedAt", default, deserialize_with = "opt_u64_str_or_num")]
    pub issued_at: Option<u64>,
    #[serde(default)]
    pub nonce: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ApprovalPoll {
    pub records: Vec<ApprovalRecord>,
    pub declines: Vec<DeclineRecord>,
    pub warnings: Vec<ApprovalDropWarning>,
}

/// The single admission boundary for syntactically valid v1 approvals.
///
/// Keeping both ingest providers on this boundary lets the mutation harness
/// restore the old admission behavior in one place. Production always takes
/// this refusal body; the ablation is applied only to a disposable source
/// copy by `scripts/test_v1_refusal_ablation.sh`.
fn refuse_v1_approval(
    poll: &mut ApprovalPoll,
    drop_counter: &mut u64,
    source: &'static str,
    record: ApprovalRecord,
) {
    let redaction_material = record_redaction_material(&record);
    poll.warnings.push(ApprovalDropWarning::new(
        drop_counter,
        source,
        V1_APPROVAL_REFUSAL_REASON,
        redaction_material,
    ));
}

/// Warning reason for a record whose `decision` value is outside the
/// allowlist {absent, "allow", "deny"}. Names the value (truncated) so the
/// audit log shows WHAT was refused, never silently reinterpreted.
fn unknown_decision_reason(value: &str) -> String {
    let shown: String = value.chars().take(64).collect();
    format!("unknown_decision:{shown}")
}

pub fn redacted_record_id(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", &hex::encode(digest)[..16])
}

pub fn record_redaction_material(record: &ApprovalRecord) -> String {
    format!(
        "target={};issuedAt={:?};nonce={}",
        record.target,
        record.issued_at,
        record.nonce.as_deref().unwrap_or("")
    )
}

/// Keep legacy behavior byte-for-byte, but require a v2 approval to name this
/// exact framed request and the kernel-issued target challenge observed for
/// that request before it can reach Lean. The signed `session` is retained as
/// approval context; the authorization-record specification does not define a
/// host-side expected-session source to compare it with.
pub fn filter_approval_context(
    records: Vec<ApprovalRecord>,
    framed_bytes: &[u8],
    expected_target: Option<&str>,
    drop_counter: &mut u64,
) -> (Vec<ApprovalRecord>, Vec<ApprovalDropWarning>) {
    let mut accepted = Vec::new();
    let mut dropped = Vec::new();
    for record in records {
        let context_matches = match record.v2() {
            None => true,
            Some(v2) => {
                expected_target == Some(v2.target.as_str())
                    && record.authorizes_framed_subject(framed_bytes)
            }
        };
        if context_matches {
            accepted.push(record);
        } else {
            dropped.push(ApprovalDropWarning::new(
                drop_counter,
                "approval-v2-context",
                "target_or_subject_mismatch",
                record_redaction_material(&record),
            ));
        }
    }
    (accepted, dropped)
}

/// An approval source. Implementations mint records; they do NOT decide —
/// the proven Lean core consumes the records (one-shot, target-bound).
pub trait ApprovalProvider {
    fn poll(&mut self) -> ApprovalPoll;
    fn name(&self) -> &'static str;
}

/// Control file: NDJSON `{"target": "<64 lowercase hex>", "issuedAt"?: ms}`,
/// each line ingested exactly once (positional seen counter).
pub struct ControlFileProvider {
    path: std::path::PathBuf,
    seen: usize,
    drop_counter: u64,
    oversize_reported: bool,
}

impl ControlFileProvider {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            seen: 0,
            drop_counter: 0,
            oversize_reported: false,
        }
    }
}

impl ApprovalProvider for ControlFileProvider {
    fn poll(&mut self) -> ApprovalPoll {
        let bytes = match read_file_bounded(&self.path, MAX_TOKEN_FILE_BYTES) {
            Ok(bytes) => {
                self.oversize_reported = false;
                bytes
            }
            Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
                if self.oversize_reported {
                    return ApprovalPoll::default();
                }
                self.oversize_reported = true;
                return ApprovalPoll {
                    warnings: vec![ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        "control-file",
                        "token_file_bytes_exceeded",
                        b"oversized-control-file",
                    )],
                    ..ApprovalPoll::default()
                };
            }
            Err(_) => return ApprovalPoll::default(),
        };
        let Ok(text) = String::from_utf8(bytes) else {
            return ApprovalPoll {
                warnings: vec![ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    "control-file",
                    "token_file_not_utf8",
                    b"non-utf8-control-file",
                )],
                ..ApprovalPoll::default()
            };
        };
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        let fresh = lines[self.seen.min(lines.len())..].to_vec();
        self.seen = lines.len();
        let source = self.name();
        let mut poll = ApprovalPoll::default();
        for line in fresh {
            if line.len() > MAX_APPROVAL_LINE_BYTES {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "approval_line_bytes_exceeded",
                    &line.as_bytes()[..MAX_APPROVAL_LINE_BYTES.min(line.len())],
                ));
                continue;
            }
            if let Err(limit) = check_json_limits(line.as_bytes()) {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    format!("approval_{}_exceeded", limit.name()),
                    line.as_bytes(),
                ));
                continue;
            }
            // Support dev unauth declines via "decision":"deny" (still unauthenticated).
            // IMPORTANT: `decision` is an ALLOWLIST — absent/null or "allow" is an
            // approval, exactly "deny" is a decline, and ANY other value drops the
            // record with a warning naming it. Never fall through to ApprovalRecord
            // (that would treat a decline-meaning record as an allow).
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                match v.get("decision") {
                    None | Some(serde_json::Value::Null) => {}
                    Some(serde_json::Value::String(s)) if s == "allow" => {}
                    Some(serde_json::Value::String(s)) if s == "deny" => {
                        match serde_json::from_str::<DeclineRecord>(line) {
                            Ok(d) => poll.declines.push(d),
                            Err(_) => {
                                poll.warnings.push(ApprovalDropWarning::new(
                                    &mut self.drop_counter,
                                    source,
                                    "parse_error",
                                    line.as_bytes(),
                                ));
                            }
                        }
                        continue;
                    }
                    Some(other) => {
                        let shown = match other {
                            serde_json::Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        poll.warnings.push(ApprovalDropWarning::new(
                            &mut self.drop_counter,
                            source,
                            unknown_decision_reason(&shown),
                            line.as_bytes(),
                        ));
                        continue;
                    }
                }
            }
            match serde_json::from_str::<LegacyApprovalRecord>(line) {
                Ok(record) => {
                    refuse_v1_approval(
                        &mut poll,
                        &mut self.drop_counter,
                        source,
                        ApprovalRecord::legacy(record.target, record.issued_at, record.nonce),
                    );
                }
                Err(_) => poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "parse_error",
                    line.as_bytes(),
                )),
            }
        }
        poll
    }

    fn name(&self) -> &'static str {
        "control-file"
    }
}

#[derive(Debug, Deserialize)]
struct SignedToken {
    /// Exact JSON payload bytes the signature covers.
    payload: String,
    /// Hex Ed25519 signature over the payload bytes.
    signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRecordV2Token {
    /// Canonical JSON text for ApprovalRecordV2Payload.
    payload: String,
    signature_algorithm: String,
    signature_encoding: String,
    signer_key_id: String,
    signature: String,
}

/// Internal for parsing signed payloads that may carry decision (decline).
#[derive(Debug, Clone, Deserialize)]
struct SignedPayload {
    #[serde(deserialize_with = "target_hex")]
    target: String,
    #[serde(rename = "issuedAt", default, deserialize_with = "opt_u64_str_or_num")]
    issued_at: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    decision: Option<String>,
}

/// Ed25519 token file: NDJSON `{"payload": "<json>", "signature": "<hex>"}`
/// where payload parses to an ApprovalRecord (or DeclineRecord) with a
/// MANDATORY nonce and issuedAt. The signature is verified over the exact
/// payload bytes against the trusted verifying key.
/// Decision field for signed v1 tokens: absent or "allow" is refused as an
/// unsupported v1 approval; "deny" remains a decline; any other value is
/// dropped with an `unknown_decision:<value>` warning.
/// NOTE: `echo >> ndjson` (control-file) and unsigned tokens are DEV-ONLY
/// and UNAUTHENTICATED — the ed25519 channel is the signed origin path.
pub struct Ed25519TokenProvider {
    path: std::path::PathBuf,
    key: VerifyingKey,
    seen: usize,
    drop_counter: u64,
    oversize_reported: bool,
}

pub fn verify_ed25519_signature(key: &VerifyingKey, payload: &[u8], signature_hex: &str) -> bool {
    verify_ed25519_signature_result(key, payload, signature_hex).is_ok()
}

fn verify_ed25519_signature_bytes(
    key: &VerifyingKey,
    payload: &[u8],
    signature_bytes: &[u8],
) -> Result<(), VerificationError> {
    let sig = Signature::from_slice(signature_bytes).map_err(|_| VerificationError::Mismatch)?;
    ed25519::verify(key, payload, &sig)
}

fn verify_ed25519_signature_result(
    key: &VerifyingKey,
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), VerificationError> {
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(bytes) => bytes,
        Err(_) => return Err(VerificationError::Mismatch),
    };
    let sig = match Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        Err(_) => return Err(VerificationError::Mismatch),
    };
    ed25519::verify(key, payload, &sig)
}

fn approval_key_id_from_key(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.to_bytes()))
}

fn verify_approval_record_v2_token(
    key: &VerifyingKey,
    original_token_bytes: &[u8],
) -> Result<ApprovalRecord, String> {
    let token: ApprovalRecordV2Token = serde_json::from_slice(original_token_bytes)
        .map_err(|_| "approval_v2_token_parse_error".to_string())?;
    if token.signature_algorithm != "Ed25519" {
        return Err("approval_v2_bad_signature_algorithm".to_string());
    }
    if token.signature_encoding != "base64url-nopad" {
        return Err("approval_v2_bad_signature_encoding".to_string());
    }
    let trusted_key_id = approval_key_id_from_key(key);
    if token.signer_key_id != trusted_key_id {
        return Err("approval_v2_wrong_signer_key_id".to_string());
    }

    let payload: ApprovalRecordV2Payload = serde_json::from_str(&token.payload)
        .map_err(|_| "approval_v2_payload_parse_error".to_string())?;
    validate_approval_v2_payload(&payload)
        .map_err(|_| "approval_v2_payload_validation_error".to_string())?;
    if payload.authorization_signer_key_id != token.signer_key_id {
        return Err("approval_v2_signer_key_id_mismatch".to_string());
    }
    if payload.authorization_signature_algorithm != token.signature_algorithm {
        return Err("approval_v2_signature_algorithm_mismatch".to_string());
    }

    let canonical = canonical_approval_v2_payload(&payload)
        .map_err(|_| "approval_v2_canonicalization_error".to_string())?;
    if token.payload.as_bytes() != canonical {
        return Err("approval_v2_payload_not_canonical".to_string());
    }
    let preimage = approval_v2_signature_preimage(&payload)
        .map_err(|_| "approval_v2_canonicalization_error".to_string())?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(token.signature.as_bytes())
        .map_err(|_| "approval_v2_bad_signature_encoding".to_string())?;
    if URL_SAFE_NO_PAD.encode(&signature_bytes) != token.signature {
        return Err("approval_v2_bad_signature_encoding".to_string());
    }
    verify_ed25519_signature_bytes(key, &preimage, &signature_bytes).map_err(
        |error| match error {
            VerificationError::NonCanonicalScalar => "non_canonical_signature_scalar".to_string(),
            VerificationError::Mismatch => "bad_signature".to_string(),
        },
    )?;

    Ok(ApprovalRecord::from_v2(
        ApprovalRecordV2::from_verified_payload(payload, original_token_bytes),
    ))
}

impl Ed25519TokenProvider {
    pub fn new(path: impl Into<std::path::PathBuf>, key_hex: &str) -> Result<Self, String> {
        let bytes: [u8; 32] = hex::decode(key_hex)
            .map_err(|e| format!("bad approval pubkey hex: {e}"))?
            .try_into()
            .map_err(|_| "approval pubkey must be 32 bytes".to_string())?;
        let key =
            VerifyingKey::from_bytes(&bytes).map_err(|e| format!("bad approval pubkey: {e}"))?;
        Ok(Self {
            path: path.into(),
            key,
            seen: 0,
            drop_counter: 0,
            oversize_reported: false,
        })
    }
}

impl ApprovalProvider for Ed25519TokenProvider {
    fn poll(&mut self) -> ApprovalPoll {
        let bytes = match read_file_bounded(&self.path, MAX_TOKEN_FILE_BYTES) {
            Ok(bytes) => {
                self.oversize_reported = false;
                bytes
            }
            Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
                if self.oversize_reported {
                    return ApprovalPoll::default();
                }
                self.oversize_reported = true;
                return ApprovalPoll {
                    warnings: vec![ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        "ed25519-token",
                        "token_file_bytes_exceeded",
                        b"oversized-ed25519-token-file",
                    )],
                    ..ApprovalPoll::default()
                };
            }
            Err(_) => return ApprovalPoll::default(),
        };
        let Ok(text) = String::from_utf8(bytes) else {
            return ApprovalPoll {
                warnings: vec![ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    "ed25519-token",
                    "token_file_not_utf8",
                    b"non-utf8-ed25519-token-file",
                )],
                ..ApprovalPoll::default()
            };
        };
        let lines: Vec<&str> = text
            .lines()
            // Keep every byte of a non-empty token line. ApprovalRecord v2
            // retains this exact slice (excluding only the NDJSON delimiter).
            .filter(|line| !line.trim().is_empty())
            .collect();
        let fresh = lines[self.seen.min(lines.len())..].to_vec();
        self.seen = lines.len();
        let source = self.name();
        let mut poll = ApprovalPoll::default();
        for original_line in fresh {
            let line = original_line;
            if line.len() > MAX_APPROVAL_LINE_BYTES {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "approval_line_bytes_exceeded",
                    &line.as_bytes()[..MAX_APPROVAL_LINE_BYTES.min(line.len())],
                ));
                continue;
            }
            if let Err(limit) = check_json_limits(line.as_bytes()) {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    format!("approval_{}_exceeded", limit.name()),
                    line.as_bytes(),
                ));
                continue;
            }
            let outer: Value = match serde_json::from_str(line) {
                Ok(value) => value,
                Err(_) => {
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        "parse_error",
                        line.as_bytes(),
                    ));
                    continue;
                }
            };
            let Some(payload_text) = outer.get("payload").and_then(Value::as_str) else {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "parse_error",
                    line.as_bytes(),
                ));
                continue;
            };
            if payload_text.len() > MAX_APPROVAL_LINE_BYTES {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "approval_payload_bytes_exceeded",
                    &payload_text.as_bytes()[..MAX_APPROVAL_LINE_BYTES],
                ));
                continue;
            }
            if let Err(limit) = check_json_limits(payload_text.as_bytes()) {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    format!("approval_payload_{}_exceeded", limit.name()),
                    payload_text.as_bytes(),
                ));
                continue;
            }
            let payload_value: Value = match serde_json::from_str(payload_text) {
                Ok(value) => value,
                Err(_) => {
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        "parse_error",
                        payload_text.as_bytes(),
                    ));
                    continue;
                }
            };
            if let Some(version) = payload_value
                .as_object()
                .and_then(|object| object.get("approval_record_version"))
            {
                if version.as_u64() != Some(2) {
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        "unsupported_approval_record_version",
                        payload_text.as_bytes(),
                    ));
                    continue;
                }
                if original_line.trim() != original_line {
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        "approval_v2_surrounding_whitespace",
                        original_line.as_bytes(),
                    ));
                    continue;
                }
                match verify_approval_record_v2_token(&self.key, line.as_bytes()) {
                    Ok(record) => poll.records.push(record),
                    Err(reason) => poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        reason,
                        line.as_bytes(),
                    )),
                }
                continue;
            }
            let token: SignedToken = match serde_json::from_str(line) {
                Ok(token) => token,
                Err(_) => {
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        "parse_error",
                        line.as_bytes(),
                    ));
                    continue;
                }
            };
            if let Err(error) = verify_ed25519_signature_result(
                &self.key,
                token.payload.as_bytes(),
                &token.signature,
            ) {
                let reason = match error {
                    VerificationError::NonCanonicalScalar => "non_canonical_signature_scalar",
                    VerificationError::Mismatch => "bad_signature",
                };
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    reason,
                    line.as_bytes(),
                ));
                continue;
            }
            if token.payload.len() > MAX_APPROVAL_LINE_BYTES {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "approval_payload_bytes_exceeded",
                    &token.payload.as_bytes()[..MAX_APPROVAL_LINE_BYTES],
                ));
                continue;
            }
            if let Err(limit) = check_json_limits(token.payload.as_bytes()) {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    format!("approval_payload_{}_exceeded", limit.name()),
                    token.payload.as_bytes(),
                ));
                continue;
            }
            // Parse to common signed payload (supports optional decision for decline).
            let sp: SignedPayload = match serde_json::from_str(&token.payload) {
                Ok(sp) => sp,
                Err(_) => {
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        "parse_error",
                        token.payload.as_bytes(),
                    ));
                    continue;
                }
            };
            // Signed tokens MUST carry nonce + issuedAt (for both allow and decline).
            if sp.nonce.is_none() || sp.issued_at.is_none() {
                let red = record_redaction_material(&ApprovalRecord::legacy(
                    sp.target.clone(),
                    sp.issued_at,
                    sp.nonce.clone(),
                ));
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "missing_required_field",
                    red,
                ));
                continue;
            }
            // Signed v1 allows are refused. Exactly "deny" remains a decline;
            // ANY other value drops with a warning naming it. A signed record
            // meaning "do not run this" must never mint an approval because its
            // decision spelling is unrecognised.
            match sp.decision.as_deref() {
                None | Some("allow") => {
                    refuse_v1_approval(
                        &mut poll,
                        &mut self.drop_counter,
                        source,
                        ApprovalRecord::legacy(sp.target, sp.issued_at, sp.nonce),
                    );
                }
                Some("deny") => poll.declines.push(DeclineRecord {
                    target: sp.target,
                    issued_at: sp.issued_at,
                    nonce: sp.nonce,
                }),
                Some(other) => {
                    let reason = unknown_decision_reason(other);
                    let red = record_redaction_material(&ApprovalRecord::legacy(
                        sp.target.clone(),
                        sp.issued_at,
                        sp.nonce.clone(),
                    ));
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        reason,
                        red,
                    ));
                }
            }
        }
        poll
    }

    fn name(&self) -> &'static str {
        "ed25519-token"
    }
}

/// Interactive human-in-the-loop: prompts on the controlling TTY for each
/// poll when a pending question is queued. The transport queues a question
/// when a call was denied for a missing approval; the human's "y" mints the
/// approval for the named target.
pub struct InteractiveProvider<R: BufRead, W: std::io::Write> {
    input: R,
    output: W,
    pub pending_target: Option<String>,
}

impl<R: BufRead, W: std::io::Write> InteractiveProvider<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self {
            input,
            output,
            pending_target: None,
        }
    }

    pub fn queue(&mut self, target: String) {
        self.pending_target = Some(target);
    }
}

impl<R: BufRead, W: std::io::Write> ApprovalProvider for InteractiveProvider<R, W> {
    fn poll(&mut self) -> ApprovalPoll {
        let Some(target) = self.pending_target.take() else {
            return ApprovalPoll::default();
        };
        let _ = writeln!(self.output, "seal-host: approve target {target}? [y/N] ");
        let _ = self.output.flush();
        let mut answer = Vec::new();
        let approved =
            match read_bounded_frame(&mut self.input, &mut answer, MAX_APPROVAL_LINE_BYTES) {
                Ok(FrameStatus::Complete | FrameStatus::Unterminated) => {
                    std::str::from_utf8(&answer).is_ok_and(|text| text.trim() == "y")
                }
                Ok(FrameStatus::Oversized) => {
                    let _ = writeln!(
                    self.output,
                    "seal-host: oversized response rejected (limit {MAX_APPROVAL_LINE_BYTES} bytes)"
                );
                    false
                }
                Ok(FrameStatus::Eof) => false,
                Err(error) => {
                    let _ = writeln!(
                        self.output,
                        "seal-host: approval response read failed: {error}"
                    );
                    false
                }
            };
        if approved {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            ApprovalPoll {
                records: vec![ApprovalRecord::legacy(target, Some(now), None)],
                declines: vec![],
                warnings: Vec::new(),
            }
        } else {
            ApprovalPoll::default()
        }
    }

    fn name(&self) -> &'static str {
        "interactive"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn digest(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn v2_payload(
        signing_key: &SigningKey,
        framed_bytes: &[u8],
        shown_bytes: &[u8],
    ) -> ApprovalRecordV2Payload {
        ApprovalRecordV2Payload {
            approval_record_version: 2,
            target: digest(b"kernel approval target"),
            authorized_at: 1_720_000_000_000,
            expiry: 1_720_000_120_000,
            nonce: "approval-v2-nonce-1".to_string(),
            session: "approval-v2-session-1".to_string(),
            subject_sha256: digest(framed_bytes),
            subject_length: framed_bytes.len() as u64,
            subject_scope: SUBJECT_SCOPE.to_string(),
            subject_encoding: "bytes".to_string(),
            shown_sha256: digest(shown_bytes),
            shown_length: shown_bytes.len() as u64,
            shown_media_type: "text/plain".to_string(),
            shown_character_encoding: "utf-8".to_string(),
            renderer: ApprovalRenderer {
                name: "seal-test-renderer".to_string(),
                version: "2.0.0".to_string(),
                manifest_sha256: digest(b"immutable renderer manifest"),
            },
            approver: "human@example.test".to_string(),
            authorization_signer_key_id: approval_key_id_from_key(&signing_key.verifying_key()),
            authorization_signature_algorithm: "Ed25519".to_string(),
            authorization_domain: APPROVAL_RECORD_V2_DOMAIN.to_string(),
        }
    }

    fn v2_token_with_signature(
        payload: &ApprovalRecordV2Payload,
        signature: &ed25519_dalek::Signature,
    ) -> String {
        let canonical = canonical_approval_v2_payload(payload).unwrap();
        serde_json::json!({
            "payload": String::from_utf8(canonical).unwrap(),
            "signature_algorithm": "Ed25519",
            "signature_encoding": "base64url-nopad",
            "signer_key_id": payload.authorization_signer_key_id,
            "signature": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        })
        .to_string()
    }

    fn sign_v2_token(
        signing_key: &SigningKey,
        payload: &ApprovalRecordV2Payload,
    ) -> (String, ed25519_dalek::Signature) {
        let signature = signing_key.sign(&approval_v2_signature_preimage(payload).unwrap());
        (v2_token_with_signature(payload, &signature), signature)
    }

    fn add_group_order_to_signature(signature: &ed25519_dalek::Signature) -> String {
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let mut bytes = signature.to_bytes();
        let mut carry = 0u16;
        for (scalar, order) in bytes[32..].iter_mut().zip(L) {
            let sum = *scalar as u16 + order as u16 + carry;
            *scalar = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "S + L fits in the 256-bit signature field");
        hex::encode(bytes)
    }

    #[test]
    fn approval_v2_binds_divergent_subject_and_shown_bytes() {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let framed_bytes = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"row40","arguments":{"integer":1234567890123456789}}}
"#;
        let shown_bytes = b"integer: 1234567890123456768";
        assert!(std::str::from_utf8(framed_bytes)
            .unwrap()
            .contains("1234567890123456789"));
        assert!(std::str::from_utf8(shown_bytes)
            .unwrap()
            .contains("1234567890123456768"));

        let payload = v2_payload(&signing_key, framed_bytes, shown_bytes);
        assert_ne!(payload.subject_sha256, payload.shown_sha256);
        let (token_line, _) = sign_v2_token(&signing_key, &payload);
        let path =
            std::env::temp_dir().join(format!("seal-approval-v2-row40-{}", std::process::id()));
        std::fs::write(&path, format!("{token_line}\n")).unwrap();
        let mut provider =
            Ed25519TokenProvider::new(&path, &hex::encode(signing_key.verifying_key().to_bytes()))
                .unwrap();
        let poll = provider.poll();
        std::fs::remove_file(&path).ok();

        assert!(poll.warnings.is_empty());
        assert_eq!(poll.records.len(), 1);
        let record = poll.records[0]
            .v2()
            .expect("v2 token must retain v2 evidence");
        assert_eq!(record.subject_sha256, digest(framed_bytes));
        assert_eq!(record.subject_length, framed_bytes.len() as u64);
        assert_eq!(record.shown_sha256, digest(shown_bytes));
        assert_eq!(record.shown_length, shown_bytes.len() as u64);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(record.authorization_token.bytes.as_bytes())
                .unwrap(),
            token_line.as_bytes()
        );
        assert!(record.matches_framed_subject(framed_bytes));

        println!(
            "DIVERGENCE framed_bytes_utf8={} displayed_bytes_utf8={}",
            String::from_utf8_lossy(framed_bytes).trim_end(),
            String::from_utf8_lossy(shown_bytes)
        );
        println!(
            "APPROVAL_RECORD_V2={}",
            serde_json::to_string(record).unwrap()
        );
        println!("SIGNATURE_VERIFIED=true");
    }

    #[test]
    fn approval_v2_displayed_tuple_tamper_invalidates_signature() {
        let signing_key = SigningKey::from_bytes(&[29u8; 32]);
        let framed_bytes = b"{\"integer\":1234567890123456789}\n";
        let shown_bytes = b"1234567890123456768";
        let payload = v2_payload(&signing_key, framed_bytes, shown_bytes);
        let (valid_token, signature) = sign_v2_token(&signing_key, &payload);

        let mut tampered_payload = payload.clone();
        tampered_payload.shown_sha256 = digest(b"1234567890123456800");
        let tampered_token = v2_token_with_signature(&tampered_payload, &signature);
        let path =
            std::env::temp_dir().join(format!("seal-approval-v2-tamper-{}", std::process::id()));
        std::fs::write(&path, format!("{valid_token}\n{tampered_token}\n")).unwrap();
        let mut provider =
            Ed25519TokenProvider::new(&path, &hex::encode(signing_key.verifying_key().to_bytes()))
                .unwrap();
        let poll = provider.poll();
        std::fs::remove_file(&path).ok();

        assert_eq!(
            poll.records.len(),
            1,
            "tampered displayed-byte tuple must be dropped"
        );
        assert_eq!(poll.warnings.len(), 1);
        assert_eq!(poll.warnings[0].reason, "bad_signature");
    }

    #[test]
    fn v2_context_filter_is_fail_closed_without_changing_legacy() {
        let signing_key = SigningKey::from_bytes(&[37u8; 32]);
        let framed_bytes = b"{\"integer\":1234567890123456789}\n";
        let payload = v2_payload(&signing_key, framed_bytes, b"1234567890123456768");
        let (token, _) = sign_v2_token(&signing_key, &payload);
        let record =
            verify_approval_record_v2_token(&signing_key.verifying_key(), token.as_bytes())
                .expect("valid v2 record");
        let legacy = ApprovalRecord::legacy(
            payload.target.clone(),
            Some(payload.authorized_at),
            Some("legacy-context".to_string()),
        );

        let mut counter = 0;
        let (accepted, dropped) = filter_approval_context(
            vec![record.clone(), legacy.clone()],
            framed_bytes,
            Some(&payload.target),
            &mut counter,
        );
        assert_eq!(accepted.len(), 2);
        assert!(dropped.is_empty());

        let (accepted, dropped) = filter_approval_context(
            vec![record, legacy],
            b"{\"integer\":1234567890123456768}\n",
            None,
            &mut counter,
        );
        assert_eq!(accepted.len(), 1, "legacy decision behavior is unchanged");
        assert!(
            accepted[0].v2().is_none(),
            "only the legacy record may survive a v2 context mismatch"
        );
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, "target_or_subject_mismatch");
    }

    #[test]
    fn control_file_refuses_oversized_line_with_named_bounded_warning() {
        let path = std::env::temp_dir().join(format!("seal-oversized-line-{}", std::process::id()));
        std::fs::write(
            &path,
            format!("{}\n", "x".repeat(MAX_APPROVAL_LINE_BYTES + 1)),
        )
        .unwrap();
        let mut provider = ControlFileProvider::new(&path);
        let poll = provider.poll();
        std::fs::remove_file(&path).ok();
        assert!(poll.records.is_empty());
        assert_eq!(poll.warnings.len(), 1);
        assert_eq!(poll.warnings[0].reason, "approval_line_bytes_exceeded");
        assert!(poll.warnings[0].record_id.starts_with("sha256:"));
        assert_eq!(poll.warnings[0].record_id.len(), 23);
    }

    #[test]
    fn token_file_size_warning_is_emitted_only_once_while_oversized() {
        let path = std::env::temp_dir().join(format!("seal-oversized-file-{}", std::process::id()));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len((MAX_TOKEN_FILE_BYTES + 1) as u64).unwrap();
        let mut provider = ControlFileProvider::new(&path);
        let first = provider.poll();
        let second = provider.poll();
        std::fs::remove_file(&path).ok();
        assert_eq!(first.warnings.len(), 1);
        assert_eq!(first.warnings[0].reason, "token_file_bytes_exceeded");
        assert!(second.warnings.is_empty());
    }

    #[test]
    fn ed25519_provider_refuses_valid_v1_and_rejects_tampered() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let target = "000000000000000000000000000000000000000000000000000000000000002a";
        let payload = format!(r#"{{"target":"{target}","issuedAt":1000,"nonce":"abc123"}}"#);
        let sig = hex::encode(sk.sign(payload.as_bytes()).to_bytes());
        let good = format!(
            r#"{{"payload":{},"signature":"{}"}}"#,
            serde_json::to_string(&payload).unwrap(),
            sig
        );
        let bad = good.replace("002a", "002b");

        let dir = std::env::temp_dir().join(format!("seal-tok-{}", std::process::id()));
        std::fs::write(&dir, format!("{good}\n{bad}\n")).unwrap();
        let mut p = Ed25519TokenProvider::new(&dir, &vk_hex).unwrap();
        let poll = p.poll();
        std::fs::remove_file(&dir).ok();
        assert!(poll.records.is_empty());
        assert_eq!(
            poll.warnings
                .iter()
                .map(|warning| warning.reason.as_str())
                .collect::<Vec<_>>(),
            [V1_APPROVAL_REFUSAL_REASON, "bad_signature"],
            "the valid v1 token is explicitly refused and the tampered token remains distinguishable"
        );
    }

    #[test]
    fn ed25519_provider_scalar_range_and_negative_controls() {
        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());
        let target = "0000000000000000000000000000000000000000000000000000000000000019";
        let valid_payload = format!(r#"{{"target":"{target}","issuedAt":5000,"nonce":"valid"}}"#);
        let valid_signature = signing_key.sign(valid_payload.as_bytes());

        let corrupted_payload =
            format!(r#"{{"target":"{target}","issuedAt":5001,"nonce":"corrupt"}}"#);
        let mut corrupted_signature = signing_key.sign(corrupted_payload.as_bytes()).to_bytes();
        corrupted_signature[0] ^= 1;

        let non_canonical_payload =
            format!(r#"{{"target":"{target}","issuedAt":5002,"nonce":"noncanonical"}}"#);
        let non_canonical_signature = signing_key.sign(non_canonical_payload.as_bytes());

        let tokens = [
            (&valid_payload, hex::encode(valid_signature.to_bytes())),
            (&corrupted_payload, hex::encode(corrupted_signature)),
            (
                &non_canonical_payload,
                add_group_order_to_signature(&non_canonical_signature),
            ),
        ]
        .into_iter()
        .map(|(payload, signature)| {
            format!(
                r#"{{"payload":{},"signature":"{signature}"}}"#,
                serde_json::to_string(payload).unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

        let path = std::env::temp_dir().join(format!("seal-scalar-range-{}", std::process::id()));
        std::fs::write(&path, format!("{tokens}\n")).unwrap();
        let mut provider = Ed25519TokenProvider::new(&path, &verifying_key_hex).unwrap();
        let poll = provider.poll();
        std::fs::remove_file(&path).ok();

        assert!(poll.records.is_empty());
        assert_eq!(
            poll.warnings
                .iter()
                .map(|warning| warning.reason.as_str())
                .collect::<Vec<_>>(),
            [
                V1_APPROVAL_REFUSAL_REASON,
                "bad_signature",
                "non_canonical_signature_scalar"
            ],
            "valid-but-v1, ordinary mismatch, and malformed RFC 8032 scalar must be distinguishable"
        );
    }

    #[test]
    fn ed25519_provider_refuses_signed_v1_allow_and_accepts_decline() {
        let sk = SigningKey::from_bytes(&[11u8; 32]);
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let target = "00000000000000000000000000000000000000000000000000000000000000ab";
        let nonce = "decline-n1";
        let allow_p = format!(r#"{{"target":"{target}","issuedAt":2000,"nonce":"n-allow"}}"#);
        let allow_sig = hex::encode(sk.sign(allow_p.as_bytes()).to_bytes());
        let allow_tok = format!(
            r#"{{"payload":{},"signature":"{}"}}"#,
            serde_json::to_string(&allow_p).unwrap(),
            allow_sig
        );

        let dec_p = format!(
            r#"{{"target":"{target}","issuedAt":2001,"nonce":"{nonce}","decision":"deny"}}"#
        );
        let dec_sig = hex::encode(sk.sign(dec_p.as_bytes()).to_bytes());
        let dec_tok = format!(
            r#"{{"payload":{},"signature":"{}"}}"#,
            serde_json::to_string(&dec_p).unwrap(),
            dec_sig
        );

        let dir = std::env::temp_dir().join(format!("seal-decline-{}", std::process::id()));
        std::fs::write(&dir, format!("{allow_tok}\n{dec_tok}\n")).unwrap();
        let mut p = Ed25519TokenProvider::new(&dir, &vk_hex).unwrap();
        let poll = p.poll();
        std::fs::remove_file(&dir).ok();
        assert!(poll.records.is_empty());
        assert_eq!(poll.warnings.len(), 1);
        assert_eq!(poll.warnings[0].reason, V1_APPROVAL_REFUSAL_REASON);
        assert_eq!(poll.declines.len(), 1);
        assert_eq!(poll.declines[0].target, target);
        assert_eq!(poll.declines[0].nonce.as_deref(), Some(nonce));
    }

    /// RED: a signed record whose `decision` is not exactly "deny"/"allow"/absent
    /// must NEVER become an approval — it is dropped with a warning naming the value.
    #[test]
    fn ed25519_provider_drops_unknown_decision_never_approves() {
        let sk = SigningKey::from_bytes(&[13u8; 32]);
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let target = "00000000000000000000000000000000000000000000000000000000000000cd";
        let mut lines = String::new();
        for (i, decision) in ["DENY", "revoke"].iter().enumerate() {
            let p = format!(
                r#"{{"target":"{target}","issuedAt":300{i},"nonce":"n-{i}","decision":"{decision}"}}"#
            );
            let sig = hex::encode(sk.sign(p.as_bytes()).to_bytes());
            lines.push_str(&format!(
                "{}\n",
                format_args!(
                    r#"{{"payload":{},"signature":"{}"}}"#,
                    serde_json::to_string(&p).unwrap(),
                    sig
                )
            ));
        }

        let path = std::env::temp_dir().join(format!("seal-unk-{}", std::process::id()));
        std::fs::write(&path, lines).unwrap();
        let mut p = Ed25519TokenProvider::new(&path, &vk_hex).unwrap();
        let poll = p.poll();
        std::fs::remove_file(&path).ok();
        assert!(
            poll.records.is_empty(),
            "unknown decision values must not mint approvals"
        );
        assert!(
            poll.declines.is_empty(),
            "unknown decision values are dropped, not reinterpreted as declines"
        );
        assert_eq!(poll.warnings.len(), 2);
        assert_eq!(poll.warnings[0].reason, "unknown_decision:DENY");
        assert_eq!(poll.warnings[1].reason, "unknown_decision:revoke");
    }

    /// T4 (audit-stream injection): the reason bounds attacker input to 64 chars
    /// BEFORE it becomes a warning. Existing tests use short values; this pins the
    /// clamp itself against a long, multibyte, hostile value — the reason is
    /// exactly `unknown_decision:` + the first 64 *characters* (never bytes: the
    /// `.chars().take(64)` must not split a multibyte codepoint), and never grows
    /// with attacker length. The clamp caps volume; `json!()` at emission caps
    /// shape.
    #[test]
    fn unknown_decision_reason_clamps_long_hostile_value_to_64_chars() {
        // 200 chars of newline/quote/ANSI/multibyte smuggling attempts.
        let hostile: String = "\"}\n\u{1b}[31m日本語✓".chars().cycle().take(200).collect();
        let reason = unknown_decision_reason(&hostile);
        let shown = reason
            .strip_prefix("unknown_decision:")
            .expect("prefix present");
        assert_eq!(
            shown.chars().count(),
            64,
            "value must be clamped to 64 chars"
        );
        // Clamp is by character, not byte: re-encoding the shown chars is lossless
        // (no codepoint was split), and it is a genuine prefix of the input.
        assert!(
            hostile.starts_with(shown),
            "clamp must be a prefix of the input"
        );
        // Length does not grow with attacker input beyond the fixed bound.
        assert_eq!(
            unknown_decision_reason(&"x".repeat(10_000)),
            format!("unknown_decision:{}", "x".repeat(64))
        );
    }

    /// V1 allow spellings are refused on the signed channel.
    #[test]
    fn ed25519_provider_refuses_v1_absent_and_allow() {
        let sk = SigningKey::from_bytes(&[17u8; 32]);
        let vk_hex = hex::encode(sk.verifying_key().to_bytes());
        let target = "00000000000000000000000000000000000000000000000000000000000000ef";
        let absent_p = format!(r#"{{"target":"{target}","issuedAt":4000,"nonce":"n-abs"}}"#);
        let allow_p = format!(
            r#"{{"target":"{target}","issuedAt":4001,"nonce":"n-alw","decision":"allow"}}"#
        );
        let mut lines = String::new();
        for p in [&absent_p, &allow_p] {
            let sig = hex::encode(sk.sign(p.as_bytes()).to_bytes());
            lines.push_str(&format!(
                "{}\n",
                format_args!(
                    r#"{{"payload":{},"signature":"{}"}}"#,
                    serde_json::to_string(p).unwrap(),
                    sig
                )
            ));
        }

        let path = std::env::temp_dir().join(format!("seal-alw-{}", std::process::id()));
        std::fs::write(&path, lines).unwrap();
        let mut p = Ed25519TokenProvider::new(&path, &vk_hex).unwrap();
        let poll = p.poll();
        std::fs::remove_file(&path).ok();
        assert_eq!(poll.warnings.len(), 2);
        assert!(poll
            .warnings
            .iter()
            .all(|warning| warning.reason == V1_APPROVAL_REFUSAL_REASON));
        assert!(poll.declines.is_empty());
        assert!(poll.records.is_empty());
    }

    /// RED: same allowlist on the control-file channel — "DENY"/"revoke" never approve.
    #[test]
    fn control_file_drops_unknown_decision_never_approves() {
        let target = "0000000000000000000000000000000000000000000000000000000000000011";
        let path = std::env::temp_dir().join(format!("seal-cf-unk-{}", std::process::id()));
        std::fs::write(
            &path,
            format!(
                "{{\"target\":\"{target}\",\"decision\":\"DENY\"}}\n{{\"target\":\"{target}\",\"decision\":\"revoke\"}}\n"
            ),
        )
        .unwrap();
        let mut p = ControlFileProvider::new(&path);
        let poll = p.poll();
        std::fs::remove_file(&path).ok();
        assert!(
            poll.records.is_empty(),
            "unknown decision values must not mint approvals"
        );
        assert!(poll.declines.is_empty());
        assert_eq!(poll.warnings.len(), 2);
        assert_eq!(poll.warnings[0].reason, "unknown_decision:DENY");
        assert_eq!(poll.warnings[1].reason, "unknown_decision:revoke");
    }

    /// Control-file v1 allows are refused; exact "deny" remains a decline.
    #[test]
    fn control_file_refuses_v1_absent_and_allow_and_declines_deny() {
        let target = "0000000000000000000000000000000000000000000000000000000000000022";
        let path = std::env::temp_dir().join(format!("seal-cf-alw-{}", std::process::id()));
        std::fs::write(
            &path,
            format!(
                "{{\"target\":\"{target}\"}}\n{{\"target\":\"{target}\",\"decision\":\"allow\"}}\n{{\"target\":\"{target}\",\"decision\":\"deny\"}}\n"
            ),
        )
        .unwrap();
        let mut p = ControlFileProvider::new(&path);
        let poll = p.poll();
        std::fs::remove_file(&path).ok();
        assert_eq!(poll.warnings.len(), 2);
        assert!(poll
            .warnings
            .iter()
            .all(|warning| warning.reason == V1_APPROVAL_REFUSAL_REASON));
        assert!(poll.records.is_empty());
        assert_eq!(poll.declines.len(), 1);
        assert_eq!(poll.declines[0].target, target);
    }

    #[test]
    fn interactive_provider_mints_on_yes_only() {
        let mut p = InteractiveProvider::new(std::io::Cursor::new(b"y\n".to_vec()), Vec::new());
        let target = "0000000000000000000000000000000000000000000000000000000000000007".to_string();
        p.queue(target.clone());
        let records = p.poll().records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target, target);

        let mut p = InteractiveProvider::new(std::io::Cursor::new(b"n\n".to_vec()), Vec::new());
        p.queue("0000000000000000000000000000000000000000000000000000000000000007".to_string());
        let p2 = p.poll();
        assert!(p2.records.is_empty());
        assert!(p2.declines.is_empty());
    }

    #[test]
    fn interactive_provider_rejects_oversized_response() {
        let input = format!("{}\n", "y".repeat(MAX_APPROVAL_LINE_BYTES + 1));
        let mut p = InteractiveProvider::new(std::io::Cursor::new(input.into_bytes()), Vec::new());
        p.queue("00".repeat(32));
        let poll = p.poll();
        assert!(poll.records.is_empty());
        let output = String::from_utf8(p.output).unwrap();
        assert!(output.contains("oversized response rejected"), "{output}");
    }
}
