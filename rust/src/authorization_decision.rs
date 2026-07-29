// SPDX-License-Identifier: Apache-2.0
//! Canonical v2 authorization decisions for the deployed native host.
//!
//! The Lean step output remains the authority for verdicts and certificates.
//! This module only assembles that material with the exact request, signed
//! config and approval records the host supplied to Lean, then persists the
//! result before any ALLOW is forwarded.

use crate::providers::ApprovalRecord;
use crate::{lean, secure_fs};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

const VERIFIED_WASM: &[u8] = include_bytes!("../../receipt-verifier/wasm/seal.wasm");
pub const VERIFIED_WASM_SHA256: &str =
    "d7d81e277ba0b5e9df385129d86abf6f7469e6da2a65bb2ec35626caa44ea2be";

/// Declared verification profile of seal-host's authorization-decision verifier surface
/// (seal-assurance-kit docs/VERIFY-PROFILES.md): P-ENFORCE — the production
/// authorization-decision gate. The embedded re-derivation body above is the verifier body
/// authorization decisions name via `kernel_identity.wasm_sha256`; the gating surface
/// (`scripts/v2_receipt_conformance.py`, the Golden Path demos) always
/// supplies the config-signer trust-anchor pin (`--expected-config-pubkey`)
/// and consumes the pinned external verifiers' 0/4/3/1-class exit codes.
/// The fleet differentials key expected agreement/divergence off this
/// declaration; changing it is a design decision, not a refactor.
pub const VERIFY_PROFILE: &str = "P-ENFORCE";

#[derive(Debug, Clone)]
pub struct ApprovalIdentity {
    pub channel: String,
    pub key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SignedConfig {
    pub payload: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Debug)]
pub struct DecisionInput<'a> {
    pub line: &'a str,
    /// Exact delimiter-bearing request frame used by ApprovalRecord v2
    /// admission. This can differ from `line` by LF/CRLF framing (and, for a
    /// principal envelope, by the outer envelope).
    pub framed_subject: &'a [u8],
    /// Boot-scoped host runtime context. Authorization-decision-only: this is not supplied
    /// to Lean and has no role in authorization or freshness.
    pub session: &'a str,
    pub now: u64,
    pub emitted_bytes: &'a str,
    pub kernel_config: &'a Value,
    pub signed_config: &'a SignedConfig,
    pub approvals: &'a [ApprovalRecord],
    pub approval_identity: &'a ApprovalIdentity,
    pub approval_ttl_ms: u64,
}

#[derive(Debug)]
pub struct AuthorizationDecisionWriter {
    dir: PathBuf,
    next_entry: u64,
    native_executable_sha256: String,
    lean_ffi_sha256: String,
}

#[derive(Debug, Clone)]
pub struct PersistedAuthorizationDecision {
    pub path: PathBuf,
    pub consumed_target: Option<String>,
}

/// The host's request-commitment primitive: SHA-256 of the given bytes, lower
/// hex. This is the exact fn the host commits a mediated line with (the
/// `host_request_sha256` cross-check below). Exposed `pub` so the T3 terminator
/// pin in the `main.rs` binary commits the golden vector with the PRODUCTION
/// hash, not a coincidental re-implementation that could not catch host-side
/// drift.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hash_file(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path)
        .map_err(|e| format!("cannot read identity artifact {}: {e}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

fn canonical_json_sha256(value: &Value) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|e| format!("cannot serialize canonical JSON: {e}"))
}

#[derive(Debug, Clone, PartialEq)]
pub struct RequestParts {
    pub tool: String,
    pub arguments: Value,
    pub metadata: Option<Value>,
    pub request_state: Option<Value>,
    pub input_responses: Option<Value>,
}

fn canonical_request(parts: &RequestParts) -> Value {
    let mut params = Map::new();
    params.insert("name".into(), Value::String(parts.tool.clone()));
    params.insert("arguments".into(), parts.arguments.clone());
    if let Some(metadata) = &parts.metadata {
        params.insert("_meta".into(), metadata.clone());
    }
    if let Some(request_state) = &parts.request_state {
        params.insert("requestState".into(), request_state.clone());
    }
    if let Some(input_responses) = &parts.input_responses {
        params.insert("inputResponses".into(), input_responses.clone());
    }
    let mut request = Map::new();
    request.insert("jsonrpc".into(), Value::String("2.0".into()));
    request.insert("id".into(), Value::from(1));
    request.insert("method".into(), Value::String("tools/call".into()));
    request.insert("params".into(), Value::Object(params));
    Value::Object(request)
}

/// Build the authorization-decision-only MCP projection. Every value here is either a
/// constant descriptor, boot/request context already held by the host, or a
/// by-value projection of the line `request_parts` parsed. It is deliberately
/// not an input to Lean, signature verification, routing, or A3 freshness.
fn effect_view(
    input: &DecisionInput<'_>,
    step: &Value,
    parts: &RequestParts,
    request_sha256: &str,
    policy_hash: &str,
) -> Value {
    let mut view = Map::new();
    view.insert("schema".into(), Value::String("seal.effect-view/v0".into()));
    view.insert(
        "source".into(),
        Value::String("mcp-jsonrpc/tools-call@1".into()),
    );
    view.insert(
        "adapter".into(),
        serde_json::json!({
            "type": "mcp-jsonrpc/tools-call",
            "version": "1"
        }),
    );
    // Preserve the authorization decision's honesty rule: never mint a `principal` key when
    // the kernel authenticated none. When present, the id comes only from the
    // authoritative step output and is paired with passive session context.
    if let Some(id) = step.get("principal").and_then(Value::as_str) {
        view.insert(
            "principal".into(),
            serde_json::json!({"id": id, "session": input.session}),
        );
    }
    view.insert("session".into(), Value::String(input.session.to_owned()));
    let mut effect = Map::new();
    effect.insert("resource".into(), Value::String(parts.tool.clone()));
    effect.insert("action".into(), Value::String("call".into()));
    effect.insert("arguments".into(), parts.arguments.clone());
    if let Some(metadata) = &parts.metadata {
        effect.insert("_meta".into(), metadata.clone());
    }
    if let Some(request_state) = &parts.request_state {
        // Opaque by construction: copy the complete top-level value without
        // member lookup, decoding, or semantic projection.
        effect.insert("requestState".into(), request_state.clone());
    }
    if let Some(input_responses) = &parts.input_responses {
        effect.insert("inputResponses".into(), input_responses.clone());
    }
    view.insert("effect".into(), Value::Object(effect));
    view.insert(
        "raw_preimage_sha256".into(),
        Value::String(request_sha256.to_owned()),
    );
    view.insert("policy_hash".into(), Value::String(policy_hash.to_owned()));
    // Content-addressed within one runtime session. This reuses the existing
    // kernel-cross-checked request hash; it does not canonicalize or re-hash
    // the authenticated line. Durable collision/replay enforcement is a
    // documented follow-up, not a verdict gate in this release.
    view.insert(
        "idempotency_key".into(),
        Value::String(format!("{}:{request_sha256}", input.session)),
    );
    // `epoch` is a required field of the successfully verified config. Keep
    // this best-effort so authorization-decision enrichment can never veto a kernel verdict.
    if let Some(policy_version) = input.kernel_config.get("epoch") {
        view.insert("policy_version".into(), policy_version.clone());
        view.insert("policy_version_enforced".into(), Value::Bool(false));
    }
    view.insert("authoritative".into(), Value::Bool(false));
    Value::Object(view)
}

/// Best-effort structured view of the wire line for the authorization decision's derived
/// fields. This is DESCRIPTIVE material only: the kernel is deliberately the
/// more tolerant parser (the differential corpus pins lines Lean mediates
/// that serde rejects, e.g. `1e309`), so a failure here must never influence
/// whether the kernel's verdict is enacted — the authorization decision records the raw
/// line hash instead and the decision stands.
/// Public so the parser-boundary conformance test (`tests/parser_boundary.rs`)
/// exercises the SAME structured-view parser the authorization-decision layer runs — the
/// lib.rs no-test-mirror rule.
pub fn request_parts(line: &str) -> Result<RequestParts, String> {
    let request: Value = serde_json::from_str(line.trim())
        .map_err(|e| format!("cannot parse mediated request for authorization decision: {e}"))?;
    let params = request
        .pointer("/params")
        .and_then(Value::as_object)
        .ok_or("mediated request lacks object params")?;
    let tool = request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .ok_or("mediated request lacks params.name")?
        .to_owned();
    let arguments = request
        .pointer("/params/arguments")
        .filter(|v| v.is_object())
        .ok_or("mediated request lacks object params.arguments")?
        .clone();
    let metadata = match params.get("_meta") {
        None => None,
        Some(value) if value.is_object() => Some(value.clone()),
        Some(_) => return Err("mediated request has non-object params._meta".into()),
    };
    // MRTR identity is complete-value identity. Unlike `_meta`, neither
    // field has a semantic shape restriction at this descriptive boundary:
    // preserve structural absence and clone every present JSON value whole.
    let request_state = params.get("requestState").cloned();
    let input_responses = params.get("inputResponses").cloned();
    Ok(RequestParts {
        tool,
        arguments,
        metadata,
        request_state,
        input_responses,
    })
}

fn authorization_decision_from_step(input: &DecisionInput<'_>) -> Result<Value, String> {
    let step: Value = serde_json::from_str(input.emitted_bytes)
        .map_err(|e| format!("cannot parse authoritative Lean step output: {e}"))?;
    let route = step
        .get("route")
        .and_then(Value::as_str)
        .ok_or("authoritative Lean step output lacks route")?;
    if route != "forward" && route != "block" {
        return Err(format!(
            "no authorization decision for non-mediated route {route}"
        ));
    }
    let audit_text = step
        .get("audit")
        .and_then(Value::as_str)
        .ok_or("authoritative Lean step output lacks audit")?;
    let audit: Value = serde_json::from_str(audit_text)
        .map_err(|e| format!("cannot parse authoritative Lean audit: {e}"))?;
    // The kernel's own commitment to the bytes it judged (Host/Audit.lean).
    // The host recomputes the hash of the line IT holds; disagreement means
    // host and kernel are not talking about the same request. That is a
    // SEAM failure and fails closed: the Err surfaces as SEAM_ERROR_RESPONSE
    // in main.rs and nothing forwards. Absence is equally fatal — the kernel
    // this host ships with always emits the field, and an audit without it
    // is by definition not from that kernel.
    let kernel_request_sha256 = audit
        .get("request_sha256")
        .and_then(Value::as_str)
        .ok_or("authoritative Lean audit lacks the kernel request commitment (request_sha256)")?;
    let host_request_sha256 = sha256_hex(input.line.as_bytes());
    if kernel_request_sha256 != host_request_sha256 {
        return Err(format!(
            "kernel-attested request_sha256 {kernel_request_sha256} disagrees with \
             the host's line hash {host_request_sha256}; refusing to assert the pairing"
        ));
    }
    let certs = audit
        .get("certs")
        .and_then(Value::as_array)
        .ok_or("authoritative Lean audit lacks certs")?
        .clone();
    let denied = certs
        .iter()
        .find(|c| c.get("verdict").and_then(Value::as_str) == Some("deny"));
    let (verdict, reason, deny_kernel) = if route == "block" {
        match denied {
            Some(cert) => {
                let kernel = cert
                    .get("kernel")
                    .and_then(Value::as_str)
                    .ok_or("deny certificate lacks kernel")?;
                let why = cert
                    .get("reason")
                    .and_then(Value::as_str)
                    .ok_or("deny certificate lacks reason")?;
                (
                    "BLOCK",
                    format!("{kernel} kernel: {why}"),
                    Value::String(kernel.to_owned()),
                )
            }
            None => ("BLOCK", "no kernel gated this call".to_owned(), Value::Null),
        }
    } else {
        (
            "ALLOW",
            "every gating kernel allows".to_owned(),
            Value::Null,
        )
    };

    // The authorization decision derives structured request material only when the line
    // parses; otherwise it records the raw line hash and the parse error.
    // Never an Err: the authorization-decision layer holds no veto over the kernel.
    let request_material = request_parts(input.line);

    let safety_target = certs
        .iter()
        .find(|c| c.get("kernel").and_then(Value::as_str) == Some("safety"))
        .and_then(|c| c.get("reason"))
        .and_then(Value::as_str);
    let explicit_policy_allow =
        verdict == "ALLOW" && safety_target == Some("explicit policy allow");
    let consumed: Option<&ApprovalRecord> = if verdict == "ALLOW" && !explicit_policy_allow {
        Some(
            safety_target
                .and_then(|target| input.approvals.iter().find(|r| r.target == target))
                .ok_or("approval-authorized ALLOW has no exact consumed approval record")?,
        )
    } else {
        None
    };

    let policy_hash = canonical_json_sha256(input.kernel_config)?;
    let mut receipt = Map::new();
    receipt.insert(
        "record_type".into(),
        Value::String("seal.authorization-decision".into()),
    );
    receipt.insert("record_version".into(), Value::from(2));
    if let Ok(parts) = &request_material {
        receipt.insert("tool".into(), Value::String(parts.tool.clone()));
        receipt.insert("arguments".into(), parts.arguments.clone());
        if let Some(metadata) = &parts.metadata {
            receipt.insert("_meta".into(), metadata.clone());
        }
        if let Some(request_state) = &parts.request_state {
            receipt.insert("requestState".into(), request_state.clone());
        }
        if let Some(input_responses) = &parts.input_responses {
            receipt.insert("inputResponses".into(), input_responses.clone());
        }
        receipt.insert(
            "args_hash".into(),
            Value::String(canonical_json_sha256(&parts.arguments)?),
        );
        receipt.insert(
            "effect_view".into(),
            effect_view(input, &step, parts, &host_request_sha256, &policy_hash),
        );
    }
    receipt.insert("now".into(), Value::from(input.now));
    if let Ok(parts) = &request_material {
        let canonical = canonical_request(parts);
        let canonical_text = serde_json::to_string(&canonical)
            .map_err(|e| format!("cannot serialize canonical request: {e}"))?;
        receipt.insert(
            "canonical_request".into(),
            Value::String(canonical_text.clone()),
        );
        receipt.insert(
            "canonical_request_sha256".into(),
            Value::String(sha256_hex(canonical_text.as_bytes())),
        );
    }
    // Hash of the terminator-stripped body judged by the kernel — present on
    // every authorization decision, and the only body identity when the line
    // is unparseable. This established field is intentionally unchanged.
    // Cross-checked above against the kernel-attested hash in the audit, so
    // this value is kernel-backed, not merely host-asserted.
    receipt.insert("request_sha256".into(), Value::String(host_request_sha256));
    // ApprovalRecord v2 binds the raw delimiter-bearing frame, not the body
    // above. Keep both identities adjacent and explicitly named so operators
    // cannot mistake one digest for the other.
    receipt.insert(
        "framed_subject_sha256".into(),
        Value::String(sha256_hex(input.framed_subject)),
    );
    receipt.insert(
        "framed_subject_length".into(),
        Value::from(input.framed_subject.len() as u64),
    );
    // V2.1 authenticated principal — copied ONLY from the authoritative Lean
    // step output (the parse-path `Host.verifyEnvelope` value; this is the
    // whole Rust half of the R-PRINC seam: one producer, zero derivation).
    // Absent when the kernel returned none — never null-filled, never read
    // from the request line, arguments, or any approval record.
    if let Some(principal) = step.get("principal").and_then(Value::as_str) {
        receipt.insert("principal".into(), Value::String(principal.to_owned()));
    }
    if let Err(parse_error) = &request_material {
        receipt.insert(
            "request_parse_error".into(),
            Value::String(parse_error.clone()),
        );
    }
    receipt.insert("bypass".into(), Value::Bool(false));
    receipt.insert("verdict".into(), Value::String(verdict.into()));
    if verdict == "ALLOW" {
        receipt.insert(
            "authorization".into(),
            Value::String(
                if explicit_policy_allow {
                    "explicit_policy_allow"
                } else {
                    "approval"
                }
                .into(),
            ),
        );
    }
    receipt.insert("reason".into(), Value::String(reason));
    receipt.insert("deny_kernel".into(), deny_kernel);

    if let Some(record) = consumed {
        let mut identity = Map::new();
        identity.insert(
            "channel".into(),
            Value::String(input.approval_identity.channel.clone()),
        );
        if let Some(key_id) = &input.approval_identity.key_id {
            identity.insert("key_id".into(), Value::String(key_id.clone()));
        }
        let mut approval = Map::new();
        approval.insert("approval_identity".into(), Value::Object(identity));
        if let Some(nonce) = &record.nonce {
            approval.insert("nonce".into(), Value::String(nonce.clone()));
        }
        if let Some(issued_at) = record.issued_at {
            approval.insert("issued_at".into(), Value::from(issued_at));
            approval.insert(
                "expiry".into(),
                Value::from(issued_at.saturating_add(input.approval_ttl_ms)),
            );
        }
        approval.insert("policy_hash".into(), Value::String(policy_hash));
        receipt.insert("approval".into(), Value::Object(approval));
    }

    receipt.insert("certs".into(), Value::Array(certs));
    receipt.insert(
        "emitted_bytes".into(),
        Value::String(input.emitted_bytes.to_owned()),
    );
    receipt.insert("kernel_identity".into(), serde_json::json!({
        "wasm_sha256": VERIFIED_WASM_SHA256,
        "self_verified": sha256_hex(VERIFIED_WASM) == VERIFIED_WASM_SHA256,
        "note": "Re-derive against this wasm; the native executor is identified separately, not proven equivalent."
    }));
    receipt.insert("host_identity".into(), Value::Null); // filled by AuthorizationDecisionWriter
    receipt.insert("asserted_provenance".into(), serde_json::json!({
        "verified_in_browser": false,
        "lean_toolchain": "leanprover/lean4:v4.28.0",
        "axioms": ["propext", "Classical.choice", "Quot.sound"],
        "note": "Source-level provenance asserted by the producer; not established by this authorization decision."
    }));
    receipt.insert(
        "signed_config".into(),
        serde_json::json!({
            "payload": input.signed_config.payload,
            "signature": input.signed_config.signature,
            "pubkey": input.signed_config.pubkey,
        }),
    );
    receipt.insert("kernel_config".into(), input.kernel_config.clone());
    receipt.insert(
        "granted_capabilities".into(),
        Value::Array(
            input
                .approvals
                .iter()
                .map(|r| serde_json::json!({"target": r.target}))
                .collect(),
        ),
    );
    Ok(Value::Object(receipt))
}

impl AuthorizationDecisionWriter {
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        secure_fs::ensure_private_dir(&dir, "authorization decision directory")?;
        let probe = dir.join(format!(".seal-receipt-probe-{}", std::process::id()));
        let mut probe_file = secure_fs::open_private_new(&probe, "authorization decision probe")?;
        probe_file
            .write_all(b"probe")
            .and_then(|_| probe_file.sync_all())
            .map_err(|e| {
                format!(
                    "authorization decision directory {} is not writable: {e}",
                    dir.display()
                )
            })?;
        drop(probe_file);
        std::fs::remove_file(&probe).map_err(|e| {
            format!(
                "cannot clean authorization decision probe {}: {e}",
                probe.display()
            )
        })?;

        let exe =
            std::env::current_exe().map_err(|e| format!("cannot identify host executable: {e}"))?;
        let ffi = lean::loaded_ffi_path().ok_or("cannot identify loaded Lean FFI artifact")?;
        Ok(Self {
            dir,
            next_entry: 0,
            native_executable_sha256: hash_file(&exe)?,
            lean_ffi_sha256: hash_file(&ffi)?,
        })
    }

    pub fn persist(
        &mut self,
        input: DecisionInput<'_>,
    ) -> Result<PersistedAuthorizationDecision, String> {
        let mut receipt = authorization_decision_from_step(&input)?;
        receipt
            .as_object_mut()
            .expect("authorization decision object")
            .insert(
                "host_identity".into(),
                serde_json::json!({
                    "native_executable_sha256": self.native_executable_sha256,
                    "lean_ffi_sha256": self.lean_ffi_sha256,
                    "equivalence": "not_proven"
                }),
            );
        // Filename identity: canonical request hash when the line parsed
        // (unchanged for every previously-possible receipt), raw line hash
        // otherwise — always present, so naming can never veto persistence.
        let request_hash = receipt
            .get("canonical_request_sha256")
            .or_else(|| receipt.get("request_sha256"))
            .and_then(Value::as_str)
            .ok_or("authorization decision lacks a request hash")?;
        let consumed_target = receipt
            .get("approval")
            .and_then(|a| a.get("approval_identity"))
            .and_then(|_| {
                receipt
                    .get("certs")?
                    .as_array()?
                    .iter()
                    .find(|c| c.get("kernel").and_then(Value::as_str) == Some("safety"))?
                    .get("reason")?
                    .as_str()
                    .map(str::to_owned)
            });
        let bytes = serde_json::to_string_pretty(&receipt)
            .map_err(|e| format!("cannot serialize v2 authorization decision: {e}"))?
            + "\n";

        loop {
            let name = format!("receipt-{:020}-{}.json", self.next_entry, request_hash);
            let final_path = self.dir.join(name);
            let tmp_path = self.dir.join(format!(
                ".receipt-{}-{:020}.tmp",
                std::process::id(),
                self.next_entry
            ));
            self.next_entry = self.next_entry.saturating_add(1);
            if final_path.exists() {
                continue;
            }
            let write_result = (|| -> std::io::Result<()> {
                let mut file =
                    secure_fs::open_private_new(&tmp_path, "authorization decision temp")
                        .map_err(std::io::Error::other)?;
                file.write_all(bytes.as_bytes())?;
                file.sync_all()?;
                std::fs::rename(&tmp_path, &final_path)?;
                secure_fs::validate_private_file(&final_path, "authorization decision")
                    .map_err(std::io::Error::other)?;
                secure_fs::sync_dir(&self.dir, "authorization decision directory")
                    .map_err(std::io::Error::other)?;
                Ok(())
            })();
            if let Err(e) = write_result {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(format!(
                    "cannot persist authorization decision in {}: {e}",
                    self.dir.display()
                ));
            }
            return Ok(PersistedAuthorizationDecision {
                path: final_path,
                consumed_target,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_wasm_matches_the_pinned_rederivation_identity() {
        assert_eq!(sha256_hex(VERIFIED_WASM), VERIFIED_WASM_SHA256);
    }

    /// Profile self-check (docs/VERIFY-PROFILES.md): the declaration is
    /// P-ENFORCE and satisfies the spec's extraction grammar — the token
    /// name, then a quoted profile id, on one non-comment line of this
    /// file — so the fleet tools can read it without compiling this
    /// crate. A red here means the copy re-declared itself — a design
    /// decision, not a refactor; report it.
    #[test]
    fn verify_profile_declared_and_grammar_extractable() {
        assert_eq!(VERIFY_PROFILE, "P-ENFORCE");
        let src = include_str!("authorization_decision.rs");
        let extracted = src.lines().find_map(|l| {
            let code = l.trim_start();
            if code.starts_with("//") || code.starts_with("///") {
                return None;
            }
            let idx = code.find("VERIFY_PROFILE")?;
            let rest = &code[idx..];
            let start = rest.find('"')? + 1;
            let end = start + rest[start..].find('"')?;
            let v = &rest[start..end];
            if v.starts_with("P-") {
                Some(v.to_string())
            } else {
                None
            }
        });
        assert_eq!(extracted.as_deref(), Some("P-ENFORCE"));
    }

    /// Golden vectors twinned with Host/Audit.lean's `#guard_msgs` block:
    /// the kernel-attested `request_sha256` (SHA-256 of `String.toUTF8`)
    /// and the host's `sha256_hex(input.line.as_bytes())` must agree
    /// byte-for-byte, including on the pinned serde-unparseable line
    /// (1e309) and on multibyte UTF-8. If these can disagree, the kernel
    /// request commitment is theatre.
    #[test]
    fn request_hash_golden_vectors_match_lean() {
        let unparseable = r#"{"jsonrpc":"2.0","id":90,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table accounts","x":1e309}}}"#;
        assert_eq!(
            sha256_hex(unparseable.as_bytes()),
            "c88367514666fdf3ec74b6157deeae7ea2018bea9ce87d6e64120502df81fd30"
        );
        let multibyte = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"héllo","arguments":{"memo":"naïve 日本語 ✓"}}}"#;
        assert_eq!(
            sha256_hex(multibyte.as_bytes()),
            "e7c75841cb1440437b83851d8ccfbbee7fe47a510cf48ef7de6fab6aaedc8d96"
        );
        assert_eq!(
            sha256_hex(b"x"),
            "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
        );
    }

    /// Synthetic kernel output for `line`: the audit carries the kernel
    /// request commitment the real kernel (Host/Audit.lean) always emits.
    fn allow_step_output(line: &str) -> String {
        let audit = serde_json::json!({
            "certs": [{"kernel": "safety", "verdict": "allow",
                       "reason": "explicit policy allow", "certHash": "1"}],
            "verdict": "allow",
            "request_sha256": sha256_hex(line.as_bytes())
        })
        .to_string();
        serde_json::json!({"route": "forward", "audit": audit}).to_string()
    }

    fn build(line: &str, step: &str) -> Result<Value, String> {
        let framed_subject = format!("{line}\n");
        let kernel_config = serde_json::json!({"epoch": 1});
        let signed_config = SignedConfig {
            payload: "p".into(),
            signature: "s".into(),
            pubkey: "k".into(),
        };
        let identity = ApprovalIdentity {
            channel: "file".into(),
            key_id: None,
        };
        authorization_decision_from_step(&DecisionInput {
            line,
            framed_subject: framed_subject.as_bytes(),
            session: "test-session",
            now: 1000,
            emitted_bytes: step,
            kernel_config: &kernel_config,
            signed_config: &signed_config,
            approvals: &[],
            approval_identity: &identity,
            approval_ttl_ms: 1000,
        })
    }

    /// RED: a kernel-allowed line serde cannot parse still yields an authorization decision
    /// — raw line hash + named parse error, structured fields ABSENT. The
    /// authorization-decision layer never vetoes the kernel (this call returned Err before
    /// the de-parse, refusing a Lean-allowed call).
    #[test]
    fn unparseable_line_yields_authorization_decision_with_raw_hash_not_an_error() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"x":1e309}}}"#;
        let receipt = build(line, &allow_step_output(line))
            .expect("de-parsed authorization decision must persist");
        assert_eq!(
            receipt["request_sha256"],
            Value::String(sha256_hex(line.as_bytes()))
        );
        assert_eq!(
            receipt["framed_subject_sha256"],
            Value::String(sha256_hex(format!("{line}\n").as_bytes()))
        );
        assert_eq!(receipt["framed_subject_length"], line.len() + 1);
        assert!(receipt["request_parse_error"]
            .as_str()
            .expect("parse error named")
            .contains("cannot parse mediated request"));
        for absent in [
            "tool",
            "arguments",
            "args_hash",
            "canonical_request",
            "canonical_request_sha256",
            "effect_view",
        ] {
            assert!(receipt.get(absent).is_none(), "{absent} must be absent");
        }
        assert_eq!(receipt["verdict"], "ALLOW");
    }

    /// BLUE: parseable lines keep every existing field and gain the raw
    /// line hash.
    #[test]
    fn parseable_line_keeps_structured_fields_and_gains_raw_hash() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"x":1}}}"#;
        let receipt = build(line, &allow_step_output(line)).expect("authorization decision");
        assert_eq!(receipt["tool"], "t");
        assert!(receipt["arguments"].is_object());
        assert!(receipt["args_hash"].is_string());
        assert!(receipt["canonical_request_sha256"].is_string());
        assert_eq!(
            receipt["request_sha256"],
            Value::String(sha256_hex(line.as_bytes()))
        );
        assert_eq!(
            receipt["framed_subject_sha256"],
            Value::String(sha256_hex(format!("{line}\n").as_bytes()))
        );
        assert_eq!(receipt["framed_subject_length"], line.len() + 1);
        assert!(receipt.get("request_parse_error").is_none());
    }

    #[test]
    fn effect_view_is_non_authoritative_by_value_and_authorization_decision_only() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.add","arguments":{"z":1,"a":2,"effect":{"resource":"forged","action":"allow"}}}}"#;
        let mut step: Value = serde_json::from_str(&allow_step_output(line)).unwrap();
        step["principal"] = Value::String("alice".into());
        let receipt = build(line, &step.to_string()).expect("authorization decision");
        let view = &receipt["effect_view"];

        assert_eq!(view["schema"], "seal.effect-view/v0");
        assert_eq!(view["source"], "mcp-jsonrpc/tools-call@1");
        assert_eq!(view["adapter"]["type"], "mcp-jsonrpc/tools-call");
        assert_eq!(view["adapter"]["version"], "1");
        assert_eq!(view["authoritative"], false);
        assert_eq!(view["principal"]["id"], "alice");
        assert_eq!(view["principal"]["session"], "test-session");
        assert_eq!(view["effect"]["resource"], "notes.add");
        assert_eq!(view["effect"]["action"], "call");
        assert_eq!(view["effect"]["arguments"], receipt["arguments"]);
        assert_eq!(view["raw_preimage_sha256"], receipt["request_sha256"]);
        assert_eq!(view["policy_hash"].as_str().unwrap().len(), 64);
        assert_eq!(
            view["idempotency_key"],
            Value::String(format!(
                "test-session:{}",
                receipt["request_sha256"].as_str().unwrap()
            ))
        );
        assert_eq!(view["policy_version"], 1);
        assert_eq!(view["policy_version_enforced"], false);
        assert_eq!(receipt["verdict"], "ALLOW");
    }

    /// RED (the security property of the kernel request commitment):
    /// a forged pairing — kernel material minted for line A presented with
    /// line B as the request — is refused. Before this cross-check the
    /// authorization-decision layer would happily pair any kernel output with any line;
    /// the host asserted the pairing and nothing could catch it lying.
    #[test]
    fn forged_line_pairing_is_refused() {
        let line_a = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"x":1}}}"#;
        let line_b = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"x":2}}}"#;
        let err = build(line_b, &allow_step_output(line_a))
            .expect_err("a forged line pairing must fail closed");
        assert!(err.contains("disagrees"), "{err}");
    }

    /// RED: an audit with no kernel request commitment at all is refused —
    /// the shipped kernel always emits it, so its absence means this is not
    /// that kernel's output. Fail closed, never assume.
    #[test]
    fn audit_without_request_commitment_is_refused() {
        let audit = serde_json::json!({
            "certs": [{"kernel": "safety", "verdict": "allow",
                       "reason": "explicit policy allow", "certHash": "1"}],
            "verdict": "allow"
        })
        .to_string();
        let step = serde_json::json!({"route": "forward", "audit": audit}).to_string();
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"x":1}}}"#;
        let err = build(line, &step)
            .expect_err("an audit without the kernel request commitment must fail closed");
        assert!(err.contains("lacks the kernel request commitment"), "{err}");
    }

    #[test]
    fn canonical_request_preserves_argument_order() {
        let args: Value = serde_json::from_str(r#"{"z":1,"a":2}"#).unwrap();
        let line = serde_json::to_string(&canonical_request(&RequestParts {
            tool: "x".into(),
            arguments: args,
            metadata: None,
            request_state: None,
            input_responses: None,
        }))
        .unwrap();
        assert_eq!(
            line,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"z":1,"a":2}}}"#
        );
    }

    /// M.1 stage 3 cross-layer control. The host's reader-facing projection
    /// and the kernel-emitted raw request commitment need not have the same
    /// digest (their preimages are deliberately different), but they MUST
    /// agree on the identity question: did changing only `_meta` change the
    /// committed request? The exact positive twin rules out time/config/test
    /// noise as the source of the negative pair's difference.
    #[test]
    fn meta_identity_controls_receipt_projection_and_kernel_agree() {
        let line_a = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"select 1"},"_meta":{"example.com/invocation":"a"}}}"#;
        let line_b = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"select 1"},"_meta":{"example.com/invocation":"b"}}}"#;

        let receipt_a =
            build(line_a, &allow_step_output(line_a)).expect("metadata A authorization decision");
        let receipt_a_twin =
            build(line_a, &allow_step_output(line_a)).expect("metadata A positive twin");
        let receipt_b =
            build(line_b, &allow_step_output(line_b)).expect("metadata B authorization decision");

        let bytes_a = serde_json::to_vec(&receipt_a).unwrap();
        let bytes_a_twin = serde_json::to_vec(&receipt_a_twin).unwrap();
        let bytes_b = serde_json::to_vec(&receipt_b).unwrap();
        assert_eq!(
            bytes_a, bytes_a_twin,
            "POSITIVE-TWIN RED key=_meta: identical input did not produce a byte-identical receipt"
        );
        println!("RECEIPT-POSITIVE-TWIN GREEN key=_meta bytes=byte-identical");

        assert_eq!(
            receipt_a["_meta"]["example.com/invocation"], "a",
            "RECEIPT-VISIBILITY RED key=_meta: receipt omitted metadata A"
        );
        assert_eq!(
            receipt_b["_meta"]["example.com/invocation"], "b",
            "RECEIPT-VISIBILITY RED key=_meta: receipt omitted metadata B"
        );
        assert_eq!(
            receipt_a["effect_view"]["effect"]["_meta"],
            receipt_a["_meta"]
        );
        assert_eq!(
            receipt_b["effect_view"]["effect"]["_meta"],
            receipt_b["_meta"]
        );
        assert_ne!(
            bytes_a, bytes_b,
            "RECEIPT-DISTINGUISHABILITY RED key=_meta: metadata-only mutation produced identical receipt bytes"
        );

        let host_projection_changed =
            receipt_a["canonical_request_sha256"] != receipt_b["canonical_request_sha256"];
        assert!(
            host_projection_changed,
            "HOST-PROJECTION RED key=_meta: canonical_request_sha256 ignored the metadata-only mutation"
        );
        let canonical_a: Value =
            serde_json::from_str(receipt_a["canonical_request"].as_str().unwrap()).unwrap();
        let canonical_b: Value =
            serde_json::from_str(receipt_b["canonical_request"].as_str().unwrap()).unwrap();
        assert_eq!(
            canonical_a.pointer("/params/_meta"),
            Some(&receipt_a["_meta"])
        );
        assert_eq!(
            canonical_b.pointer("/params/_meta"),
            Some(&receipt_b["_meta"])
        );
        println!(
            "RECEIPT-DISTINGUISHABILITY GREEN key=_meta canonical_sha_a={} canonical_sha_b={}",
            receipt_a["canonical_request_sha256"].as_str().unwrap(),
            receipt_b["canonical_request_sha256"].as_str().unwrap()
        );

        let kernel_commitment = |receipt: &Value| -> String {
            let step: Value =
                serde_json::from_str(receipt["emitted_bytes"].as_str().unwrap()).unwrap();
            let audit: Value = serde_json::from_str(step["audit"].as_str().unwrap()).unwrap();
            let kernel = audit["request_sha256"].as_str().unwrap();
            assert_eq!(
                Some(kernel),
                receipt["request_sha256"].as_str(),
                "RAW-HASH-SEAM RED key=_meta: kernel and host request commitments disagree"
            );
            kernel.to_owned()
        };
        let kernel_a = kernel_commitment(&receipt_a);
        let kernel_b = kernel_commitment(&receipt_b);
        let kernel_commitment_changed = kernel_a != kernel_b;
        assert_eq!(
            host_projection_changed, kernel_commitment_changed,
            "HOST-KERNEL-AGREEMENT RED key=_meta: host projection and kernel commitment disagree about identity change"
        );
        println!(
            "HOST-KERNEL-AGREEMENT GREEN key=_meta host_projection_changed={} kernel_request_commitment_changed={} kernel_sha_a={} kernel_sha_b={}",
            host_projection_changed, kernel_commitment_changed, kernel_a, kernel_b
        );
    }

    /// M.4 stage 3 control. Each field-specific negative pair changes only
    /// one complete MRTR value and is preceded by an exact positive twin.
    /// The host's canonical projection and the kernel-attested raw request
    /// commitment must give the same changed/not-changed answer.
    #[test]
    fn mrtr_identity_controls_receipt_projection_and_kernel_agree() {
        let request = |request_state: Option<&str>, input_responses: Option<&str>| {
            let mut raw = String::from(
                r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"select 1"}"#,
            );
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
        };

        let kernel_commitment = |field: &str, receipt: &Value| -> String {
            let step: Value =
                serde_json::from_str(receipt["emitted_bytes"].as_str().unwrap()).unwrap();
            let audit: Value = serde_json::from_str(step["audit"].as_str().unwrap()).unwrap();
            let kernel = audit["request_sha256"].as_str().unwrap();
            assert_eq!(
                Some(kernel),
                receipt["request_sha256"].as_str(),
                "MRTR-RAW-HASH-SEAM RED field={field}: kernel and host request commitments disagree"
            );
            kernel.to_owned()
        };

        let checked = |field: &str, raw: &str| {
            let first = build(raw, &allow_step_output(raw)).expect("MRTR authorization decision");
            let twin = build(raw, &allow_step_output(raw)).expect("MRTR positive-twin decision");
            assert_eq!(
                serde_json::to_vec(&first).unwrap(),
                serde_json::to_vec(&twin).unwrap(),
                "MRTR-POSITIVE-TWIN RED field={field}: byte-identical requests produced different receipts"
            );
            println!(
                "MRTR-POSITIVE-TWIN GREEN field={field} request=byte-identical receipt=byte-identical"
            );
            first
        };

        let check_discrimination = |field: &str,
                                    left_raw: String,
                                    right_raw: String,
                                    left_value: Value,
                                    right_value: Value| {
            let left = checked(&format!("{field}.left"), &left_raw);
            let right = checked(&format!("{field}.right"), &right_raw);

            assert_eq!(
                left.get(field),
                Some(&left_value),
                "MRTR-RECEIPT-VISIBILITY RED field={field}: left complete value missing"
            );
            assert_eq!(
                right.get(field),
                Some(&right_value),
                "MRTR-RECEIPT-VISIBILITY RED field={field}: right complete value missing"
            );
            assert_eq!(
                left["effect_view"]["effect"].get(field),
                Some(&left_value),
                "MRTR-EFFECT-VIEW RED field={field}: left complete value missing"
            );
            assert_eq!(
                right["effect_view"]["effect"].get(field),
                Some(&right_value),
                "MRTR-EFFECT-VIEW RED field={field}: right complete value missing"
            );

            let host_changed =
                left["canonical_request_sha256"] != right["canonical_request_sha256"];
            assert!(
                host_changed,
                "HOST-PROJECTION RED field={field}: canonical_request_sha256 ignored MRTR mutation"
            );
            let left_canonical: Value =
                serde_json::from_str(left["canonical_request"].as_str().unwrap()).unwrap();
            let right_canonical: Value =
                serde_json::from_str(right["canonical_request"].as_str().unwrap()).unwrap();
            assert_eq!(
                left_canonical["params"].get(field),
                Some(&left_value),
                "MRTR-CANONICAL-VISIBILITY RED field={field}: left complete value missing"
            );
            assert_eq!(
                right_canonical["params"].get(field),
                Some(&right_value),
                "MRTR-CANONICAL-VISIBILITY RED field={field}: right complete value missing"
            );
            let kernel_left = kernel_commitment(field, &left);
            let kernel_right = kernel_commitment(field, &right);
            let kernel_changed = kernel_left != kernel_right;
            assert_eq!(
                    host_changed, kernel_changed,
                    "HOST-KERNEL-AGREEMENT RED field={field}: host projection and kernel commitment disagree about identity change"
                );
            assert_ne!(
                    serde_json::to_vec(&left).unwrap(),
                    serde_json::to_vec(&right).unwrap(),
                    "RECEIPT-DISTINGUISHABILITY RED field={field}: mutation produced identical receipt bytes"
                );
            println!(
                    "MRTR-RECEIPT-DISTINGUISHABILITY GREEN field={field} complete-value=visible receipt=different"
                );
            println!(
                    "MRTR-HOST-KERNEL-AGREEMENT GREEN field={field} host_projection_changed={host_changed} kernel_request_commitment_changed={kernel_changed}"
                );
        };

        let state_left = serde_json::json!({
            "opaque": {"token": "state-a", "ignoredSemantics": [1, null, false]},
            "sibling": "retained"
        });
        let state_right = serde_json::json!({
            "opaque": {"token": "state-b", "ignoredSemantics": [1, null, false]},
            "sibling": "retained"
        });
        check_discrimination(
            "requestState",
            request(Some(&state_left.to_string()), None),
            request(Some(&state_right.to_string()), None),
            state_left,
            state_right,
        );

        let responses_left = serde_json::json!({
            "confirm": {"action": "accept", "content": true},
            "survey": {"score": 5},
            "extension": ["one", "two"]
        });
        let responses_right = serde_json::json!({
            "confirm": {"action": "decline", "content": false},
            "survey": {"score": 5},
            "extension": ["one", "two"]
        });
        check_discrimination(
            "inputResponses",
            request(None, Some(&responses_left.to_string())),
            request(None, Some(&responses_right.to_string())),
            responses_left,
            responses_right,
        );

        for field in ["requestState", "inputResponses"] {
            let raw_for = |value: Option<&str>| match field {
                "requestState" => request(value, None),
                "inputResponses" => request(None, value),
                _ => unreachable!(),
            };
            let absent = checked(&format!("{field}.absent"), &raw_for(None));
            let empty = checked(&format!("{field}.present-empty"), &raw_for(Some("{}")));
            let null = checked(&format!("{field}.present-null"), &raw_for(Some("null")));
            let identities = [
                &absent["canonical_request_sha256"],
                &empty["canonical_request_sha256"],
                &null["canonical_request_sha256"],
            ];
            assert!(
                identities[0] != identities[1]
                    && identities[0] != identities[2]
                    && identities[1] != identities[2],
                "MRTR-ABSENCE RED field={field}: absent/present-empty/present-null collapsed"
            );
            assert!(
                absent.get(field).is_none()
                    && empty.get(field) == Some(&serde_json::json!({}))
                    && null.get(field) == Some(&Value::Null),
                "MRTR-ABSENCE RED field={field}: receipt presence rendering is dishonest"
            );
            println!(
                "MRTR-ABSENCE GREEN field={field} absent/present-empty/present-null=three-distinct-receipt-identities"
            );
        }
    }

    #[test]
    fn canonical_request_carries_metadata_in_member_order() {
        let args: Value = serde_json::from_str(r#"{"z":1,"a":2}"#).unwrap();
        let metadata: Value =
            serde_json::from_str(r#"{"traceparent":"00-a","example.com/invocation":"7"}"#).unwrap();
        let line = serde_json::to_string(&canonical_request(&RequestParts {
            tool: "x".into(),
            arguments: args,
            metadata: Some(metadata),
            request_state: None,
            input_responses: None,
        }))
        .unwrap();
        assert_eq!(
            line,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"z":1,"a":2},"_meta":{"traceparent":"00-a","example.com/invocation":"7"}}}"#
        );
    }

    #[test]
    fn canonical_request_carries_complete_mrtr_values_in_fixed_member_order() {
        let args: Value = serde_json::from_str(r#"{"z":1,"a":2}"#).unwrap();
        let metadata: Value = serde_json::from_str(r#"{"traceparent":"00-a"}"#).unwrap();
        let request_state: Value =
            serde_json::from_str(r#"{"opaque":{"nested":[1,null]},"sibling":"kept"}"#).unwrap();
        let input_responses: Value =
            serde_json::from_str(r#"{"first":{"action":"accept"},"second":{"content":{"x":1}}}"#)
                .unwrap();
        let line = serde_json::to_string(&canonical_request(&RequestParts {
            tool: "x".into(),
            arguments: args,
            metadata: Some(metadata),
            request_state: Some(request_state),
            input_responses: Some(input_responses),
        }))
        .unwrap();
        assert_eq!(
            line,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"z":1,"a":2},"_meta":{"traceparent":"00-a"},"requestState":{"opaque":{"nested":[1,null]},"sibling":"kept"},"inputResponses":{"first":{"action":"accept"},"second":{"content":{"x":1}}}}}"#
        );
    }
}
