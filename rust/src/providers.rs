// SPDX-License-Identifier: Apache-2.0
//! The extensible approval back-channel: trait-based providers that mint
//! approval records without touching the proven core. The host polls the
//! active provider before each mediated call; records then pass A3
//! (nonce/replay/TTL) before reaching Lean.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::io::BufRead;

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
pub struct ApprovalRecord {
    #[serde(deserialize_with = "target_hex")]
    pub target: String,
    #[serde(rename = "issuedAt", default, deserialize_with = "opt_u64_str_or_num")]
    pub issued_at: Option<u64>,
    #[serde(default)]
    pub nonce: Option<String>,
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
}

impl ControlFileProvider {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            path: path.into(),
            seen: 0,
            drop_counter: 0,
        }
    }
}

impl ApprovalProvider for ControlFileProvider {
    fn poll(&mut self) -> ApprovalPoll {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return ApprovalPoll::default();
        };
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let fresh = lines[self.seen.min(lines.len())..].to_vec();
        self.seen = lines.len();
        let source = self.name();
        let mut poll = ApprovalPoll::default();
        for line in fresh {
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
            match serde_json::from_str::<ApprovalRecord>(line) {
                Ok(record) => poll.records.push(record),
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
/// Decision field: absent or "allow" => approval record; "deny" => decline;
/// any other value => record dropped with an `unknown_decision:<value>` warning.
/// NOTE: `echo >> ndjson` (control-file) and unsigned tokens are DEV-ONLY
/// and UNAUTHENTICATED — the ed25519 channel is the signed origin path.
pub struct Ed25519TokenProvider {
    path: std::path::PathBuf,
    key: VerifyingKey,
    seen: usize,
    drop_counter: u64,
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
        })
    }
}

impl ApprovalProvider for Ed25519TokenProvider {
    fn poll(&mut self) -> ApprovalPoll {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return ApprovalPoll::default();
        };
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let fresh = lines[self.seen.min(lines.len())..].to_vec();
        self.seen = lines.len();
        let source = self.name();
        let mut poll = ApprovalPoll::default();
        for line in fresh {
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
            let sig_bytes = match hex::decode(&token.signature) {
                Ok(bytes) => bytes,
                Err(_) => {
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        "bad_signature",
                        line.as_bytes(),
                    ));
                    continue;
                }
            };
            let sig = match Signature::from_slice(&sig_bytes) {
                Ok(sig) => sig,
                Err(_) => {
                    poll.warnings.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        source,
                        "bad_signature",
                        line.as_bytes(),
                    ));
                    continue;
                }
            };
            if self.key.verify(token.payload.as_bytes(), &sig).is_err() {
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "bad_signature",
                    line.as_bytes(),
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
                let red = record_redaction_material(&ApprovalRecord {
                    target: sp.target.clone(),
                    issued_at: sp.issued_at,
                    nonce: sp.nonce.clone(),
                });
                poll.warnings.push(ApprovalDropWarning::new(
                    &mut self.drop_counter,
                    source,
                    "missing_required_field",
                    red,
                ));
                continue;
            }
            // ALLOWLIST on decision: absent or "allow" => approval; exactly "deny"
            // => decline; ANY other value => drop with a warning naming it. A signed
            // record meaning "do not run this" must never mint an approval because
            // its decision spelling is unrecognised.
            match sp.decision.as_deref() {
                None | Some("allow") => poll.records.push(ApprovalRecord {
                    target: sp.target,
                    issued_at: sp.issued_at,
                    nonce: sp.nonce,
                }),
                Some("deny") => poll.declines.push(DeclineRecord {
                    target: sp.target,
                    issued_at: sp.issued_at,
                    nonce: sp.nonce,
                }),
                Some(other) => {
                    let reason = unknown_decision_reason(other);
                    let red = record_redaction_material(&ApprovalRecord {
                        target: sp.target.clone(),
                        issued_at: sp.issued_at,
                        nonce: sp.nonce.clone(),
                    });
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
        let mut answer = String::new();
        if self.input.read_line(&mut answer).is_ok() && answer.trim() == "y" {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            ApprovalPoll {
                records: vec![ApprovalRecord {
                    target,
                    issued_at: Some(now),
                    nonce: None,
                }],
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

    #[test]
    fn ed25519_provider_accepts_valid_rejects_tampered() {
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
        assert_eq!(poll.warnings.len(), 1, "tampered token emits one warning");
        assert_eq!(poll.warnings[0].reason, "bad_signature");
        let records = poll.records;
        assert_eq!(records.len(), 1, "tampered token must be dropped");
        assert_eq!(records[0].target, target);
    }

    #[test]
    fn ed25519_provider_accepts_signed_decline_and_allow() {
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
        assert!(
            poll.warnings.is_empty(),
            "valid signed allow+decline must have zero warnings"
        );
        assert_eq!(poll.records.len(), 1);
        assert_eq!(poll.records[0].target, target);
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

    /// BLUE: the allowlisted spellings still work on the signed channel —
    /// absent decision and explicit "allow" both mint approvals.
    #[test]
    fn ed25519_provider_still_approves_absent_and_allow() {
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
        assert!(poll.warnings.is_empty());
        assert!(poll.declines.is_empty());
        assert_eq!(poll.records.len(), 2);
        assert_eq!(poll.records[0].nonce.as_deref(), Some("n-abs"));
        assert_eq!(poll.records[1].nonce.as_deref(), Some("n-alw"));
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

    /// BLUE: control-file channel still approves absent decision and "allow",
    /// and still parses exact "deny" as a decline.
    #[test]
    fn control_file_still_approves_absent_and_allow_and_declines_deny() {
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
        assert!(poll.warnings.is_empty());
        assert_eq!(poll.records.len(), 2);
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
}
