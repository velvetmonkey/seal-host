// SPDX-License-Identifier: Apache-2.0
//! The extensible approval back-channel: trait-based providers that mint
//! approval records without touching the proven core. The host polls the
//! active provider before each mediated call; records then pass A3
//! (nonce/replay/TTL) before reaching Lean.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::io::BufRead;

#[derive(Debug, Clone, Deserialize)]
pub struct ApprovalRecord {
    pub target: u64,
    #[serde(rename = "issuedAt")]
    pub issued_at: Option<u64>,
    pub nonce: Option<String>,
}

/// An approval source. Implementations mint records; they do NOT decide —
/// the proven Lean core consumes the records (one-shot, target-bound).
pub trait ApprovalProvider {
    fn poll(&mut self) -> Vec<ApprovalRecord>;
    fn name(&self) -> &'static str;
}

/// V1-compatible control file: NDJSON `{"target": n, "issuedAt"?: ms}`,
/// each line ingested exactly once (positional seen counter).
pub struct ControlFileProvider {
    path: std::path::PathBuf,
    seen: usize,
}

impl ControlFileProvider {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into(), seen: 0 }
    }
}

impl ApprovalProvider for ControlFileProvider {
    fn poll(&mut self) -> Vec<ApprovalRecord> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        let lines: Vec<&str> =
            text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        let fresh = lines[self.seen.min(lines.len())..].to_vec();
        self.seen = lines.len();
        fresh
            .into_iter()
            .filter_map(|l| serde_json::from_str::<ApprovalRecord>(l).ok())
            .collect()
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

/// Ed25519 token file: NDJSON `{"payload": "<json>", "signature": "<hex>"}`
/// where payload parses to an ApprovalRecord with a MANDATORY nonce and
/// issuedAt. The signature is verified over the exact payload bytes against
/// the trusted verifying key — same byte-exact discipline as the Lean-side
/// config envelope, so the G6 Ed25519 swap covers the same bytes.
pub struct Ed25519TokenProvider {
    path: std::path::PathBuf,
    key: VerifyingKey,
    seen: usize,
}

impl Ed25519TokenProvider {
    pub fn new(path: impl Into<std::path::PathBuf>, key_hex: &str) -> Result<Self, String> {
        let bytes: [u8; 32] = hex::decode(key_hex)
            .map_err(|e| format!("bad approval pubkey hex: {e}"))?
            .try_into()
            .map_err(|_| "approval pubkey must be 32 bytes".to_string())?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|e| format!("bad approval pubkey: {e}"))?;
        Ok(Self { path: path.into(), key, seen: 0 })
    }
}

impl ApprovalProvider for Ed25519TokenProvider {
    fn poll(&mut self) -> Vec<ApprovalRecord> {
        let Ok(text) = std::fs::read_to_string(&self.path) else {
            return Vec::new();
        };
        let lines: Vec<&str> =
            text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        let fresh = lines[self.seen.min(lines.len())..].to_vec();
        self.seen = lines.len();
        fresh
            .into_iter()
            .filter_map(|l| {
                let token: SignedToken = serde_json::from_str(l).ok()?;
                let sig_bytes = hex::decode(&token.signature).ok()?;
                let sig = Signature::from_slice(&sig_bytes).ok()?;
                self.key.verify(token.payload.as_bytes(), &sig).ok()?;
                let record: ApprovalRecord = serde_json::from_str(&token.payload).ok()?;
                // Signed tokens MUST carry nonce + issuedAt for A3.
                if record.nonce.is_none() || record.issued_at.is_none() {
                    return None;
                }
                Some(record)
            })
            .collect()
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
    pub pending_target: Option<u64>,
}

impl<R: BufRead, W: std::io::Write> InteractiveProvider<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self { input, output, pending_target: None }
    }

    pub fn queue(&mut self, target: u64) {
        self.pending_target = Some(target);
    }
}

impl<R: BufRead, W: std::io::Write> ApprovalProvider for InteractiveProvider<R, W> {
    fn poll(&mut self) -> Vec<ApprovalRecord> {
        let Some(target) = self.pending_target.take() else {
            return Vec::new();
        };
        let _ = writeln!(self.output, "seal-host: approve target {target}? [y/N] ");
        let _ = self.output.flush();
        let mut answer = String::new();
        if self.input.read_line(&mut answer).is_ok() && answer.trim() == "y" {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            vec![ApprovalRecord { target, issued_at: Some(now), nonce: None }]
        } else {
            Vec::new()
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
        let payload = r#"{"target":42,"issuedAt":1000,"nonce":"abc123"}"#;
        let sig = hex::encode(sk.sign(payload.as_bytes()).to_bytes());
        let good = format!(r#"{{"payload":{},"signature":"{}"}}"#,
            serde_json::to_string(payload).unwrap(), sig);
        let bad = good.replace("42", "43");

        let dir = std::env::temp_dir().join(format!("seal-tok-{}", std::process::id()));
        std::fs::write(&dir, format!("{good}\n{bad}\n")).unwrap();
        let mut p = Ed25519TokenProvider::new(&dir, &vk_hex).unwrap();
        let records = p.poll();
        std::fs::remove_file(&dir).ok();
        assert_eq!(records.len(), 1, "tampered token must be dropped");
        assert_eq!(records[0].target, 42);
    }

    #[test]
    fn interactive_provider_mints_on_yes_only() {
        let mut p = InteractiveProvider::new(std::io::Cursor::new(b"y\n".to_vec()), Vec::new());
        p.queue(7);
        let records = p.poll();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target, 7);

        let mut p = InteractiveProvider::new(std::io::Cursor::new(b"n\n".to_vec()), Vec::new());
        p.queue(7);
        assert!(p.poll().is_empty());
    }
}
