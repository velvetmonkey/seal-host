// SPDX-License-Identifier: Apache-2.0
//! Production receipt commitment for deployed audit records.
//!
//! This mirrors `scripts/seal_log.mjs`: the prior head is the 64-character
//! lowercase hex string, not raw digest bytes, then a unit separator and the
//! byte-identical audit payload are hashed with SHA-256.

use crate::limits::read_file_bounded;
use crate::secure_fs;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const COMMITMENT: &str = "sha256(prevHead || 0x1f || payload)";
const GENESIS_PREIMAGE: &[u8] = b"seal-verifiable-record/genesis/v1";

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn genesis() -> String {
    sha256_hex(GENESIS_PREIMAGE)
}

pub fn commit(prev_head_hex: &str, payload: &str) -> String {
    let mut h = Sha256::new();
    h.update(prev_head_hex.as_bytes());
    h.update(b"\x1f");
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

#[derive(Debug, Clone)]
pub struct ReceiptChain {
    head: String,
    entry_index: u64,
    session: String,
    prior_session: Option<String>,
    state_path: Option<PathBuf>,
}

impl ReceiptChain {
    pub fn new() -> Self {
        Self {
            head: genesis(),
            entry_index: 0,
            session: "ephemeral-test-session".into(),
            prior_session: None,
            state_path: None,
        }
    }

    pub fn open(dir: &Path, session: &str) -> Result<Self, String> {
        secure_fs::validate_private_dir(dir, "audit state directory")?;
        let state_path = dir.join(".seal-audit-head.state");
        let (head, prior_session) = if state_path.exists() {
            secure_fs::validate_private_file(&state_path, "audit head state")?;
            let bytes = read_file_bounded(&state_path, 16 * 1024)
                .map_err(|e| format!("cannot read audit head state: {e}"))?;
            let state: Value = serde_json::from_slice(&bytes)
                .map_err(|e| format!("cannot parse audit head state: {e}"))?;
            if state.get("seal_audit_state").and_then(Value::as_str) != Some("v1") {
                return Err("audit head state has unknown format".into());
            }
            let head = state
                .get("head")
                .and_then(Value::as_str)
                .filter(|head| {
                    head.len() == 64 && head.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                })
                .ok_or("audit head state has invalid head")?;
            let previous = state
                .get("session")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or("audit head state has invalid session")?;
            (head.to_owned(), Some(previous.to_owned()))
        } else {
            (genesis(), None)
        };
        Ok(Self {
            head,
            entry_index: 0,
            session: session.to_owned(),
            prior_session,
            state_path: Some(state_path),
        })
    }

    pub fn observe(&mut self, payload: &str) -> Result<ReceiptRecord, String> {
        let prev_head = self.head.clone();
        let head = commit(&self.head, payload);
        let record = ReceiptRecord {
            entry: self.entry_index,
            head: head.clone(),
            prev_head,
            session: self.session.clone(),
            prior_session: if self.entry_index == 0 {
                self.prior_session.clone()
            } else {
                None
            },
        };
        if let Some(state_path) = &self.state_path {
            let parent = state_path.parent().unwrap_or_else(|| Path::new("."));
            let tmp_path = parent.join(format!(
                ".seal-audit-head-{}-{}.tmp",
                std::process::id(),
                self.entry_index
            ));
            let bytes = serde_json::to_vec(&json!({
                "seal_audit_state": "v1",
                "session": self.session,
                "head": head,
            }))
            .map_err(|e| format!("cannot serialize audit head state: {e}"))?;
            let persist = (|| -> Result<(), String> {
                let mut file = secure_fs::open_private_new(&tmp_path, "audit head temp")?;
                file.write_all(&bytes)
                    .and_then(|_| file.write_all(b"\n"))
                    .and_then(|_| file.sync_all())
                    .map_err(|e| format!("cannot sync audit head temp: {e}"))?;
                std::fs::rename(&tmp_path, state_path)
                    .map_err(|e| format!("cannot replace audit head state: {e}"))?;
                secure_fs::validate_private_file(state_path, "audit head state")?;
                secure_fs::sync_dir(parent, "audit state directory")?;
                Ok(())
            })();
            if let Err(error) = persist {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(error);
            }
        }
        self.head = head;
        self.entry_index += 1;
        Ok(record)
    }
}

impl Default for ReceiptChain {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptRecord {
    pub entry: u64,
    pub head: String,
    pub prev_head: String,
    pub session: String,
    pub prior_session: Option<String>,
}

impl ReceiptRecord {
    pub fn to_json_line(&self) -> String {
        json!({
            "seal_record": "v1",
            "entry": self.entry,
            "commitment": COMMITMENT,
            "session": self.session,
            "prev_head": self.prev_head,
            "prior_session": self.prior_session,
            "head": self.head,
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vectors_match_node_receipt_chain() {
        assert_eq!(
            genesis(),
            "0633b0b4c5ca8207b3174d64fe438b99eaa1f5d95d0d4bbaa5d3fe6bd5f700a9"
        );
        assert_eq!(
            commit(&genesis(), "audit-0"),
            "8dd24f08c8674e9b7b950837337c93d09d5240e1aedbb7d54269ee9381b84a4c"
        );
    }

    #[test]
    fn observe_advances_index_and_head() {
        let mut c = ReceiptChain::new();
        let r0 = c.observe("audit-0").unwrap();
        let r1 = c.observe("audit-1").unwrap();
        assert_eq!(r0.entry, 0);
        assert_eq!(r1.entry, 1);
        assert_eq!(r0.head, commit(&genesis(), "audit-0"));
        assert_eq!(r1.head, commit(&r0.head, "audit-1"));
    }

    #[test]
    fn persisted_head_cross_links_a_new_session() {
        let dir = std::env::temp_dir().join(format!(
            "seal-audit-chain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        secure_fs::ensure_private_dir(&dir, "test audit dir").unwrap();
        let first_head = {
            let mut first = ReceiptChain::open(&dir, "session-a").unwrap();
            first.observe("audit-a").unwrap().head
        };
        let mut second = ReceiptChain::open(&dir, "session-b").unwrap();
        let linked = second.observe("audit-b").unwrap();
        assert_eq!(linked.prev_head, first_head);
        assert_eq!(linked.prior_session.as_deref(), Some("session-a"));
        assert_eq!(linked.session, "session-b");
        assert_eq!(linked.head, commit(&first_head, "audit-b"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
