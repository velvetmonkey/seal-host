// SPDX-License-Identifier: Apache-2.0
//! Production receipt commitment for deployed audit records.
//!
//! This mirrors `scripts/seal_log.mjs`: the prior head is the 64-character
//! lowercase hex string, not raw digest bytes, then a unit separator and the
//! byte-identical audit payload are hashed with SHA-256.

use serde_json::json;
use sha2::{Digest, Sha256};

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
}

impl ReceiptChain {
    pub fn new() -> Self {
        Self {
            head: genesis(),
            entry_index: 0,
        }
    }

    pub fn observe(&mut self, payload: &str) -> ReceiptRecord {
        let head = commit(&self.head, payload);
        let record = ReceiptRecord {
            entry: self.entry_index,
            head: head.clone(),
        };
        self.head = head;
        self.entry_index += 1;
        record
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
}

impl ReceiptRecord {
    pub fn to_json_line(&self) -> String {
        json!({
            "seal_record": "v1",
            "entry": self.entry,
            "commitment": COMMITMENT,
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
        let r0 = c.observe("audit-0");
        let r1 = c.observe("audit-1");
        assert_eq!(r0.entry, 0);
        assert_eq!(r1.entry, 1);
        assert_eq!(r0.head, commit(&genesis(), "audit-0"));
        assert_eq!(r1.head, commit(&r0.head, "audit-1"));
    }
}
