// SPDX-License-Identifier: Apache-2.0
//! A3 — host-side freshness: the clock and replay state the Lean kernels
//! trust the host for. Every approval record passes through here before it
//! reaches Lean:
//!
//! * nonce replay: a nonce is accepted at most once per session;
//! * TTL freshness: a record older than the approval TTL is dead on arrival;
//! * clock skew: a record from the future (beyond a small skew) is rejected.
//!
//! Records without a nonce (the V1 control-file channel) skip the nonce
//! check — their replay protection is the positional seen counter plus
//! Lean's one-shot consumption. Signed-token records always carry nonces
//! (the provider enforces it).

use crate::providers::ApprovalRecord;
use std::collections::HashSet;

const MAX_FUTURE_SKEW_MS: u64 = 5_000;

pub struct A3Filter {
    seen_nonces: HashSet<String>,
    ttl_ms: u64,
}

impl A3Filter {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            seen_nonces: HashSet::new(),
            ttl_ms,
        }
    }

    /// Filter records fail-closed; returns survivors and a reason per drop
    /// (for the audit log).
    pub fn filter(
        &mut self,
        records: Vec<ApprovalRecord>,
        now_ms: u64,
    ) -> (Vec<ApprovalRecord>, Vec<String>) {
        let mut ok = Vec::new();
        let mut dropped = Vec::new();
        for r in records {
            if let Some(issued) = r.issued_at {
                if issued > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
                    dropped.push(format!("a3: future issuedAt for target {}", r.target));
                    continue;
                }
                if now_ms.saturating_sub(issued) > self.ttl_ms {
                    dropped.push(format!("a3: expired record for target {}", r.target));
                    continue;
                }
            }
            if let Some(nonce) = &r.nonce {
                if !self.seen_nonces.insert(nonce.clone()) {
                    dropped.push(format!("a3: replayed nonce for target {}", r.target));
                    continue;
                }
            }
            ok.push(r);
        }
        (ok, dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(target: u64, issued: Option<u64>, nonce: Option<&str>) -> ApprovalRecord {
        ApprovalRecord {
            target,
            issued_at: issued,
            nonce: nonce.map(String::from),
        }
    }

    #[test]
    fn replayed_nonce_rejected() {
        let mut a3 = A3Filter::new(120_000);
        let (ok, dropped) = a3.filter(
            vec![
                rec(1, Some(1000), Some("n1")),
                rec(1, Some(1000), Some("n1")),
            ],
            2000,
        );
        assert_eq!(ok.len(), 1);
        assert_eq!(dropped.len(), 1);
        assert!(dropped[0].contains("replayed nonce"));
        // Replay in a later poll also rejected.
        let (ok2, dropped2) = a3.filter(vec![rec(1, Some(1500), Some("n1"))], 2500);
        assert!(ok2.is_empty());
        assert_eq!(dropped2.len(), 1);
    }

    #[test]
    fn expired_and_future_rejected() {
        let mut a3 = A3Filter::new(1_000);
        let (ok, dropped) = a3.filter(
            vec![
                rec(1, Some(0), Some("old")),       // 10s old, ttl 1s
                rec(2, Some(100_000), Some("fut")), // far future
                rec(3, Some(9_800), Some("fresh")), // 200ms old
            ],
            10_000,
        );
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].target, 3);
        assert_eq!(dropped.len(), 2);
    }

    #[test]
    fn nonceless_records_pass_freshness_only() {
        let mut a3 = A3Filter::new(1_000);
        let (ok, _) = a3.filter(vec![rec(1, None, None), rec(1, None, None)], 10_000);
        assert_eq!(
            ok.len(),
            2,
            "control-file records rely on seen-counter + one-shot"
        );
    }
}
