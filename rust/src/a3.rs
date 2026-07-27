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

use crate::providers::{record_redaction_material, ApprovalDropWarning, ApprovalRecord};
use crate::replay_store::{InMemoryReplayStore, ReplayStore, ReplayStoreError};
use std::collections::HashMap;

const MAX_FUTURE_SKEW_MS: u64 = 5_000;
const PRUNE_INTERVAL_ACCEPTS: u64 = 256;

pub struct A3Filter {
    seen_nonces: HashMap<String, u64>,
    replay_store: Box<dyn ReplayStore>,
    ttl_ms: u64,
    drop_counter: u64,
    accepted_since_prune: u64,
}

impl A3Filter {
    pub fn new(ttl_ms: u64) -> Self {
        Self {
            seen_nonces: HashMap::new(),
            replay_store: Box::<InMemoryReplayStore>::default(),
            ttl_ms,
            drop_counter: 0,
            accepted_since_prune: 0,
        }
    }

    pub fn with_store(
        ttl_ms: u64,
        mut replay_store: Box<dyn ReplayStore>,
        now_ms: u64,
    ) -> Result<Self, ReplayStoreError> {
        replay_store.prune_expired(now_ms)?;
        let seen_nonces = replay_store
            .load_unexpired(now_ms)?
            .into_iter()
            .map(|stored| (stored.nonce, stored.expiry_at))
            .collect();
        Ok(Self {
            seen_nonces,
            replay_store,
            ttl_ms,
            drop_counter: 0,
            accepted_since_prune: 0,
        })
    }

    fn prune_seen(&mut self, now_ms: u64) {
        self.seen_nonces.retain(|_, expiry_at| *expiry_at >= now_ms);
    }

    fn replay_store_drop(&mut self, record: &ApprovalRecord) -> ApprovalDropWarning {
        ApprovalDropWarning::new(
            &mut self.drop_counter,
            "a3",
            "replay_store_error",
            record_redaction_material(record),
        )
    }

    fn replayed_nonce_drop(&mut self, record: &ApprovalRecord) -> ApprovalDropWarning {
        ApprovalDropWarning::new(
            &mut self.drop_counter,
            "a3",
            "replayed_nonce",
            record_redaction_material(record),
        )
    }

    fn note_accept_and_maybe_prune_store(&mut self, now_ms: u64) -> Result<(), ReplayStoreError> {
        self.accepted_since_prune += 1;
        if self.accepted_since_prune >= PRUNE_INTERVAL_ACCEPTS {
            self.replay_store.prune_expired(now_ms)?;
            self.prune_seen(now_ms);
            self.accepted_since_prune = 0;
        }
        Ok(())
    }

    fn persist_nonce(
        &mut self,
        record: &ApprovalRecord,
        nonce: &str,
        now_ms: u64,
    ) -> Result<bool, ReplayStoreError> {
        self.prune_seen(now_ms);
        if self.seen_nonces.contains_key(nonce) {
            return Ok(false);
        }

        let issued_at = record.issued_at.unwrap_or(now_ms);
        let expiry_at = issued_at.saturating_add(self.ttl_ms);
        match self
            .replay_store
            .insert_returning_is_new(nonce, issued_at, expiry_at)?
        {
            true => {
                self.seen_nonces.insert(nonce.to_string(), expiry_at);
                self.note_accept_and_maybe_prune_store(now_ms)?;
                Ok(true)
            }
            false => {
                // A stale row may still be present between periodic prunes.
                // Prune once and retry so expired rows do not block a fresh
                // token; if the row remains, it is an active replay.
                self.replay_store.prune_expired(now_ms)?;
                self.prune_seen(now_ms);
                if self.seen_nonces.contains_key(nonce) {
                    return Ok(false);
                }
                let inserted = self
                    .replay_store
                    .insert_returning_is_new(nonce, issued_at, expiry_at)?;
                if inserted {
                    self.seen_nonces.insert(nonce.to_string(), expiry_at);
                    self.note_accept_and_maybe_prune_store(now_ms)?;
                }
                Ok(inserted)
            }
        }
    }

    /// Filter records fail-closed; returns survivors and a reason per drop
    /// (for the audit log).
    pub fn filter(
        &mut self,
        records: Vec<ApprovalRecord>,
        now_ms: u64,
    ) -> (Vec<ApprovalRecord>, Vec<ApprovalDropWarning>) {
        let mut ok = Vec::new();
        let mut dropped = Vec::new();
        for r in records {
            if let Some(v2) = r.v2() {
                if now_ms > v2.expiry {
                    dropped.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        "a3",
                        "expired",
                        record_redaction_material(&r),
                    ));
                    continue;
                }
            }
            if let Some(issued) = r.issued_at {
                if issued > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
                    dropped.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        "a3",
                        "future_issued_at",
                        record_redaction_material(&r),
                    ));
                    continue;
                }
                if now_ms.saturating_sub(issued) > self.ttl_ms {
                    dropped.push(ApprovalDropWarning::new(
                        &mut self.drop_counter,
                        "a3",
                        "expired",
                        record_redaction_material(&r),
                    ));
                    continue;
                }
            }
            if let Some(nonce) = &r.nonce {
                match self.persist_nonce(&r, nonce, now_ms) {
                    Ok(true) => {}
                    Ok(false) => {
                        dropped.push(self.replayed_nonce_drop(&r));
                        continue;
                    }
                    Err(_) => {
                        dropped.push(self.replay_store_drop(&r));
                        continue;
                    }
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
    use crate::replay_store::{SqliteReplayStore, StoredNonce};
    use std::cell::RefCell;
    use std::rc::Rc;

    fn rec(target: &str, issued: Option<u64>, nonce: Option<&str>) -> ApprovalRecord {
        ApprovalRecord::legacy(target.to_string(), issued, nonce.map(String::from))
    }

    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "seal-a3-{tag}-{}-{}.sqlite",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn remove_sqlite_files(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
        let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    }

    #[test]
    fn replayed_nonce_rejected() {
        let mut a3 = A3Filter::new(120_000);
        let (ok, dropped) = a3.filter(
            vec![
                rec(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    Some(1000),
                    Some("n1"),
                ),
                rec(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    Some(1000),
                    Some("n1"),
                ),
            ],
            2000,
        );
        assert_eq!(ok.len(), 1);
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, "replayed_nonce");
        // Replay in a later poll also rejected.
        let (ok2, dropped2) = a3.filter(
            vec![rec(
                "0000000000000000000000000000000000000000000000000000000000000001",
                Some(1500),
                Some("n1"),
            )],
            2500,
        );
        assert!(ok2.is_empty());
        assert_eq!(dropped2.len(), 1);
        assert_eq!(dropped2[0].reason, "replayed_nonce");
    }

    #[test]
    fn expired_and_future_rejected() {
        let mut a3 = A3Filter::new(1_000);
        let (ok, dropped) = a3.filter(
            vec![
                rec(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                    Some(0),
                    Some("old"),
                ), // 10s old, ttl 1s
                rec(
                    "0000000000000000000000000000000000000000000000000000000000000002",
                    Some(100_000),
                    Some("fut"),
                ), // far future
                rec(
                    "0000000000000000000000000000000000000000000000000000000000000003",
                    Some(9_800),
                    Some("fresh"),
                ), // 200ms old
            ],
            10_000,
        );
        assert_eq!(ok.len(), 1);
        assert_eq!(
            ok[0].target,
            "0000000000000000000000000000000000000000000000000000000000000003"
        );
        assert_eq!(dropped.len(), 2);
        assert_eq!(dropped[0].reason, "expired");
        assert_eq!(dropped[1].reason, "future_issued_at");
    }

    #[test]
    fn nonceless_records_pass_freshness_only() {
        let mut a3 = A3Filter::new(1_000);
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        let (ok, _) = a3.filter(
            vec![rec(target, None, None), rec(target, None, None)],
            10_000,
        );
        assert_eq!(
            ok.len(),
            2,
            "control-file records rely on seen-counter + one-shot"
        );
    }

    #[test]
    fn sqlite_replay_survives_restart() {
        let path = temp_db_path("restart");
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        {
            let store = Box::new(SqliteReplayStore::open(&path).unwrap());
            let mut a3 = A3Filter::with_store(10_000, store, 1_000).unwrap();
            let (ok, dropped) = a3.filter(vec![rec(target, Some(1_000), Some("nonce-1"))], 1_000);
            assert_eq!(ok.len(), 1);
            assert!(dropped.is_empty());
        }
        {
            let store = Box::new(SqliteReplayStore::open(&path).unwrap());
            let mut a3 = A3Filter::with_store(10_000, store, 2_000).unwrap();
            let (ok, dropped) = a3.filter(vec![rec(target, Some(2_000), Some("nonce-1"))], 2_000);
            assert!(ok.is_empty());
            assert_eq!(dropped.len(), 1);
            assert_eq!(dropped[0].reason, "replayed_nonce");
        }
        remove_sqlite_files(&path);
    }

    #[test]
    fn expired_sqlite_nonce_not_loaded_or_blocking_after_restart() {
        let path = temp_db_path("expired");
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        {
            let mut store = SqliteReplayStore::open(&path).unwrap();
            assert!(store
                .insert_returning_is_new("nonce-1", 1_000, 2_000)
                .unwrap());
        }
        {
            let store = Box::new(SqliteReplayStore::open(&path).unwrap());
            let mut a3 = A3Filter::with_store(1_000, store, 3_000).unwrap();
            let (ok, dropped) = a3.filter(vec![rec(target, Some(3_000), Some("nonce-1"))], 3_000);
            assert_eq!(ok.len(), 1);
            assert!(dropped.is_empty());
        }
        remove_sqlite_files(&path);
    }

    #[derive(Default)]
    struct FailingStore;

    impl ReplayStore for FailingStore {
        fn insert_returning_is_new(
            &mut self,
            _nonce: &str,
            _issued_at: u64,
            _expiry_at: u64,
        ) -> Result<bool, ReplayStoreError> {
            Err(ReplayStoreError::new("injected failure"))
        }

        fn load_unexpired(&mut self, _now_ms: u64) -> Result<Vec<StoredNonce>, ReplayStoreError> {
            Ok(Vec::new())
        }

        fn prune_expired(&mut self, _now_ms: u64) -> Result<(), ReplayStoreError> {
            Ok(())
        }
    }

    #[test]
    fn store_write_failure_drops_fail_closed() {
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        let mut a3 = A3Filter::with_store(10_000, Box::new(FailingStore), 1_000).unwrap();
        let (ok, dropped) = a3.filter(vec![rec(target, Some(1_000), Some("nonce-1"))], 1_000);
        assert!(ok.is_empty());
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, "replay_store_error");
    }

    #[derive(Default)]
    struct SharedStore {
        inner: Rc<RefCell<SharedStoreInner>>,
    }

    #[derive(Default)]
    struct SharedStoreInner {
        entries: std::collections::HashMap<String, (u64, u64)>,
        prune_calls: usize,
    }

    impl ReplayStore for SharedStore {
        fn insert_returning_is_new(
            &mut self,
            nonce: &str,
            issued_at: u64,
            expiry_at: u64,
        ) -> Result<bool, ReplayStoreError> {
            let mut inner = self.inner.borrow_mut();
            if inner.entries.contains_key(nonce) {
                return Ok(false);
            }
            inner
                .entries
                .insert(nonce.to_string(), (issued_at, expiry_at));
            Ok(true)
        }

        fn load_unexpired(&mut self, now_ms: u64) -> Result<Vec<StoredNonce>, ReplayStoreError> {
            Ok(self
                .inner
                .borrow()
                .entries
                .iter()
                .filter(|(_, (_, expiry_at))| *expiry_at >= now_ms)
                .map(|(nonce, (_, expiry_at))| StoredNonce {
                    nonce: nonce.clone(),
                    expiry_at: *expiry_at,
                })
                .collect())
        }

        fn prune_expired(&mut self, now_ms: u64) -> Result<(), ReplayStoreError> {
            let mut inner = self.inner.borrow_mut();
            inner.prune_calls += 1;
            inner
                .entries
                .retain(|_, (_, expiry_at)| *expiry_at >= now_ms);
            Ok(())
        }
    }

    #[test]
    fn opportunistic_prune_runs_in_long_lived_filter() {
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        let shared = Rc::new(RefCell::new(SharedStoreInner::default()));
        let store = SharedStore {
            inner: shared.clone(),
        };
        let mut a3 = A3Filter::with_store(10_000, Box::new(store), 1_000).unwrap();
        shared
            .borrow_mut()
            .entries
            .insert("expired".to_string(), (0, 1));

        for i in 0..PRUNE_INTERVAL_ACCEPTS {
            let nonce = format!("nonce-{i}");
            let (ok, dropped) = a3.filter(vec![rec(target, Some(1_000), Some(&nonce))], 1_000);
            assert_eq!(ok.len(), 1);
            assert!(dropped.is_empty());
        }

        let inner = shared.borrow();
        assert!(
            inner.prune_calls >= 2,
            "startup plus opportunistic prune must run"
        );
        assert!(!inner.entries.contains_key("expired"));
    }
}
