// SPDX-License-Identifier: Apache-2.0
//! A3 — host-side freshness: the clock and replay state the Lean kernels
//! trust the host for. Every approval record passes through here before it
//! reaches Lean:
//!
//! * nonce replay, two-phase: `filter` durably RESERVES a nonce before its
//!   record reaches Lean (a hold blocks any second presentation exactly as a
//!   burn would); the host durably COMMITS the burn via `commit_nonce` only
//!   at RECORDED, once the authorization-decision receipt exists. Startup
//!   (`with_store`) reclaims holds that never reached RECORDED, so a crash
//!   between reserve and RECORDED leaves the approval usable again;
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
        // Startup recovery, before any state is read: a hold that never
        // reached RECORDED belongs to a dead process. Reclaiming it makes
        // the crash indistinguishable from the approval never having been
        // presented. Committed burns are untouched (T3 direction).
        replay_store.reclaim_uncommitted()?;
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

    fn reserve_nonce(
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
            .reserve_returning_is_new(nonce, issued_at, expiry_at)?
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
                let reserved = self
                    .replay_store
                    .reserve_returning_is_new(nonce, issued_at, expiry_at)?;
                if reserved {
                    self.seen_nonces.insert(nonce.to_string(), expiry_at);
                    self.note_accept_and_maybe_prune_store(now_ms)?;
                }
                Ok(reserved)
            }
        }
    }

    /// Phase 2 of the two-phase burn: durably commit a reserved nonce, called
    /// by the host at RECORDED — after the authorization-decision receipt is
    /// durable and before any byte reaches the child. Fails closed when the
    /// store cannot prove it flipped an open reservation; the caller must
    /// then refuse the forward.
    pub fn commit_nonce(&mut self, nonce: &str, now_ms: u64) -> Result<(), ReplayStoreError> {
        if self.replay_store.commit_reservation(nonce, now_ms)? {
            Ok(())
        } else {
            Err(ReplayStoreError::new(
                "no open reservation to commit for approval nonce",
            ))
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
                match self.reserve_nonce(&r, nonce, now_ms) {
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
    use crate::replay_store::{ReplayStoreLineage, SqliteReplayStore, StoredNonce};
    use std::cell::RefCell;
    use std::rc::Rc;

    fn rec(target: &str, issued: Option<u64>, nonce: Option<&str>) -> ApprovalRecord {
        ApprovalRecord::legacy(target.to_string(), issued, nonce.map(String::from))
    }

    /// A store path under a CONFORMING parent: a fresh 0700 host-owned
    /// directory, as `SqliteReplayStore::open`'s parent guard requires. The
    /// shared temp directory itself is 1777 and is refused.
    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "seal-a3-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir.join("replay.sqlite")
    }

    fn remove_sqlite_files(path: &std::path::Path) {
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
    }

    fn initialize_store(path: &std::path::Path) {
        SqliteReplayStore::initialize(path, ReplayStoreLineage::CURRENT).unwrap();
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

    /// T3 direction (unit shape): a nonce committed at RECORDED stays burned
    /// across restart — recovery must never un-burn it.
    #[test]
    fn committed_nonce_survives_restart() {
        let path = temp_db_path("restart");
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        initialize_store(&path);
        {
            let store =
                Box::new(SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap());
            let mut a3 = A3Filter::with_store(10_000, store, 1_000).unwrap();
            let (ok, dropped) = a3.filter(vec![rec(target, Some(1_000), Some("nonce-1"))], 1_000);
            assert_eq!(ok.len(), 1);
            assert!(dropped.is_empty());
            a3.commit_nonce("nonce-1", 1_100).unwrap();
        }
        {
            let store =
                Box::new(SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap());
            let mut a3 = A3Filter::with_store(10_000, store, 2_000).unwrap();
            let (ok, dropped) = a3.filter(vec![rec(target, Some(2_000), Some("nonce-1"))], 2_000);
            assert!(ok.is_empty());
            assert_eq!(dropped.len(), 1);
            assert_eq!(dropped[0].reason, "replayed_nonce");
        }
        remove_sqlite_files(&path);
    }

    /// T1 direction (unit shape): a reservation that never reached RECORDED
    /// is reclaimed on startup, and the same nonce is usable again.
    #[test]
    fn uncommitted_reservation_reclaimed_on_restart() {
        let path = temp_db_path("reclaim");
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        initialize_store(&path);
        {
            let store =
                Box::new(SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap());
            let mut a3 = A3Filter::with_store(10_000, store, 1_000).unwrap();
            let (ok, dropped) = a3.filter(vec![rec(target, Some(1_000), Some("nonce-1"))], 1_000);
            assert_eq!(ok.len(), 1);
            assert!(dropped.is_empty());
            // No commit_nonce: the process "crashes" before RECORDED.
        }
        {
            let store =
                Box::new(SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap());
            let mut a3 = A3Filter::with_store(10_000, store, 2_000).unwrap();
            let (ok, dropped) = a3.filter(vec![rec(target, Some(2_000), Some("nonce-1"))], 2_000);
            assert_eq!(
                ok.len(),
                1,
                "an unrecorded hold must be reclaimed: the approval was never used"
            );
            assert!(dropped.is_empty());
        }
        remove_sqlite_files(&path);
    }

    /// T2 (unit shape): while a reservation is OPEN — no commit has happened
    /// and never does in this test — a second presentation of the same nonce
    /// fails. The block comes from the hold itself, not from the burn.
    #[test]
    fn second_presentation_fails_while_reservation_open() {
        let path = temp_db_path("open-hold");
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        initialize_store(&path);
        let store = Box::new(SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap());
        let mut a3 = A3Filter::with_store(10_000, store, 1_000).unwrap();
        let (ok, dropped) = a3.filter(vec![rec(target, Some(1_000), Some("nonce-1"))], 1_000);
        assert_eq!(ok.len(), 1);
        assert!(dropped.is_empty());
        let (ok2, dropped2) = a3.filter(vec![rec(target, Some(1_200), Some("nonce-1"))], 1_200);
        assert!(ok2.is_empty(), "open hold must block a second presentation");
        assert_eq!(dropped2.len(), 1);
        assert_eq!(dropped2[0].reason, "replayed_nonce");
        remove_sqlite_files(&path);
    }

    #[test]
    fn commit_without_reservation_refuses() {
        let path = temp_db_path("no-hold");
        initialize_store(&path);
        let store = Box::new(SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap());
        let mut a3 = A3Filter::with_store(10_000, store, 1_000).unwrap();
        let error = a3.commit_nonce("never-reserved", 1_000).unwrap_err();
        assert!(error.to_string().contains("no open reservation"));
        remove_sqlite_files(&path);
    }

    #[test]
    fn expired_sqlite_nonce_not_loaded_or_blocking_after_restart() {
        let path = temp_db_path("expired");
        let target = "0000000000000000000000000000000000000000000000000000000000000001";
        initialize_store(&path);
        {
            let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
            // Committed (not merely held), so startup recovery does not
            // delete it: what unblocks the nonce below is EXPIRY alone.
            assert!(store
                .reserve_returning_is_new("nonce-1", 1_000, 2_000)
                .unwrap());
            assert!(store.commit_reservation("nonce-1", 1_100).unwrap());
        }
        {
            let store =
                Box::new(SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap());
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
        fn reserve_returning_is_new(
            &mut self,
            _nonce: &str,
            _issued_at: u64,
            _expiry_at: u64,
        ) -> Result<bool, ReplayStoreError> {
            Err(ReplayStoreError::new("injected failure"))
        }

        fn commit_reservation(
            &mut self,
            _nonce: &str,
            _committed_at_ms: u64,
        ) -> Result<bool, ReplayStoreError> {
            Err(ReplayStoreError::new("injected failure"))
        }

        fn reclaim_uncommitted(&mut self) -> Result<usize, ReplayStoreError> {
            Ok(0)
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
        entries: std::collections::HashMap<String, (u64, u64, bool)>,
        prune_calls: usize,
    }

    impl ReplayStore for SharedStore {
        fn reserve_returning_is_new(
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
                .insert(nonce.to_string(), (issued_at, expiry_at, false));
            Ok(true)
        }

        fn commit_reservation(
            &mut self,
            nonce: &str,
            _committed_at_ms: u64,
        ) -> Result<bool, ReplayStoreError> {
            let mut inner = self.inner.borrow_mut();
            match inner.entries.get_mut(nonce) {
                Some((_, _, committed @ false)) => {
                    *committed = true;
                    Ok(true)
                }
                _ => Ok(false),
            }
        }

        fn reclaim_uncommitted(&mut self) -> Result<usize, ReplayStoreError> {
            let mut inner = self.inner.borrow_mut();
            let before = inner.entries.len();
            inner.entries.retain(|_, (_, _, committed)| *committed);
            Ok(before - inner.entries.len())
        }

        fn load_unexpired(&mut self, now_ms: u64) -> Result<Vec<StoredNonce>, ReplayStoreError> {
            Ok(self
                .inner
                .borrow()
                .entries
                .iter()
                .filter(|(_, (_, expiry_at, _))| *expiry_at >= now_ms)
                .map(|(nonce, (_, expiry_at, _))| StoredNonce {
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
                .retain(|_, (_, expiry_at, _)| *expiry_at >= now_ms);
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
            .insert("expired".to_string(), (0, 1, true));

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
