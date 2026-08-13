// SPDX-License-Identifier: Apache-2.0
//! Durable replay store for signed-token nonces — two-phase burn.
//!
//! Phase 1 (`reserve_returning_is_new`): before an approval record flows to
//! Lean its nonce is durably HELD. A hold blocks any second presentation of
//! the same nonce exactly as a burn does, but it is not yet a burn.
//!
//! Phase 2 (`commit_reservation`): when the authorization decision is
//! RECORDED (the durable receipt exists), the hold is flipped to a committed
//! burn. Only a committed burn survives startup recovery.
//!
//! Recovery (`reclaim_uncommitted`): on startup, holds that never reached
//! RECORDED are deleted — a crash between reserve and RECORDED must leave
//! the approval usable again, with no receipt and no burned nonce (G2 cut
//! (a), ruled by Ben 2026-08-06).
//!
//! The SQLite implementation is the production channel; the in-memory
//! implementation keeps legacy/demo/tests lightweight.

use crate::secure_fs;
use rusqlite::{params, Connection, ErrorCode, OpenFlags, OptionalExtension};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayStoreError {
    msg: String,
}

impl ReplayStoreError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }
}

impl fmt::Display for ReplayStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for ReplayStoreError {}

impl From<rusqlite::Error> for ReplayStoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::new(value.to_string())
    }
}

pub trait ReplayStore {
    /// Phase 1: durably hold the nonce. Returns `false` when any hold or
    /// committed burn for this nonce already exists.
    fn reserve_returning_is_new(
        &mut self,
        nonce: &str,
        issued_at: u64,
        expiry_at: u64,
    ) -> Result<bool, ReplayStoreError>;
    /// Phase 2: at RECORDED, flip an open hold to a committed burn. Returns
    /// `false` when no open hold exists (already committed, or never
    /// reserved) — the caller must treat that as a refusal, never as a
    /// silent re-burn.
    fn commit_reservation(
        &mut self,
        nonce: &str,
        committed_at_ms: u64,
    ) -> Result<bool, ReplayStoreError>;
    /// Startup recovery: delete every hold that never reached RECORDED and
    /// return how many were reclaimed. Committed burns are never touched.
    fn reclaim_uncommitted(&mut self) -> Result<usize, ReplayStoreError>;
    fn load_unexpired(&mut self, now_ms: u64) -> Result<Vec<StoredNonce>, ReplayStoreError>;
    fn prune_expired(&mut self, now_ms: u64) -> Result<(), ReplayStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNonce {
    pub nonce: String,
    pub expiry_at: u64,
}

/// Database-wide replay-store lineage selected by authority-signed config.
///
/// `schema_version` covers the SQLite table contract. The namespace encoding
/// version covers the byte/string encoding used to derive replay namespaces,
/// which can change without changing the SQL columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayStoreLineage {
    pub schema_version: u32,
    pub namespace_encoding_version: u32,
}

impl ReplayStoreLineage {
    /// Schema 2: two-phase burn. `nonces.committed_at` is NULL for an open
    /// reservation and set at RECORDED. Schema 1 (single-phase burn on
    /// insert) is obsolete and refused; re-initialize the store.
    pub const CURRENT: Self = Self {
        schema_version: 2,
        namespace_encoding_version: 1,
    };

    pub fn require_supported(self) -> Result<Self, ReplayStoreError> {
        if self.schema_version != Self::CURRENT.schema_version {
            return Err(ReplayStoreError::new(format!(
                "unsupported or transitional expected replay-store schema version {}; \
                 this host supports only {}",
                self.schema_version,
                Self::CURRENT.schema_version
            )));
        }
        if self.namespace_encoding_version != Self::CURRENT.namespace_encoding_version {
            return Err(ReplayStoreError::new(format!(
                "unsupported or transitional expected replay-store namespace-encoding version {}; \
                 this host supports only {}",
                self.namespace_encoding_version,
                Self::CURRENT.namespace_encoding_version
            )));
        }
        Ok(self)
    }
}

fn to_i64(label: &str, value: u64) -> Result<i64, ReplayStoreError> {
    i64::try_from(value).map_err(|_| ReplayStoreError::new(format!("{label} out of i64 range")))
}

pub struct SqliteReplayStore {
    conn: Connection,
}

impl SqliteReplayStore {
    /// Deliberately create and stamp a new replay store.
    ///
    /// This is separate from `open`: normal startup must never turn a missing
    /// or unstamped store into an implicitly adopted empty replay history.
    pub fn initialize(
        path: impl AsRef<Path>,
        expected: ReplayStoreLineage,
    ) -> Result<(), ReplayStoreError> {
        let path = path.as_ref();
        let expected = expected.require_supported()?;
        secure_fs::validate_private_parent(path, "replay database directory")
            .map_err(ReplayStoreError::new)?;
        let reserved =
            secure_fs::open_private_new(path, "replay database").map_err(ReplayStoreError::new)?;
        drop(reserved);

        let result = (|| {
            let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
            conn.pragma_update(None, "journal_mode", "WAL")?;
            conn.pragma_update(None, "synchronous", "FULL")?;
            let tx = conn.transaction()?;
            tx.execute_batch(
                "CREATE TABLE nonces (
                    nonce TEXT PRIMARY KEY,
                    issued_at INTEGER NOT NULL,
                    expiry_at INTEGER NOT NULL,
                    committed_at INTEGER
                );
                CREATE TABLE replay_store_lineage (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    schema_version INTEGER NOT NULL,
                    namespace_encoding_version INTEGER NOT NULL
                );",
            )?;
            tx.execute(
                "INSERT INTO replay_store_lineage (
                    singleton, schema_version, namespace_encoding_version
                ) VALUES (1, ?1, ?2)",
                params![
                    i64::from(expected.schema_version),
                    i64::from(expected.namespace_encoding_version)
                ],
            )?;
            tx.commit()?;
            conn.execute_batch("PRAGMA wal_checkpoint(FULL);")?;
            secure_fs::validate_private_file(path, "replay database")
                .map_err(ReplayStoreError::new)?;
            secure_fs::sync_dir(
                path.parent().unwrap_or_else(|| Path::new(".")),
                "replay database directory",
            )
            .map_err(ReplayStoreError::new)?;
            Ok(())
        })();

        if result.is_err() {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
            let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
        }
        result
    }

    /// Open an already-stamped store and fail closed unless its lineage
    /// exactly matches the authority-signed expected lineage.
    pub fn open(
        path: impl AsRef<Path>,
        expected: ReplayStoreLineage,
    ) -> Result<Self, ReplayStoreError> {
        let path = path.as_ref();
        let expected = expected.require_supported()?;
        // The file checks below (non-symlink, owner uid, mode 0600) constrain
        // the CONTENT at the signed path; they say nothing about who may
        // REPLACE it. On Unix, swapping a file is a directory-write
        // operation, so a writable parent lets anyone holding that write bit
        // `rename()` an already host-owned 0600 store — a backup, a prior
        // init, a blue/green leftover — into this path, and every nonce the
        // live store had consumed comes back. Requiring the parent to be a
        // non-symlink, host-owned, 0700 directory narrows the
        // substitution-capable set to {host euid, root}, which is already
        // inside the declared TCB. It does NOT detect substitution by those
        // two principals: see `store_substitution_is_not_detected` in
        // `tests/replay_store_substitution.rs` and residual A7 in CLAIMS.md.
        // Fail closed: an unreadable or non-conforming parent REFUSES.
        secure_fs::validate_private_parent(path, "replay database directory")
            .map_err(ReplayStoreError::new)?;
        secure_fs::validate_private_file(path, "replay database").map_err(ReplayStoreError::new)?;
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let lineage_table_exists = conn
            .query_row(
                "SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'replay_store_lineage'",
                [],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !lineage_table_exists {
            return Err(ReplayStoreError::new(
                "replay store lineage stamp is missing; refusing to adopt or initialize it",
            ));
        }
        let row_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM replay_store_lineage", [], |row| {
                row.get(0)
            })
            .map_err(|error| {
                ReplayStoreError::new(format!("replay store lineage format mismatch: {error}"))
            })?;
        if row_count != 1 {
            return Err(ReplayStoreError::new(format!(
                "replay store lineage format mismatch: expected exactly one row, found {row_count}"
            )));
        }
        let actual = conn
            .query_row(
                "SELECT schema_version, namespace_encoding_version
                 FROM replay_store_lineage WHERE singleton = 1",
                [],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .map_err(|error| {
                ReplayStoreError::new(format!("replay store lineage format mismatch: {error}"))
            })?;
        if actual.0 != i64::from(expected.schema_version) {
            return Err(ReplayStoreError::new(format!(
                "replay store schema version mismatch: expected {}, found {}",
                expected.schema_version, actual.0
            )));
        }
        if actual.1 != i64::from(expected.namespace_encoding_version) {
            return Err(ReplayStoreError::new(format!(
                "replay store namespace-encoding version mismatch: expected {}, found {}",
                expected.namespace_encoding_version, actual.1
            )));
        }
        secure_fs::validate_private_file(path, "replay database").map_err(ReplayStoreError::new)?;
        Ok(Self { conn })
    }

    /// Reconcile the durable receipt side of the two-phase burn before A3
    /// rebuilds its in-memory replay view. A receipt names a hold by exact
    /// nonce equality. Receipt-backed open holds are committed; every other
    /// open hold is reclaimed. Missing or malformed hold state refuses startup.
    pub fn reconcile_recorded(
        &mut self,
        recorded_nonces: &HashSet<String>,
        committed_at_ms: u64,
    ) -> Result<usize, ReplayStoreError> {
        let committed_at_ms = to_i64("committed_at", committed_at_ms)?;
        let tx = self.conn.transaction()?;
        let mut stmt = tx
            .prepare(
                "SELECT nonce, issued_at FROM nonces WHERE committed_at IS NULL ORDER BY nonce",
            )
            .map_err(|error| {
                ReplayStoreError::new(format!(
                    "replay recovery refused: hold table unreadable: {error}"
                ))
            })?;
        let holds = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Option<i64>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                ReplayStoreError::new(format!(
                    "replay recovery refused: hold table unreadable: {error}"
                ))
            })?;
        drop(stmt);
        let mut reclaimed = 0;
        for (nonce, issued_at) in holds {
            let Some(issued_at) = issued_at else {
                return Err(ReplayStoreError::new(format!(
                    "replay recovery refused: hold {nonce} has no issued_at timestamp"
                )));
            };
            if issued_at < 0 {
                return Err(ReplayStoreError::new(format!(
                    "replay recovery refused: hold {nonce} has invalid issued_at timestamp"
                )));
            }
            if recorded_nonces.contains(&nonce) {
                tx.execute(
                    "UPDATE nonces SET committed_at = ?2
                     WHERE nonce = ?1 AND committed_at IS NULL",
                    params![nonce, committed_at_ms],
                )?;
            } else {
                tx.execute(
                    "DELETE FROM nonces WHERE nonce = ?1 AND committed_at IS NULL",
                    params![nonce],
                )?;
                reclaimed += 1;
            }
        }
        for nonce in recorded_nonces {
            let present = tx
                .query_row(
                    "SELECT 1 FROM nonces WHERE nonce = ?1 LIMIT 1",
                    params![nonce],
                    |_| Ok(()),
                )
                .optional()?;
            if present.is_none() {
                return Err(ReplayStoreError::new(format!(
                    "replay recovery refused: RECORDED receipt names missing approval hold {nonce}"
                )));
            }
        }
        tx.commit()?;
        Ok(reclaimed)
    }
}

impl SqliteReplayStore {
    /// Test-only READ-ONLY committed-state probe: `None` = absent,
    /// `Some(false)` = open hold, `Some(true)` = committed burn.
    #[cfg(test)]
    pub fn nonce_state(&self, nonce: &str) -> Option<bool> {
        self.conn
            .query_row(
                "SELECT committed_at IS NOT NULL FROM nonces WHERE nonce = ?1",
                params![nonce],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .unwrap()
    }

    /// Test-only READ-ONLY presence probe. Not part of the production trait
    /// (nothing in the live path asks "is this nonce present" without
    /// committing); tests must observe the store without mutating it.
    #[cfg(test)]
    fn contains_nonce(&self, nonce: &str) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM nonces WHERE nonce = ?1 LIMIT 1",
                params![nonce],
                |_| Ok(()),
            )
            .optional()
            .unwrap()
            .is_some()
    }
}

impl ReplayStore for SqliteReplayStore {
    fn reserve_returning_is_new(
        &mut self,
        nonce: &str,
        issued_at: u64,
        expiry_at: u64,
    ) -> Result<bool, ReplayStoreError> {
        let issued_at = to_i64("issued_at", issued_at)?;
        let expiry_at = to_i64("expiry_at", expiry_at)?;
        let tx = self.conn.transaction()?;
        let inserted = match tx.execute(
            "INSERT INTO nonces (nonce, issued_at, expiry_at, committed_at)
             VALUES (?1, ?2, ?3, NULL)",
            params![nonce, issued_at, expiry_at],
        ) {
            Ok(1) => true,
            Ok(_) => false,
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == ErrorCode::ConstraintViolation =>
            {
                false
            }
            Err(e) => return Err(e.into()),
        };
        tx.commit()?;
        Ok(inserted)
    }

    fn commit_reservation(
        &mut self,
        nonce: &str,
        committed_at_ms: u64,
    ) -> Result<bool, ReplayStoreError> {
        let committed_at_ms = to_i64("committed_at", committed_at_ms)?;
        let tx = self.conn.transaction()?;
        let flipped = tx.execute(
            "UPDATE nonces SET committed_at = ?2
             WHERE nonce = ?1 AND committed_at IS NULL",
            params![nonce, committed_at_ms],
        )?;
        tx.commit()?;
        Ok(flipped == 1)
    }

    fn reclaim_uncommitted(&mut self) -> Result<usize, ReplayStoreError> {
        let tx = self.conn.transaction()?;
        let reclaimed = tx.execute("DELETE FROM nonces WHERE committed_at IS NULL", [])?;
        tx.commit()?;
        Ok(reclaimed)
    }

    fn load_unexpired(&mut self, now_ms: u64) -> Result<Vec<StoredNonce>, ReplayStoreError> {
        let now_ms = to_i64("now_ms", now_ms)?;
        let mut stmt = self
            .conn
            .prepare("SELECT nonce, expiry_at FROM nonces WHERE expiry_at >= ?1 ORDER BY nonce")?;
        let rows = stmt.query_map(params![now_ms], |row| {
            let expiry_at = row.get::<_, i64>(1)?;
            let expiry_at = u64::try_from(expiry_at)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(1, expiry_at))?;
            Ok(StoredNonce {
                nonce: row.get::<_, String>(0)?,
                expiry_at,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn prune_expired(&mut self, now_ms: u64) -> Result<(), ReplayStoreError> {
        let now_ms = to_i64("now_ms", now_ms)?;
        self.conn
            .execute("DELETE FROM nonces WHERE expiry_at < ?1", params![now_ms])?;
        Ok(())
    }
}

#[derive(Default)]
pub struct InMemoryReplayStore {
    /// nonce -> (issued_at, expiry_at, committed_at). `None` = open hold.
    entries: HashMap<String, (u64, u64, Option<u64>)>,
}

impl InMemoryReplayStore {
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Test-only READ-ONLY presence probe; see SqliteReplayStore::contains_nonce.
    #[cfg(test)]
    fn contains_nonce(&self, nonce: &str) -> bool {
        self.entries.contains_key(nonce)
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn reserve_returning_is_new(
        &mut self,
        nonce: &str,
        issued_at: u64,
        expiry_at: u64,
    ) -> Result<bool, ReplayStoreError> {
        if self.entries.contains_key(nonce) {
            return Ok(false);
        }
        self.entries
            .insert(nonce.to_string(), (issued_at, expiry_at, None));
        Ok(true)
    }

    fn commit_reservation(
        &mut self,
        nonce: &str,
        committed_at_ms: u64,
    ) -> Result<bool, ReplayStoreError> {
        match self.entries.get_mut(nonce) {
            Some((_, _, committed_at @ None)) => {
                *committed_at = Some(committed_at_ms);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn reclaim_uncommitted(&mut self) -> Result<usize, ReplayStoreError> {
        let before = self.entries.len();
        self.entries
            .retain(|_, (_, _, committed_at)| committed_at.is_some());
        Ok(before - self.entries.len())
    }

    fn load_unexpired(&mut self, now_ms: u64) -> Result<Vec<StoredNonce>, ReplayStoreError> {
        Ok(self
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
        self.entries
            .retain(|_, (_, expiry_at, _)| *expiry_at >= now_ms);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store path under a CONFORMING parent: a fresh 0700 host-owned
    /// directory. `SqliteReplayStore::open` requires this — the shared temp
    /// directory itself is 1777 and is refused, which is the point of the
    /// parent guard.
    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "seal-replay-{tag}-{}-{}",
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

    fn initialize(path: &std::path::Path) {
        SqliteReplayStore::initialize(path, ReplayStoreLineage::CURRENT).unwrap();
    }

    #[test]
    fn sqlite_reopens_committed_nonce() {
        let path = temp_db_path("reopen");
        initialize(&path);
        {
            let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
            assert!(store
                .reserve_returning_is_new("nonce-1", 1_000, 10_000)
                .unwrap());
            assert!(!store
                .reserve_returning_is_new("nonce-1", 1_000, 10_000)
                .unwrap());
            assert!(store.commit_reservation("nonce-1", 1_500).unwrap());
        }
        {
            let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
            assert_eq!(store.nonce_state("nonce-1"), Some(true));
            assert_eq!(
                store.load_unexpired(2_000).unwrap(),
                vec![StoredNonce {
                    nonce: "nonce-1".to_string(),
                    expiry_at: 10_000
                }]
            );
        }
        remove_sqlite_files(&path);
    }

    #[test]
    fn sqlite_commit_flips_only_an_open_hold() {
        let path = temp_db_path("commit");
        initialize(&path);
        let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
        assert!(
            !store.commit_reservation("never-reserved", 1_000).unwrap(),
            "committing without a reservation must refuse"
        );
        assert!(store
            .reserve_returning_is_new("nonce-1", 1_000, 10_000)
            .unwrap());
        assert_eq!(store.nonce_state("nonce-1"), Some(false));
        assert!(store.commit_reservation("nonce-1", 1_500).unwrap());
        assert_eq!(store.nonce_state("nonce-1"), Some(true));
        assert!(
            !store.commit_reservation("nonce-1", 2_000).unwrap(),
            "a burn must not be silently re-committed"
        );
        remove_sqlite_files(&path);
    }

    #[test]
    fn sqlite_reclaim_deletes_only_uncommitted_holds() {
        let path = temp_db_path("reclaim");
        initialize(&path);
        let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
        assert!(store
            .reserve_returning_is_new("held", 1_000, 10_000)
            .unwrap());
        assert!(store
            .reserve_returning_is_new("burned", 1_000, 10_000)
            .unwrap());
        assert!(store.commit_reservation("burned", 1_500).unwrap());
        assert_eq!(store.reclaim_uncommitted().unwrap(), 1);
        assert_eq!(store.nonce_state("held"), None, "open hold reclaimed");
        assert_eq!(
            store.nonce_state("burned"),
            Some(true),
            "recovery must never un-burn a committed nonce"
        );
        remove_sqlite_files(&path);
    }

    #[test]
    fn recovery_commits_receipt_match_and_reclaims_unmatched_hold() {
        let path = temp_db_path("receipt-reconcile");
        initialize(&path);
        let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
        assert!(store
            .reserve_returning_is_new("receipt-backed", 1_000, 10_000)
            .unwrap());
        assert!(store
            .reserve_returning_is_new("crashed", 1_000, 10_000)
            .unwrap());
        let recorded = HashSet::from(["receipt-backed".to_string()]);
        assert_eq!(store.reconcile_recorded(&recorded, 1_500).unwrap(), 1);
        assert_eq!(store.nonce_state("receipt-backed"), Some(true));
        assert_eq!(store.nonce_state("crashed"), None);
        remove_sqlite_files(&path);
    }

    #[test]
    fn recovery_refuses_missing_timestamp_unreadable_table_and_missing_hold() {
        let path = temp_db_path("recovery-refusals");
        secure_fs::ensure_private_file(&path, "test replay database").unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE nonces (
                nonce TEXT PRIMARY KEY,
                issued_at INTEGER,
                expiry_at INTEGER NOT NULL,
                committed_at INTEGER
            );
            CREATE TABLE replay_store_lineage (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                schema_version INTEGER NOT NULL,
                namespace_encoding_version INTEGER NOT NULL
            );
            INSERT INTO replay_store_lineage VALUES (1, 2, 1);
            INSERT INTO nonces VALUES ('no-time', NULL, 999999, NULL);",
        )
        .unwrap();
        drop(conn);
        let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
        let error = store
            .reconcile_recorded(&HashSet::new(), 1_500)
            .unwrap_err();
        println!("missing timestamp outcome: {error}");
        assert!(error
            .to_string()
            .contains("hold no-time has no issued_at timestamp"));

        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM nonces", []).unwrap();
        conn.execute("DROP TABLE nonces", []).unwrap();
        drop(conn);
        let error = store
            .reconcile_recorded(&HashSet::new(), 1_500)
            .unwrap_err();
        println!("unreadable hold table outcome: {error}");
        assert!(error.to_string().contains("hold table unreadable"));

        remove_sqlite_files(&path);
        let path = temp_db_path("missing-receipt-hold");
        initialize(&path);
        let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
        let error = store
            .reconcile_recorded(&HashSet::from(["missing".to_string()]), 1_500)
            .unwrap_err();
        println!("missing hold outcome: {error}");
        assert!(error
            .to_string()
            .contains("RECORDED receipt names missing approval hold missing"));
        remove_sqlite_files(&path);
    }

    #[test]
    fn sqlite_prunes_expired_nonces() {
        let path = temp_db_path("prune");
        initialize(&path);
        let mut store = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT).unwrap();
        assert!(store.reserve_returning_is_new("old", 1_000, 2_000).unwrap());
        assert!(store
            .reserve_returning_is_new("fresh", 3_000, 5_000)
            .unwrap());

        assert_eq!(
            store.load_unexpired(3_000).unwrap(),
            vec![StoredNonce {
                nonce: "fresh".to_string(),
                expiry_at: 5_000
            }]
        );
        store.prune_expired(3_000).unwrap();
        assert!(!store.contains_nonce("old"));
        assert!(store.contains_nonce("fresh"));
        remove_sqlite_files(&path);
    }

    #[test]
    fn sqlite_refuses_missing_mismatched_and_unsupported_lineage() {
        let path = temp_db_path("lineage");
        secure_fs::ensure_private_file(&path, "test replay database").unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE nonces (
                nonce TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expiry_at INTEGER NOT NULL
            );
            INSERT INTO nonces VALUES ('already-consumed', 1, 999999);",
        )
        .unwrap();
        drop(conn);
        let missing = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT)
            .err()
            .expect("unstamped populated store must refuse");
        assert!(missing.to_string().contains("lineage stamp is missing"));

        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE replay_store_lineage (
                singleton INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL,
                namespace_encoding_version INTEGER NOT NULL
            );
            INSERT INTO replay_store_lineage VALUES (1, 2, 2);",
        )
        .unwrap();
        drop(conn);
        let mismatch = SqliteReplayStore::open(&path, ReplayStoreLineage::CURRENT)
            .err()
            .expect("namespace mismatch must refuse");
        assert!(mismatch
            .to_string()
            .contains("namespace-encoding version mismatch: expected 1, found 2"));

        let unsupported = ReplayStoreLineage {
            schema_version: 0,
            namespace_encoding_version: 1,
        }
        .require_supported()
        .unwrap_err();
        assert!(unsupported
            .to_string()
            .contains("unsupported or transitional expected replay-store schema version 0"));

        // Schema 1 (single-phase burn on insert) is obsolete, not grandfathered.
        let obsolete = ReplayStoreLineage {
            schema_version: 1,
            namespace_encoding_version: 1,
        }
        .require_supported()
        .unwrap_err();
        assert!(obsolete
            .to_string()
            .contains("unsupported or transitional expected replay-store schema version 1"));
        remove_sqlite_files(&path);
    }

    #[test]
    fn memory_store_two_phase_matches_sqlite_semantics() {
        let mut store = InMemoryReplayStore::default();
        assert!(store
            .reserve_returning_is_new("held", 1_000, 9_000)
            .unwrap());
        assert!(store
            .reserve_returning_is_new("burned", 1_000, 9_000)
            .unwrap());
        assert!(!store
            .reserve_returning_is_new("held", 1_000, 9_000)
            .unwrap());
        assert!(store.commit_reservation("burned", 1_500).unwrap());
        assert!(!store.commit_reservation("burned", 1_600).unwrap());
        assert!(!store.commit_reservation("missing", 1_600).unwrap());
        assert_eq!(store.reclaim_uncommitted().unwrap(), 1);
        assert!(!store.contains_nonce("held"));
        assert!(store.contains_nonce("burned"));
    }

    #[test]
    fn memory_store_prunes_expired_nonces() {
        let mut store = InMemoryReplayStore::default();
        assert!(store.reserve_returning_is_new("old", 1_000, 2_000).unwrap());
        assert!(store
            .reserve_returning_is_new("fresh", 3_000, 5_000)
            .unwrap());
        store.prune_expired(3_000).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.contains_nonce("old"));
        assert!(store.contains_nonce("fresh"));
    }
}
