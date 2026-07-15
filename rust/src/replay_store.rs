// SPDX-License-Identifier: Apache-2.0
//! Durable replay store for signed-token nonces.
//!
//! A nonce must be persisted before its approval record can flow to Lean.
//! The SQLite implementation is the production channel; the in-memory
//! implementation keeps legacy/demo/tests lightweight.

use rusqlite::{params, Connection, ErrorCode};
use std::collections::HashMap;
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
    fn insert_returning_is_new(
        &mut self,
        nonce: &str,
        issued_at: u64,
        expiry_at: u64,
    ) -> Result<bool, ReplayStoreError>;
    fn load_unexpired(&mut self, now_ms: u64) -> Result<Vec<StoredNonce>, ReplayStoreError>;
    fn prune_expired(&mut self, now_ms: u64) -> Result<(), ReplayStoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredNonce {
    pub nonce: String,
    pub expiry_at: u64,
}

fn to_i64(label: &str, value: u64) -> Result<i64, ReplayStoreError> {
    i64::try_from(value).map_err(|_| ReplayStoreError::new(format!("{label} out of i64 range")))
}

pub struct SqliteReplayStore {
    conn: Connection,
}

impl SqliteReplayStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayStoreError> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nonces (
                nonce TEXT PRIMARY KEY,
                issued_at INTEGER NOT NULL,
                expiry_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self { conn })
    }
}

impl SqliteReplayStore {
    /// Test-only READ-ONLY presence probe. Not part of the production trait
    /// (nothing in the live path asks "is this nonce present" without
    /// committing); tests must observe the store without mutating it.
    #[cfg(test)]
    fn contains_nonce(&self, nonce: &str) -> bool {
        use rusqlite::OptionalExtension;
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
    fn insert_returning_is_new(
        &mut self,
        nonce: &str,
        issued_at: u64,
        expiry_at: u64,
    ) -> Result<bool, ReplayStoreError> {
        let issued_at = to_i64("issued_at", issued_at)?;
        let expiry_at = to_i64("expiry_at", expiry_at)?;
        let tx = self.conn.transaction()?;
        let inserted = match tx.execute(
            "INSERT INTO nonces (nonce, issued_at, expiry_at) VALUES (?1, ?2, ?3)",
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
    entries: HashMap<String, (u64, u64)>,
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
    fn insert_returning_is_new(
        &mut self,
        nonce: &str,
        issued_at: u64,
        expiry_at: u64,
    ) -> Result<bool, ReplayStoreError> {
        if self.entries.contains_key(nonce) {
            return Ok(false);
        }
        self.entries
            .insert(nonce.to_string(), (issued_at, expiry_at));
        Ok(true)
    }

    fn load_unexpired(&mut self, now_ms: u64) -> Result<Vec<StoredNonce>, ReplayStoreError> {
        Ok(self
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
        self.entries
            .retain(|_, (_, expiry_at)| *expiry_at >= now_ms);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "seal-replay-{tag}-{}-{}.sqlite",
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
    fn sqlite_reopens_unexpired_nonce() {
        let path = temp_db_path("reopen");
        {
            let mut store = SqliteReplayStore::open(&path).unwrap();
            assert!(store
                .insert_returning_is_new("nonce-1", 1_000, 10_000)
                .unwrap());
            assert!(!store
                .insert_returning_is_new("nonce-1", 1_000, 10_000)
                .unwrap());
        }
        {
            let mut store = SqliteReplayStore::open(&path).unwrap();
            assert!(store.contains_nonce("nonce-1"));
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
    fn sqlite_prunes_expired_nonces() {
        let path = temp_db_path("prune");
        let mut store = SqliteReplayStore::open(&path).unwrap();
        assert!(store.insert_returning_is_new("old", 1_000, 2_000).unwrap());
        assert!(store
            .insert_returning_is_new("fresh", 3_000, 5_000)
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
    fn memory_store_prunes_expired_nonces() {
        let mut store = InMemoryReplayStore::default();
        assert!(store.insert_returning_is_new("old", 1_000, 2_000).unwrap());
        assert!(store
            .insert_returning_is_new("fresh", 3_000, 5_000)
            .unwrap());
        store.prune_expired(3_000).unwrap();
        assert_eq!(store.len(), 1);
        assert!(!store.contains_nonce("old"));
        assert!(store.contains_nonce("fresh"));
    }
}
