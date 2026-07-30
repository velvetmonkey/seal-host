// SPDX-License-Identifier: Apache-2.0
//! Replay-store INSTANCE integrity: what the parent guard buys, and the
//! residual it deliberately leaves open (`CLAIMS.md` residual A7).
//!
//! `SqliteReplayStore::open` validates the file at the signed path —
//! non-symlink, owner uid, mode 0600 (`rust/src/secure_fs.rs:14-69`). Those
//! checks constrain the file's CONTENT, not who may REPLACE it. On Unix,
//! replacing a file is a directory-write operation, so the guard that
//! matters for substitution is on the PARENT.
//!
//! Two facts, one per test:
//!
//!   * a non-conforming parent is REFUSED, so the set of principals that can
//!     rename a stale but host-owned 0600 store into the signed path is
//!     narrowed to {host euid, root} — both already inside the declared TCB;
//!   * a substitution performed BY one of those two principals is NOT
//!     detected. `store_substitution_is_not_detected` asserts the acceptance.

use seal_host_rs::a3::A3Filter;
use seal_host_rs::providers::ApprovalRecord;
use seal_host_rs::replay_store::SqliteReplayStore;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const TARGET: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const TTL_MS: u64 = 10_000;

/// A fresh 0700 host-owned scratch root. Every directory this test creates
/// under it is explicitly moded, so a case that needs a NON-conforming
/// parent says so in one place and nothing is inherited by accident.
fn scratch_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "seal-replay-subst-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn dir_with_mode(root: &Path, name: &str, mode: u32) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
    dir
}

fn record(nonce: &str, issued_at: u64) -> ApprovalRecord {
    ApprovalRecord::legacy(TARGET.to_string(), Some(issued_at), Some(nonce.to_string()))
}

/// The substitution itself: `rename()` `from` over `to`, exactly the move an
/// attacker with the parent's write bit makes. The sidecar WAL/SHM files are
/// cleared first because a real swap moves the whole store, and a stale WAL
/// belonging to the DISPLACED database must not be replayed onto the one
/// moved in.
fn substitute(from: &Path, to: &Path) {
    for sidecar in ["-wal", "-shm"] {
        let mut name = to.as_os_str().to_os_string();
        name.push(sidecar);
        let _ = std::fs::remove_file(PathBuf::from(name));
    }
    std::fs::rename(from, to).unwrap();
}

/// Consume `nonce` in the store at `path`, then close it. Returns nothing:
/// the observable effect is durable state in the store.
fn consume(path: &Path, nonce: &str, now_ms: u64) {
    let store = Box::new(SqliteReplayStore::open(path).unwrap());
    let mut a3 = A3Filter::with_store(TTL_MS, store, now_ms).unwrap();
    let (ok, dropped) = a3.filter(vec![record(nonce, now_ms)], now_ms);
    assert_eq!(ok.len(), 1, "first use of {nonce} must be accepted");
    assert!(dropped.is_empty());
}

/// ITEM 1 — the guard. A stale-but-host-owned 0600 store renamed into the
/// signed path under a world-traversable, group/other-writable parent is
/// REFUSED, and the refusal names the parent, not the file.
#[test]
fn substitution_capable_parent_is_refused() {
    let root = scratch_root("refused");
    // Where the attacker's store is MADE: conforming, because a store the
    // host itself once created is the realistic source (a backup, a prior
    // init, a blue/green leftover). The attacker forges nothing.
    let staging = dir_with_mode(&root, "staging", 0o700);
    let stale = staging.join("replay.sqlite");
    consume(&stale, "nonce-1", 1_000);

    // The victim path's parent is 0755: any uid can traverse it and the
    // owning uid's group/other write bit is what a misdeployed host leaves
    // behind. 0755 is not writable by other, but it is not 0700 either, and
    // the guard is a whitelist: only 0700 passes.
    let victim_dir = dir_with_mode(&root, "store", 0o755);
    let victim = victim_dir.join("replay.sqlite");
    substitute(&stale, &victim);

    // The substituted file itself passes every EXISTING check: it is a
    // regular non-symlink file, owned by the host euid, mode 0600. Without
    // the parent guard this opens cleanly.
    let metadata = std::fs::symlink_metadata(&victim).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let error = SqliteReplayStore::open(&victim)
        .err()
        .expect("open must refuse a store whose parent is not 0700")
        .to_string();
    assert!(
        error.contains("replay database directory") && error.contains("required 0700"),
        "refusal must name the PARENT directory, got: {error}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

/// ITEM 2 — the REMAINING limitation, in executable form.
///
/// THIS TEST ASSERTS THAT A REPLAY SUCCEEDS. That is deliberate and it is
/// not a bug to fix in place. The parent guard above narrows the set of
/// principals who can substitute the store to {host euid, root}; it does not
/// and cannot DETECT a substitution performed by one of them, because a
/// store the host itself wrote is indistinguishable from the store the host
/// expects. No field of the authority-signed payload binds a store
/// instance, so there is nothing to compare against.
///
/// This limitation is stated as residual A7 in `CLAIMS.md`. If a future
/// change makes the host detect instance substitution, this test MUST be
/// edited and A7 MUST be retired in the same commit — that coupling is the
/// whole point of asserting the acceptance rather than writing a comment.
/// Do not "fix" this test on its own; a green replay here with A7 still on
/// the books is the honest state, and a red test here with A7 unedited
/// means the claim surface and the code have drifted apart.
#[test]
fn store_substitution_is_not_detected() {
    let root = scratch_root("accepted");
    let store_dir = dir_with_mode(&root, "store", 0o700);
    let live = store_dir.join("replay.sqlite");

    // A pristine store — a prior init that never saw nonce-1. Its parent is
    // conforming too: the attacker here IS the host euid.
    let backup_dir = dir_with_mode(&root, "backup", 0o700);
    let pristine = backup_dir.join("replay.sqlite");
    drop(SqliteReplayStore::open(&pristine).unwrap());

    // Baseline: durable replay protection works across a restart.
    consume(&live, "nonce-1", 1_000);
    {
        let store = Box::new(SqliteReplayStore::open(&live).unwrap());
        let mut a3 = A3Filter::with_store(TTL_MS, store, 2_000).unwrap();
        let (ok, dropped) = a3.filter(vec![record("nonce-1", 2_000)], 2_000);
        assert!(ok.is_empty(), "replay must be blocked before substitution");
        assert_eq!(dropped.len(), 1);
        assert_eq!(dropped[0].reason, "replayed_nonce");
    }

    // The substitution, as the host euid, with a CONFORMING parent.
    substitute(&pristine, &live);

    // ACCEPTED — the analogue of the host exiting 0 and running on.
    let store = Box::new(
        SqliteReplayStore::open(&live)
            .expect("a conforming parent must still open: the guard is not over-broad"),
    );

    // And the consumed nonce comes back.
    let mut a3 = A3Filter::with_store(TTL_MS, store, 3_000).unwrap();
    let (ok, dropped) = a3.filter(vec![record("nonce-1", 3_000)], 3_000);
    assert_eq!(
        ok.len(),
        1,
        "residual A7: a substituted store re-accepts a consumed nonce"
    );
    assert!(dropped.is_empty());

    std::fs::remove_dir_all(&root).unwrap();
}
