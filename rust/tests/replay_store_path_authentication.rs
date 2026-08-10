// SPDX-License-Identifier: Apache-2.0
//! Ablation backing for the A7 row's "host authenticates the store path"
//! claim (`CLAIMS.md` residual A7).
//!
//! The row asserts four path properties. Two already had tests that fail
//! when their check is removed:
//!
//!   * parent mode 0700 — `replay_store_substitution.rs::
//!     parent_mode_0755_is_refused_by_strict_0700_whitelist`;
//!   * file mode 0600 — indirectly, via `production_preflight` refusing on
//!     restart (`tests/host_path.rs`), but nothing handed `open` itself a
//!     wrong-mode file.
//!
//! The symlink refusals (file AND parent) had NO test at all: deleting the
//! symlink checks from `secure_fs::metadata_without_symlinks` and switching
//! it to link-following `fs::metadata` left the whole suite green
//! (measured 2026-07-30, lane a7pindrift). These tests close that gap and
//! put the file-mode refusal at the layer the claim names: `open`.
//!
//! Each test was watched failing against the mutation it guards:
//!
//!   * symlink tests red under "follow symlinks, drop the symlink refusal"
//!     in `secure_fs.rs`;
//!   * mode test red under "drop the `mode != 0o600` refusal" in
//!     `secure_fs::validate_private_file`.
//!
//! The fourth property — file owned by the host euid — remains untested:
//! an unprivileged test cannot create a file owned by another uid. That is
//! a documented waiver, not coverage.

use seal_host_rs::replay_store::{ReplayStoreLineage, SqliteReplayStore};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// A fresh 0700 host-owned scratch root; every directory created under it
/// is explicitly moded, mirroring `replay_store_substitution.rs`.
fn scratch_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "seal-replay-authn-{tag}-{}-{}",
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

/// A conforming store the host itself created: real file, 0600, under a
/// 0700 parent. The positive control inside every test — if THIS open
/// fails, the test is measuring the environment, not the check.
fn conforming_store(root: &Path, name: &str) -> PathBuf {
    let dir = dir_with_mode(root, name, 0o700);
    let store = dir.join("replay.sqlite");
    SqliteReplayStore::initialize(&store, ReplayStoreLineage::CURRENT).unwrap();
    drop(
        SqliteReplayStore::open(&store, ReplayStoreLineage::CURRENT)
            .expect("conforming store must open"),
    );
    store
}

/// A symlink at the signed path — pointing at a store that itself passes
/// every check — must be refused, and the refusal must name the symlink,
/// not fall through to some later error.
#[test]
fn symlinked_store_file_is_refused() {
    let root = scratch_root("file-symlink");
    let real = conforming_store(&root, "real");

    let link_dir = dir_with_mode(&root, "link", 0o700);
    let link = link_dir.join("replay.sqlite");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let error = SqliteReplayStore::open(&link, ReplayStoreLineage::CURRENT)
        .err()
        .expect("open must refuse a symlinked store file")
        .to_string();
    assert!(
        error.contains("replay database") && error.contains("must not be a symlink"),
        "refusal must name the store-file symlink, got: {error}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

/// A symlinked PARENT is the substitution-relevant variant: the directory
/// the signed path resolves through is not the directory the host vetted.
/// Even when the link's target is itself a conforming 0700 host-owned
/// directory holding a conforming store, the symlink is refused.
#[test]
fn symlinked_parent_directory_is_refused() {
    let root = scratch_root("parent-symlink");
    let real = conforming_store(&root, "real");
    let real_dir = real.parent().unwrap().to_path_buf();

    let link_dir = root.join("linkdir");
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();
    let through_link = link_dir.join("replay.sqlite");

    let error = SqliteReplayStore::open(&through_link, ReplayStoreLineage::CURRENT)
        .err()
        .expect("open must refuse a store whose parent is a symlink")
        .to_string();
    assert!(
        error.contains("replay database directory") && error.contains("must not be a symlink"),
        "refusal must name the PARENT symlink, got: {error}"
    );

    std::fs::remove_dir_all(&root).unwrap();
}

/// A wrong-mode store file handed directly to `open` is refused. The
/// preflight in `main.rs` also checks this, but the A7 row claims the
/// authentication of the path itself — so the refusal must live in `open`,
/// not depend on a different layer running first.
#[test]
fn wrong_mode_store_file_is_refused() {
    let root = scratch_root("file-mode");
    let store = conforming_store(&root, "store");
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = SqliteReplayStore::open(&store, ReplayStoreLineage::CURRENT)
        .err()
        .expect("open must refuse a store file that is not 0600")
        .to_string();
    assert!(
        error.contains("replay database")
            && error.contains("has mode 0644")
            && error.contains("required 0600"),
        "refusal must name the file's mode, got: {error}"
    );

    // The refusal is the check, not damage: restoring 0600 opens cleanly.
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(
        SqliteReplayStore::open(&store, ReplayStoreLineage::CURRENT)
            .expect("restored 0600 store must open"),
    );

    std::fs::remove_dir_all(&root).unwrap();
}
