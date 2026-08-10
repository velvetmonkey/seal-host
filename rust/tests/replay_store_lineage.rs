// SPDX-License-Identifier: Apache-2.0
//! M.4a controls for the replay-store lineage startup gate.
//!
//! These drive the real host binary with an authority-signed config and
//! `/bin/cat` as the guarded server. A successful positive control therefore
//! proves both startup and one served round trip.

use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use seal_host_rs::replay_store::{ReplayStoreLineage, SqliteReplayStore};
use seal_host_rs::secure_fs;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

const INITIALIZE_REQUEST: &str = r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#;
const GUARDED_REQUEST: &str = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"db.execute","arguments":{"sql":"drop table lineage_probe"}}}"#;

struct Fixture {
    root: PathBuf,
    config: PathBuf,
    replay: PathBuf,
    tokens: PathBuf,
    receipts: PathBuf,
    config_pubkey: String,
    approval_pubkey: String,
}

impl Fixture {
    fn new(tag: &str, expected: ReplayStoreLineage) -> Self {
        let root = std::env::temp_dir().join(format!(
            "seal-replay-lineage-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        secure_fs::ensure_private_dir(&root, "lineage test directory").unwrap();
        let approvals = root.join("approvals.ndjson");
        let tokens = root.join("tokens.ndjson");
        let receipts = root.join("receipts");
        secure_fs::ensure_private_file(&approvals, "test approvals").unwrap();
        secure_fs::ensure_private_file(&tokens, "test tokens").unwrap();
        secure_fs::ensure_private_dir(&receipts, "test receipts").unwrap();

        let config_key = SigningKey::from_bytes(&[41; 32]);
        let approval_key = SigningKey::from_bytes(&[42; 32]);
        let config_pubkey = hex::encode(config_key.verifying_key().to_bytes());
        let approval_pubkey = hex::encode(approval_key.verifying_key().to_bytes());
        let replay = root.join("replay.sqlite");
        let payload = json!({
            "epoch": 1,
            "safety": {
                "approval": {
                    "control_file": approvals,
                    "ttl_seconds": 120,
                    "replay_store": {
                        "sqlite_path": replay,
                        "schema_version": expected.schema_version,
                        "namespace_encoding_version": expected.namespace_encoding_version
                    }
                },
                "tools": [{
                    "name": "db.execute",
                    "mode": "guarded",
                    "match": {
                        "type": "contains_any_ci",
                        "arg": "sql",
                        "needles": ["drop"]
                    },
                    "target": [{"full_arguments": true}]
                }]
            }
        })
        .to_string();
        let envelope = json!({
            "payload": payload,
            "signature": hex::encode(config_key.sign(payload.as_bytes()).to_bytes())
        })
        .to_string();
        let config = root.join("trusted.json");
        std::fs::write(&config, envelope).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();

        Self {
            root,
            config,
            replay,
            tokens,
            receipts,
            config_pubkey,
            approval_pubkey,
        }
    }

    fn initialize(&self) -> Output {
        Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
            .args([
                "--config",
                self.config.to_str().unwrap(),
                "--pubkey",
                &self.config_pubkey,
                "--initialize-replay-store",
            ])
            .output()
            .unwrap()
    }

    fn serve(&self) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_seal-host-rs"))
            .args([
                "--config",
                self.config.to_str().unwrap(),
                "--pubkey",
                &self.config_pubkey,
                "--channel",
                "ed25519",
                "--token-file",
                self.tokens.to_str().unwrap(),
                "--approval-pubkey",
                &self.approval_pubkey,
                "--receipt-dir",
                self.receipts.to_str().unwrap(),
                "--",
                "/bin/cat",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(format!("{INITIALIZE_REQUEST}\n{GUARDED_REQUEST}\n").as_bytes())
            .unwrap();
        drop(child.stdin.take());
        child.wait_with_output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn matching_lineage_starts_and_serves() {
    let fixture = Fixture::new("matching", ReplayStoreLineage::CURRENT);
    SqliteReplayStore::initialize(&fixture.replay, ReplayStoreLineage::CURRENT).unwrap();

    let run = fixture.serve();
    assert_eq!(run.status.code(), Some(0), "stderr:\n{}", text(&run.stderr));
    let stdout = text(&run.stdout);
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some(INITIALIZE_REQUEST),
        "stderr:\n{}",
        text(&run.stderr)
    );
    assert!(
        lines
            .next()
            .is_some_and(|line| line.contains("approval required: ")),
        "host did not serve the guarded denial:\n{stdout}\nstderr:\n{}",
        text(&run.stderr)
    );
    println!(
        "CONTROL 1 matching lineage: status=0 served_initialize=true \
         served_guarded_denial=true"
    );
}

#[test]
fn mismatched_lineage_refuses_startup_and_names_dimension() {
    let fixture = Fixture::new("mismatch", ReplayStoreLineage::CURRENT);
    SqliteReplayStore::initialize(&fixture.replay, ReplayStoreLineage::CURRENT).unwrap();
    let conn = Connection::open(&fixture.replay).unwrap();
    conn.execute(
        "UPDATE replay_store_lineage SET namespace_encoding_version = 2 WHERE singleton = 1",
        [],
    )
    .unwrap();
    drop(conn);

    let run = fixture.serve();
    let stderr = text(&run.stderr);
    println!(
        "CONTROL 2 mismatched lineage: status={:?} error={}",
        run.status.code(),
        stderr.trim()
    );
    assert!(
        !run.status.success(),
        "ABLATION DETECTED: mismatched replay store served a request\nstdout:\n{}",
        text(&run.stdout)
    );
    assert!(
        stderr.contains("replay store namespace-encoding version mismatch: expected 1, found 2"),
        "mismatch error did not name the dimension and values:\n{stderr}"
    );
    assert!(run.stdout.is_empty(), "refused host wrote to stdout");
}

#[test]
fn populated_store_without_stamp_refuses_and_is_not_adopted() {
    let fixture = Fixture::new("missing-stamp", ReplayStoreLineage::CURRENT);
    secure_fs::ensure_private_file(&fixture.replay, "test replay database").unwrap();
    let conn = Connection::open(&fixture.replay).unwrap();
    conn.execute_batch(
        "CREATE TABLE nonces (
            nonce TEXT PRIMARY KEY,
            issued_at INTEGER NOT NULL,
            expiry_at INTEGER NOT NULL
        );
        INSERT INTO nonces VALUES ('already-consumed', 1, 9999999999999);",
    )
    .unwrap();
    drop(conn);

    let run = fixture.serve();
    println!(
        "CONTROL 3 missing stamp: status={:?} error={}",
        run.status.code(),
        text(&run.stderr).trim()
    );
    assert!(!run.status.success(), "unstamped populated store served");
    assert!(
        text(&run.stderr)
            .contains("replay store lineage stamp is missing; refusing to adopt or initialize it"),
        "stderr:\n{}",
        text(&run.stderr)
    );
    let conn = Connection::open(&fixture.replay).unwrap();
    let stamp_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE type = 'table' AND name = 'replay_store_lineage'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stamp_count, 0, "startup silently stamped the legacy store");
}

#[test]
fn empty_new_store_requires_deliberate_initialization() {
    let fixture = Fixture::new("deliberate-init", ReplayStoreLineage::CURRENT);

    let ordinary = fixture.serve();
    println!(
        "CONTROL 4 ordinary startup: status={:?} store_created={}",
        ordinary.status.code(),
        fixture.replay.exists()
    );
    assert!(
        !ordinary.status.success(),
        "absent store silently initialized"
    );
    assert!(
        !fixture.replay.exists(),
        "ordinary startup created the store"
    );

    let initialized = fixture.initialize();
    println!(
        "CONTROL 4 deliberate initializer: status={:?} store_created={}",
        initialized.status.code(),
        fixture.replay.exists()
    );
    assert_eq!(
        initialized.status.code(),
        Some(0),
        "stderr:\n{}",
        text(&initialized.stderr)
    );
    assert!(text(&initialized.stderr).contains("replay store initialized:"));
    assert!(fixture.replay.exists());

    let repeated = fixture.initialize();
    println!(
        "CONTROL 4 repeated initializer: status={:?} error={}",
        repeated.status.code(),
        text(&repeated.stderr).trim()
    );
    assert!(
        !repeated.status.success(),
        "initializer overwrote or adopted an existing store"
    );
    assert!(
        text(&repeated.stderr).contains("cannot create replay database"),
        "stderr:\n{}",
        text(&repeated.stderr)
    );

    let run = fixture.serve();
    assert_eq!(run.status.code(), Some(0), "stderr:\n{}", text(&run.stderr));
    let stdout = text(&run.stdout);
    let mut lines = stdout.lines();
    assert_eq!(
        lines.next(),
        Some(INITIALIZE_REQUEST),
        "stderr:\n{}",
        text(&run.stderr)
    );
    assert!(
        lines
            .next()
            .is_some_and(|line| line.contains("approval required: ")),
        "host did not serve after deliberate initialization:\n{stdout}\nstderr:\n{}",
        text(&run.stderr)
    );
    println!(
        "CONTROL 4 post-initialization startup: status=0 served_initialize=true \
         served_guarded_denial=true"
    );
}
