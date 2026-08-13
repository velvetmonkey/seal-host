// SPDX-License-Identifier: Apache-2.0

use seal_host_rs::three_artifact_byte_lock::{
    decode, encode, Content, DurabilityClass, ReleaseStatus, DOMAIN_TAG,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

fn witness() -> Content {
    Content {
        object_a: b"object-a".to_vec(),
        approval_statement: Some(b"approval-statement".to_vec()),
        object_b: b"object-b".to_vec(),
        release_status: ReleaseStatus::Pending,
        operation_id: b"operation-17".to_vec(),
        durability_class: DurabilityClass::AssertedLocalFsync,
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn temp_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "seal-g2lock-{label}-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn emitted_receipt(label: &str) -> (PathBuf, PathBuf, Vec<u8>) {
    use seal_host_rs::release::{attach_signed_artifacts, ReleaseStore};

    let dir = temp_dir(label);
    let store = ReleaseStore::open(&dir).unwrap();
    let mut record = serde_json::json!({"verdict": "DENY"});
    attach_signed_artifacts(&mut record, b"object-a", Some(b"approval-statement")).unwrap();
    store.attach_and_sign(&mut record, None).unwrap();
    let bytes = serde_json::to_vec_pretty(&record).unwrap();
    let path = dir.join("receipt.json");
    fs::write(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    (dir, path, bytes)
}

fn verify(dir: &Path, receipt: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_seal-three-artifact-verify"))
        .arg(dir)
        .arg(receipt)
        .output()
        .unwrap()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn exact_lean_rust_byte_agreement() {
    let rust = encode(&witness());
    let lean_exe = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(".lake/build/bin/three_artifact_byte_lock");
    let output = Command::new(&lean_exe).output().unwrap_or_else(|error| {
        panic!(
            "cannot run Lean byte-lock witness {}: {error}",
            lean_exe.display()
        )
    });
    assert!(
        output.status.success(),
        "Lean witness exited {}",
        output.status
    );
    assert_eq!(rust, output.stdout, "Lean and Rust bytes differ");
    println!("LEAN_SHA256={}", digest(&output.stdout));
    println!("RUST_SHA256={}", digest(&rust));
}

#[test]
fn domain_and_logical_field_tampers_change_or_refuse_bytes() {
    let original = encode(&witness());
    let mut physical = original.clone();
    physical[0] ^= 1;
    assert_eq!(
        decode(&physical).unwrap_err(),
        "unrecognised three-artifact domain tag"
    );
    assert_eq!(decode(&original).unwrap(), witness());

    let mut status = witness();
    status.release_status = ReleaseStatus::Released;
    let status_bytes = encode(&status);
    assert_ne!(digest(&original), digest(&status_bytes));
    let mut operation = witness();
    operation.operation_id = b"operation-18".to_vec();
    let operation_bytes = encode(&operation);
    assert_ne!(digest(&original), digest(&operation_bytes));
    let mut durability = witness();
    durability.durability_class = DurabilityClass::Unknown;
    let durability_bytes = encode(&durability);
    assert_ne!(digest(&original), digest(&durability_bytes));
    assert_eq!(&original[..DOMAIN_TAG.len()], DOMAIN_TAG);
    println!("FIELD_BASE_SHA256={}", digest(&original));
    println!("FIELD_RELEASE_STATUS_SHA256={}", digest(&status_bytes));
    println!("FIELD_OPERATION_ID_SHA256={}", digest(&operation_bytes));
    println!(
        "FIELD_DURABILITY_CLASS_SHA256={}",
        digest(&durability_bytes)
    );
}

#[test]
fn missing_fields_and_fourth_values_refuse() {
    for value in ["best_effort", "asserted_local_fsync_without_prefix", ""] {
        assert!(serde_json::from_str::<DurabilityClass>(&format!("\"{value}\"")).is_err());
    }
    for value in ["best_effort", "witnessed_external", "fourth_value"] {
        let error = seal_host_rs::release::v1_durability_for_emission(value).unwrap_err();
        assert!(error.contains("refused v1 durability_class"));
        println!("EMIT_REFUSED value={value} error={error}");
    }
    assert_eq!(
        seal_host_rs::release::v1_durability_for_emission("asserted_local_fsync").unwrap(),
        serde_json::json!("asserted_local_fsync")
    );
    println!("SIGNED_DURABILITY=asserted_local_fsync");
}

#[test]
fn physical_one_byte_tamper_refuses_and_restore_accepts() {
    let (dir, path, original) = emitted_receipt("physical-tamper");
    let accepted = verify(&dir, &path);
    assert!(accepted.status.success(), "{}", stderr(&accepted));

    let operation = serde_json::from_slice::<serde_json::Value>(&original).unwrap()["operation_id"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    let start = original
        .windows(operation.len())
        .position(|window| window == operation)
        .unwrap();
    let mut tampered = original.clone();
    tampered[start] = if tampered[start] == b'0' { b'1' } else { b'0' };
    fs::write(&path, &tampered).unwrap();
    let refused = verify(&dir, &path);
    assert!(!refused.status.success());
    assert!(stderr(&refused).contains("receipt signature verification failed"));
    println!(
        "PHYSICAL_TAMPER_EXIT={} {}",
        refused.status.code().unwrap_or(-1),
        stderr(&refused).trim()
    );
    println!("ORIGINAL_SHA256={}", digest(&original));
    println!("TAMPERED_SHA256={}", digest(&tampered));

    fs::write(&path, &original).unwrap();
    let restored = verify(&dir, &path);
    assert!(restored.status.success(), "{}", stderr(&restored));
    println!("RESTORED_SHA256={}", digest(&fs::read(&path).unwrap()));
}

#[test]
fn silence_missing_receipt_key_is_named_nonzero_refusal() {
    let (dir, path, _) = emitted_receipt("missing-key");
    fs::remove_file(dir.join(".seal-receipt-ed25519.key")).unwrap();
    let output = verify(&dir, &path);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("missing host receipt key"));
    println!(
        "MISSING_KEY_EXIT={} {}",
        output.status.code().unwrap_or(-1),
        stderr(&output).trim()
    );
}

#[test]
fn silence_unreadable_receipt_key_is_named_nonzero_refusal() {
    let (dir, path, _) = emitted_receipt("unreadable-key");
    let key = dir.join(".seal-receipt-ed25519.key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o000)).unwrap();
    let output = verify(&dir, &path);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("host receipt key"));
    println!(
        "UNREADABLE_KEY_EXIT={} {}",
        output.status.code().unwrap_or(-1),
        stderr(&output).trim()
    );
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn silence_absent_signed_field_is_named_nonzero_refusal() {
    let (dir, path, original) = emitted_receipt("absent-field");
    let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
    record.as_object_mut().unwrap().remove("durability_class");
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let output = verify(&dir, &path);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("signed receipt lacks durability_class"));
    println!(
        "ABSENT_FIELD_EXIT={} {}",
        output.status.code().unwrap_or(-1),
        stderr(&output).trim()
    );
}

#[test]
fn silence_unrecognised_domain_is_named_nonzero_refusal() {
    let (dir, path, original) = emitted_receipt("domain");
    let mut record: serde_json::Value = serde_json::from_slice(&original).unwrap();
    record["signature"]["domain"] = serde_json::json!("seal.object-b/v999");
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let output = verify(&dir, &path);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("unrecognised receipt signature domain tag"));
    println!(
        "UNKNOWN_DOMAIN_EXIT={} {}",
        output.status.code().unwrap_or(-1),
        stderr(&output).trim()
    );
}
