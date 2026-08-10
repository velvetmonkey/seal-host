// SPDX-License-Identifier: Apache-2.0
//! Signed release authority and crash recovery for mediated ALLOW decisions.
//!
//! The authorization-decision file is the write-ahead authority. The
//! operation-state file is derived state: startup may recreate a missing
//! operation burn only after verifying the receipt signature and its bound
//! `post_state_hash`.

use crate::{ed25519, secure_fs};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const RECEIPT_KEY_FILE: &str = ".seal-receipt-ed25519.key";
const OPERATION_STATE_FILE: &str = ".seal-operation-state.json";
const SIGNATURE_DOMAIN: &[u8] = b"seal.object-b/v1\0";
const SIGNATURE_DOMAIN_NAME: &str = "seal.object-b/v1";
const OPERATION_ID_WIRE_FIELD: &str = "operation_id";

/// Every value a verifier is allowed to read. This type deliberately has no
/// `Serialize`: v1 production uses the narrower type below, so merely defining
/// `witnessed_external` cannot make it emittable by a v1 record producer.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReadableDurabilityClass {
    AssertedLocalFsync,
    WitnessedExternal,
    Unknown,
}

/// Values the v1 host can serialize. `witnessed_external` is absent by type.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum V1DurabilityClass {
    AssertedLocalFsync,
    Unknown,
}

const V1_DURABILITY_VOCABULARY: [V1DurabilityClass; 2] = [
    V1DurabilityClass::AssertedLocalFsync,
    V1DurabilityClass::Unknown,
];

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseStatus {
    Pending,
    Unknown,
    Released,
    NotApplicable,
}

#[derive(Debug, Clone)]
pub struct ReleaseInput {
    pub operation_id: String,
    pub frame: Vec<u8>,
    pub valid_until: u64,
    pub post_state_hash: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedRelease {
    pub status: ReleaseStatus,
    pub operation_id: String,
    pub durability_class: ReadableDurabilityClass,
    pub frame: Vec<u8>,
    pub valid_until: u64,
    pub post_state_hash: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryReport {
    pub redone_state_transitions: usize,
    pub released: usize,
    pub stale: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptSignature {
    domain: String,
    algorithm: String,
    public_key: String,
    key_id: String,
    encoding: String,
    value: String,
}

#[derive(Debug)]
struct ReceiptSigner {
    key: SigningKey,
    public_key_hex: String,
    key_id: String,
}

#[derive(Debug)]
pub struct ReleaseStore {
    dir: PathBuf,
    signer: ReceiptSigner,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn random_32(label: &str) -> Result<[u8; 32], String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("cannot generate {label}: {error}"))?;
    Ok(bytes)
}

fn signature_preimage(record: &Value) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| format!("cannot serialize receipt signature preimage: {error}"))?;
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 8 + bytes.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    preimage.extend_from_slice(&bytes);
    Ok(preimage)
}

fn operation_state_value(operation_id: &str, frame_sha256: &str) -> Value {
    serde_json::json!({
        "operation_id": operation_id,
        "release_frame_sha256": frame_sha256,
    })
}

fn operation_state_hash(operation_id: &str, frame_sha256: &str) -> Result<String, String> {
    serde_json::to_vec(&operation_state_value(operation_id, frame_sha256))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| format!("cannot serialize operation post-state: {error}"))
}

fn split_terminator(frame: &[u8]) -> (&[u8], &[u8]) {
    if let Some(body) = frame.strip_suffix(b"\r\n") {
        (body, b"\r\n")
    } else if let Some(body) = frame.strip_suffix(b"\n") {
        (body, b"\n")
    } else {
        (frame, b"")
    }
}

fn frame_with_operation_id(frame: &[u8], operation_id: &str) -> Result<Vec<u8>, String> {
    let (body, terminator) = split_terminator(frame);
    let request: Value = serde_json::from_slice(body)
        .map_err(|error| format!("cannot attach operation_id to forwarded request: {error}"))?;
    let object = request
        .as_object()
        .ok_or("cannot attach operation_id: forwarded request is not a JSON object")?;
    if object.contains_key(OPERATION_ID_WIRE_FIELD) {
        return Err("forwarded request already contains reserved operation_id".into());
    }
    let closing_brace = body
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .filter(|index| body[*index] == b'}')
        .ok_or("cannot attach operation_id: request object lacks closing brace")?;
    let encoded_operation_id = serde_json::to_string(operation_id)
        .map_err(|error| format!("cannot encode operation_id: {error}"))?;
    let mut output = Vec::with_capacity(frame.len() + encoded_operation_id.len() + 16);
    output.extend_from_slice(&body[..closing_brace]);
    if !object.is_empty() {
        output.push(b',');
    }
    output.extend_from_slice(b"\"operation_id\":");
    output.extend_from_slice(encoded_operation_id.as_bytes());
    output.extend_from_slice(&body[closing_brace..]);
    output.extend_from_slice(terminator);
    Ok(output)
}

impl ReleaseInput {
    pub fn prepare(frame: &[u8], now: u64, validity_ms: u64) -> Result<Self, String> {
        let operation_id = hex::encode(random_32("operation_id")?);
        let frame = frame_with_operation_id(frame, &operation_id)?;
        let frame_sha256 = sha256_hex(&frame);
        let post_state_hash = operation_state_hash(&operation_id, &frame_sha256)?;
        Ok(Self {
            operation_id,
            frame,
            valid_until: now.saturating_add(validity_ms),
            post_state_hash,
        })
    }
}

impl ReceiptSigner {
    fn load_or_create(dir: &Path) -> Result<Self, String> {
        let path = dir.join(RECEIPT_KEY_FILE);
        let key_bytes: [u8; 32] = if path.exists() {
            secure_fs::validate_private_file(&path, "host receipt key")?;
            std::fs::read(&path)
                .map_err(|error| {
                    format!("cannot read host receipt key {}: {error}", path.display())
                })?
                .try_into()
                .map_err(|_| "host receipt key must be exactly 32 bytes")?
        } else {
            let bytes = random_32("host receipt key")?;
            let mut file = secure_fs::open_private_new(&path, "host receipt key")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| {
                    format!(
                        "cannot persist host receipt key {}: {error}",
                        path.display()
                    )
                })?;
            secure_fs::sync_dir(dir, "authorization decision directory")?;
            bytes
        };
        let key = SigningKey::from_bytes(&key_bytes);
        let public_key_hex = hex::encode(key.verifying_key().to_bytes());
        let key_id = sha256_hex(&key.verifying_key().to_bytes());
        Ok(Self {
            key,
            public_key_hex,
            key_id,
        })
    }

    fn sign(&self, record: &mut Value) -> Result<(), String> {
        let object = record
            .as_object_mut()
            .ok_or("authorization decision must be an object")?;
        object.remove("signature");
        let signature = self.key.sign(&signature_preimage(record)?);
        record.as_object_mut().expect("checked object").insert(
            "signature".into(),
            serde_json::json!({
                "domain": SIGNATURE_DOMAIN_NAME,
                "algorithm": "Ed25519",
                "public_key": self.public_key_hex,
                "key_id": self.key_id,
                "encoding": "base64url-nopad",
                "value": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            }),
        );
        Ok(())
    }

    fn verify(&self, record: &Value) -> Result<(), String> {
        let mut unsigned = record.clone();
        let signature_value = unsigned
            .as_object_mut()
            .ok_or("authorization decision must be an object")?
            .remove("signature")
            .ok_or("authorization decision lacks signature")?;
        let signature: ReceiptSignature = serde_json::from_value(signature_value)
            .map_err(|error| format!("bad receipt signature object: {error}"))?;
        if signature.domain != SIGNATURE_DOMAIN_NAME
            || signature.algorithm != "Ed25519"
            || signature.encoding != "base64url-nopad"
        {
            return Err("unsupported receipt signature parameters".into());
        }
        if signature.public_key != self.public_key_hex || signature.key_id != self.key_id {
            return Err("receipt signer does not match this installation's receipt key".into());
        }
        let public_key: [u8; 32] = hex::decode(&signature.public_key)
            .map_err(|error| format!("bad receipt public key: {error}"))?
            .try_into()
            .map_err(|_| "receipt public key must be 32 bytes")?;
        let signature_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature.value.as_bytes())
            .map_err(|_| "bad receipt signature encoding")?
            .try_into()
            .map_err(|_| "receipt signature must be 64 bytes")?;
        let key = VerifyingKey::from_bytes(&public_key)
            .map_err(|error| format!("bad receipt public key: {error}"))?;
        ed25519::verify(
            &key,
            &signature_preimage(&unsigned)?,
            &ed25519_dalek::Signature::from_bytes(&signature_bytes),
        )
        .map_err(|error| format!("receipt signature verification failed: {error:?}"))
    }
}

impl ReleaseStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, String> {
        let dir = dir.into();
        secure_fs::ensure_private_dir(&dir, "authorization decision directory")?;
        let signer = ReceiptSigner::load_or_create(&dir)?;
        Ok(Self { dir, signer })
    }

    pub fn attach_and_sign(
        &self,
        record: &mut Value,
        release: Option<&ReleaseInput>,
    ) -> Result<(), String> {
        let object = record
            .as_object_mut()
            .ok_or("authorization decision must be an object")?;
        let is_allow = object.get("verdict").and_then(Value::as_str) == Some("ALLOW");
        if is_allow {
            let release = release.ok_or("ALLOW decision lacks release authority")?;
            object.insert(
                "release_status".into(),
                serde_json::to_value(ReleaseStatus::Pending).unwrap(),
            );
            object.insert(
                "operation_id".into(),
                Value::String(release.operation_id.clone()),
            );
            object.insert(
                "durability_class".into(),
                serde_json::to_value(V1_DURABILITY_VOCABULARY[0]).unwrap(),
            );
            object.insert(
                "release_valid_until".into(),
                Value::from(release.valid_until),
            );
            object.insert(
                "post_state_hash".into(),
                Value::String(release.post_state_hash.clone()),
            );
            object.insert(
                "release_frame".into(),
                serde_json::json!({
                    "encoding": "base64",
                    "length": release.frame.len(),
                    "sha256": sha256_hex(&release.frame),
                    "base64": base64::engine::general_purpose::STANDARD.encode(&release.frame),
                }),
            );
        } else {
            object.insert(
                "release_status".into(),
                serde_json::to_value(ReleaseStatus::NotApplicable).unwrap(),
            );
            object.insert(
                "operation_id".into(),
                Value::String(hex::encode(random_32("operation_id")?)),
            );
            object.insert(
                "durability_class".into(),
                serde_json::to_value(V1_DURABILITY_VOCABULARY[0]).unwrap(),
            );
        }
        self.signer.sign(record)
    }

    pub fn verify_record(&self, record: &Value) -> Result<Option<VerifiedRelease>, String> {
        self.signer.verify(record)?;
        let durability_class: ReadableDurabilityClass = serde_json::from_value(
            record
                .get("durability_class")
                .cloned()
                .ok_or("signed receipt lacks durability_class")?,
        )
        .map_err(|error| format!("bad durability_class: {error}"))?;
        let status: ReleaseStatus = serde_json::from_value(
            record
                .get("release_status")
                .cloned()
                .ok_or("signed receipt lacks release_status")?,
        )
        .map_err(|error| format!("bad release_status: {error}"))?;
        let operation_id = record
            .get("operation_id")
            .and_then(Value::as_str)
            .ok_or("signed receipt lacks operation_id")?
            .to_string();
        if status == ReleaseStatus::NotApplicable {
            return Ok(None);
        }
        let frame_object = record
            .get("release_frame")
            .and_then(Value::as_object)
            .ok_or("signed ALLOW receipt lacks release_frame")?;
        let frame = base64::engine::general_purpose::STANDARD
            .decode(
                frame_object
                    .get("base64")
                    .and_then(Value::as_str)
                    .ok_or("release_frame lacks base64")?,
            )
            .map_err(|error| format!("bad release_frame base64: {error}"))?;
        let frame_sha256 = sha256_hex(&frame);
        if frame_object.get("length").and_then(Value::as_u64) != Some(frame.len() as u64)
            || frame_object.get("sha256").and_then(Value::as_str) != Some(frame_sha256.as_str())
        {
            return Err("release_frame length or digest mismatch".into());
        }
        let frame_json: Value = serde_json::from_slice(split_terminator(&frame).0)
            .map_err(|error| format!("signed release_frame is not JSON: {error}"))?;
        if frame_json
            .get(OPERATION_ID_WIRE_FIELD)
            .and_then(Value::as_str)
            != Some(operation_id.as_str())
        {
            return Err("signed operation_id is not forwarded unchanged in release_frame".into());
        }
        let valid_until = record
            .get("release_valid_until")
            .and_then(Value::as_u64)
            .ok_or("signed ALLOW receipt lacks release_valid_until")?;
        let post_state_hash = record
            .get("post_state_hash")
            .and_then(Value::as_str)
            .ok_or("signed ALLOW receipt lacks post_state_hash")?
            .to_string();
        let expected_post_state_hash = operation_state_hash(&operation_id, &frame_sha256)?;
        if post_state_hash != expected_post_state_hash {
            return Err("signed post_state_hash does not bind the operation state".into());
        }
        Ok(Some(VerifiedRelease {
            status,
            operation_id,
            durability_class,
            frame,
            valid_until,
            post_state_hash,
        }))
    }

    pub fn read_verified(&self, path: &Path) -> Result<(Value, Option<VerifiedRelease>), String> {
        secure_fs::validate_private_file(path, "authorization decision")?;
        let record: Value = serde_json::from_slice(&std::fs::read(path).map_err(|error| {
            format!(
                "cannot read authorization decision {}: {error}",
                path.display()
            )
        })?)
        .map_err(|error| format!("bad authorization decision {}: {error}", path.display()))?;
        let release = self.verify_record(&record)?;
        Ok((record, release))
    }

    fn atomic_write(&self, path: &Path, bytes: &[u8], label: &str) -> Result<(), String> {
        let tmp = self
            .dir
            .join(format!(".{}-{}.tmp", label, std::process::id()));
        let result = (|| -> Result<(), String> {
            let mut file = secure_fs::open_private_new(&tmp, label)?;
            file.write_all(bytes)
                .and_then(|_| file.sync_all())
                .map_err(|error| format!("cannot sync {label} {}: {error}", tmp.display()))?;
            std::fs::rename(&tmp, path)
                .map_err(|error| format!("cannot install {label} {}: {error}", path.display()))?;
            secure_fs::validate_private_file(path, label)?;
            secure_fs::sync_dir(&self.dir, "authorization decision directory")
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    fn write_signed_record(&self, path: &Path, record: &mut Value) -> Result<(), String> {
        self.signer.sign(record)?;
        let bytes = serde_json::to_string_pretty(record)
            .map_err(|error| format!("cannot serialize signed authorization decision: {error}"))?
            + "\n";
        self.atomic_write(path, bytes.as_bytes(), "authorization-decision-rewrite")
    }

    pub fn transition(
        &self,
        path: &Path,
        expected: ReleaseStatus,
        next: ReleaseStatus,
    ) -> Result<(), String> {
        if !matches!(
            (expected, next),
            (ReleaseStatus::Pending, ReleaseStatus::Unknown)
                | (ReleaseStatus::Unknown, ReleaseStatus::Released)
        ) {
            return Err(format!(
                "forbidden release status transition {expected:?} -> {next:?}"
            ));
        }
        let (mut record, release) = self.read_verified(path)?;
        let release = release.ok_or("cannot transition a non-ALLOW authorization decision")?;
        if release.status != expected {
            return Err(format!(
                "release status transition expected {expected:?}, found {:?}",
                release.status
            ));
        }
        record
            .as_object_mut()
            .expect("verified record object")
            .insert("release_status".into(), serde_json::to_value(next).unwrap());
        self.write_signed_record(path, &mut record)
    }

    fn load_operation_state(&self) -> Result<Value, String> {
        let path = self.dir.join(OPERATION_STATE_FILE);
        if !path.exists() {
            return Ok(serde_json::json!({
                "schema": "seal.operation-state/v1",
                "operations": {},
            }));
        }
        secure_fs::validate_private_file(&path, "operation state")?;
        let state: Value =
            serde_json::from_slice(&std::fs::read(&path).map_err(|error| {
                format!("cannot read operation state {}: {error}", path.display())
            })?)
            .map_err(|error| format!("bad operation state {}: {error}", path.display()))?;
        if state.get("schema").and_then(Value::as_str) != Some("seal.operation-state/v1")
            || !state.get("operations").is_some_and(Value::is_object)
        {
            return Err("operation state has the wrong schema".into());
        }
        Ok(state)
    }

    pub fn commit_operation_state(&self, path: &Path) -> Result<bool, String> {
        let (_, release) = self.read_verified(path)?;
        let release = release.ok_or("cannot commit state for a non-ALLOW decision")?;
        let frame_sha256 = sha256_hex(&release.frame);
        let entry = operation_state_value(&release.operation_id, &frame_sha256);
        if sha256_hex(&serde_json::to_vec(&entry).unwrap()) != release.post_state_hash {
            return Err("operation state transition disagrees with signed post_state_hash".into());
        }
        let mut state = self.load_operation_state()?;
        let operations = state
            .get_mut("operations")
            .and_then(Value::as_object_mut)
            .expect("validated operations object");
        if let Some(existing) = operations.get(&release.operation_id) {
            if existing != &entry {
                return Err("operation_id is already burned for different state".into());
            }
            return Ok(false);
        }
        operations.insert(release.operation_id, entry);
        let bytes = serde_json::to_string_pretty(&state)
            .map_err(|error| format!("cannot serialize operation state: {error}"))?
            + "\n";
        self.atomic_write(
            &self.dir.join(OPERATION_STATE_FILE),
            bytes.as_bytes(),
            "operation-state",
        )?;
        Ok(true)
    }

    pub fn operation_count(&self) -> Result<usize, String> {
        Ok(self
            .load_operation_state()?
            .get("operations")
            .and_then(Value::as_object)
            .expect("validated operations object")
            .len())
    }

    fn receipt_paths(&self) -> Result<Vec<PathBuf>, String> {
        let mut paths = Vec::new();
        for entry in std::fs::read_dir(&self.dir)
            .map_err(|error| format!("cannot scan authorization decisions: {error}"))?
        {
            let path = entry
                .map_err(|error| format!("cannot scan authorization decision entry: {error}"))?
                .path();
            if path.extension().and_then(|value| value.to_str()) == Some("json")
                && path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name.starts_with("receipt-"))
            {
                paths.push(path);
            }
        }
        paths.sort();
        Ok(paths)
    }

    pub fn recover_pending(
        &self,
        now: u64,
        mut forward: impl FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<RecoveryReport, String> {
        let mut report = RecoveryReport::default();
        for path in self.receipt_paths()? {
            let (_, release) = self.read_verified(&path)?;
            let Some(release) = release else { continue };
            if release.status != ReleaseStatus::Pending {
                continue;
            }
            if now > release.valid_until {
                report.stale += 1;
                continue;
            }
            if self.commit_operation_state(&path)? {
                report.redone_state_transitions += 1;
            }
            self.transition(&path, ReleaseStatus::Pending, ReleaseStatus::Unknown)?;
            forward(&release.frame)?;
            self.transition(&path, ReleaseStatus::Unknown, ReleaseStatus::Released)?;
            report.released += 1;
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use std::os::unix::fs::PermissionsExt;

    fn temp_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "seal-release-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn signed_pending_receipt(
        store: &ReleaseStore,
        dir: &Path,
        now: u64,
        validity_ms: u64,
    ) -> PathBuf {
        let release = ReleaseInput::prepare(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n",
            now,
            validity_ms,
        )
        .unwrap();
        let mut record = serde_json::json!({
            "record_type": "seal.authorization-decision",
            "record_version": 3,
            "verdict": "ALLOW",
        });
        store.attach_and_sign(&mut record, Some(&release)).unwrap();
        let path = dir.join("receipt-00000000000000000000-test.json");
        let mut file = secure_fs::open_private_new(&path, "test authorization decision").unwrap();
        file.write_all(&(serde_json::to_vec_pretty(&record).unwrap()))
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .unwrap();
        secure_fs::sync_dir(dir, "test receipt directory").unwrap();
        path
    }

    #[test]
    fn witnessed_external_is_readable_but_unreachable_to_v1_emitters() {
        for value in ["asserted_local_fsync", "witnessed_external", "unknown"] {
            let parsed: ReadableDurabilityClass =
                serde_json::from_value(Value::String(value.into())).unwrap();
            assert_eq!(
                parsed,
                match value {
                    "asserted_local_fsync" => ReadableDurabilityClass::AssertedLocalFsync,
                    "witnessed_external" => ReadableDurabilityClass::WitnessedExternal,
                    "unknown" => ReadableDurabilityClass::Unknown,
                    _ => unreachable!(),
                }
            );
        }
        let v1_emittable: Vec<_> = V1_DURABILITY_VOCABULARY
            .into_iter()
            .map(|value| serde_json::to_value(value).unwrap())
            .collect();
        assert_eq!(
            v1_emittable,
            vec![
                Value::String("asserted_local_fsync".into()),
                Value::String("unknown".into()),
            ]
        );
        assert!(!v1_emittable.contains(&Value::String("witnessed_external".into())));
        assert!(
            serde_json::from_value::<ReadableDurabilityClass>(Value::String("best_effort".into()))
                .is_err()
        );
    }

    #[test]
    fn operation_id_is_forwarded_and_binds_post_state() {
        let input = ReleaseInput::prepare(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n",
            10,
            20,
        )
        .unwrap();
        let (body, _) = split_terminator(&input.frame);
        let wire: Value = serde_json::from_slice(body).unwrap();
        assert_eq!(wire["operation_id"], input.operation_id);
        assert_eq!(input.valid_until, 30);
        assert_eq!(
            input.post_state_hash,
            operation_state_hash(&input.operation_id, &sha256_hex(&input.frame)).unwrap()
        );
    }

    #[test]
    fn base64_wire_alphabets_and_padding_are_exact() {
        let bytes = [0xfb, 0xff];
        assert_eq!(STANDARD.encode(bytes), "+/8=");
        assert_eq!(URL_SAFE_NO_PAD.encode(bytes), "-_8");
        assert_eq!(STANDARD.decode("+/8=").unwrap(), bytes);
        assert_eq!(URL_SAFE_NO_PAD.decode("-_8").unwrap(), bytes);
    }

    #[test]
    fn receipt_input_absent_empty_and_unreadable_fail() {
        let dir = temp_dir("invalid-input");
        let store = ReleaseStore::open(&dir).unwrap();

        let absent = dir.join("absent.json");
        assert!(store.read_verified(&absent).is_err());

        let empty = dir.join("empty.json");
        std::fs::write(&empty, b"").unwrap();
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.read_verified(&empty).is_err());

        let unreadable = dir.join("unreadable.json");
        std::fs::write(&unreadable, b"{}").unwrap();
        std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(store.read_verified(&unreadable).is_err());

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn per_install_key_is_stable_and_private() {
        let dir = temp_dir("key");
        let first = ReleaseStore::open(&dir).unwrap();
        let first_public = first.signer.public_key_hex.clone();
        drop(first);
        let second = ReleaseStore::open(&dir).unwrap();
        assert_eq!(second.signer.public_key_hex, first_public);
        assert_eq!(
            std::fs::metadata(dir.join(RECEIPT_KEY_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn startup_recovery_replays_only_fresh_pending_authority() {
        let fresh_dir = temp_dir("fresh-recovery");
        let fresh_store = ReleaseStore::open(&fresh_dir).unwrap();
        let fresh_path = signed_pending_receipt(&fresh_store, &fresh_dir, 10, 20);
        let mut forwarded = Vec::new();
        let report = fresh_store
            .recover_pending(30, |frame| {
                forwarded.push(frame.to_vec());
                Ok(())
            })
            .unwrap();
        assert_eq!(
            report,
            RecoveryReport {
                redone_state_transitions: 1,
                released: 1,
                stale: 0,
            }
        );
        assert_eq!(forwarded.len(), 1);
        assert_eq!(fresh_store.operation_count().unwrap(), 1);
        assert_eq!(
            fresh_store
                .read_verified(&fresh_path)
                .unwrap()
                .1
                .unwrap()
                .status,
            ReleaseStatus::Released
        );

        let stale_dir = temp_dir("stale-recovery");
        let stale_store = ReleaseStore::open(&stale_dir).unwrap();
        let stale_path = signed_pending_receipt(&stale_store, &stale_dir, 10, 20);
        let report = stale_store
            .recover_pending(31, |_| panic!("stale authority must not forward"))
            .unwrap();
        assert_eq!(report.stale, 1);
        assert_eq!(report.released, 0);
        assert_eq!(stale_store.operation_count().unwrap(), 0);
        assert_eq!(
            stale_store
                .read_verified(&stale_path)
                .unwrap()
                .1
                .unwrap()
                .status,
            ReleaseStatus::Pending
        );
        std::fs::remove_dir_all(fresh_dir).unwrap();
        std::fs::remove_dir_all(stale_dir).unwrap();
    }

    #[test]
    fn signed_release_status_tampering_is_refused() {
        let dir = temp_dir("tamper");
        let store = ReleaseStore::open(&dir).unwrap();
        let path = signed_pending_receipt(&store, &dir, 10, 20);
        let mut record: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["release_status"] = Value::String("RELEASED".into());
        std::fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.read_verified(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
