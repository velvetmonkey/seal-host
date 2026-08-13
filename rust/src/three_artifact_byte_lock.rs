// SPDX-License-Identifier: Apache-2.0
//! Rust emission of `Host.ThreeArtifactByteLock`; Lean owns this format.

use serde::{Deserialize, Serialize};

pub const DOMAIN_NAME: &str = "seal.object-b/v2";
pub const DOMAIN_TAG: &[u8] = b"seal.object-b/v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReleaseStatus {
    Pending,
    Unknown,
    Released,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityClass {
    AssertedLocalFsync,
    WitnessedExternal,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Content {
    pub object_a: Vec<u8>,
    pub approval_statement: Option<Vec<u8>>,
    pub object_b: Vec<u8>,
    pub release_status: ReleaseStatus,
    pub operation_id: Vec<u8>,
    pub durability_class: DurabilityClass,
}

fn blob(output: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        output.extend_from_slice(&[0, *byte]);
    }
    output.push(1);
}

fn release_tag(value: ReleaseStatus) -> u8 {
    match value {
        ReleaseStatus::Pending => 4,
        ReleaseStatus::Unknown => 5,
        ReleaseStatus::Released => 6,
        ReleaseStatus::NotApplicable => 7,
    }
}

fn durability_tag(value: DurabilityClass) -> u8 {
    match value {
        DurabilityClass::AssertedLocalFsync => 8,
        DurabilityClass::WitnessedExternal => 9,
        DurabilityClass::Unknown => 10,
    }
}

pub fn encode(content: &Content) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(DOMAIN_TAG);
    blob(&mut output, &content.object_a);
    match &content.approval_statement {
        None => output.push(2),
        Some(bytes) => {
            output.push(3);
            blob(&mut output, bytes);
        }
    }
    blob(&mut output, &content.object_b);
    output.push(release_tag(content.release_status));
    blob(&mut output, &content.operation_id);
    output.push(durability_tag(content.durability_class));
    output
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn byte(&mut self, refusal: &'static str) -> Result<u8, String> {
        let byte = self.bytes.get(self.at).copied().ok_or(refusal)?;
        self.at += 1;
        Ok(byte)
    }

    fn blob(&mut self, refusal: &'static str) -> Result<Vec<u8>, String> {
        let mut output = Vec::new();
        loop {
            match self.byte(refusal)? {
                1 => return Ok(output),
                0 => output.push(self.byte(refusal)?),
                _ => return Err(refusal.into()),
            }
        }
    }
}

pub fn decode(bytes: &[u8]) -> Result<Content, String> {
    if !bytes.starts_with(DOMAIN_TAG) {
        return Err("unrecognised three-artifact domain tag".into());
    }
    let mut cursor = Cursor {
        bytes,
        at: DOMAIN_TAG.len(),
    };
    let object_a = cursor.blob("invalid Object A byte frame")?;
    let approval_statement = match cursor.byte("absent Approval Statement tag")? {
        2 => None,
        3 => Some(cursor.blob("invalid Approval Statement byte frame")?),
        _ => return Err("unrecognised Approval Statement tag".into()),
    };
    let object_b = cursor.blob("invalid Object B byte frame")?;
    let release_status = match cursor.byte("absent release_status")? {
        4 => ReleaseStatus::Pending,
        5 => ReleaseStatus::Unknown,
        6 => ReleaseStatus::Released,
        7 => ReleaseStatus::NotApplicable,
        _ => return Err("unrecognised release_status".into()),
    };
    let operation_id = cursor.blob("absent or invalid operation_id")?;
    let durability_class = match cursor.byte("absent durability_class")? {
        8 => DurabilityClass::AssertedLocalFsync,
        9 => DurabilityClass::WitnessedExternal,
        10 => DurabilityClass::Unknown,
        _ => return Err("unrecognised durability_class".into()),
    };
    if cursor.at != bytes.len() {
        return Err("trailing bytes after three-artifact lock".into());
    }
    Ok(Content {
        object_a,
        approval_statement,
        object_b,
        release_status,
        operation_id,
        durability_class,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn exact_round_trip_and_field_discrimination() {
        let expected = witness();
        assert_eq!(decode(&encode(&expected)).unwrap(), expected);
        let mut changed = witness();
        changed.durability_class = DurabilityClass::Unknown;
        assert_ne!(encode(&witness()), encode(&changed));
    }

    #[test]
    fn fourth_durability_values_are_refused() {
        for value in ["best_effort", "asserted_local_fsync_without_prefix"] {
            assert!(serde_json::from_str::<DurabilityClass>(&format!("\"{value}\"")).is_err());
        }
    }

    #[test]
    fn asserted_prefix_survives_serialization() {
        assert_eq!(
            serde_json::from_str::<DurabilityClass>("\"asserted_local_fsync\"").unwrap(),
            DurabilityClass::AssertedLocalFsync
        );
        assert_eq!(durability_tag(DurabilityClass::AssertedLocalFsync), 8);
    }
}
