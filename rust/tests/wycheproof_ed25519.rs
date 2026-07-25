// SPDX-License-Identifier: Apache-2.0
//! External Ed25519 verification instrument over Project Wycheproof.
//!
//! The corpus is one byte-for-byte file pinned to an exact upstream commit.
//! `valid` and `invalid` are asserted. `acceptable` is observation-only.

use ed25519_dalek::VerifyingKey;
use seal_host_rs::providers::verify_ed25519_signature;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const CORPUS_COMMIT: &str = "b61843a9a5115bb758134b6a1f5d5e502d445342";
const CORPUS_DIGEST: &str = "70471c053c711731f2195ef4875b60ea7f5d6793939d99058ac12da810cb8e00";
const VECTOR_FLOOR: usize = 150;
const CORPUS_FILE_ENV: &str = "WYCHEPROOF_ED25519_CORPUS_FILE";
const FORCE_INVALID_VERIFIED_ENV: &str = "WYCHEPROOF_FORCE_INVALID_VERIFIED_TC_ID";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Corpus {
    number_of_tests: usize,
    test_groups: Vec<TestGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestGroup {
    public_key: PublicKey,
    tests: Vec<TestVector>,
}

#[derive(Debug, Deserialize)]
struct PublicKey {
    pk: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum VectorResult {
    Valid,
    Invalid,
    Acceptable,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestVector {
    tc_id: u64,
    flags: Vec<String>,
    msg: String,
    sig: String,
    result: VectorResult,
}

fn corpus_path() -> PathBuf {
    env::var_os(CORPUS_FILE_ENV).map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpora/Wycheproof/ed25519_test.json"),
        PathBuf::from,
    )
}

fn force_invalid_verified_tc_id() -> Option<u64> {
    env::var(FORCE_INVALID_VERIFIED_ENV).ok().map(|value| {
        value.parse().unwrap_or_else(|e| {
            panic!(
                "invalid {FORCE_INVALID_VERIFIED_ENV} value {value:?}: \
                 expected a decimal tcId: {e}"
            )
        })
    })
}

fn seal_verifies(group: &TestGroup, test: &TestVector) -> bool {
    let public_key: [u8; 32] = match hex::decode(&group.public_key.pk)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
    {
        Some(public_key) => public_key,
        None => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&public_key) {
        Ok(verifying_key) => verifying_key,
        Err(_) => return false,
    };
    let message = hex::decode(&test.msg).unwrap_or_else(|e| {
        panic!(
            "Wycheproof Ed25519 malformed message hex: tcId={} error={e}",
            test.tc_id
        )
    });
    verify_ed25519_signature(&verifying_key, &message, &test.sig)
}

#[test]
fn wycheproof_ed25519_verification() {
    let path = corpus_path();
    let bytes = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "Wycheproof Ed25519 corpus unreadable at {}: {e} \
             (expected commit {CORPUS_COMMIT}; override with {CORPUS_FILE_ENV})",
            path.display()
        )
    });
    let corpus: Corpus = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "Wycheproof Ed25519 corpus parse failure at {}: {e}",
            path.display()
        )
    });

    let mut valid_count = 0;
    let mut invalid_count = 0;
    let mut acceptable_count = 0;
    for test in corpus.test_groups.iter().flat_map(|group| &group.tests) {
        match test.result {
            VectorResult::Valid => valid_count += 1,
            VectorResult::Invalid => invalid_count += 1,
            VectorResult::Acceptable => acceptable_count += 1,
        }
    }
    let total = valid_count + invalid_count + acceptable_count;
    eprintln!(
        "Wycheproof Ed25519 vectors: total={total} valid={valid_count} \
         invalid={invalid_count} acceptable={acceptable_count} asserted_floor={VECTOR_FLOOR}"
    );
    assert!(
        total >= VECTOR_FLOOR,
        "Wycheproof Ed25519 vector floor failure: expected at least {VECTOR_FLOOR}, \
         actual {total}, corpus={}",
        path.display()
    );
    assert_eq!(
        corpus.number_of_tests,
        total,
        "Wycheproof Ed25519 declared vector count mismatch: declared {}, \
         actual {total}, corpus={}",
        corpus.number_of_tests,
        path.display()
    );

    let actual_digest = hex::encode(Sha256::digest(&bytes));
    assert_eq!(
        actual_digest,
        CORPUS_DIGEST,
        "Wycheproof Ed25519 corpus hash mismatch: expected {CORPUS_DIGEST}, \
         actual {actual_digest}, commit={CORPUS_COMMIT}, corpus={}",
        path.display()
    );

    let force_invalid_verified = force_invalid_verified_tc_id();
    for group in &corpus.test_groups {
        for test in &group.tests {
            let verified = seal_verifies(group, test);
            match test.result {
                VectorResult::Valid => assert!(
                    verified,
                    "Wycheproof Ed25519 valid vector did not verify: tcId={} \
                     flags={:?} seal=not_verified",
                    test.tc_id, test.flags
                ),
                VectorResult::Invalid => {
                    let forced = force_invalid_verified == Some(test.tc_id);
                    assert!(
                        !verified && !forced,
                        "Wycheproof Ed25519 invalid vector verified: tcId={} \
                         flags={:?} seal={} forced_appears_verified={forced}",
                        test.tc_id,
                        test.flags,
                        if verified { "verified" } else { "not_verified" }
                    );
                }
                VectorResult::Acceptable => eprintln!(
                    "Wycheproof Ed25519 acceptable tcId={} flags={:?} seal={}",
                    test.tc_id,
                    test.flags,
                    if verified { "verified" } else { "not_verified" }
                ),
            }
        }
    }
    eprintln!(
        "Wycheproof Ed25519 complete: total={total} valid={valid_count} \
         invalid={invalid_count} acceptable={acceptable_count}"
    );
}
