// SPDX-License-Identifier: Apache-2.0
//! External parser-boundary instrument over JSONTestSuite.
//!
//! The corpus is vendored at one exact upstream commit. Every vector is
//! embedded byte-for-byte as `params.arguments` in an otherwise fixed MCP
//! `tools/call`; no vector is parsed, normalized, or rewritten first.
//!
//! `y_*` and `n_*` are assertions supplied by JSONTestSuite. The `i_*`
//! implementation-defined class is observation-only: its Rust and Lean views
//! (and any disagreement) are printed, never allowlisted or asserted.

use seal_host_rs::lean::LeanHost;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const CORPUS_COMMIT: &str = "1ef36fa01286573e846ac449e8683f8833c5b26a";
const CORPUS_DIGEST: &str = "c80de9c62f456f949d4479bb686eab521f2362deea15ef9f808d8b45dfd724d3";
const VECTOR_FLOOR: usize = 300;
const CORPUS_DIR_ENV: &str = "JSONTESTSUITE_CORPUS_DIR";

const CALL_PREFIX: &[u8] =
    br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"external.json_corpus","arguments":"#;
const CALL_SUFFIX: &[u8] = b"}}";

#[derive(Clone, Debug, PartialEq, Eq)]
enum RustView {
    Act,
    NotAct,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LeanView {
    Act,
    Passthrough,
    Refuse,
    NonUtf8Refuse,
    SeamError(String),
    ContractViolation(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    rust: RustView,
    lean: LeanView,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VectorClass {
    Yes,
    No,
    ImplementationDefined,
}

struct Vector {
    name: String,
    path: PathBuf,
    class: VectorClass,
}

fn corpus_dir() -> PathBuf {
    env::var_os(CORPUS_DIR_ENV).map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpora/JSONTestSuite/test_parsing"),
        PathBuf::from,
    )
}

fn load_vectors(dir: &Path) -> Result<Vec<Vector>, String> {
    if !dir.is_dir() {
        return Err(format!(
            "JSONTestSuite corpus missing: {} is not a directory \
             (expected commit {CORPUS_COMMIT}; override with {CORPUS_DIR_ENV})",
            dir.display()
        ));
    }

    let entries = fs::read_dir(dir).map_err(|e| {
        format!(
            "JSONTestSuite corpus unreadable at {}: {e} \
             (expected commit {CORPUS_COMMIT})",
            dir.display()
        )
    })?;
    let mut vectors = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| {
            format!(
                "JSONTestSuite corpus entry unreadable at {}: {e}",
                dir.display()
            )
        })?;
        let file_type = entry.file_type().map_err(|e| {
            format!(
                "JSONTestSuite corpus entry type unreadable for {}: {e}",
                entry.path().display()
            )
        })?;
        if !file_type.is_file() {
            return Err(format!(
                "JSONTestSuite corpus contains a non-file entry: {}",
                entry.path().display()
            ));
        }
        let name = entry.file_name().into_string().map_err(|_| {
            format!(
                "JSONTestSuite corpus has a non-UTF-8 filename: {}",
                entry.path().display()
            )
        })?;
        let class = if name.starts_with("y_") && name.ends_with(".json") {
            VectorClass::Yes
        } else if name.starts_with("n_") && name.ends_with(".json") {
            VectorClass::No
        } else if name.starts_with("i_") && name.ends_with(".json") {
            VectorClass::ImplementationDefined
        } else {
            return Err(format!(
                "JSONTestSuite corpus contains an unclassified file: {name}"
            ));
        };
        vectors.push(Vector {
            name,
            path: entry.path(),
            class,
        });
    }
    vectors.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(vectors)
}

/// Aggregate digest format, version 1:
///
/// `domain || Σ(u64be(name_len) || name || u64be(data_len) || data)`,
///
/// with vectors sorted by filename and `domain` equal to the literal below.
/// This commits both names and byte-for-byte contents and detects additions,
/// removals, renames, and edits without requiring Git in the test environment.
fn corpus_digest(vectors: &[Vector]) -> Result<String, String> {
    let mut digest = Sha256::new();
    digest.update(b"JSONTestSuite/test_parsing\0sha256-record-v1\0");
    for vector in vectors {
        let bytes = fs::read(&vector.path).map_err(|e| {
            format!(
                "JSONTestSuite vector unreadable: {}: {e}",
                vector.path.display()
            )
        })?;
        let name = vector.name.as_bytes();
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(&bytes);
    }
    Ok(hex::encode(digest.finalize()))
}

fn envelope(vector: &[u8]) -> Vec<u8> {
    let mut line = Vec::with_capacity(CALL_PREFIX.len() + vector.len() + CALL_SUFFIX.len());
    line.extend_from_slice(CALL_PREFIX);
    line.extend_from_slice(vector);
    line.extend_from_slice(CALL_SUFFIX);
    line
}

fn rust_view(line: &[u8]) -> RustView {
    let Ok(json) = serde_json::from_slice::<Value>(line) else {
        return RustView::NotAct;
    };
    if json.get("method").and_then(Value::as_str) == Some("tools/call")
        && json
            .get("params")
            .and_then(|params| params.get("name"))
            .and_then(Value::as_str)
            .is_some()
    {
        RustView::Act
    } else {
        RustView::NotAct
    }
}

fn lean_view(host: &LeanHost, line: &[u8]) -> LeanView {
    let Ok(line) = std::str::from_utf8(line) else {
        // This is the production host's pre-FFI behavior: bytes that cannot be
        // represented by a Lean String are refused, never forwarded.
        return LeanView::NonUtf8Refuse;
    };
    match host.classify(line) {
        Ok(0) => LeanView::Passthrough,
        Ok(1) => LeanView::Act,
        Ok(2) => LeanView::Refuse,
        Ok(other) => LeanView::ContractViolation(other),
        Err(e) => LeanView::SeamError(e.to_string()),
    }
}

fn observe(host: &LeanHost, vector: &[u8]) -> Observation {
    let line = envelope(vector);
    Observation {
        rust: rust_view(&line),
        lean: lean_view(host, &line),
    }
}

fn is_lean_act(view: &LeanView) -> bool {
    matches!(view, LeanView::Act)
}

#[test]
fn json_test_suite_parser_boundary() {
    let dir = corpus_dir();
    let vectors =
        load_vectors(&dir).unwrap_or_else(|e| panic!("external corpus setup failure: {e}"));

    let mut y_count = 0;
    let mut n_count = 0;
    let mut i_count = 0;
    for vector in &vectors {
        match vector.class {
            VectorClass::Yes => y_count += 1,
            VectorClass::No => n_count += 1,
            VectorClass::ImplementationDefined => i_count += 1,
        }
    }
    let total = vectors.len();
    eprintln!(
        "JSONTestSuite vectors: total={total} y_={y_count} n_={n_count} \
         i_={i_count} asserted_floor={VECTOR_FLOOR}"
    );
    assert!(
        total >= VECTOR_FLOOR,
        "JSONTestSuite vector floor failure: expected at least {VECTOR_FLOOR}, \
         actual {total}, corpus={}",
        dir.display()
    );

    let actual_digest =
        corpus_digest(&vectors).unwrap_or_else(|e| panic!("external corpus setup failure: {e}"));
    assert_eq!(
        actual_digest,
        CORPUS_DIGEST,
        "JSONTestSuite corpus hash mismatch: expected {CORPUS_DIGEST}, \
         actual {actual_digest}, commit={CORPUS_COMMIT}, corpus={}",
        dir.display()
    );

    let host = LeanHost::new();
    let mut failures = Vec::new();
    let mut divergences = 0;
    let mut lean_act = 0;
    let mut lean_passthrough = 0;
    let mut lean_refuse = 0;
    let mut lean_non_utf8_refuse = 0;
    let mut lean_seam_error = 0;
    let mut lean_contract_violation = 0;
    let mut y_lean_act = 0;
    let mut y_lean_refuse = 0;
    let mut y_number_count = 0;
    let mut y_number_lean_act = 0;
    let mut y_number_lean_refuse = 0;
    for vector in vectors {
        let bytes = match fs::read(&vector.path) {
            Ok(bytes) => bytes,
            Err(e) => {
                failures.push(format!("{}: vector became unreadable: {e}", vector.name));
                continue;
            }
        };
        let observation = observe(&host, &bytes);
        match &observation.lean {
            LeanView::Act => lean_act += 1,
            LeanView::Passthrough => lean_passthrough += 1,
            LeanView::Refuse => lean_refuse += 1,
            LeanView::NonUtf8Refuse => lean_non_utf8_refuse += 1,
            LeanView::SeamError(_) => lean_seam_error += 1,
            LeanView::ContractViolation(_) => lean_contract_violation += 1,
        }
        match vector.class {
            VectorClass::No => {
                if observation.rust == RustView::Act || is_lean_act(&observation.lean) {
                    failures.push(format!(
                        "{}: n_* vector reached a mediated act \
                         (rust={:?} lean={:?})",
                        vector.name, observation.rust, observation.lean
                    ));
                }
            }
            VectorClass::Yes => {
                y_lean_act += usize::from(matches!(observation.lean, LeanView::Act));
                y_lean_refuse += usize::from(matches!(observation.lean, LeanView::Refuse));
                if vector.name.starts_with("y_number") {
                    y_number_count += 1;
                    y_number_lean_act += usize::from(matches!(observation.lean, LeanView::Act));
                    y_number_lean_refuse +=
                        usize::from(matches!(observation.lean, LeanView::Refuse));
                }
                if !is_lean_act(&observation.lean) {
                    eprintln!(
                        "JSONTestSuite y_* {} lean={:?}",
                        vector.name, observation.lean
                    );
                }
                let repeated = observe(&host, &bytes);
                if observation != repeated {
                    failures.push(format!(
                        "{}: y_* vector did not reach a deterministic verdict \
                         (first={observation:?} second={repeated:?})",
                        vector.name
                    ));
                }
                if observation.rust != RustView::Act {
                    failures.push(format!(
                        "{}: y_* vector was not accepted by the Rust view \
                         ({observation:?})",
                        vector.name
                    ));
                }
                if matches!(
                    observation.lean,
                    LeanView::SeamError(_) | LeanView::ContractViolation(_)
                ) {
                    failures.push(format!(
                        "{}: y_* vector had no definite Lean verdict \
                         ({observation:?})",
                        vector.name
                    ));
                }
            }
            VectorClass::ImplementationDefined => {
                let divergence =
                    (observation.rust == RustView::Act) != is_lean_act(&observation.lean);
                divergences += usize::from(divergence);
                eprintln!(
                    "JSONTestSuite i_* {} rust={:?} lean={:?} divergence={divergence}",
                    vector.name, observation.rust, observation.lean
                );
            }
        }
    }
    eprintln!(
        "JSONTestSuite complete: total={total} y_={y_count} n_={n_count} \
         i_={i_count} i_divergences={divergences}"
    );
    eprintln!(
        "JSONTestSuite Lean classifications: act={lean_act} \
         passthrough={lean_passthrough} refuse={lean_refuse} \
         non_utf8_refuse={lean_non_utf8_refuse} seam_error={lean_seam_error} \
         contract_violation={lean_contract_violation}"
    );
    eprintln!(
        "JSONTestSuite accepted controls: y_act={y_lean_act}/{y_count} \
         y_refuse={y_lean_refuse}/{y_count} \
         y_number_act={y_number_lean_act}/{y_number_count} \
         y_number_refuse={y_number_lean_refuse}/{y_number_count}"
    );
    if !failures.is_empty() {
        panic!(
            "JSONTestSuite assertion failure(s): {}\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}
