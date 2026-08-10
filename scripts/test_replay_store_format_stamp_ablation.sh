#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Mutation control for the M.4a replay-store namespace encoding-version (format
# stamp) startup gate.
#
# A committed tree is copied to a disposable directory, the namespace
# encoding-version (format stamp) comparison is removed there, and the real-host
# mismatch control must fail by reporting that the mismatched store served a
# request.

set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR=.
fi
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/seal-replay-namespace-version-ablation.XXXXXX")"
MUTANT="$SCRATCH/source"
ARCHIVE="$SCRATCH/source.tar"
BUILD_LOG="$SCRATCH/build.log"
TEST_LOG="$SCRATCH/test.log"

cleanup() {
    rm -rf -- "$SCRATCH"
}
trap cleanup EXIT

mkdir -p "$MUTANT"
git -C "$ROOT" archive --format=tar --output="$ARCHIVE" HEAD
tar -xf "$ARCHIVE" -C "$MUTANT"

git -C "$MUTANT" apply <<'PATCH'
--- a/rust/src/replay_store.rs
+++ b/rust/src/replay_store.rs
@@ -218,8 +218,3 @@
         }
-        if actual.1 != i64::from(expected.namespace_encoding_version) {
-            return Err(ReplayStoreError::new(format!(
-                "replay store namespace-encoding version mismatch: expected {}, found {}",
-                expected.namespace_encoding_version, actual.1
-            )));
-        }
+        // ABLATION: namespace encoding-version (format stamp) comparison removed.
         secure_fs::validate_private_file(path, "replay database").map_err(ReplayStoreError::new)?;
PATCH

export SEAL_FFI_LIB_DIR="${SEAL_FFI_LIB_DIR:-$ROOT/.lake/build/lib}"
export LIBRARY_PATH="$SEAL_FFI_LIB_DIR${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$SEAL_FFI_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# Reuse the already-populated CI target directory. The mutant source path still
# gets its own package fingerprints and artifacts, while dependency artifacts
# are not rebuilt into a second multi-gigabyte tree under /tmp.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/rust/target}"

# Build separately, check its status, and only then execute the artifact.
if ! (
    cd "$MUTANT/rust"
    cargo test --test replay_store_lineage --no-run >"$BUILD_LOG" 2>&1
); then
    echo "ABLATION ERROR: mutant build failed; no artifact was run" >&2
    sed -n '1,240p' "$BUILD_LOG" >&2
    exit 1
fi
echo "ABLATION BUILD: PASS"

set +e
(
    cd "$MUTANT/rust"
    cargo test --test replay_store_lineage \
        mismatched_lineage_refuses_startup_and_names_dimension -- --exact --nocapture \
        >"$TEST_LOG" 2>&1
)
status=$?
set -e

if [[ "$status" -eq 0 ]]; then
    echo "ABLATION FAILURE: mismatch control still passed with the check removed" >&2
    sed -n '1,240p' "$TEST_LOG" >&2
    exit 1
fi
if ! grep -Fq "ABLATION DETECTED: mismatched replay store served a request" "$TEST_LOG"; then
    echo "ABLATION ERROR: test failed for a reason other than serving the mismatched store" >&2
    sed -n '1,240p' "$TEST_LOG" >&2
    exit 1
fi

echo "ABLATION ON: mismatched replay store served; refusal control failed (test exit $status)"
echo "ABLATION RESTORED: disposable mutant removed on exit"
