#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Mutation test for the v1 approval refusal boundary.
#
# The production source always refuses v1 approvals. This script archives the
# committed tree into a temporary directory, changes the one shared refusal
# helper there to restore v1 admission, and proves that every named refusal
# test fails under that mutation. The mutated source is deleted on exit.

set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR=.
fi
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/seal-v1-refusal-ablation.XXXXXX")"
MUTANT="$SCRATCH/source"
ARCHIVE="$SCRATCH/source.tar"
LOG_DIR="$SCRATCH/logs"

cleanup() {
    rm -rf -- "$SCRATCH"
}
trap cleanup EXIT

mkdir -p "$MUTANT" "$LOG_DIR"
git -C "$ROOT" archive --format=tar --output="$ARCHIVE" HEAD
tar -xf "$ARCHIVE" -C "$MUTANT"

# This is the ablation control: both v1-capable providers call this one helper.
# The insecure body exists only as patch input here, never in a compiled normal
# source tree.
git -C "$MUTANT" apply <<'PATCH'
--- a/rust/src/providers.rs
+++ b/rust/src/providers.rs
@@ -452,14 +452,9 @@
 fn refuse_v1_approval(
     poll: &mut ApprovalPoll,
     drop_counter: &mut u64,
     source: &'static str,
     record: ApprovalRecord,
 ) {
-    let redaction_material = record_redaction_material(&record);
-    poll.warnings.push(ApprovalDropWarning::new(
-        drop_counter,
-        source,
-        V1_APPROVAL_REFUSAL_REASON,
-        redaction_material,
-    ));
+    let _ = (drop_counter, source);
+    poll.records.push(record);
 }
PATCH

export SEAL_FFI_LIB_DIR="${SEAL_FFI_LIB_DIR:-$ROOT/.lake/build/lib}"
export LIBRARY_PATH="$SEAL_FFI_LIB_DIR${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$SEAL_FFI_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export CARGO_TARGET_DIR="$SCRATCH/target"

failed=0

expect_refusal_test_failure() {
    local test_name="$1"
    shift
    local log="$LOG_DIR/$test_name.log"
    local status

    set +e
    (
        cd "$MUTANT/rust"
        cargo test "$@" >"$log" 2>&1
    )
    status=$?
    set -e

    if [[ "$status" -eq 0 ]]; then
        echo "ABLATION FAILURE: $test_name PASSED with v1 admission restored" >&2
        echo "The refusal assertion is not load-bearing: $test_name" >&2
        failed=1
        return
    fi
    if ! grep -Fq "test $test_name ... FAILED" "$log"; then
        echo "ABLATION ERROR: $test_name did not produce its named test failure" >&2
        sed -n '1,240p' "$log" >&2
        failed=1
        return
    fi

    echo "ABLATION ON: test $test_name ... FAILED"
}

for test_name in \
    ed25519_provider_refuses_valid_v1_and_rejects_tampered \
    ed25519_provider_scalar_range_and_negative_controls \
    ed25519_provider_refuses_signed_v1_allow_and_accepts_decline \
    ed25519_provider_refuses_v1_absent_and_allow \
    control_file_refuses_v1_absent_and_allow_and_declines_deny
do
    expect_refusal_test_failure \
        "providers::tests::$test_name" \
        --lib "providers::tests::$test_name" -- --exact
done

expect_refusal_test_failure \
    v1_refusal_happens_before_replay_admission \
    --test host_path v1_refusal_happens_before_replay_admission -- --exact

if [[ "$failed" -ne 0 ]]; then
    echo "v1 refusal ablation did not kill every required assertion" >&2
    exit 1
fi

echo "v1 refusal ablation killed all six required assertions"
