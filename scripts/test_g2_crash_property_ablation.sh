#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Product-mutation ablation for the G2 crash properties (T1/T3).
#
# The G2 crash suite in rust/tests/host_path.rs is the only place that pins
# what a mid-transaction process death may and may not leave behind. Every
# structural check we have — check 11 of the PINS gate included — witnesses
# that those tests exist, are armed with a crash point, and are selected by CI.
# None of them witnesses that the assertions inside them are load-bearing: an
# assertion body can be hollowed out
# (`assert!(rows[0].1.is_some(), "...")` -> `let _ = (rows[0].1.is_some(), "...")`)
# with the test name, attributes, arming tuple, crash behaviour and CI
# selection all intact, and every local signal — the suite itself included —
# stays green.
#
# The detector for that is the dual of the hollowing. A hollow assertion cannot
# fail on a deliberately broken product, so:
#
#     MUTATE THE PRODUCT. EXPECT THE SUITE TO FAIL.
#
# A committed tree is archived into a disposable directory, ONE product mutant
# is applied there per round, and the G2 test that is supposed to pin the
# broken property must fail — by name, and with the specific assertion message
# that names the property. A mutant round that PASSES is the gutted-assertion
# detector firing: this script then goes red (fail closed), because the only
# way a broken product satisfies its own crash test is that the test no longer
# asserts anything about it.
#
# Each mutant targets a DIFFERENT property in a DIFFERENT file, so a single
# hollow assertion cannot hide behind another test's coverage.
#
# The unmutated tree is run first as the harness control. If the G2 tests do
# not pass unmutated, nothing after that means anything and the script says so
# rather than reporting mutant "failures" that are really harness failures.
#
# The mutants exist only as patch input here. They are never applied to the
# working tree and never compiled from a normal source tree.

set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR=.
fi
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/seal-g2-crash-property-ablation.XXXXXX")"
ARCHIVE="$SCRATCH/source.tar"
LOG_DIR="$SCRATCH/logs"

cleanup() {
    rm -rf -- "$SCRATCH"
}
trap cleanup EXIT

mkdir -p "$LOG_DIR"
git -C "$ROOT" archive --format=tar --output="$ARCHIVE" HEAD

export SEAL_FFI_LIB_DIR="${SEAL_FFI_LIB_DIR:-$ROOT/.lake/build/lib}"
export LIBRARY_PATH="$SEAL_FFI_LIB_DIR${LIBRARY_PATH:+:$LIBRARY_PATH}"
export LD_LIBRARY_PATH="$SEAL_FFI_LIB_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
# Reuse the already-populated CI target directory. The mutant source paths get
# their own package fingerprints and artifacts; dependency artifacts are not
# rebuilt into a second multi-gigabyte tree under the scratch mount.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/rust/target}"

# extract_tree <destination>
extract_tree() {
    local destination="$1"
    mkdir -p "$destination"
    tar -xf "$ARCHIVE" -C "$destination"
}

# Mutant 1 — T3 property: the two-phase burn commits at RECORDED.
#
# `commit_consumed_approval_nonce` is phase 2 of the burn: at RECORDED, the
# consumed approval's nonce flips from reserved hold to committed burn
# (rust/src/main.rs, "Two-phase burn, phase 2 (G2 cut (a))"). Skipping it
# leaves `committed_at` NULL, so the crash at `g2-after-burn` lands on a hold
# rather than a burn, startup recovery reclaims it, and the used approval is
# spendable again — precisely the defect G2 T3 exists to forbid
# ("Recovery must NOT un-burn the used approval").
read -r -d '' MUTANT_1_PATCH <<'PATCH' || true
--- a/rust/src/main.rs
+++ b/rust/src/main.rs
@@ -443,13 +443,8 @@
     let Some(nonce) = &record.nonce else {
         return Ok(());
     };
-    a3.commit_nonce(nonce, now_ms).map_err(|error| {
-        eprintln!(
-            "{}",
-            json!({
-                "error": "approval nonce burn commit failure",
-                "detail": error.to_string()
-            })
-        );
-    })
+    // ABLATION: phase 2 of the two-phase burn is skipped. RECORDED leaves the
+    // nonce a reserved hold instead of a committed burn.
+    let _ = (a3, nonce, now_ms);
+    Ok(())
 }
PATCH

# Mutant 3 — T1 recovery property: receipt reconciliation deletes unmatched
# open holds. This is the production mechanism that currently covers the
# older A3Filter::with_store reclaim path.
read -r -d '' MUTANT_3_PATCH <<'PATCH' || true
--- a/rust/src/replay_store.rs
+++ b/rust/src/replay_store.rs
@@ -321,9 +321,5 @@
                     params![nonce, committed_at_ms],
                 )?;
             } else {
-                tx.execute(
-                    "DELETE FROM nonces WHERE nonce = ?1 AND committed_at IS NULL",
-                    params![nonce],
-                )?;
-                reclaimed += 1;
+                // ABLATION: unmatched RECORDED holds are not reclaimed.
             }
         }
         for nonce in recorded_nonces {
# Mutant 4 — residual G2 property: receipt-backed holds are committed during
# startup reconciliation after a crash at g2-after-record.
read -r -d '' MUTANT_4_PATCH <<'PATCH' || true
--- a/rust/src/replay_store.rs
+++ b/rust/src/replay_store.rs
@@ -317,8 +317,4 @@
             }
             if recorded_nonces.contains(&nonce) {
-                tx.execute(
-                    "UPDATE nonces SET committed_at = ?2
-                     WHERE nonce = ?1 AND committed_at IS NULL",
-                    params![nonce, committed_at_ms],
-                )?;
+                // ABLATION: receipt-backed hold is not committed.
             } else {
PATCH

# Mutant 5 — cut (b): pending durable releases resume exactly once.
read -r -d '' MUTANT_5_PATCH <<'PATCH' || true
--- a/rust/src/release.rs
+++ b/rust/src/release.rs
@@ -695,7 +695,7 @@
             if self.commit_operation_state(&path)? {
                 report.redone_state_transitions += 1;
             }
             self.transition(&path, ReleaseStatus::Pending, ReleaseStatus::Unknown)?;
-            forward(&release.frame)?;
+            // ABLATION: pending release is not forwarded after restart.
             self.transition(&path, ReleaseStatus::Unknown, ReleaseStatus::Released)?;
             report.released += 1;
PATCH

# Mutant 2 — T1 property: startup recovery reclaims an unrecorded hold.
#
# `A3Filter::with_store` reclaims, before any state is read, every hold that
# never reached RECORDED (rust/src/a3.rs, "Startup recovery, before any state
# is read"). Skipping it leaves the dead process's reservation in the store, so
# after the T1 crash at `g2-before-record` the restarted host still sees the
# nonce as held and refuses the byte-identical re-presentation as a replay —
# an approval that was never used is permanently burned.
read -r -d '' MUTANT_2_PATCH <<'PATCH' || true
--- a/rust/src/a3.rs
+++ b/rust/src/a3.rs
@@ -52,5 +52,5 @@
         // reached RECORDED belongs to a dead process. Reclaiming it makes
         // the crash indistinguishable from the approval never having been
         // presented. Committed burns are untouched (T3 direction).
-        replay_store.reclaim_uncommitted()?;
+        // ABLATION: startup reclaim of never-RECORDED holds is skipped.
         replay_store.prune_expired(now_ms)?;
PATCH

# Mutant 6 — cut (c): committed operation state is reconciled before release.
read -r -d '' MUTANT_6_PATCH <<'PATCH' || true
--- a/rust/src/release.rs
+++ b/rust/src/release.rs
@@ -695,4 +695,2 @@
-            if self.commit_operation_state(&path)? {
-                report.redone_state_transitions += 1;
-            }
+            // ABLATION: operation state is not reconciled.
+             self.transition(&path, ReleaseStatus::Pending, ReleaseStatus::Unknown)?;
PATCH

# Mutant 7 — cut (d): an ambiguous partial child write is never retried.
read -r -d '' MUTANT_7_PATCH <<'PATCH' || true
--- a/rust/src/release.rs
+++ b/rust/src/release.rs
@@ -685,4 +685,8 @@
             let (_, release) = self.read_verified(&path)?;
             let Some(release) = release else { continue };
+            if release.status == ReleaseStatus::Unknown {
+                // ABLATION: ambiguous release is incorrectly finalized.
+                self.transition(&path, ReleaseStatus::Unknown, ReleaseStatus::Released)?;
+            }
             if release.status != ReleaseStatus::Pending {
                 continue;
             }
PATCH

# Mutant 8 — cut (e): a Released operation is not emitted again before ack.
read -r -d '' MUTANT_8_PATCH <<'PATCH' || true
--- a/rust/src/release.rs
+++ b/rust/src/release.rs
@@ -685,4 +685,8 @@
             let (_, release) = self.read_verified(&path)?;
             let Some(release) = release else { continue };
+            if release.status == ReleaseStatus::Released {
+                // ABLATION: already Released operation is emitted again.
+                forward(&release.frame)?;
+            }
             if release.status != ReleaseStatus::Pending {
                 continue;
             }
PATCH

failed=0

# run_g2_test <tree> <test_name> <log>
# Runs exactly one G2 test in one scratch tree. Returns the cargo exit status.
run_g2_test() {
    local tree="$1"
    local test_name="$2"
    local log="$3"
    local status=0

    (
        cd "$tree/rust"
        cargo test --test host_path "$test_name" -- --exact --nocapture >"$log" 2>&1
    ) || status=$?
    return "$status"
}

# The harness control. An unmutated scratch tree must pass the G2 tests. If it
# does not, the mutant rounds below would "fail" for harness reasons and a
# broken probe would read as a working one.
CONTROL_TREE="$SCRATCH/control"
extract_tree "$CONTROL_TREE"

if ! (
    cd "$CONTROL_TREE/rust"
    cargo test --test host_path --no-run >"$LOG_DIR/control-build.log" 2>&1
); then
    echo "ABLATION ERROR: unmutated scratch tree failed to build; no artifact was run" >&2
    sed -n '1,240p' "$LOG_DIR/control-build.log" >&2
    exit 1
fi

for control_test in \
    g2_t1_crash_between_reserve_and_recorded_recovers_the_approval \
    g2_t3_crash_after_recorded_keeps_burn_and_receipt \
    g2_crash_after_recorded_before_commit_reconciles_burn \
    g2_cut_b_recorded_receipt_redoes_state_and_releases_on_restart \
    g2_cut_c_committed_state_resumes_release_once_on_restart \
    g2_cut_d_partial_child_write_is_ambiguous_and_not_retried_on_restart \
    g2_cut_e_released_operation_is_not_released_again_before_ack
do
    if ! run_g2_test "$CONTROL_TREE" "$control_test" "$LOG_DIR/control-$control_test.log"; then
        echo "ABLATION ERROR: $control_test FAILED in the UNMUTATED scratch tree." >&2
        echo "The harness is broken; no mutant result below would mean anything." >&2
        sed -n '1,240p' "$LOG_DIR/control-$control_test.log" >&2
        exit 1
    fi
    echo "ABLATION CONTROL: unmutated $control_test ... ok"
done
rm -rf -- "$CONTROL_TREE"

# expect_mutant_kills_test <label> <patch> <test_name> <assertion_message>
#
# Applies one product mutant to a fresh scratch tree and requires the named G2
# test to fail there, citing the assertion that pins the mutated property.
expect_mutant_kills_test() {
    local label="$1"
    local patch="$2"
    local test_name="$3"
    local assertion="$4"
    local tree="$SCRATCH/mutant-$label"
    local build_log="$LOG_DIR/$label-build.log"
    local test_log="$LOG_DIR/$label-test.log"
    local status=0

    extract_tree "$tree"
    if ! printf '%s\n' "$patch" | git -C "$tree" apply --whitespace=nowarn -; then
        echo "ABLATION ERROR: mutant $label did not apply; the product moved under it" >&2
        failed=1
        rm -rf -- "$tree"
        return
    fi

    # Build separately, check its status, and only then execute the artifact. A
    # mutant that does not compile proves nothing about the assertions.
    if ! (
        cd "$tree/rust"
        cargo test --test host_path --no-run >"$build_log" 2>&1
    ); then
        echo "ABLATION ERROR: mutant $label failed to build; no artifact was run" >&2
        sed -n '1,240p' "$build_log" >&2
        failed=1
        rm -rf -- "$tree"
        return
    fi
    echo "ABLATION BUILD: mutant $label compiles"

    run_g2_test "$tree" "$test_name" "$test_log" || status=$?

    if [[ "$status" -eq 0 ]]; then
        echo "ABLATION FAILURE: $test_name PASSED against mutant $label" >&2
        echo "The product property is broken and its own crash test does not notice." >&2
        echo "Either the assertion is hollow or the test never pinned this property." >&2
        sed -n '1,240p' "$test_log" >&2
        failed=1
        rm -rf -- "$tree"
        return
    fi
    if ! grep -Fq "test $test_name ... FAILED" "$test_log"; then
        echo "ABLATION ERROR: mutant $label did not produce the named test failure" >&2
        sed -n '1,240p' "$test_log" >&2
        failed=1
        rm -rf -- "$tree"
        return
    fi
    if ! grep -Fq "$assertion" "$test_log"; then
        echo "ABLATION ERROR: $test_name failed under mutant $label for some other" >&2
        echo "reason than the mutated property; expected assertion: $assertion" >&2
        sed -n '1,240p' "$test_log" >&2
        failed=1
        rm -rf -- "$tree"
        return
    fi

    echo "ABLATION ON: mutant $label — test $test_name ... FAILED (\"$assertion\")"
    rm -rf -- "$tree"
}

expect_mutant_kills_test \
    t3-burn-not-committed \
    "$MUTANT_1_PATCH" \
    g2_t3_crash_after_recorded_keeps_burn_and_receipt \
    "the burn committed at RECORDED"

expect_mutant_kills_test \
    t1-hold-not-reclaimed \
    "$MUTANT_2_PATCH" \
    g2_t1_crash_between_reserve_and_recorded_recovers_the_approval \
    "recovery reclaimed the unrecorded hold: state as if never presented"

expect_mutant_kills_test \
    t1-reconcile-hold-not-deleted \
    "$MUTANT_3_PATCH" \
    g2_t1_crash_between_reserve_and_recorded_recovers_the_approval \
    "reconcile_recorded reclaimed the unmatched hold"

expect_mutant_kills_test \
    after-record-reconcile-not-committed \
    "$MUTANT_4_PATCH" \
    g2_crash_after_recorded_before_commit_reconciles_burn \
    "reconcile_recorded committed the receipt-backed hold"

expect_mutant_kills_test \
    pending-release-not-forwarded \
    "$MUTANT_5_PATCH" \
    g2_cut_b_recorded_receipt_redoes_state_and_releases_on_restart \
    "crash recovery property for g2-b-after-recorded"

expect_mutant_kills_test \
    operation-state-not-reconciled \
    "$MUTANT_6_PATCH" \
    g2_cut_c_committed_state_resumes_release_once_on_restart \
    "crash recovery property for g2-c-after-state-commit"

expect_mutant_kills_test \
    ambiguous-release-retried \
    "$MUTANT_7_PATCH" \
    g2_cut_d_partial_child_write_is_ambiguous_and_not_retried_on_restart \
    "crash recovery property for g2-d-during-child-write"

expect_mutant_kills_test \
    released-operation-retried \
    "$MUTANT_8_PATCH" \
    g2_cut_e_released_operation_is_not_released_again_before_ack \
    "crash recovery property for g2-e-after-released"

if [[ "$failed" -ne 0 ]]; then
    echo "G2 crash-property ablation did not kill every mutated property" >&2
    exit 1
fi

echo "G2 crash-property ablation killed all eight mutated properties"
echo "ABLATION RESTORED: disposable mutant trees removed on exit"
