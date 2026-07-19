#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Anti-drift gate for the single-source policy codec.
#
#   1. BYTE-COMPARE `seal-host-rs schema` against the schema artifact checked
#      into the pinned authority (.lake/packages/mcp-seal/docs/
#      policy-bundle.schema.json). A stale artifact fails CI.
#   2. Run `seal-host-rs validate` — the Lean parser chain AND the
#      emitted-schema validator in the SAME invocation — over every real
#      policy payload in the repo (config examples, profile payloads,
#      envelope example) and assert full agreement (agree_accept).
#   3. Run the negative parity corpus (unknown keys, missing fields, wrong
#      types, enum/discriminator, aliases, defaults, parser-only
#      refinements) and assert the EXPECTED agreement class per case —
#      including the host-layer duplicate-Budget-cap rejection the signer
#      does not check (lean stage=host, schema accepts: the documented gap).
#
# Any schema_rejects_parsed_policy anywhere is drift and fails (exit 1 from
# the binary); any unexpected agreement class fails this script.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
BIN="${SEAL_HOST_BIN:-rust/target/debug/seal-host-rs}"
ARTIFACT=".lake/packages/mcp-seal/docs/policy-bundle.schema.json"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> [1/3] schema byte-compare vs pinned authority artifact"
"$BIN" schema > "$TMP/schema.json"
if ! diff -u "$ARTIFACT" "$TMP/schema.json"; then
  echo "FAIL: emitted schema differs from pinned authority artifact" >&2
  exit 1
fi
echo "    schema byte-identical to $ARTIFACT"

expect_class() { # file expected-class [expected-lean-stage]
  local file="$1" expected="$2" stage="${3:-}"
  local line
  line="$("$BIN" validate "$file")" || {
    # nonzero exit is legal only for expected hard failures; we never expect one
    echo "FAIL: validate exited nonzero on $file" >&2; exit 1; }
  local got
  got="$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["agreement"])')"
  if [ "$got" != "$expected" ]; then
    echo "FAIL: $file expected $expected got $got" >&2
    printf '%s\n' "$line" >&2
    exit 1
  fi
  if [ -n "$stage" ]; then
    local gotstage
    gotstage="$(printf '%s' "$line" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["lean_stage"])')"
    if [ "$gotstage" != "$stage" ]; then
      echo "FAIL: $file expected lean stage $stage got $gotstage" >&2
      printf '%s\n' "$line" >&2
      exit 1
    fi
  fi
  echo "    ok: $(basename "$file") -> $expected${stage:+ (stage=$stage)}"
}

echo "==> [2/3] real payloads: parser and schema must both accept"
for f in config/payload.example.json config/trusted.example.json \
         profiles/policies-v1/*.payload.json profiles/policies-v2/*.payload.json; do
  expect_class "$f" agree_accept
done

echo "==> [3/3] negative parity corpus"
SAFETY='"safety":{"approval":{"control_file":"/tmp/a","ttl_seconds":60},"tools":[{"name":"t","mode":"guard","target":[{"full_arguments":true}]}]}'

mk() { printf '%s' "$2" > "$TMP/$1"; }

# agree_reject: strictness both sides see
mk unknown-top.json          '{"epoch":1,'"$SAFETY"',"temporral":{}}'
mk unknown-section-key.json  '{"epoch":1,'"$SAFETY"',"budget":{"budgets":[],"cap":1}}'
mk unknown-entry-key.json    '{"epoch":1,'"$SAFETY"',"budget":{"budgets":[{"name":"n","cap":1,"tools":[],"costs":1}]}}'
mk missing-epoch.json        '{'"$SAFETY"'}'
mk epoch-zero.json           '{"epoch":0,'"$SAFETY"'}'
mk missing-safety.json       '{"epoch":1}'
mk missing-control-file.json '{"epoch":1,"safety":{"approval":{"ttl_seconds":9},"tools":[]}}'
mk wrong-type-cap.json       '{"epoch":1,'"$SAFETY"',"budget":{"budgets":[{"name":"n","cap":"1","tools":[]}]}}'
mk bad-mode-enum.json        '{"epoch":1,"safety":{"approval":{"control_file":"c"},"tools":[{"name":"t","mode":"block"}]}}'
mk bad-match-discriminator.json '{"epoch":1,"safety":{"approval":{"control_file":"c"},"tools":[{"name":"t","mode":"guard","match":{"type":"regex","arg":"a"}}]}}'
mk bad-temporal-type.json    '{"epoch":1,'"$SAFETY"',"temporal":{"policies":[{"name":"n","type":"eventually","trigger":[],"forbidden":[]}]}}'
for f in unknown-top unknown-section-key unknown-entry-key missing-epoch epoch-zero \
         missing-safety missing-control-file wrong-type-cap bad-mode-enum \
         bad-match-discriminator bad-temporal-type; do
  expect_class "$TMP/$f.json" agree_reject
done

# agree_accept: aliases, defaults, permissive interior, every match variant
mk alias-guarded.json        '{"epoch":1,"safety":{"approval":{"control_file":"c"},"tools":[{"name":"a","mode":"guard"},{"name":"b","mode":"guarded"}]}}'
mk defaults.json             '{"epoch":1,"safety":{"approval":{"control_file":"c"},"tools":[{"name":"t","mode":"allow"}]}}'
mk permissive-interior.json  '{"epoch":1,"safety":{"approval":{"control_file":"c"},"tools":[{"name":"t","mode":"guard","_comment":"x","match":{"type":"always","note":1},"target":[{"literal":"x","junk":[]}]}]}}'
mk match-variants.json       '{"epoch":1,"safety":{"approval":{"control_file":"c"},"tools":[{"name":"t","mode":"guard","match":{"type":"all","matches":[{"type":"always"},{"type":"equals","arg":"a.b","value":"v"},{"type":"starts_with","arg":"p","value":"q"},{"type":"contains_any_ci","arg":"s","needles":["x"]},{"type":"any","matches":[{"type":"always"}]}]}}]}}'
mk target-literal-first.json '{"epoch":1,"safety":{"approval":{"control_file":"c"},"tools":[{"name":"t","mode":"guard","target":[{"literal":"x","arg":"ignored"},{"arg":"a.b"},{"full_arguments":true}]}]}}'
for f in alias-guarded defaults permissive-interior match-variants target-literal-first; do
  expect_class "$TMP/$f.json" agree_accept
done

# parser_refinement: Lean-only refinements the schema cannot express
mk server-conflict.json      '{"epoch":1,"server":"outer","safety":{"server":"inner","approval":{"control_file":"c"},"tools":[]}}'
mk calibration-delta.json    '{"epoch":1,'"$SAFETY"',"calibration":{"delta_num":3,"delta_den":2,"min_samples":1,"records_file":"r","gated_tools":[]}}'
mk pathological-number.json  '{"epoch":1,'"$SAFETY"',"budget":{"budgets":[{"name":"n","cap":1e9999999,"tools":[]}]}}'
expect_class "$TMP/server-conflict.json" parser_refinement parse
expect_class "$TMP/calibration-delta.json" parser_refinement parse
# both lanes refuse the pathological exponent (Lean: fail-closed number
# guard; serde_json: "number out of range"), so this is agree_reject —
# asserted with the stage pinned so the Lean side is provably the guard.
expect_class "$TMP/pathological-number.json" agree_reject number-guard

# the signer/host gap: duplicate Budget cap conflict — parser AND schema
# accept, the host mapping rejects; `seal validate` must catch it (stage=host)
mk dup-budget-cap.json       '{"epoch":1,'"$SAFETY"',"budget":{"budgets":[{"name":"n","cap":1,"tools":[]},{"name":"n","cap":2,"tools":[]}]}}'
expect_class "$TMP/dup-budget-cap.json" parser_refinement host

# equal-cap duplicates stay legal end to end
mk dup-budget-equal.json     '{"epoch":1,'"$SAFETY"',"budget":{"budgets":[{"name":"n","cap":1,"tools":[]},{"name":"n","cap":1,"tools":[]}]}}'
expect_class "$TMP/dup-budget-equal.json" agree_accept

echo "POLICY SCHEMA GATE PASS"
