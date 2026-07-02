#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Verifiable-record receipt demo — cold-reviewer runnable in under 5 minutes.
#
#   1. An agent attempts a destructive delete through the mediated MCP boundary.
#   2. seal BLOCKS it (default-deny: no approval for the delete).
#   3. The decision's audit certificate is sealed into a tamper-evident
#      hash-chain (SHA-256), and VERIFIES with one command.
#   4. Tamper check: mutate one sealed entry → the verifier REJECTS.
#
# The block in step 2 is decided by the real Lean-verified gate (the L0
# four-gate kernel, via the Rust host over a `cat` server). The chain in step 3
# is the concrete instance of the machine-checked `Host.Record.tamper_evident`
# theorem (H = SHA-256). No mocks.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="$ROOT/rust/target/release/seal-host-rs"
SEAL="$ROOT/scripts/seal_log.mjs"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [ ! -x "$HOST" ]; then
  echo "building release host…"
  ( cd "$ROOT/rust" && cargo build --release >/dev/null 2>&1 )
fi

# --- trusted policy: db.execute is guarded when the SQL is destructive -------
PK="receipt-demo-pk"
APPROVALS="$WORK/approvals.ndjson"
: > "$APPROVALS"
# Build the stub envelope with node (G1–G5 stub signature scheme:
# `stub-ed25519:<pk>:<payload>` commits to the exact payload bytes).
APPROVALS="$APPROVALS" PK="$PK" node -e '
const payload = JSON.stringify({
  epoch: 1,
  safety: {
    approval: { control_file: process.env.APPROVALS, ttl_seconds: 120 },
    tools: [{
      name: "db.execute", mode: "guarded",
      match: { type: "contains_any_ci", arg: "sql", needles: ["drop","delete","truncate"] },
      target: [{literal:"db"},{arg:"database"},{literal:"write"},{arg:"sql"}]
    }]
  }
});
const envelope = JSON.stringify({ payload, signature: `stub-ed25519:${process.env.PK}:${payload}` });
process.stdout.write(envelope);
' > "$WORK/trusted.json"

echo "==============================================================="
echo " STEP 1+2 — agent attempts destructive deletes; seal decides"
echo "==============================================================="
# A short session: three destructive calls through the mediated boundary.
{
  echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table customers"}}}'
  echo '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"delete from ledger"}}}'
  echo '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"truncate audit"}}}'
} > "$WORK/agent.jsonl"
echo "  agent → 3 destructive db.execute calls (drop / delete / truncate on prod)"

# Drive the real gate. stdout = client-facing responses; stderr = audit certs.
"$HOST" --config "$WORK/trusted.json" --pubkey "$PK" -- /bin/cat \
  < "$WORK/agent.jsonl" > "$WORK/response.jsonl" 2> "$WORK/audit.raw" || true

BLOCKS="$(grep -c 'approval required' "$WORK/response.jsonl" || true)"
echo "  seal  → $BLOCKS/3 BLOCKED by default-deny (nothing reached the database)."
if [ "$BLOCKS" -ne 3 ]; then
  echo "DEMO FAIL: expected 3 BLOCK responses"; cat "$WORK/response.jsonl"; exit 1
fi

# The audit certificates, one per decision (kernel certs, per-gate verdicts).
grep -E '"certs":\[.*"verdict":' "$WORK/audit.raw" > "$WORK/audit.lines" || true
NENTRIES="$(wc -l < "$WORK/audit.lines" | tr -d ' ')"
if [ "$NENTRIES" -lt 3 ]; then
  echo "DEMO FAIL: expected 3 audit certificates, got $NENTRIES"; exit 1
fi
echo "  audit certs: $NENTRIES decisions recorded (one per call)."

echo
echo "==============================================================="
echo " STEP 3 — seal the decision into the tamper-evident record"
echo "==============================================================="
node "$SEAL" seal "$WORK/audit.lines" "$WORK/sealed.json"
echo
echo "  verify the record (one command):"
echo "  \$ node scripts/seal_log.mjs verify sealed.json"
node "$SEAL" verify "$WORK/sealed.json"

echo
echo "==============================================================="
echo " STEP 4a — tamper check: MUTATE a middle entry, re-verify"
echo "==============================================================="
cp "$WORK/sealed.json" "$WORK/mutated.json"
# Rewrite entry 1's recorded verdict deny → allow WITHOUT recomputing the
# chain — exactly what an attacker rewriting history would do.
node -e '
const fs=require("fs"), f=process.argv[1];
const s=JSON.parse(fs.readFileSync(f,"utf8"));
s.entries[1].payload=s.entries[1].payload.replace("\"verdict\":\"deny\"","\"verdict\":\"allow\"");
fs.writeFileSync(f,JSON.stringify(s,null,2)+"\n");
console.log("  attacker rewrote entry 1 (deny → allow), kept the recorded heads");
' "$WORK/mutated.json"
echo "  \$ node scripts/seal_log.mjs verify mutated.json"
if node "$SEAL" verify "$WORK/mutated.json"; then
  echo "DEMO FAIL: verifier accepted a mutated log!"; exit 1
fi
echo "  ✓ mutation REJECTED."

echo
echo "==============================================================="
echo " STEP 4b — tamper check: REORDER two entries, re-verify"
echo "==============================================================="
cp "$WORK/sealed.json" "$WORK/reordered.json"
node -e '
const fs=require("fs"), f=process.argv[1];
const s=JSON.parse(fs.readFileSync(f,"utf8"));
[s.entries[0],s.entries[1]]=[s.entries[1],s.entries[0]];  // swap, keep recorded heads
fs.writeFileSync(f,JSON.stringify(s,null,2)+"\n");
console.log("  attacker swapped entries 0 and 1, kept the recorded heads");
' "$WORK/reordered.json"
echo "  \$ node scripts/seal_log.mjs verify reordered.json"
if node "$SEAL" verify "$WORK/reordered.json"; then
  echo "DEMO FAIL: verifier accepted a reordered log!"; exit 1
fi
echo "  ✓ reorder REJECTED — both mutation and reordering break the hash-chain."

echo
echo "==============================================================="
echo " RECEIPT DEMO PASSED"
echo "   • destructive delete BLOCKED by the Lean-verified gate"
echo "   • decision sealed into a hash-chain (machine-checked structure:"
echo "     Host.Record.tamper_evident, H = SHA-256)"
echo "   • intact log VERIFIES; any mutation is REJECTED"
echo "==============================================================="
