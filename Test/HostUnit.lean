/- SPDX-License-Identifier: Apache-2.0 -/

import Host
import Kernels

open Host
open SealCore

def check (name : String) (b : Bool) : IO Unit :=
  unless b do
    throw <| IO.userError s!"FAIL: {name}"

private def mkV (kind : VerdictKind) (reason : String := "r") : Verdict :=
  { kernel := "k", kind, reason, certHash := 0 }

-- Test policy mirroring test/integration: db.execute guarded on destructive
-- sql, approve flat-denied.
private def testPolicy : Seal.Policy := {
  approvalTtlMs := 120000
  approvalFile := System.FilePath.mk "/tmp/unused-approvals.ndjson"
  tools := [
    { name := "db.execute"
      mode := .guarded
      matcher := .containsAnyCi ["sql"] ["drop", "delete", "truncate"]
      target := [.literal "db", .argPath ["database"], .literal "write", .argPath ["sql"]] },
    { name := "approve", mode := .deny }
  ]
}

private def dbArgs : Lean.Json :=
  Lean.Json.mkObj [
    ("database", Lean.Json.str "prod"),
    ("sql", Lean.Json.str "drop table users")
  ]

private def dbTarget : SealCore.Hash :=
  Seal.stableHashParts ["db.execute", "db", "prod", "write", "drop table users"]

private def mkAct (tool : String) (args : Lean.Json) : CanonicalAction :=
  { tool, argsJson := args, ast := SealV2.AST.null, raw := "", requestId := Lean.Json.null }

private def decideS (act : CanonicalAction) (ev : Kernels.SafetyEvidence)
    (st : SealCore.State) : Verdict × SealCore.State :=
  Kernels.safetyKernel.decide act testPolicy ev st

private def goodLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"drop table users\"}}}"

-- Lean.Json accepts the \t escape; the SealV2 canonical parser rejects
-- escape sequences, so this is a tools/call by V1 routing that the canonical
-- gate must block.
private def escapedLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"a\\tb\"}}}"

def main : IO Unit := do
  -- combineVerdicts: fail-closed truth table
  check "empty -> deny" (combineVerdicts [] == .deny)
  check "[allow] -> allow" (combineVerdicts [mkV .allow] == .allow)
  check "[deny] -> deny" (combineVerdicts [mkV .deny] == .deny)
  check "[allow,deny] -> deny" (combineVerdicts [mkV .allow, mkV .deny] == .deny)
  check "[deny,allow] -> deny" (combineVerdicts [mkV .deny, mkV .allow] == .deny)
  check "denyReason picks first deny"
    (denyReason [mkV .allow "a", mkV .deny "b", mkV .deny "c"] == "b")
  check "denyReason empty fail-closed" (denyReason [] == "no kernel gated this call")

  -- classifyLine routing parity with V1 + canonical gate
  check "non-json -> passthrough"
    (match classifyLine "not json at all" with | .passthrough => true | _ => false)
  check "json non-tools/call -> passthrough"
    (match classifyLine "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}" with
     | .passthrough => true | _ => false)
  check "tools/call canonical -> act with tool name"
    (match classifyLine goodLine with | .act a => a.tool == "db.execute" | _ => false)
  check "tools/call with escape -> blockMalformed"
    (match classifyLine escapedLine with | .blockMalformed _ => true | _ => false)

  -- checkTrustedConfig: fail-closed loader core
  let payload := "{\"epoch\":3,\"safety\":{\"approval\":{\"control_file\":\"/tmp/a.ndjson\",\"ttl_seconds\":120},\"tools\":[]}}"
  let goodSig := s!"stub-ed25519:test-pk:{payload}"
  check "good config accepted, epoch read from signed payload"
    (match checkTrustedConfig "test-pk" payload goodSig with
     | .ok c => c.epoch == 3 | .error _ => false)
  check "wrong signature rejected"
    (match checkTrustedConfig "test-pk" payload "stub-ed25519:test-pk:other" with
     | .error _ => true | .ok _ => false)
  check "wrong pubkey rejected"
    (match checkTrustedConfig "other-pk" payload goodSig with
     | .error _ => true | .ok _ => false)
  check "mutated payload rejected"
    (match checkTrustedConfig "test-pk" (payload ++ " ") goodSig with
     | .error _ => true | .ok _ => false)
  let payloadE0 := "{\"epoch\":0,\"safety\":{\"approval\":{\"control_file\":\"/tmp/a.ndjson\",\"ttl_seconds\":120},\"tools\":[]}}"
  check "epoch 0 rejected"
    (match checkTrustedConfig "test-pk" payloadE0 s!"stub-ed25519:test-pk:{payloadE0}" with
     | .error _ => true | .ok _ => false)
  -- \t escape makes the payload non-canonical even though Lean.Json parses it
  let payloadNc := "{\"epoch\":1,\"safety\":{\"approval\":{\"control_file\":\"/tmp/a\\tb\",\"ttl_seconds\":120},\"tools\":[]}}"
  check "non-canonical payload rejected"
    (match checkTrustedConfig "test-pk" payloadNc s!"stub-ed25519:test-pk:{payloadNc}" with
     | .error _ => true | .ok _ => false)

  -- kernel S decision traces (V1 semantics)
  let now := 1000000
  let noEv : Kernels.SafetyEvidence := { now, approvalEvents := [] }
  let act := mkAct "db.execute" dbArgs

  let (v1, st1) := decideS act noEv State.empty
  check "guarded without approval -> deny" (v1.kind == .deny)
  check "deny reason carries target text" (v1.reason == toString dbTarget.toNat)

  let approvedEv : Kernels.SafetyEvidence :=
    { now, approvalEvents := [.approval dbTarget (now + 120000)] }
  let (v2, st2) := decideS act approvedEv st1
  check "guarded with live approval -> allow" (v2.kind == .allow)
  let (v3, _) := decideS act { now, approvalEvents := [] } st2
  check "approval consumed: replay -> deny" (v3.kind == .deny)

  let expiredEv : Kernels.SafetyEvidence :=
    { now, approvalEvents := [.approval dbTarget now] }
  let (v4, _) := decideS act expiredEv State.empty
  check "expired approval -> deny" (v4.kind == .deny)

  let (v5, _) := decideS (mkAct "unknown.tool" Lean.Json.null) noEv State.empty
  check "unknown tool -> deny" (v5.kind == .deny)

  let (v6, _) := decideS (mkAct "approve" Lean.Json.null) noEv State.empty
  check "flat deny tool -> deny" (v6.kind == .deny)

  let benignArgs := Lean.Json.mkObj [("database", Lean.Json.str "prod"), ("sql", Lean.Json.str "select 1")]
  let (v7, _) := decideS (mkAct "db.execute" benignArgs) noEv State.empty
  check "guarded tool, unmatched needles -> deny (V1 unmatched-policy semantics)" (v7.kind == .deny)

  IO.println "all host unit tests passed"
