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

-- Emulate the host's two-phase dispatch for one kernel: commit ingest, then
-- decide on the ingested state.
private def decideS (act : CanonicalAction) (ev : Kernels.SafetyEvidence)
    (st : SealCore.State) : Verdict × SealCore.State :=
  Kernels.safetyKernel.decide act testPolicy ev (Kernels.safetyKernel.ingest ev st)

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

  -- kernel T: no-destructive-after-revoke over Temporal.monitor
  let pol : Kernels.TemporalPolicy :=
    { name := "no-destructive-after-revoke"
      trigger := ["session.revoke"]
      forbidden := ["db.execute"] }
  let decideT := fun (tool : String) (st : Kernels.TemporalState) =>
    Kernels.temporalKernel.decide (mkAct tool Lean.Json.null) [pol] () st
  let t0 : Kernels.TemporalState := Kernels.temporalKernel.init

  let (tv1, t1) := decideT "db.execute" t0
  check "T: destructive before revoke -> allow" (tv1.kind == .allow)
  let (tv2, t2) := decideT "session.revoke" t1
  check "T: revoke itself -> allow" (tv2.kind == .allow)
  let (tv3, t3) := decideT "db.execute" t2
  check "T: destructive after revoke -> deny" (tv3.kind == .deny)
  check "T: deny reason names policy" (tv3.reason == "temporal policy violated: no-destructive-after-revoke")
  check "T: denied call not appended to trace" (t3.executed == t2.executed)
  let (tv4, _) := decideT "other.tool" t2
  check "T: unrelated tool after revoke -> allow" (tv4.kind == .allow)
  let (tv5, _) := decideT "db.execute" { executed := ["db.execute", "other.tool"] }
  check "T: no trigger executed -> destructive still allowed" (tv5.kind == .allow)
  check "T: empty policy list allows" ((Kernels.temporalKernel.decide (mkAct "db.execute" Lean.Json.null) [] () t2).1.kind == .allow)

  -- temporal config section parsing
  let temporalJson := "{\"epoch\":1,\"temporal\":{\"policies\":[{\"name\":\"p1\",\"type\":\"no_after\",\"trigger\":[\"a\"],\"forbidden\":[\"b\",\"c\"]}]}}"
  check "temporal section parses"
    (match Lean.Json.parse temporalJson >>= parseTemporalSection with
     | .ok [p] => p.name == "p1" && p.trigger == ["a"] && p.forbidden == ["b", "c"]
     | _ => false)
  check "missing temporal section -> no policies"
    (match Lean.Json.parse "{\"epoch\":1}" >>= parseTemporalSection with
     | .ok [] => true | _ => false)
  check "unknown temporal policy type rejected"
    (match Lean.Json.parse "{\"temporal\":{\"policies\":[{\"name\":\"p\",\"type\":\"weird\",\"trigger\":[],\"forbidden\":[]}]}}" >>= parseTemporalSection with
     | .error _ => true | .ok _ => false)

  -- kernel C: quorum-certificate gate over Consensus.Checker.validB
  let cCfg : Kernels.ConsensusConfig :=
    { roster := [1, 2, 3]
      votesFile := System.FilePath.mk "/tmp/unused-votes.ndjson"
      highStakes := ["payments.send"] }
  let pay := mkAct "payments.send" Lean.Json.null
  let decideC := fun (votes : Consensus.Checker.Votes) =>
    (Kernels.consensusKernel.decide pay cCfg votes ()).1
  check "C: gates high-stakes tool" (Kernels.consensusKernel.gates cCfg pay == true)
  check "C: ignores other tools" (Kernels.consensusKernel.gates cCfg (mkAct "db.execute" Lean.Json.null) == false)
  check "C: 2-of-3 quorum -> allow" ((decideC [(1, "payments.send"), (2, "payments.send")]).kind == .allow)
  check "C: no votes -> deny" ((decideC []).kind == .deny)
  check "C: minority 1-of-3 -> deny" ((decideC [(1, "payments.send")]).kind == .deny)
  check "C: duplicate voter does not double-count"
    ((decideC [(1, "payments.send"), (1, "payments.send")]).kind == .deny)
  check "C: rogue acceptor outside roster -> deny"
    ((decideC [(9, "payments.send"), (1, "payments.send")]).kind == .deny)
  check "C: acceptor's first vote binds (conflicting later vote rejected)"
    ((decideC [(1, "other.value"), (1, "payments.send"), (2, "payments.send")]).kind == .deny)
  check "C: 3-of-3 -> allow"
    ((decideC [(1, "payments.send"), (2, "payments.send"), (3, "payments.send")]).kind == .allow)

  -- consensus config section parsing
  let consensusJson := "{\"consensus\":{\"roster\":[1,2,3],\"votes_file\":\"/tmp/v.ndjson\",\"high_stakes\":[\"payments.send\"]}}"
  check "consensus section parses"
    (match Lean.Json.parse consensusJson >>= parseConsensusSection with
     | .ok (some c) => c.roster == [1, 2, 3] && c.highStakes == ["payments.send"]
     | _ => false)
  check "missing consensus section -> none"
    (match Lean.Json.parse "{\"epoch\":1}" >>= parseConsensusSection with
     | .ok none => true | _ => false)

  -- kernel V: only proven-convergent ops admitted
  let vCfg : Kernels.ConvergenceConfig := [{ tool := "store.update", opArg := ["op"] }]
  let storeAct := fun (op : Lean.Json) =>
    mkAct "store.update" (Lean.Json.mkObj [("op", op)])
  let decideV := fun (args : Lean.Json) =>
    (Kernels.convergenceKernel.decide (mkAct "store.update" args) vCfg () ()).1
  check "V: gates replicated tool"
    (Kernels.convergenceKernel.gates vCfg (storeAct (Lean.Json.str "x")) == true)
  check "V: ignores other tools"
    (Kernels.convergenceKernel.gates vCfg (mkAct "db.execute" Lean.Json.null) == false)
  check "V: convergent op (orset.add) -> allow"
    ((decideV (Lean.Json.mkObj [("op", Lean.Json.str "orset.add")])).kind == .allow)
  check "V: gcounter.inc -> allow"
    ((decideV (Lean.Json.mkObj [("op", Lean.Json.str "gcounter.inc")])).kind == .allow)
  check "V: LWW assign -> deny"
    ((decideV (Lean.Json.mkObj [("op", Lean.Json.str "assign")])).kind == .deny)
  check "V: missing op field -> deny" ((decideV Lean.Json.null).kind == .deny)
  check "V: non-scalar op -> deny"
    ((decideV (Lean.Json.mkObj [("op", Lean.Json.arr #[])])).kind == .deny)

  -- kernel K: calibration gate (experimental)
  let kCfg : Kernels.CalibrationConfig :=
    { enabled := true, deltaNum := 1, deltaDen := 20, minSamples := 10
      recordsFile := System.FilePath.mk "/tmp/unused-forecasts.ndjson"
      gatedTools := ["model.act"] }
  let modelAct := mkAct "model.act" Lean.Json.null
  let decideK := fun (records : List Kernels.ForecastRecord) =>
    (Kernels.calibrationKernel.decide modelAct kCfg records ()).1
  let calibrated : List Kernels.ForecastRecord :=
    (List.range 20).map fun i => { confidence := 0.5, outcome := i % 2 == 0 }
  let overconfident : List Kernels.ForecastRecord :=
    (List.range 20).map fun _ => { confidence := 0.9, outcome := false }
  check "K: gates configured tool" (Kernels.calibrationKernel.gates kCfg modelAct == true)
  check "K: ignores other tools"
    (Kernels.calibrationKernel.gates kCfg (mkAct "db.execute" Lean.Json.null) == false)
  check "K: calibrated window -> allow" ((decideK calibrated).kind == .allow)
  check "K: overconfident forecaster -> deny" ((decideK overconfident).kind == .deny)
  check "K: too few samples -> deny (fail-closed)"
    ((decideK (calibrated.take 5)).kind == .deny)
  check "K: empty window -> deny" ((decideK []).kind == .deny)

  -- convergence + calibration config parsing
  check "convergence section parses"
    (match Lean.Json.parse "{\"convergence\":{\"tools\":[{\"tool\":\"store.update\",\"op_arg\":\"op\"}]}}" >>= parseConvergenceSection with
     | .ok [r] => r.tool == "store.update" && r.opArg == ["op"]
     | _ => false)
  check "missing convergence section -> empty"
    (match Lean.Json.parse "{}" >>= parseConvergenceSection with
     | .ok [] => true | _ => false)
  let kJson := "{\"calibration\":{\"enabled\":true,\"delta_num\":1,\"delta_den\":20,\"min_samples\":10,\"records_file\":\"/tmp/f.ndjson\",\"gated_tools\":[\"model.act\"]}}"
  check "calibration section parses"
    (match Lean.Json.parse kJson >>= parseCalibrationSection with
     | .ok (some c) => c.enabled && c.deltaNum == 1 && c.minSamples == 10
     | _ => false)
  check "calibration delta >= 1 rejected"
    (match Lean.Json.parse "{\"calibration\":{\"enabled\":true,\"delta_num\":2,\"delta_den\":2,\"min_samples\":1,\"records_file\":\"/tmp/f\",\"gated_tools\":[]}}" >>= parseCalibrationSection with
     | .error _ => true | .ok _ => false)

  -- kernel L: linear capability accounting (no double-spend)
  let lCfg : Kernels.LinearConfig :=
    { grantsFile := System.FilePath.mk "/tmp/unused-grants.ndjson"
      tools := [{ tool := "key.use", capArg := ["key"] }] }
  let keyAct := mkAct "key.use" (Lean.Json.mkObj [("key", Lean.Json.str "k7")])
  let decideL := fun (st : LinearCore.LState) =>
    Kernels.linearKernel.decide keyAct lCfg [] st
  check "L: gates configured tool" (Kernels.linearKernel.gates lCfg keyAct == true)
  check "L: never-granted capability -> deny" ((decideL LinearCore.LState.empty).1.kind == .deny)
  let lst1 := Kernels.linearKernel.ingest [.grant "k7" 1] LinearCore.LState.empty
  let (lv1, lst2) := decideL lst1
  check "L: granted once -> first spend allows" (lv1.kind == .allow)
  let (lv2, _) := decideL lst2
  check "L: double-spend -> deny" (lv2.kind == .deny)
  check "L: deny names double-spend" (lv2.reason == "capability exhausted, double-spend denied: k7")
  let lst3 := Kernels.linearKernel.ingest [.grant "k7" 2] LinearCore.LState.empty
  let (lw1, lst4) := decideL lst3
  let (lw2, lst5) := decideL lst4
  let (lw3, _) := decideL lst5
  check "L: multiplicity 2 -> exactly two spends"
    (lw1.kind == .allow && lw2.kind == .allow && lw3.kind == .deny)
  check "L: missing capability field -> deny"
    ((Kernels.linearKernel.decide (mkAct "key.use" Lean.Json.null) lCfg [] lst3).1.kind == .deny)

  -- kernel B: monotone budget gate
  let bCfg : Kernels.BudgetConfig :=
    [{ name := "db-calls", cap := 2, tools := ["db.execute"], costArg := none },
     { name := "spend", cap := 10, tools := ["payments.send"], costArg := some ["amount"] }]
  let dbAct := mkAct "db.execute" Lean.Json.null
  let decideB := fun (a : CanonicalAction) (st : Kernels.BudgetState) =>
    Kernels.budgetKernel.decide a bCfg () st
  check "B: gates covered tool" (Kernels.budgetKernel.gates bCfg dbAct == true)
  let (bv1, bst1) := decideB dbAct Kernels.budgetKernel.init
  let (bv2, bst2) := decideB dbAct bst1
  let (bv3, _) := decideB dbAct bst2
  check "B: call-rate cap 2 -> two allows then deny"
    (bv1.kind == .allow && bv2.kind == .allow && bv3.kind == .deny)
  let payAmt := fun (n : Nat) =>
    mkAct "payments.send" (Lean.Json.mkObj [("amount", Lean.Json.num n)])
  let (bw1, bst3) := decideB (payAmt 7) Kernels.budgetKernel.init
  let (bw2, _) := decideB (payAmt 4) bst3
  check "B: cost-arg budget 7 then 4 over cap 10 -> deny second"
    (bw1.kind == .allow && bw2.kind == .deny)
  check "B: missing cost field -> deny"
    ((decideB (mkAct "payments.send" Lean.Json.null) Kernels.budgetKernel.init).1.kind == .deny)

  -- linear + budget config parsing
  check "linear section parses"
    (match Lean.Json.parse "{\"linear\":{\"grants_file\":\"/tmp/g.ndjson\",\"tools\":[{\"tool\":\"key.use\",\"cap_arg\":\"key\"}]}}" >>= parseLinearSection with
     | .ok (some c) => c.tools.length == 1
     | _ => false)
  check "budget section parses"
    (match Lean.Json.parse "{\"budget\":{\"budgets\":[{\"name\":\"b\",\"cap\":2,\"tools\":[\"x\"]}]}}" >>= parseBudgetSection with
     | .ok [b] => b.cap == 2 && b.costArg.isNone
     | _ => false)

  IO.println "all host unit tests passed"
