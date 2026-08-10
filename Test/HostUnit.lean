/- SPDX-License-Identifier: Apache-2.0 -/

import Host
import Kernels

set_option maxRecDepth 4096

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
      target := [.fullArguments] },
    { name := "approve", mode := .deny }
  ]
}

private def dbArgs : Lean.Json :=
  Lean.Json.mkObj [
    ("database", Lean.Json.str "prod"),
    ("sql", Lean.Json.str "drop table users")
  ]

private def dbTarget : SealCore.TargetHash :=
  Seal.guardTarget testPolicy "db.execute" [dbArgs.compress] .absent

private def mkAct (tool : String) (args : Lean.Json) : CanonicalAction :=
  { tool, argsJson := args, ast? := none, raw := "", requestId := Lean.Json.null }

-- Emulate the host's two-phase dispatch for one kernel: commit ingest, then
-- decide on the ingested state.
private def decideS (act : CanonicalAction) (ev : Kernels.SafetyEvidence)
    (st : SealCore.State) : Verdict × SealCore.State :=
  Kernels.safetyKernel.decide act testPolicy ev (Kernels.safetyKernel.ingest ev st)

private def goodLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"drop table users\"}}}"

-- The SealV2 canonical parser is escape-aware: the canonical escape form
-- (SealV2/Escape.lean) encodes ALL Unicode strings with exactly one byte
-- representation, and \t IS the canonical escape of a tab. A line carrying
-- it is genuinely canonical — both views agree.
private def escapedLine : String :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"a\\tb\"}}}"

-- Kernel-section config parsing goes through the policy-v2 bundle now:
-- payload JSON → Seal.parsePolicyBundle → Host.ofBundle → TrustedConfig.
private def cfgSafetyPart : String :=
  "\"safety\":{\"approval\":{\"control_file\":\"/tmp/a\"},\"tools\":[]}"

private def cfgOf (sections : String) : Except String Host.TrustedConfig :=
  (Lean.Json.parse ("{\"epoch\":1," ++ cfgSafetyPart ++ sections ++ "}")
    >>= Seal.parsePolicyBundle) >>= Host.ofBundle

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
  -- Pin of the escape-aware parser: a tools/call carrying an escape is
  -- mediated AND carries a canonical ast — \t is the canonical escape of a
  -- tab, so escaped/Unicode tool args are canonical, decided, never refused.
  -- (Previously the canonical parser rejected escapes and this asserted
  -- ast?.isNone; that parser no longer exists.)
  check "tools/call with escape -> mediated act WITH canonical ast (escape-aware)"
    (match classifyLine escapedLine with
     | .act a => a.tool == "db.execute" && a.ast?.isSome
     | _ => false)
  check "canonical tools/call -> act carries canonical ast"
    (match classifyLine goodLine with | .act a => a.ast?.isSome | _ => false)

  -- checkTrustedConfig: fail-closed loader core
  let payload := "{\"epoch\":3,\"safety\":{\"approval\":{\"control_file\":\"/tmp/a.ndjson\",\"ttl_seconds\":120},\"tools\":[]}}"
  let configPk := "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a"
  let goodSig := "8489877ad60dba5c0a2a0ed391202737f06746fa6d2395171ed9ee952ba95effb3242c3d640cf2ecaef52c52b1418fce3ed14b8ad75ceb08be126efb20f72d08"
  let zeroPk := "0000000000000000000000000000000000000000000000000000000000000000"
  let zeroSig := "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  check "good config accepted, epoch read from signed payload"
    (match checkTrustedConfig configPk payload goodSig with
     | .ok c => c.epoch == 3 | .error _ => false)
  check "wrong signature rejected"
    (match checkTrustedConfig configPk payload zeroSig with
     | .error _ => true | .ok _ => false)
  check "wrong pubkey rejected"
    (match checkTrustedConfig zeroPk payload goodSig with
     | .error _ => true | .ok _ => false)
  check "mutated payload rejected"
    (match checkTrustedConfig configPk (payload ++ " ") goodSig with
     | .error _ => true | .ok _ => false)
  let payloadE0 := "{\"epoch\":0,\"safety\":{\"approval\":{\"control_file\":\"/tmp/a.ndjson\",\"ttl_seconds\":120},\"tools\":[]}}"
  let payloadE0Sig := "1023a1362b4e371d60265e5dc5b0d25100bf133001c3af91dd70c67b86a30e3b75b99ee1fb94515388d8c2cd9c4cf114e84d8da3d9803b0976bd666950553f02"
  check "epoch 0 rejected"
    (match checkTrustedConfig configPk payloadE0 payloadE0Sig with
     | .error _ => true | .ok _ => false)
  -- Non-canonicality now lives in numbers/structure, not strings (the
  -- escape-aware parser admits every string in its one canonical byte form).
  -- A leading-zero integer is non-canonical; Lean.Json would parse past it,
  -- the SealV2 gate must reject it. Asserting the EXACT canonicality error
  -- proves the rejection came from the canonical gate, not from the (garbage)
  -- signature — checkTrustedConfig checks canonicality first.
  let payloadNc := "{\"epoch\":01,\"safety\":{\"approval\":{\"control_file\":\"/tmp/a.ndjson\",\"ttl_seconds\":120},\"tools\":[]}}"
  check "non-canonical payload (leading-zero int) rejected by the canonical gate"
    (match checkTrustedConfig configPk payloadNc zeroSig with
     | .error msg => msg == "config payload is not canonical (SealV2 parse rejected it)"
     | .ok _ => false)
  -- Second structural witness: a duplicate key is non-canonical even though
  -- Lean.Json would swallow it (last write wins).
  let payloadDup := "{\"epoch\":1,\"epoch\":1,\"safety\":{\"approval\":{\"control_file\":\"/tmp/a.ndjson\",\"ttl_seconds\":120},\"tools\":[]}}"
  check "non-canonical payload (duplicate key) rejected by the canonical gate"
    (match checkTrustedConfig configPk payloadDup zeroSig with
     | .error msg => msg == "config payload is not canonical (SealV2 parse rejected it)"
     | .ok _ => false)
  -- Pin of the new behaviour at the config level: a payload whose string
  -- carries a \t escape IS canonical now. This payload was this suite's old
  -- "non-canonical" witness; its rejection today must come from the
  -- signature (garbage here), NOT from the canonical gate.
  let payloadEsc := "{\"epoch\":1,\"safety\":{\"approval\":{\"control_file\":\"/tmp/a\\tb\",\"ttl_seconds\":120},\"tools\":[]}}"
  check "escaped payload is canonical now (rejection is signature-only)"
    (match checkTrustedConfig configPk payloadEsc zeroSig with
     | .error msg => msg == "config signature verification failed"
     | .ok _ => false)
  -- And positively: under its genuine signature the escaped payload is
  -- ACCEPTED end-to-end (this signature was minted for the old
  -- "non-canonical payload rejected" test, which never got as far as
  -- verifying it).
  let payloadEscSig := "fc29ff1d44e60d90373783b3b85e2648840729a3ce602b158562f772d0bbf8431189520dbe6e2aeaf57c01dfbd78571ed7ea3a29047db331e0cffc1489396f0f"
  check "escaped payload accepted under its genuine signature"
    (match checkTrustedConfig configPk payloadEsc payloadEscSig with
     | .ok c => c.epoch == 1 | .error _ => false)

  -- kernel S decision traces (V1 semantics)
  let now := 1000000
  let noEv : Kernels.SafetyEvidence := { now, approvalEvents := [] }
  let act := mkAct "db.execute" dbArgs

  let (v1, st1) := decideS act noEv State.empty
  check "guarded without approval -> deny" (v1.kind == .deny)
  check "deny reason carries target text" (v1.reason == "85545fe075783b72f2703c8b4769da0b5ef1962bc2e8ecf62e3c9bf366a65aca")

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

  -- temporal config section parsing (bundle path)
  check "temporal section parses"
    (match cfgOf ",\"temporal\":{\"policies\":[{\"name\":\"p1\",\"type\":\"no_after\",\"trigger\":[\"a\"],\"forbidden\":[\"b\",\"c\"]}]}" with
     | .ok cfg =>
        match cfg.temporal with
        | [p] => p.name == "p1" && p.trigger == ["a"] && p.forbidden == ["b", "c"]
        | _ => false
     | .error _ => false)
  check "missing temporal section -> no policies"
    (match cfgOf "" with
     | .ok cfg => cfg.temporal.isEmpty
     | .error _ => false)
  check "unknown temporal policy type rejected"
    (match cfgOf ",\"temporal\":{\"policies\":[{\"name\":\"p\",\"type\":\"weird\",\"trigger\":[],\"forbidden\":[]}]}" with
     | .error _ => true | .ok _ => false)
  check "disabled temporal section -> no policies (registered but vacuous)"
    (match cfgOf ",\"temporal\":{\"enabled\":false,\"policies\":[{\"name\":\"p1\",\"type\":\"no_after\",\"trigger\":[\"a\"],\"forbidden\":[\"b\"]}]}" with
     | .ok cfg => cfg.temporal.isEmpty
     | .error _ => false)
  check "unknown top-level config key rejected (typo cannot drop a kernel)"
    (match cfgOf ",\"temporral\":{\"policies\":[]}" with
     | .error e => (e.splitOn "temporral").length > 1 | .ok _ => false)

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

  -- consensus config section parsing (bundle path)
  check "consensus section parses"
    (match cfgOf ",\"consensus\":{\"roster\":[1,2,3],\"votes_file\":\"/tmp/v.ndjson\",\"high_stakes\":[\"payments.send\"]}" with
     | .ok cfg =>
        match cfg.consensus with
        | some c => c.roster == [1, 2, 3] && c.highStakes == ["payments.send"]
        | none => false
     | .error _ => false)
  check "missing consensus section -> none"
    (match cfgOf "" with
     | .ok cfg => cfg.consensus.isNone
     | .error _ => false)
  check "disabled consensus section -> none (enabled:false is deletion)"
    (match cfgOf ",\"consensus\":{\"enabled\":false,\"roster\":[1,2,3],\"votes_file\":\"/tmp/v.ndjson\",\"high_stakes\":[\"payments.send\"]}" with
     | .ok cfg => cfg.consensus.isNone
     | .error _ => false)

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

  -- convergence + calibration config parsing (bundle path)
  check "convergence section parses"
    (match cfgOf ",\"convergence\":{\"tools\":[{\"tool\":\"store.update\",\"op_arg\":\"op\"}]}" with
     | .ok cfg =>
        match cfg.convergence with
        | [r] => r.tool == "store.update" && r.opArg == ["op"]
        | _ => false
     | .error _ => false)
  check "missing convergence section -> empty"
    (match cfgOf "" with
     | .ok cfg => cfg.convergence.isEmpty
     | .error _ => false)
  check "calibration section parses"
    (match cfgOf ",\"calibration\":{\"enabled\":true,\"delta_num\":1,\"delta_den\":20,\"min_samples\":10,\"records_file\":\"/tmp/f.ndjson\",\"gated_tools\":[\"model.act\"]}" with
     | .ok cfg =>
        match cfg.calibration with
        | some c => c.enabled && c.deltaNum == 1 && c.minSamples == 10
        | none => false
     | .error _ => false)
  check "calibration delta >= 1 rejected"
    (match cfgOf ",\"calibration\":{\"enabled\":true,\"delta_num\":2,\"delta_den\":2,\"min_samples\":1,\"records_file\":\"/tmp/f\",\"gated_tools\":[]}" with
     | .error _ => true | .ok _ => false)
  check "calibration enabled:false stays present-but-disabled (double gate)"
    (match cfgOf ",\"calibration\":{\"enabled\":false,\"delta_num\":1,\"delta_den\":20,\"min_samples\":10,\"records_file\":\"/tmp/f.ndjson\",\"gated_tools\":[\"model.act\"]}" with
     | .ok cfg =>
        match cfg.calibration with
        | some c => c.enabled == false
        | none => false
     | .error _ => false)

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

  -- linear + budget config parsing (bundle path)
  check "linear section parses"
    (match cfgOf ",\"linear\":{\"grants_file\":\"/tmp/g.ndjson\",\"tools\":[{\"tool\":\"key.use\",\"cap_arg\":\"key\"}]}" with
     | .ok cfg =>
        match cfg.linear with
        | some { tools := [_], .. } => true
        | _ => false
     | .error _ => false)
  check "budget section parses"
    (match cfgOf ",\"budget\":{\"budgets\":[{\"name\":\"b\",\"cap\":2,\"tools\":[\"x\"]}]}" with
     | .ok cfg =>
        match cfg.budget with
        | [b] => b.cap == 2 && b.costArg.isNone
        | _ => false
     | .error _ => false)

  -- budget config lint: same-name budgets share one counter, so conflicting
  -- caps are a silent misconfiguration — the loader rejects them fail-closed
  check "duplicate budget name with conflicting caps rejected with exact message"
    (match cfgOf ",\"budget\":{\"budgets\":[{\"name\":\"b\",\"cap\":2,\"tools\":[\"x\"]},{\"name\":\"b\",\"cap\":5,\"tools\":[\"y\"]}]}" with
     | .error msg => msg == "duplicate budget name with conflicting caps"
     | .ok _ => false)
  check "same-name equal-cap budgets accepted (one shared counter)"
    (match cfgOf ",\"budget\":{\"budgets\":[{\"name\":\"b\",\"cap\":2,\"tools\":[\"x\"]},{\"name\":\"b\",\"cap\":2,\"tools\":[\"y\"]}]}" with
     | .ok cfg =>
        match cfg.budget with
        | [a, b] => a.name == "b" && b.name == "b" && a.cap == 2 && b.cap == 2
        | _ => false
     | .error _ => false)
  check "budgetCapsConsistent: empty config consistent"
    (Kernels.budgetCapsConsistent [])
  check "budgetCapsConsistent: distinct names always consistent"
    (Kernels.budgetCapsConsistent
      [{ name := "a", cap := 1, tools := [], costArg := none },
       { name := "b", cap := 9, tools := [], costArg := none }])
  check "budgetCapsConsistent: same name same cap consistent"
    (Kernels.budgetCapsConsistent
      [{ name := "a", cap := 3, tools := [], costArg := none },
       { name := "a", cap := 3, tools := [], costArg := none }])
  check "budgetCapsConsistent: same name conflicting caps inconsistent"
    (!Kernels.budgetCapsConsistent
      [{ name := "a", cap := 3, tools := [], costArg := none },
       { name := "a", cap := 4, tools := [], costArg := none }])

  -- V2.1 per-principal budget: the pure counter map at the pair key. (No
  -- AuthenticatedPrincipal is constructed here — the constructor is private,
  -- which is the point; behavioral coverage of decide/verify lives in the
  -- compiled dx_surface_tests lane.)
  let pbSt := Kernels.setPbState (Kernels.setPbState []
    ("alice", "notes") { spent := 2 }) ("bob", "notes") { spent := 1 }
  check "pbState: alice's counter reads back"
    ((Kernels.pbStateFor pbSt ("alice", "notes")).spent == 2)
  check "pbState: bob's counter isolated"
    ((Kernels.pbStateFor pbSt ("bob", "notes")).spent == 1)
  check "pbState: same principal, other budget empty"
    ((Kernels.pbStateFor pbSt ("alice", "other")).spent == 0)
  check "pbState: other principal, same budget empty"
    ((Kernels.pbStateFor pbSt ("carol", "notes")).spent == 0)
  let pk := fun (id pub : String) => ({ id, pubkey := pub } : Host.PrincipalKey)
  let bspec := fun (name : String) (cap : Nat) =>
    ({ name, cap, tools := ["t"], costArg := none } : Kernels.BudgetSpec)
  check "principalsConsistent: well-formed section accepted"
    (Host.principalsConsistent
      { registry := [pk "alice" "aa", pk "bob" "bb"], budgets := [bspec "p" 1] })
  check "principalsConsistent: duplicate id same pubkey accepted"
    (Host.principalsConsistent
      { registry := [pk "alice" "aa", pk "alice" "aa"], budgets := [] })
  check "principalsConsistent: duplicate id different pubkey rejected"
    (!Host.principalsConsistent
      { registry := [pk "alice" "aa", pk "alice" "bb"], budgets := [] })
  check "principalsConsistent: conflicting per-principal caps rejected"
    (!Host.principalsConsistent
      { registry := [pk "alice" "aa"], budgets := [bspec "p" 1, bspec "p" 2] })
  check "principalsConsistent: budgets with empty registry rejected"
    (!Host.principalsConsistent
      { registry := [], budgets := [bspec "p" 1] })
  check "principalsConsistent: empty section accepted"
    (Host.principalsConsistent { registry := [], budgets := [] })

  IO.println "all host unit tests passed"
