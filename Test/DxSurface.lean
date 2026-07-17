/- SPDX-License-Identifier: Apache-2.0 -/

import Ffi

/-! # DX-surface teeth: JSON policy in → kernel verdict out, all 7 kernels

End-to-end tests through the policy-v2 DX path: a bundle payload string goes
through `Ffi.modelInitFromTrustedPayload` (SealV2 canonicality →
`Seal.parsePolicyBundle` → `Host.ofBundle`) and mediation steps go through
`Ffi.modelStep` (the same `stepImpl` the native `.so` and wasm export, minus
the FFI marshalling) — the real `registryFor` and two-phase `dispatch`.

Per kernel: at least one deny and one allow case. Vacuity guard (the Part-B
lesson): every positive assertion demands the audit's certs array contain a
certificate NAMING the kernel under test — a scenario where the kernel never
gated anything cannot pass.

Also here: the budget × linear characterization — runtime evidence for the
PROVEN deny-side composition (`Host.registry_deny_ingest_only`,
`Host.dispatch_plan`: denied calls commit no decide-phase state anywhere in
the 7-kernel registry) and for the remaining caller-dimension feature gap
(counters are global by design; a feature gap, not a proof gap). Proofs and
tests are different tripwires — these run the compiled dispatch path the
theorems' IO shell does not cover. -/

open Lean

private def fail (msg : String) : IO Unit :=
  throw <| IO.userError s!"FAIL: {msg}"

private def check (name : String) (b : Bool) : IO Unit :=
  unless b do fail name

/-- Initialise the session from a bundle payload; hard-fails unless accepted. -/
private def initCfg (label payload : String) : IO Unit := do
  let out ← Ffi.modelInitFromTrustedPayload payload
  match Json.parse out with
  | .ok j =>
      unless (j.getObjVal? "ok").toOption == some (Json.bool true) do
        fail s!"{label}: init rejected: {out}"
  | .error e => fail s!"{label}: init returned non-JSON ({e}): {out}"

/-- Initialise expecting rejection; returns the error text. -/
private def initRejected (label payload : String) : IO String := do
  let out ← Ffi.modelInitFromTrustedPayload payload
  match Json.parse out with
  | .ok j =>
      if (j.getObjVal? "ok").toOption == some (Json.bool true) then
        fail s!"{label}: init unexpectedly accepted"; pure ""
      else
        pure (((j.getObjVal? "error").toOption.bind (·.getStr?.toOption)).getD "")
  | .error e => fail s!"{label}: init returned non-JSON ({e}): {out}"; pure ""

private def toolCallLine (id : Nat) (tool : String) (args : Json) : String :=
  (Json.mkObj [
    ("jsonrpc", Json.str "2.0"),
    ("id", Json.num id),
    ("method", Json.str "tools/call"),
    ("params", Json.mkObj [("name", Json.str tool), ("arguments", args)])
  ]).compress

/-- One mediation step; returns the parsed output object. -/
private def step (label : String) (line : String) (now : Nat := 1000000)
    (votes : String := "") (grants : String := "") (forecasts : String := "") :
    IO Json := do
  let input := (Json.mkObj [
    ("line", Json.str line),
    ("now", Json.num now),
    ("approvals", Json.arr #[]),
    ("votes", Json.str votes),
    ("grants", Json.str grants),
    ("forecasts", Json.str forecasts)
  ]).compress
  let out ← Ffi.modelStep input
  match Json.parse out with
  | .ok j => pure j
  | .error e => fail s!"{label}: step returned non-JSON ({e}): {out}"; pure Json.null

private def routeOf (j : Json) : String :=
  ((j.getObjVal? "route").toOption.bind (·.getStr?.toOption)).getD "<none>"

private def certsOf (label : String) (j : Json) : IO (List Json) := do
  let some auditText := (j.getObjVal? "audit").toOption.bind (·.getStr?.toOption)
    | fail s!"{label}: no audit in step output"; pure []
  match Json.parse auditText with
  | .error e => fail s!"{label}: audit not JSON ({e})"; pure []
  | .ok audit =>
      match (audit.getObjVal? "certs").toOption.bind (·.getArr?.toOption) with
      | some arr => pure arr.toList
      | none => fail s!"{label}: audit has no certs array"; pure []

private def certKernel (c : Json) : String :=
  ((c.getObjVal? "kernel").toOption.bind (·.getStr?.toOption)).getD ""

private def certVerdict (c : Json) : String :=
  ((c.getObjVal? "verdict").toOption.bind (·.getStr?.toOption)).getD ""

/-- The vacuity guard: the step's audit must carry a NON-EMPTY certs array
    including a certificate from `kernel` with the expected verdict. -/
private def assertCert (label : String) (j : Json) (kernel verdict : String) :
    IO Unit := do
  let certs ← certsOf label j
  if certs.isEmpty then fail s!"{label}: certs array empty (vacuous scenario)"
  match certs.find? (fun c => certKernel c == kernel) with
  | some c =>
      unless certVerdict c == verdict do
        fail s!"{label}: {kernel} verdict {certVerdict c}, expected {verdict}"
  | none => fail s!"{label}: no certificate from kernel '{kernel}'"

private def assertNoCert (label : String) (j : Json) (kernel : String) :
    IO Unit := do
  let certs ← certsOf label j
  if certs.any (fun c => certKernel c == kernel) then
    fail s!"{label}: unexpected certificate from kernel '{kernel}'"

private def assertRoute (label : String) (j : Json) (route : String) : IO Unit :=
  check s!"{label}: route {routeOf j}, expected {route}" (routeOf j == route)

/-! ## Payloads — one documented bundle per kernel scenario.

Safety gates every call (unmatched tools deny), so each scenario's safety
section explicitly allows the tools that scenario exercises; a deny from a
non-Safety kernel is then attributable to that kernel alone (asserted via its
certificate). -/

private def allowRule (tool : String) : String :=
  "{\"name\":\"" ++ tool ++ "\",\"mode\":\"allow\"}"

private def safetyAllowing (tools : List String) : String :=
  "\"safety\":{\"approval\":{\"control_file\":\"/tmp/dx-approvals.ndjson\"},\"tools\":["
    ++ String.intercalate "," (tools.map allowRule) ++ "]}"

private def payload (sections : List String) : String :=
  "{\"epoch\":1," ++ String.intercalate "," sections ++ "}"

def main : IO Unit := do
  -- ===== S: Safety ========================================================
  -- deny: guarded destructive sql without approval; allow: explicit rule.
  initCfg "S" (payload [
    "\"safety\":{\"approval\":{\"control_file\":\"/tmp/dx-approvals.ndjson\"},\"tools\":[{\"name\":\"db.execute\",\"mode\":\"guard\",\"match\":{\"type\":\"contains_any_ci\",\"arg\":\"sql\",\"needles\":[\"drop\"]},\"target\":[{\"full_arguments\":true}]},{\"name\":\"docs.read\",\"mode\":\"allow\"}]}"])
  let sDeny ← step "S deny" (toolCallLine 1 "db.execute"
    (Json.mkObj [("sql", Json.str "drop table users")]))
  assertRoute "S deny" sDeny "block"
  assertCert "S deny" sDeny "safety" "deny"
  let sAllow ← step "S allow" (toolCallLine 2 "docs.read"
    (Json.mkObj [("path", Json.str "readme")]))
  assertRoute "S allow" sAllow "forward"
  assertCert "S allow" sAllow "safety" "allow"

  -- ===== T: Temporal ======================================================
  -- no_after: once session.revoke executes, audit.read freezes.
  initCfg "T" (payload [
    safetyAllowing ["audit.read", "session.revoke"],
    "\"temporal\":{\"policies\":[{\"name\":\"freeze-after-revoke\",\"type\":\"no_after\",\"trigger\":[\"session.revoke\"],\"forbidden\":[\"audit.read\"]}]}"])
  let tBefore ← step "T allow before trigger" (toolCallLine 1 "audit.read" (Json.mkObj []))
  assertRoute "T allow before trigger" tBefore "forward"
  assertCert "T allow before trigger" tBefore "temporal" "allow"
  let tTrig ← step "T trigger" (toolCallLine 2 "session.revoke" (Json.mkObj []))
  assertRoute "T trigger" tTrig "forward"
  let tAfter ← step "T deny after trigger" (toolCallLine 3 "audit.read" (Json.mkObj []))
  assertRoute "T deny after trigger" tAfter "block"
  assertCert "T deny after trigger" tAfter "temporal" "deny"

  -- ===== C: Consensus =====================================================
  -- strict majority of the trusted roster must ratify the high-stakes tool.
  let cPayload := payload [
    safetyAllowing ["payments.send"],
    "\"consensus\":{\"roster\":[1,2,3],\"votes_file\":\"/tmp/dx-votes.ndjson\",\"high_stakes\":[\"payments.send\"]}"]
  initCfg "C" cPayload
  let cDeny ← step "C deny no quorum" (toolCallLine 1 "payments.send"
    (Json.mkObj [("amount", Json.num 5)]))
  assertRoute "C deny no quorum" cDeny "block"
  assertCert "C deny no quorum" cDeny "consensus" "deny"
  let quorum := "{\"acceptor\":1,\"value\":\"payments.send\"}\n{\"acceptor\":2,\"value\":\"payments.send\"}"
  let cAllow ← step "C allow quorum" (toolCallLine 2 "payments.send"
    (Json.mkObj [("amount", Json.num 5)])) (votes := quorum)
  assertRoute "C allow quorum" cAllow "forward"
  assertCert "C allow quorum" cAllow "consensus" "allow"

  -- ===== V: Convergence ===================================================
  -- only ops in the fixed proven-convergent set are admitted.
  initCfg "V" (payload [
    safetyAllowing ["store.update"],
    "\"convergence\":{\"tools\":[{\"tool\":\"store.update\",\"op_arg\":\"op\"}]}"])
  let vDeny ← step "V deny nonconvergent" (toolCallLine 1 "store.update"
    (Json.mkObj [("op", Json.str "assign")]))
  assertRoute "V deny nonconvergent" vDeny "block"
  assertCert "V deny nonconvergent" vDeny "convergence" "deny"
  let vAllow ← step "V allow convergent" (toolCallLine 2 "store.update"
    (Json.mkObj [("op", Json.str "orset.add")]))
  assertRoute "V allow convergent" vAllow "forward"
  assertCert "V allow convergent" vAllow "convergence" "allow"

  -- ===== K: Calibration (EXPERIMENTAL, double-gated) ======================
  let kSection := fun (enabled : String) =>
    "\"calibration\":{\"enabled\":" ++ enabled ++ ",\"delta_num\":1,\"delta_den\":20,\"min_samples\":10,\"records_file\":\"/tmp/dx-forecasts.ndjson\",\"gated_tools\":[\"model.act\"]}"
  initCfg "K" (payload [safetyAllowing ["model.act"], kSection "true"])
  let overconfident := String.intercalate "\n"
    ((List.range 20).map fun _ => "{\"confidence\":0.9,\"outcome\":0}")
  let kDeny ← step "K deny overconfident" (toolCallLine 1 "model.act" (Json.mkObj []))
    (forecasts := overconfident)
  assertRoute "K deny overconfident" kDeny "block"
  assertCert "K deny overconfident" kDeny "calibration" "deny"
  let calibrated := String.intercalate "\n"
    ((List.range 20).map fun i =>
      "{\"confidence\":0.5,\"outcome\":" ++ (if i % 2 == 0 then "1" else "0") ++ "}")
  let kAllow ← step "K allow calibrated" (toolCallLine 2 "model.act" (Json.mkObj []))
    (forecasts := calibrated)
  assertRoute "K allow calibrated" kAllow "forward"
  assertCert "K allow calibrated" kAllow "calibration" "allow"
  -- enabled:false — damning forecasts supplied, K must not gate at all.
  initCfg "K disabled" (payload [safetyAllowing ["model.act"], kSection "false"])
  let kOff ← step "K disabled not gating" (toolCallLine 3 "model.act" (Json.mkObj []))
    (forecasts := overconfident)
  assertRoute "K disabled not gating" kOff "forward"
  assertNoCert "K disabled not gating" kOff "calibration"

  -- ===== L: Linear resources ==============================================
  -- one grant, one spend; the replay is denied. (The host feeds only NEW
  -- grant-file lines per step — mirrored here: grant on step 1, none later.)
  initCfg "L" (payload [
    safetyAllowing ["key.use"],
    "\"linear\":{\"grants_file\":\"/tmp/dx-grants.ndjson\",\"tools\":[{\"tool\":\"key.use\",\"cap_arg\":\"key\"}]}"])
  let lAllow ← step "L allow granted" (toolCallLine 1 "key.use"
    (Json.mkObj [("key", Json.str "k1")])) (grants := "{\"cap\":\"k1\",\"uses\":1}")
  assertRoute "L allow granted" lAllow "forward"
  assertCert "L allow granted" lAllow "linear" "allow"
  let lDeny ← step "L deny exhausted" (toolCallLine 2 "key.use"
    (Json.mkObj [("key", Json.str "k1")]))
  assertRoute "L deny exhausted" lDeny "block"
  assertCert "L deny exhausted" lDeny "linear" "deny"

  -- ===== B: Budget/rate ===================================================
  -- rate budget cap 2: two calls flow, the third exceeds the cap.
  initCfg "B" (payload [
    safetyAllowing ["notes.add"],
    "\"budget\":{\"budgets\":[{\"name\":\"notes\",\"cap\":2,\"tools\":[\"notes.add\"]}]}"])
  let b1 ← step "B allow 1/2" (toolCallLine 1 "notes.add" (Json.mkObj []))
  assertRoute "B allow 1/2" b1 "forward"
  assertCert "B allow 1/2" b1 "budget" "allow"
  let b2 ← step "B allow 2/2" (toolCallLine 2 "notes.add" (Json.mkObj []))
  assertRoute "B allow 2/2" b2 "forward"
  let b3 ← step "B deny over cap" (toolCallLine 3 "notes.add" (Json.mkObj []))
  assertRoute "B deny over cap" b3 "block"
  assertCert "B deny over cap" b3 "budget" "deny"

  -- ===== enabled:false is deletion, end to end ============================
  initCfg "B disabled" (payload [
    safetyAllowing ["notes.add"],
    "\"budget\":{\"enabled\":false,\"budgets\":[{\"name\":\"notes\",\"cap\":0,\"tools\":[\"notes.add\"]}]}"])
  let bOff ← step "B disabled not gating" (toolCallLine 1 "notes.add" (Json.mkObj []))
  assertRoute "B disabled not gating" bOff "forward"
  assertNoCert "B disabled not gating" bOff "budget"
  initCfg "C disabled" (payload [
    safetyAllowing ["payments.send"],
    "\"consensus\":{\"enabled\":false,\"roster\":[1,2,3],\"votes_file\":\"/tmp/dx-votes.ndjson\",\"high_stakes\":[\"payments.send\"]}"])
  let cOff ← step "C disabled not gating" (toolCallLine 1 "payments.send"
    (Json.mkObj [("amount", Json.num 5)]))
  assertRoute "C disabled not gating" cOff "forward"
  assertNoCert "C disabled not gating" cOff "consensus"

  -- ===== parser strictness reaches the host init path =====================
  let e1 ← initRejected "unknown top-level key" (payload [
    safetyAllowing ["notes.add"], "\"temporral\":{\"policies\":[]}"])
  check "unknown top-level key names the typo" ((e1.splitOn "temporral").length > 1)
  let e2 ← initRejected "unknown section key" (payload [
    safetyAllowing ["notes.add"],
    "\"budget\":{\"budgets\":[],\"cap\":1}"])
  check "unknown section key names the stray" ((e2.splitOn "'cap'").length > 1)

  -- ===== budget × linear honesty characterization =========================
  -- (a) A Safety-denied call spends NO budget: the PROVEN deny composition
  -- (`registry_deny_ingest_only`, `registry_deny_no_budget_spend`, built on
  -- `pureCommit_deny_no_decide_commit`, `budget_commitStep_deny`) exhibited
  -- through the real dispatch path — runtime evidence across the IO shell the
  -- theorems name as TCB. Budget cap 1 covers BOTH tools; the safety-denied
  -- db.execute must leave the whole cap for notes.add.
  initCfg "BxL deny spends nothing" (payload [
    "\"safety\":{\"approval\":{\"control_file\":\"/tmp/dx-approvals.ndjson\"},\"tools\":[{\"name\":\"db.execute\",\"mode\":\"guard\",\"match\":{\"type\":\"contains_any_ci\",\"arg\":\"sql\",\"needles\":[\"drop\"]},\"target\":[{\"full_arguments\":true}]},{\"name\":\"notes.add\",\"mode\":\"allow\"}]}",
    "\"budget\":{\"budgets\":[{\"name\":\"ops\",\"cap\":1,\"tools\":[\"db.execute\",\"notes.add\"]}]}"])
  let x1 ← step "BxL safety-denied call" (toolCallLine 1 "db.execute"
    (Json.mkObj [("sql", Json.str "drop table users")]))
  assertRoute "BxL safety-denied call" x1 "block"
  assertCert "BxL safety-denied call" x1 "safety" "deny"
  let x2 ← step "BxL budget intact after denied call" (toolCallLine 2 "notes.add" (Json.mkObj []))
  assertRoute "BxL budget intact after denied call" x2 "forward"
  assertCert "BxL budget intact after denied call" x2 "budget" "allow"
  let x3 ← step "BxL then cap enforced" (toolCallLine 3 "notes.add" (Json.mkObj []))
  assertRoute "BxL then cap enforced" x3 "block"
  assertCert "BxL then cap enforced" x3 "budget" "deny"

  -- (b) NO CALLER DIMENSION (a feature gap, not a proof gap — counters are
  -- global by design). Two calls differing only in a caller-ish argument
  -- drain ONE counter — the first caller exhausts the second's allowance.
  initCfg "BxL no caller dimension" (payload [
    safetyAllowing ["notes.add"],
    "\"budget\":{\"budgets\":[{\"name\":\"notes\",\"cap\":1,\"tools\":[\"notes.add\"]}]}"])
  let y1 ← step "BxL caller A spends" (toolCallLine 1 "notes.add"
    (Json.mkObj [("caller", Json.str "alice")]))
  assertRoute "BxL caller A spends" y1 "forward"
  let y2 ← step "BxL caller B starved (global counter)" (toolCallLine 2 "notes.add"
    (Json.mkObj [("caller", Json.str "bob")]))
  assertRoute "BxL caller B starved (global counter)" y2 "block"
  assertCert "BxL caller B starved (global counter)" y2 "budget" "deny"

  IO.println "DX-SURFACE TESTS PASS (7 kernels: deny+allow each, enable flags, strictness, budget×linear characterization)"
