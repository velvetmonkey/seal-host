/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import Host.Canonical
import Host.Step
import Host.Config
import Host.Registry
import Host.Audit
import Host.Evidence
import Seal.Block
import Kernels

/-!
# FFI surface — the verified decide, exported to the Rust host

The Rust host owns transport (stdio MITM, child process), the approval
back-channel providers, A3 freshness (nonce/replay/TTL) and the wall clock.
Lean owns everything decision-bearing: canonical parsing, config
verification, every kernel's `ingest`/`decide`, the fail-closed
AND-combination and the audit certs. The seam is string-in/string-out JSON —
no structs cross the boundary.

TCB note (documented in TCB.md): this boundary GROWS the trusted base — the
Rust transport, the evidence gatherers, the C ABI and the JSON marshalling
are all trusted, where the pure-Lean stdio host trusts only the Lean
runtime. The stdio sidecar remains the cleanest assurance story; the FFI
host trades TCB for deployability.

Threading: the exports are NOT thread-safe; the Rust host serialises calls
(it does — single mediation thread).
-/

namespace Ffi

open Lean Host

structure Session where
  config : TrustedConfig
  safetyRef : IO.Ref SealCore.State
  temporalRef : IO.Ref Kernels.TemporalState
  linearRef : IO.Ref LinearCore.LState
  budgetRef : IO.Ref Kernels.BudgetState
  unitRef : IO.Ref Unit

initialize sessionRef : IO.Ref (Option Session) ← IO.mkRef none

private def errJson (msg : String) : String :=
  (Json.mkObj [("ok", Json.bool false), ("error", Json.str msg)]).compress

private def initFromConfig (config : TrustedConfig) : IO String := do
  let session : Session := {
    config
    safetyRef := ← IO.mkRef SealCore.State.empty
    temporalRef := ← IO.mkRef Kernels.temporalKernel.init
    linearRef := ← IO.mkRef LinearCore.LState.empty
    budgetRef := ← IO.mkRef []
    unitRef := ← IO.mkRef ()
  }
  sessionRef.set (some session)
  pure <| (Json.mkObj [
    ("ok", Json.bool true),
    ("epoch", toJson config.epoch),
    ("approval_ttl_ms", toJson config.safety.approvalTtlMs),
    ("approval_file", Json.str config.safety.approvalFile.toString),
    ("votes_file", Json.str (config.consensus.map (·.votesFile.toString) |>.getD "")),
    ("grants_file", Json.str (config.linear.map (·.grantsFile.toString) |>.getD "")),
    ("forecasts_file", Json.str (config.calibration.map (·.recordsFile.toString) |>.getD ""))
  ]).compress

/-- Initialise the session from the signed config envelope. Returns a JSON
    summary the Rust host needs for evidence gathering (file paths, TTL), or
    `{ok: false, error}` — fail-closed, no session on any failure. -/
private def initImpl (envelopeText publicKey : String) : IO String := do
  match checkEnvelope envelopeText publicKey with
  | .error err => pure (errJson s!"trusted config rejected: {err}")
  | .ok config => initFromConfig config

/-- Build the same registry `Host.Main` builds, with evidence injected from
    the step input instead of gathered from IO — `Host.dispatch` (two-phase
    ingest/decide commit) is reused verbatim.

    Public for SPECIFICATION only (see `FfiSpec.lean`: `registryFor_kernels`
    proves this list selects exactly `activeKernels s.config`, Safety and
    Temporal unconditionally). NOT callable API — the sole call site is
    `stepImpl` below; do not add another. -/
def registryFor (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) : Registry :=
  [ { kernel := Kernels.safetyKernel
      config := s.config.safety
      stateRef := s.safetyRef
      gather := fun _ => pure { now, approvalEvents } },
    { kernel := Kernels.temporalKernel
      config := s.config.temporal
      stateRef := s.temporalRef
      gather := fun _ => pure () } ]
  ++ (match s.config.consensus with
      | some cfg =>
          [{ kernel := Kernels.consensusKernel, config := cfg,
             stateRef := s.unitRef, gather := fun _ => pure votes }]
      | none => [])
  ++ (if s.config.convergence.isEmpty then []
      else
        [{ kernel := Kernels.convergenceKernel, config := s.config.convergence,
           stateRef := s.unitRef, gather := fun _ => pure () }])
  ++ (match s.config.calibration with
      | some cfg =>
          if cfg.enabled then
            [{ kernel := Kernels.calibrationKernel, config := cfg,
               stateRef := s.unitRef, gather := fun _ => pure forecasts }]
          else []
      | none => [])
  ++ (match s.config.linear with
      | some cfg =>
          [{ kernel := Kernels.linearKernel, config := cfg,
             stateRef := s.linearRef, gather := fun _ => pure grants }]
      | none => [])
  ++ (if s.config.budget.isEmpty then []
      else
        [{ kernel := Kernels.budgetKernel, config := s.config.budget,
           stateRef := s.budgetRef, gather := fun _ => pure () }])

private def getStrD (j : Json) (key : String) (d : String) : String :=
  ((j.getObjVal? key).toOption.bind (·.getStr?.toOption)).getD d

/-- The client-facing response for a line refused before parsing (a pathological
    numeric literal). A JSON-RPC "Invalid Request" — `id` is null because
    recovering the request id would mean parsing the line the guard refused to
    parse. Fixed bytes, so every lane emits the same block response. -/
private def refuseResponseLine : String :=
  (Json.mkObj [
    ("jsonrpc", Json.str "2.0"),
    ("id", Json.null),
    ("error", Json.mkObj [
      ("code", Json.num (-32600)),
      ("message", Json.str "seal-host: request refused — unsafe numeric literal")
    ])
  ]).compress ++ "\n"

/-- One mediation step. Input JSON:
    `{line, now, approvals: [{target, issuedAt?}], votes, grants, forecasts}`
    (votes/grants/forecasts as raw file text; approvals already A3-filtered
    by the Rust host). Output JSON:
    `{route: "passthrough"|"forward"|"block", response?, audit?}`. -/
private def stepImpl (inputText : String) : IO String := do
  let some session ← sessionRef.get
    | pure (errJson "session not initialised")
  -- Fail closed before parsing the step envelope: a pathological numeric
  -- literal in the STRUCTURE (e.g. `now` or an approval `issuedAt` with a
  -- monster exponent) would abort `Json.parse` here. The attacker-controlled
  -- wire line is a string field (inert to this parse; its own pathological
  -- numbers are caught by `classifyLine`'s guard), so this covers the
  -- host-supplied numeric fields. (Seal.JsonUtil.wireNumbersSafe.)
  if !Seal.JsonUtil.wireNumbersSafe inputText then
    pure (errJson "bad step input: unsafe numeric literal")
  else
  match Json.parse inputText with
  | .error err => pure (errJson s!"bad step input: {err}")
  | .ok input => do
      let line := getStrD input "line" ""
      let now := ((input.getObjVal? "now").toOption.bind (·.getNat?.toOption)).getD 0
      let approvals := Evidence.approvalEventsFromJson
        ((input.getObjVal? "approvals").toOption.getD (Json.arr #[]))
        now session.config.safety.approvalTtlMs
      let votes := Host.Evidence.parseVotesText (getStrD input "votes" "")
      let grants := Host.Evidence.parseGrantsText (getStrD input "grants" "")
      let forecasts := Host.Evidence.parseForecastsText (getStrD input "forecasts" "")
      let lc := classifyLine line
      match lc with
      | .passthrough =>
          pure (Json.mkObj [("route", Json.str "passthrough")]).compress
      | .refuse =>
          -- Pathological numeric literal (monster exponent): fail closed. Block
          -- the line WITHOUT parsing (no `Nat.pow` abort) and WITHOUT forwarding
          -- (no bypass). No act, no verdicts ⇒ no audit certificate. Every lane
          -- runs this same branch, so the bytes are identical.
          pure (Json.mkObj [
            ("route", Json.str "block"),
            ("response", Json.str refuseResponseLine)
          ]).compress
      | .act act => do
          let registry := registryFor session now approvals votes grants forecasts
          let (combined, verdicts) ← dispatch registry act
          -- `line` is the SAME binding `classifyLine` judged above — one
          -- binding, no rewrites (mirrors rust/src/main.rs). The kernel's
          -- request commitment is therefore over the exact bytes it judged.
          let audit := auditLine session.config.epoch act.tool combined verdicts line
          -- Route through the PURE `Host.stepRoute` — the function
          -- `step_forward_non_bypass` (Host.Composition) is proven over.
          -- `stepRoute (.act act) verdicts = .forward ↔ combineVerdicts verdicts
          -- = .allow` (`stepRoute_act_forward_iff`), and `dispatch` returns
          -- `combined = combineVerdicts verdicts`, so this is byte-identical to
          -- routing on `combined` directly.
          match Host.stepRoute lc verdicts with
          | .forward =>
              pure (Json.mkObj [
                ("route", Json.str "forward"), ("audit", Json.str audit)]).compress
          | .block =>
              pure (Json.mkObj [
                ("route", Json.str "block"),
                ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
                ("audit", Json.str audit)
              ]).compress
          | .passthrough =>
              -- Unreachable: `stepRoute (.act _)` is `.forward`/`.block` only.
              -- Fail-closed to block if ever reached.
              pure (Json.mkObj [
                ("route", Json.str "block"),
                ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
                ("audit", Json.str audit)
              ]).compress

/-- Conformance-bridge model oracle. These call the SAME private `initImpl` /
    `stepImpl` the FFI exports below wrap, but WITHOUT the `unsafe`/`unsafeBaseIO`
    marshalling — so `lake env lean --run` evaluates the real Lean decision core
    in the interpreter. The bridge diffs this against the compiled native `.so`
    (and, as a stretch, the emscripten wasm) to test that codegen preserves the
    proven decisions + audit bytes on the corpus. NOT an FFI export. -/
def modelInit (envelopeText publicKey : String) : IO String :=
  initImpl envelopeText publicKey

/-- MODEL ORACLE ONLY. This intentionally bypasses config-signature verification
    because the Lean interpreter cannot execute the `@[extern]` Ed25519 leaf.
    It is not `@[export]`, not called by `seal_host_init`, and is used only by
    `scripts/model_oracle.lean`; compiled native/WASM/deployed oracles still
    initialise through `initImpl` and verify real signatures. -/
def modelInitFromTrustedPayload (payloadText : String) : IO String := do
  match Host.parseCanonicalConfigPayload payloadText with
  | .error err => pure (errJson s!"trusted config rejected: {err}")
  | .ok config => initFromConfig config

def modelStep (inputText : String) : IO String :=
  stepImpl inputText

@[export seal_host_init]
unsafe def sealHostInit (envelopeText publicKey : String) : String :=
  unsafeBaseIO <| (initImpl envelopeText publicKey).catchExceptions
    (fun e => pure (errJson (toString e)))

@[export seal_host_step]
unsafe def sealHostStep (inputText : String) : String :=
  unsafeBaseIO <| (stepImpl inputText).catchExceptions
    (fun e => pure (errJson (toString e)))

/-- Routing classification for the differential harness / the native fast path:
    0 = passthrough, 1 = mediated tools/call, 2 = refused (pathological number,
    fail-closed). The Rust `route_of_classify` maps any value outside {0,1} to
    `Refuse`, so 2 fails closed on the classify fast path exactly as `.refuse`
    fails closed on the step path. -/
@[export seal_host_classify]
def sealHostClassify (line : String) : UInt32 :=
  match classifyLine line with
  | .passthrough => 0
  | .act _ => 1
  | .refuse => 2

/-! ### The step plan, spelled — `stepImpl`'s marshalling as a pure function

SPEC ONLY (dispatch IO shell wrap-up): nothing below is called by the
exports. `stepImpl` is `private` by design (the sole runtime caller is the
FFI export pair), so its specification lives HERE, in the same file, with
file-local access. `stepImpl_spelled` proves `stepImpl` IS `stepPlanFor`
wrapped around its only two IO leaves — `sessionRef.get` and `dispatch` —
discharging the "stepImpl's JSON marshalling" residual of the dispatch IO
shell: which input field feeds which parser, the single `line` binding
judged by `classifyLine` and committed to the audit, the fail-closed
uninitialised-session / unsafe-number / bad-parse / refuse branches, and
that the dispatched registry is `registryFor` applied to exactly the
marshalled values. What it does NOT cover (unchanged, named TCB): the
`unsafeBaseIO`/`catchExceptions` export wrapper above `stepImpl`, and the
IO realization inside `dispatch` (see `Host.dispatch_spelled` and the
assurance docs). -/

/-- The per-step inputs `stepImpl` marshals out of the step input JSON —
    field by field the SAME expressions, as a pure record. -/
structure StepInputs where
  line : String
  now : Nat
  approvals : List SealCore.Event
  votes : Consensus.Checker.Votes
  grants : List LinearCore.LEvent
  forecasts : List Kernels.ForecastRecord

/-- The marshalling, purely. -/
def stepInputsOf (session : Session) (input : Json) : StepInputs :=
  let now := ((input.getObjVal? "now").toOption.bind (·.getNat?.toOption)).getD 0
  { line := getStrD input "line" ""
    now := now
    approvals := Evidence.approvalEventsFromJson
      ((input.getObjVal? "approvals").toOption.getD (Json.arr #[]))
      now session.config.safety.approvalTtlMs
    votes := Host.Evidence.parseVotesText (getStrD input "votes" "")
    grants := Host.Evidence.parseGrantsText (getStrD input "grants" "")
    forecasts := Host.Evidence.parseForecastsText (getStrD input "forecasts" "") }

/-- What one mediation step does, purely: either a fixed response line
    (fail-closed guard, parse failure, passthrough, refuse) or a mediated
    dispatch of `act` at the marshalled inputs. -/
inductive StepPlan where
  | respond (out : String)
  | mediate (inputs : StepInputs) (act : CanonicalAction)

/-- The pure step plan: everything `stepImpl` decides before and between
    its two IO leaves. -/
def stepPlanFor (session : Session) (inputText : String) : StepPlan :=
  if !Seal.JsonUtil.wireNumbersSafe inputText then
    .respond (errJson "bad step input: unsafe numeric literal")
  else
    match Json.parse inputText with
    | .error err => .respond (errJson s!"bad step input: {err}")
    | .ok input =>
        let inputs := stepInputsOf session input
        match classifyLine inputs.line with
        | .passthrough =>
            .respond (Json.mkObj [("route", Json.str "passthrough")]).compress
        | .refuse =>
            .respond (Json.mkObj [
              ("route", Json.str "block"),
              ("response", Json.str refuseResponseLine)
            ]).compress
        | .act act => .mediate inputs act

/-- The response rendering after a mediated dispatch, purely: the audit
    line over the SAME judged `line` binding, routed through the proven
    `Host.stepRoute`. -/
def stepRender (session : Session) (inputs : StepInputs)
    (act : CanonicalAction) (combined : VerdictKind)
    (verdicts : List Verdict) : String :=
  let audit := auditLine session.config.epoch act.tool combined verdicts inputs.line
  match Host.stepRoute (classifyLine inputs.line) verdicts with
  | .forward =>
      (Json.mkObj [("route", Json.str "forward"), ("audit", Json.str audit)]).compress
  | .block =>
      (Json.mkObj [
        ("route", Json.str "block"),
        ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
        ("audit", Json.str audit)
      ]).compress
  | .passthrough =>
      (Json.mkObj [
        ("route", Json.str "block"),
        ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
        ("audit", Json.str audit)
      ]).compress

/-- **THE STEP IS ITS PLAN.** `stepImpl` equals the pure `stepPlanFor`
    wrapped around its two IO leaves: read the session, run the plan; a
    `.respond` plan returns its bytes with NO dispatch, a `.mediate` plan
    dispatches `registryFor` at EXACTLY the marshalled inputs and renders
    through the pure `Host.stepRoute`. Program equality in `IO` — the
    marshalling residual of the dispatch IO shell becomes this theorem. -/
theorem stepImpl_spelled (inputText : String) :
    stepImpl inputText
      = (do
        let some session ← sessionRef.get
          | pure (errJson "session not initialised")
        match stepPlanFor session inputText with
        | .respond out => pure out
        | .mediate inputs act => do
            let (combined, verdicts) ← dispatch
              (registryFor session inputs.now inputs.approvals inputs.votes
                inputs.grants inputs.forecasts) act
            pure (stepRender session inputs act combined verdicts)) := by
  unfold stepImpl stepPlanFor stepRender stepInputsOf
  refine congrArg (sessionRef.get >>= ·) (funext fun s? => ?_)
  cases s? with
  | none => rfl
  | some session =>
    dsimp only
    by_cases hw : Seal.JsonUtil.wireNumbersSafe inputText
    · simp only [hw, Bool.not_true, Bool.false_eq_true, if_false]
      cases hp : Json.parse inputText with
      | error e => rfl
      | ok input =>
        dsimp only
        cases hlc : classifyLine (getStrD input "line" "") with
        | passthrough => rfl
        | refuse => rfl
        | act act =>
            dsimp only
            rw [hlc]
            refine congrArg (_ >>= ·) (funext fun p => ?_)
            cases Host.stepRoute (LineClass.act act) p.2 <;> rfl
    · simp only [hw, Bool.not_false, if_true]

end Ffi

/-! ## Axiom pins — enforced at module build

The spelled step plan sits on Lean's three classical axioms at most; no
`sorryAx`, no `Lean.ofReduceBool`, and no new axioms — the program-equality
proof uses only core's lawful-monad laws and case analysis on the pure
plan. Drift fails the build here and again in `Test/Axioms.lean`. -/

/-- info: 'Ffi.stepInputsOf' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepInputsOf
/-- info: 'Ffi.stepPlanFor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepPlanFor
/-- info: 'Ffi.stepRender' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepRender
/-- info: 'Ffi.stepImpl_spelled' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Ffi.stepImpl_spelled
