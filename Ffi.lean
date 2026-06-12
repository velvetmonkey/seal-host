/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import Host.Canonical
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

/-- Initialise the session from the signed config envelope. Returns a JSON
    summary the Rust host needs for evidence gathering (file paths, TTL), or
    `{ok: false, error}` — fail-closed, no session on any failure. -/
private def initImpl (envelopeText publicKey : String) : IO String := do
  match checkEnvelope envelopeText publicKey with
  | .error err => pure (errJson s!"trusted config rejected: {err}")
  | .ok config => do
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

/-- Build the same registry `Host.Main` builds, with evidence injected from
    the step input instead of gathered from IO — `Host.dispatch` (two-phase
    ingest/decide commit) is reused verbatim. -/
private def registryFor (s : Session) (now : Nat)
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

/-- One mediation step. Input JSON:
    `{line, now, approvals: [{target, issuedAt?}], votes, grants, forecasts}`
    (votes/grants/forecasts as raw file text; approvals already A3-filtered
    by the Rust host). Output JSON:
    `{route: "passthrough"|"forward"|"block", response?, audit?}`. -/
private def stepImpl (inputText : String) : IO String := do
  let some session ← sessionRef.get
    | pure (errJson "session not initialised")
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
      match classifyLine line with
      | .passthrough =>
          pure (Json.mkObj [("route", Json.str "passthrough")]).compress
      | .act act => do
          let registry := registryFor session now approvals votes grants forecasts
          let (combined, verdicts) ← dispatch registry act
          let audit := auditLine session.config.epoch act.tool combined verdicts
          match combined with
          | .allow =>
              pure (Json.mkObj [
                ("route", Json.str "forward"), ("audit", Json.str audit)]).compress
          | .deny =>
              pure (Json.mkObj [
                ("route", Json.str "block"),
                ("response", Json.str (Seal.blockResponseLine act.requestId (denyReason verdicts))),
                ("audit", Json.str audit)
              ]).compress

@[export seal_host_init]
unsafe def sealHostInit (envelopeText publicKey : String) : String :=
  unsafeBaseIO <| (initImpl envelopeText publicKey).catchExceptions
    (fun e => pure (errJson (toString e)))

@[export seal_host_step]
unsafe def sealHostStep (inputText : String) : String :=
  unsafeBaseIO <| (stepImpl inputText).catchExceptions
    (fun e => pure (errJson (toString e)))

/-- Routing classification for the differential harness:
    0 = passthrough, 1 = mediated tools/call. -/
@[export seal_host_classify]
def sealHostClassify (line : String) : UInt32 :=
  match classifyLine line with
  | .passthrough => 0
  | .act _ => 1

end Ffi

/-- Unused: present only so the `ffi_shared` exe target (linked with
    `-shared` to produce a self-contained .so) elaborates. -/
def main : IO Unit := pure ()
