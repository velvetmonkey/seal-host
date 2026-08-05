/- SPDX-License-Identifier: Apache-2.0 -/

import Temporal.Monitor
import Seal.Hash
import Host.Kernel

namespace Kernels

/-- One LTL safety policy of shape "no forbidden call after a trigger call":
    once any tool in `trigger` has EXECUTED (allowed, not merely requested),
    no tool in `forbidden` may execute for the rest of the session.
    Sample instance: no destructive call after revoke. -/
structure TemporalPolicy where
  name : String
  trigger : List String
  forbidden : List String
  -- No `deriving Repr`: the derived instance specializes `List.repr'` shared
  -- with LeanSearchClient's generated C, retaining code in the wasm link that
  -- reads globals only `initialize_LeanSearchClient_*` (never run there) would
  -- assign. The link-set audit (wasm-spike/link_set_audit.py) rejects that
  -- link; re-deriving will turn the kernel build red.

/-- The per-position trace state the monitor predicate reads: the tool that
    executed at this position, and whether a trigger executed strictly
    before it. -/
structure PolState where
  tool : String
  triggerSeen : Bool

/-- The G(atom p) safety predicate for one policy: a position is good unless a
    trigger has been seen and this position's tool is forbidden. -/
def polPred (pol : TemporalPolicy) (s : PolState) : Bool :=
  !(s.triggerSeen && pol.forbidden.contains s.tool)

/-- Enrich a chronological list of executed tools into the monitor's state
    sequence, threading the trigger-seen flag. -/
def enrich (pol : TemporalPolicy) (tools : List String) : List PolState :=
  (tools.foldl
    (fun (acc : List PolState × Bool) t =>
      (acc.1 ++ [{ tool := t, triggerSeen := acc.2 }],
       acc.2 || pol.trigger.contains t))
    ([], false)).1

/-- The trace the kernel carries across the session: the chronological list of
    tools that EXECUTED (were allowed through the host). Denied calls never
    execute (`Temporal.gateEvent` semantics: executed := requested ∧ allowed),
    so they never enter the trace. -/
structure TemporalState where
  executed : List String

/-- A candidate extension satisfies one policy iff the library monitor accepts
    the enriched candidate prefix — `Temporal.monitor`, the executable monitor
    whose soundness is `Temporal.monitor_sound` (M2). -/
def policyAccepts (pol : TemporalPolicy) (executed : List String) (tool : String) : Bool :=
  Temporal.monitor (polPred pol) (enrich pol (executed ++ [tool]))

/-- Kernel T — the Temporal Monitor. Gates every tools/call: the candidate
    trace (executed prefix + this call) must be accepted by the executable
    LTL safety monitor for every configured policy. Allow appends the call to
    the trace; deny leaves the trace unchanged (a denied call is not
    executed). -/
def temporalKernel : Host.Kernel where
  name := "temporal"
  Config := List TemporalPolicy
  Evidence := Unit
  State := TemporalState
  init := { executed := [] }
  gates := fun _ _ => true
  ingest := fun _ st => st
  decide := fun act policies _ st =>
    match policies.find? (fun pol => !policyAccepts pol st.executed act.tool) with
    | some pol =>
        let reason := s!"temporal policy violated: {pol.name}"
        ({ kernel := "temporal", kind := .deny, reason,
           certHash := Seal.auditHashParts ["temporal", "deny", reason] }, st)
    | none =>
        let reason := s!"trace ok ({st.executed.length + 1} events)"
        ({ kernel := "temporal", kind := .allow, reason,
           certHash := Seal.auditHashParts ["temporal", "allow", reason] },
         { executed := st.executed ++ [act.tool] })

/-- The pure accept condition of kernel T, mirroring `Kernels.quorumAccepts`:
    no configured LTL policy is violated by executing this call after the
    current trace — i.e. the monitor finds no forbidden-after-trigger
    position. This is the internal condition the kernel's `decide` allows on. -/
def temporalAccepts (policies : List TemporalPolicy) (st : TemporalState)
    (act : Host.CanonicalAction) : Bool :=
  (policies.find? (fun pol => !policyAccepts pol st.executed act.tool)).isNone

/-- Bridge for the composition theorem: kernel T's verdict is allow exactly
    when its accept condition holds — no temporal safety policy forbids the
    call in the current trace. -/
theorem temporal_verdict_allow_iff
    (act : Host.CanonicalAction) (policies : List TemporalPolicy) (ev : Unit)
    (st : TemporalState) :
    (temporalKernel.decide act policies ev st).1.kind = .allow ↔
      temporalAccepts policies st act = true := by
  simp only [temporalKernel, temporalAccepts]
  repeat' split
  all_goals simp_all

end Kernels
