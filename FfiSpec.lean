/- SPDX-License-Identifier: Apache-2.0 -/

import Ffi
import Kernels.ConsensusBytes

/-!
# The deployed registry, specified

`Ffi.registryFor` is the one function that decides which proven kernels
actually run: `stepImpl` builds every mediation step's registry through it.
Until this module, nothing specified it — "you cannot deploy seal without
Safety" was true by accident of a list literal, and reordering that literal
would have broken no proof.

`registryFor_kernels` pins the construction exactly: the kernels registered
are `activeKernels s.config`, no more, no fewer, Safety and Temporal
unconditionally first. Corollaries:

- `safety_always_registered` / `temporal_always_registered` — S and T are in
  the registry for EVERY config and every step input. Of the 2^7 subsets of
  the seven wired kernels, the 95 omitting S or T are structurally
  unexpressible; only the 32 containing both are deployable.
- one `*_registered_iff` per config-gated kernel — membership iff the config
  selects it. Calibration's double gate is explicit: `some cfg` with
  `enabled := false` and `none` both leave it out.
- `byteConsensus_never_registered` — the honest eighth row. The bytes-level
  consensus kernel is proven (`Kernels/ConsensusBytes.lean`) but NOT wired:
  the product selects among seven kernels with two mandatory (32 topologies,
  not 64), and no config can reach the eighth.

Scope, stated honestly: these theorems specify registry CONSTRUCTION from the
trusted config. The IO around it — `Host.dispatch`'s ref-backed run, evidence
gathering, JSON marshalling, the `unsafeBaseIO` boundary — remains TCB,
exactly as carved out in `Host/Composition.lean` ("TCB (NOT proven
through)"). Composition over the constructed registry is
`Host.registry_closed_algebra`; enactment of the verdict is
`Host.step_forward_non_bypass`. This module closes the selection gap between
them.
-/

namespace Ffi

open Host

/-- The specification of the deployed kernel selection: which kernels a
    trusted config activates. Safety and Temporal are unconditional;
    consensus/linear activate on `some`; convergence/budget on a non-empty
    section; calibration is double-gated (`some cfg` AND `cfg.enabled`). -/
def activeKernels (cfg : TrustedConfig) : List Kernel :=
  [Kernels.safetyKernel, Kernels.temporalKernel]
  ++ (match cfg.consensus with
      | some _ => [Kernels.consensusKernel]
      | none => [])
  ++ (if cfg.convergence.isEmpty then [] else [Kernels.convergenceKernel])
  ++ (match cfg.calibration with
      | some c => if c.enabled then [Kernels.calibrationKernel] else []
      | none => [])
  ++ (match cfg.linear with
      | some _ => [Kernels.linearKernel]
      | none => [])
  ++ (if cfg.budget.isEmpty then [] else [Kernels.budgetKernel])

/-- THE SPEC: the registry `stepImpl` dispatches over registers exactly
    `activeKernels s.config` — for every session, every clock value and every
    piece of gathered evidence. Selection depends on the trusted config
    alone. -/
theorem registryFor_kernels (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    (registryFor s now approvalEvents votes grants forecasts).map (·.kernel)
      = activeKernels s.config := by
  unfold registryFor activeKernels
  cases hc : s.config.consensus <;>
  cases hk : s.config.calibration <;>
  cases hl : s.config.linear <;>
  simp [apply_ite (List.map (fun r : Registered => r.kernel))]

/-- No deployable topology omits Safety: `safetyKernel` is registered for
    every config and every step input. This single theorem closes the 95
    subsets of the seven wired kernels that omit S or T — no config
    expresses them. -/
theorem safety_always_registered (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    Kernels.safetyKernel
      ∈ (registryFor s now approvalEvents votes grants forecasts).map (·.kernel) := by
  rw [registryFor_kernels]
  unfold activeKernels
  simp

/-- Same for Temporal: registered unconditionally, every config, every
    input. -/
theorem temporal_always_registered (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    Kernels.temporalKernel
      ∈ (registryFor s now approvalEvents votes grants forecasts).map (·.kernel) := by
  rw [registryFor_kernels]
  unfold activeKernels
  simp

/-- A kernel whose name is absent from a list's names is absent from the
    list. Kernels are distinguished by `name`: all eight carry distinct
    string literals, so (non-)membership below is decided at the name
    level. -/
private theorem not_mem_of_name {k : Kernel} {l : List Kernel}
    (h : k.name ∉ l.map Kernel.name) : k ∉ l :=
  fun hm => h (List.mem_map_of_mem hm)

/-- The names of the selected kernels, as string literals — the one place the
    kernel definitions are unfolded, so the `*_registered_iff` proofs reason
    over literals. -/
private theorem activeKernels_names (cfg : TrustedConfig) :
    (activeKernels cfg).map Kernel.name
      = ["safety", "temporal"]
        ++ (match cfg.consensus with
            | some _ => ["consensus"]
            | none => [])
        ++ (if cfg.convergence.isEmpty then [] else ["convergence"])
        ++ (match cfg.calibration with
            | some c => if c.enabled then ["calibration"] else []
            | none => [])
        ++ (match cfg.linear with
            | some _ => ["linear"]
            | none => [])
        ++ (if cfg.budget.isEmpty then [] else ["budget"]) := by
  unfold activeKernels
  cases cfg.consensus <;>
  cases cfg.calibration <;>
  cases cfg.linear <;>
  by_cases hv : cfg.convergence.isEmpty <;>
  by_cases hb : cfg.budget.isEmpty <;>
  simp [hv, hb, apply_ite (List.map Kernel.name),
    Kernels.safetyKernel, Kernels.temporalKernel, Kernels.consensusKernel,
    Kernels.convergenceKernel, Kernels.calibrationKernel,
    Kernels.linearKernel, Kernels.budgetKernel]

/-- Consensus kernel registered iff the config carries a consensus
    section. -/
theorem consensus_registered_iff (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    Kernels.consensusKernel
        ∈ (registryFor s now approvalEvents votes grants forecasts).map (·.kernel)
      ↔ s.config.consensus.isSome := by
  rw [registryFor_kernels]
  cases hc : s.config.consensus with
  | none =>
      refine iff_of_false ?_ (by simp)
      refine not_mem_of_name ?_
      rw [activeKernels_names]
      cases hk : s.config.calibration <;>
      cases hl : s.config.linear <;>
      simp_all [Kernels.consensusKernel]
  | some cfg =>
      exact iff_of_true (by simp [activeKernels, hc]) (by simp)

/-- Convergence kernel registered iff the convergence section is
    non-empty. -/
theorem convergence_registered_iff (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    Kernels.convergenceKernel
        ∈ (registryFor s now approvalEvents votes grants forecasts).map (·.kernel)
      ↔ s.config.convergence.isEmpty = false := by
  rw [registryFor_kernels]
  by_cases hv : s.config.convergence.isEmpty
  · refine iff_of_false ?_ (by simp [hv])
    refine not_mem_of_name ?_
    rw [activeKernels_names]
    cases hc : s.config.consensus <;>
    cases hk : s.config.calibration <;>
    cases hl : s.config.linear <;>
    simp_all [Kernels.convergenceKernel]
  · exact iff_of_true (by simp [activeKernels, hv]) (by simp [hv])

/-- The double gate, as a theorem: the calibration kernel is registered iff
    the section is PRESENT and ENABLED. `none` and `some cfg` with
    `enabled := false` are distinct config states and both leave calibration
    out — and (`registryFor_kernels`) neither touches any other kernel's
    row. -/
theorem calibration_registered_iff (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    Kernels.calibrationKernel
        ∈ (registryFor s now approvalEvents votes grants forecasts).map (·.kernel)
      ↔ ∃ cfg, s.config.calibration = some cfg ∧ cfg.enabled = true := by
  rw [registryFor_kernels]
  cases hk : s.config.calibration with
  | none =>
      refine iff_of_false ?_ (by simp)
      refine not_mem_of_name ?_
      rw [activeKernels_names]
      cases hc : s.config.consensus <;>
      cases hl : s.config.linear <;>
      simp_all [Kernels.calibrationKernel]
  | some c =>
      by_cases he : c.enabled
      · exact iff_of_true (by simp [activeKernels, hk, he]) ⟨c, rfl, he⟩
      · refine iff_of_false ?_ ?_
        · refine not_mem_of_name ?_
          rw [activeKernels_names]
          cases hc : s.config.consensus <;>
          cases hl : s.config.linear <;>
          simp_all [Kernels.calibrationKernel]
        · rintro ⟨cfg, hcfg, hen⟩
          rw [Option.some.injEq] at hcfg
          subst hcfg
          exact he hen

/-- Linear kernel registered iff the config carries a linear section. -/
theorem linear_registered_iff (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    Kernels.linearKernel
        ∈ (registryFor s now approvalEvents votes grants forecasts).map (·.kernel)
      ↔ s.config.linear.isSome := by
  rw [registryFor_kernels]
  cases hl : s.config.linear with
  | none =>
      refine iff_of_false ?_ (by simp)
      refine not_mem_of_name ?_
      rw [activeKernels_names]
      cases hc : s.config.consensus <;>
      cases hk : s.config.calibration <;>
      simp_all [Kernels.linearKernel]
  | some cfg =>
      exact iff_of_true (by simp [activeKernels, hl]) (by simp)

/-- Budget kernel registered iff the budget section is non-empty. -/
theorem budget_registered_iff (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    Kernels.budgetKernel
        ∈ (registryFor s now approvalEvents votes grants forecasts).map (·.kernel)
      ↔ s.config.budget.isEmpty = false := by
  rw [registryFor_kernels]
  by_cases hb : s.config.budget.isEmpty
  · refine iff_of_false ?_ (by simp [hb])
    refine not_mem_of_name ?_
    rw [activeKernels_names]
    cases hc : s.config.consensus <;>
    cases hk : s.config.calibration <;>
    cases hl : s.config.linear <;>
    simp_all [Kernels.budgetKernel]
  · exact iff_of_true (by simp [activeKernels, hb]) (by simp [hb])

/-- The honest eighth row: `byteConsensusKernel` is PROVEN
    (`Kernels/ConsensusBytes.lean`) but NOT WIRED — no config, clock or
    evidence reaches it. The product selects among seven kernels with two
    mandatory: 32 deployable topologies, not 64. -/
theorem byteConsensus_never_registered (s : Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord) :
    Kernels.byteConsensusKernel
      ∉ (registryFor s now approvalEvents votes grants forecasts).map (·.kernel) := by
  rw [registryFor_kernels]
  refine not_mem_of_name ?_
  rw [activeKernels_names]
  cases hc : s.config.consensus <;>
  cases hk : s.config.calibration <;>
  cases hl : s.config.linear <;>
  simp_all [Kernels.byteConsensusKernel]

/-! Axiom pins: every theorem above sits on the classical baseline only — no
    `sorryAx`, no `Lean.ofReduceBool`. Drift fails the build here and again in
    `Test/Axioms.lean`. -/

/-- info: 'Ffi.registryFor_kernels' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms registryFor_kernels

/-- info: 'Ffi.safety_always_registered' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms safety_always_registered

/-- info: 'Ffi.temporal_always_registered' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms temporal_always_registered

/-- info: 'Ffi.consensus_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms consensus_registered_iff

/--
info: 'Ffi.convergence_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms convergence_registered_iff

/--
info: 'Ffi.calibration_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms calibration_registered_iff

/-- info: 'Ffi.linear_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms linear_registered_iff

/-- info: 'Ffi.budget_registered_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms budget_registered_iff

/--
info: 'Ffi.byteConsensus_never_registered' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms byteConsensus_never_registered

end Ffi
