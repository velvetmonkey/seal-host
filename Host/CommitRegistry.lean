/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Commit
import FfiSpec

/-!
# The 8-kernel deny composition — the commit discipline at the deployed registry

`Host.Commit` proves the deny-side discipline over an abstract instance list.
This module makes "over the full 8-kernel registry" literal: `commitInstsFor`
is the pure commit-model registry with EXACTLY the selection, order and
per-kernel wiring of `Ffi.registryFor` (the list `stepImpl` dispatches), and
`commitInstsFor_kernels` pins it to `Ffi.activeKernels` — the same spec, by
the same proof script, that `registryFor_kernels` pins the deployed selection
to. The flagship `registry_deny_ingest_only` is then one equation over all
eight kernels: a combined deny commits ONLY the spec-allowed ingests.

HONEST BOUNDARY: `commitInstsFor_kernels` pins the kernel SELECTION of the
mirror to the deployed spec, and `commitInstsFor_wiring` pins the
per-instance wiring: under the common projection `WiredInst` (kernel,
config, gather function, pre-call state slot) the mirror and `registryFor`
are EQUAL, instance by instance, for every pure reading of the session refs
consistent with the mirror's state arguments. What remains trusted is the IO
REALIZATION of that projection — that `dispatch`'s `stateRef.get` returns
what the reader models and that executing `gather` yields its pure constant
— i.e. the dispatch IO shell named in the assurance docs.
-/

namespace Host

open Kernels in
/-- The deployed registry as pure commit instances: the SAME selection, order
    and per-kernel wiring as `Ffi.registryFor` (Ffi.lean), with the per-call
    evidence and pre-call session states explicit instead of `gather`/`IO.Ref`.
    S and T are unconditional; C activates on `some`, V on a non-empty
    section, K double-gated (`some cfg` AND `cfg.enabled`), L on `some`, B on
    a non-empty section, PB (V2.1, per-principal budget) on `some` — `commitInstsFor_kernels` pins the selection to
    `Ffi.activeKernels`, and `commitInstsFor_wiring` pins the full
    per-instance wiring against `registryFor`. -/
def commitInstsFor (cfg : TrustedConfig) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState) : List CommitInst :=
  [⟨Kernels.safetyKernel, cfg.safety,
      ({ now := now, approvalEvents := approvalEvents } : Kernels.SafetyEvidence), sSt⟩,
   ⟨Kernels.temporalKernel, cfg.temporal, (), tSt⟩]
  ++ (match cfg.consensus with
      | some c => [⟨Kernels.consensusKernel, c, votes, ()⟩]
      | none => [])
  ++ (if cfg.convergence.isEmpty then []
      else [⟨Kernels.convergenceKernel, cfg.convergence, (), ()⟩])
  ++ (match cfg.calibration with
      | some c =>
          if c.enabled then [⟨Kernels.calibrationKernel, c, forecasts, ()⟩] else []
      | none => [])
  ++ (match cfg.linear with
      | some c => [⟨Kernels.linearKernel, c, grants, lSt⟩]
      | none => [])
  ++ (if cfg.budget.isEmpty then []
      else [⟨Kernels.budgetKernel, cfg.budget, (), bSt⟩])
  ++ (match cfg.principals with
      | some c => [⟨Kernels.principalBudgetKernel, c, principal?, pbSt⟩]
      | none => [])

/-- The commit model ranges over EXACTLY the deployed 8-kernel selection:
    `commitInstsFor`'s kernels are `Ffi.activeKernels` — the same statement
    shape, against the same spec, as `Ffi.registryFor_kernels` for the
    deployed dispatch list. -/
theorem commitInstsFor_kernels (cfg : TrustedConfig) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState) :
    (commitInstsFor cfg now approvalEvents votes grants forecasts
        principal? sSt tSt lSt bSt pbSt).map (·.kernel)
      = Ffi.activeKernels cfg := by
  unfold commitInstsFor Ffi.activeKernels
  cases hc : cfg.consensus <;>
  cases hk : cfg.calibration <;>
  cases hl : cfg.linear <;>
  cases hp : cfg.principals <;>
  simp [apply_ite (List.map (fun i : CommitInst => i.kernel))]

/-! ### Wiring fidelity — the mirror equals the deployed registry, instance by instance

`commitInstsFor_kernels` pins WHICH kernels; the theorems below pin HOW each
one is wired. `WiredInst` is the common projection both lists map onto:
kernel identity, config section, evidence SOURCE (the whole `gather`
function — every `registryFor` gather is a pure constant, so it is
comparable by plain equality against `fun _ => pure evidence`) and the
pre-call state slot. `IO.Ref` contents cannot be projected purely, so the
state slot goes through a universally quantified pure reader `read`,
constrained only to agree with the mirror's state arguments on the session's
five stateful refs (C, V and K share `unitRef` with `State = Unit` — their
slot is `()` for any reader).

COVERED by `commitInstsFor_wiring`: kernel identity and order, per-instance
config section, evidence source, state-slot wiring (safetyRef→sSt,
temporalRef→tSt, linearRef→lSt, budgetRef→bSt,
principalBudgetRef→pbSt, unitRef→()) — and hence
every gating decision (`commitInstsFor_gates`). NOT covered — the dispatch
IO shell, unchanged by these theorems: that `stateRef.get` at dispatch time
returns what `read` models, that executing `gather` returns its constant,
ref get/set sequencing and distinctness, the `for`/`do` desugaring, the
allow branch replaying held writes, `stepImpl`'s marshalling, and the
`unsafeBaseIO`/FFI boundary. -/

/-- One wired kernel instance under the common projection: identity, config,
    evidence SOURCE (the gather function itself) and pre-call state slot. -/
structure WiredInst where
  kernel : Kernel
  config : kernel.Config
  gather : CanonicalAction → IO kernel.Evidence
  state : kernel.State

/-- Project a deployed `Registered` instance through a pure reading of its
    state ref. The reader is the ONLY unrealized ingredient: everything else
    is the instance's own fields. -/
def Registered.wiredAt (read : (K : Kernel) → IO.Ref K.State → K.State)
    (r : Registered) : WiredInst :=
  ⟨r.kernel, r.config, r.gather, read r.kernel r.stateRef⟩

/-- Project a commit-model instance: its evidence becomes the constant
    gather — exactly the shape every `registryFor` gather has. -/
def CommitInst.wired (i : CommitInst) : WiredInst :=
  ⟨i.kernel, i.config, fun _ => pure i.evidence, i.state⟩

/-- **WIRING FIDELITY.** The commit-model mirror IS the deployed registry,
    instance by instance: for EVERY pure reading of the session's refs that
    agrees with the mirror's pre-call state arguments, `registryFor` and
    `commitInstsFor` project to the SAME `WiredInst` list — same kernels in
    the same order, same config section, same evidence source (each deployed
    `gather` equals the constant returning the mirror's evidence) and same
    pre-call state slot. This discharges the former "trusted by inspection"
    wiring residual; what it does NOT discharge is the IO realization of the
    reader and the gathers (the dispatch IO shell). -/
theorem commitInstsFor_wiring (s : Ffi.Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState)
    (read : (K : Kernel) → IO.Ref K.State → K.State)
    (hs : read Kernels.safetyKernel s.safetyRef = sSt)
    (ht : read Kernels.temporalKernel s.temporalRef = tSt)
    (hl : read Kernels.linearKernel s.linearRef = lSt)
    (hb : read Kernels.budgetKernel s.budgetRef = bSt)
    (hpb : read Kernels.principalBudgetKernel s.principalBudgetRef = pbSt) :
    (Ffi.registryFor s now approvalEvents votes grants forecasts principal?).map
        (Registered.wiredAt read)
      = (commitInstsFor s.config now approvalEvents votes grants forecasts
          principal? sSt tSt lSt bSt pbSt).map CommitInst.wired := by
  subst hs ht hl hb hpb
  unfold Ffi.registryFor commitInstsFor
  cases hc : s.config.consensus <;>
  cases hk : s.config.calibration <;>
  cases hlin : s.config.linear <;>
  cases hpr : s.config.principals <;>
  simp [Registered.wiredAt, CommitInst.wired,
    apply_ite (List.map (Registered.wiredAt read)),
    apply_ite (List.map CommitInst.wired)] <;>
  -- What simp cannot see: C/V/K sit on `unitRef`, whose `State` is `Unit` —
  -- every remaining slot equation (`read _ s.unitRef = ()`) is definitional
  -- by `Unit` eta.
  (repeat apply And.intro) <;> rfl

/-- **GATING FIDELITY** (corollary shape, proved directly): the deployed
    registry and the mirror make the SAME gating decision at every instance,
    for every action — gating depends only on kernel and config, both pinned
    by the wiring. -/
theorem commitInstsFor_gates (s : Ffi.Session) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState)
    (act : CanonicalAction) :
    (Ffi.registryFor s now approvalEvents votes grants forecasts principal?).map
        (fun r => r.kernel.gates r.config act)
      = (commitInstsFor s.config now approvalEvents votes grants forecasts
          principal? sSt tSt lSt bSt pbSt).map (fun i => i.kernel.gates i.config act) := by
  unfold Ffi.registryFor commitInstsFor
  cases hc : s.config.consensus <;>
  cases hk : s.config.calibration <;>
  cases hlin : s.config.linear <;>
  cases hpr : s.config.principals <;>
  simp [apply_ite (List.map (fun r : Registered => r.kernel.gates r.config act)),
    apply_ite (List.map (fun i : CommitInst => i.kernel.gates i.config act))]

/-- Kernel L's spec-allowed deny-side state at the deployed registry: this
    call's grants folded in when L is configured AND gates the call, the
    untouched state otherwise. The spend is NEVER part of this. -/
def linearIngested (cfg : TrustedConfig) (act : CanonicalAction)
    (grants : List LinearCore.LEvent) (lSt : LinearCore.LState) : LinearCore.LState :=
  match cfg.linear with
  | some c =>
      if Kernels.linearKernel.gates c act
      then Kernels.linearKernel.ingest grants lSt else lSt
  | none => lSt

/-- Kernel S gates every call — `safetyKernel.gates` is constantly `true`. -/
@[simp] theorem safetyKernel_gates_true (pol : Seal.Policy) (act : CanonicalAction) :
    Kernels.safetyKernel.gates pol act = true := rfl

/-- Kernel T gates every call — `temporalKernel.gates` is constantly `true`. -/
@[simp] theorem temporalKernel_gates_true (policies : List Kernels.TemporalPolicy)
    (act : CanonicalAction) :
    Kernels.temporalKernel.gates policies act = true := rfl

/-- **THE 7-KERNEL DENY COMPOSITION.** On a combined deny — forced by ANY one
    gating kernel's deny (`pureCommit_deny_of_member`) — the committed
    registry is the SAME registry with ONLY the spec-allowed ingests applied:

    * **S**: approvals folded (evidence read from the control file must
      survive a deny) — the decide consume/prune transition is withheld;
    * **L**: this call's grants folded when L gates the call
      (`linearIngested`) — the spend is withheld; the deployed grant fold can
      only GROW holdings (`linear_ingest_grant_only_holds`);
    * **T**: trace byte-identical — no event appended, a denied call never
      executed;
    * **B**: counters byte-identical — no budget spend;
    * **PB** (V2.1): per-principal counters byte-identical — no principal
      budget spend, whoever the call authenticated as;
    * **C, V, K**: `State = Unit` — nothing to move.

    Registry vocabulary is literal: `commitInstsFor_kernels` maps this
    instance list onto `Ffi.activeKernels cfg`, the selection
    `registryFor_kernels` proves the deployed `stepImpl` dispatches. -/
theorem registry_deny_ingest_only (cfg : TrustedConfig) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState)
    (act : CanonicalAction)
    (hdeny : (pureCommit (commitInstsFor cfg now approvalEvents votes grants
        forecasts principal? sSt tSt lSt bSt pbSt) act).1 = .deny) :
    (pureCommit (commitInstsFor cfg now approvalEvents votes grants
        forecasts principal? sSt tSt lSt bSt pbSt) act).2
      = commitInstsFor cfg now approvalEvents votes grants forecasts principal?
          (Kernels.safetyKernel.ingest
            ({ now := now, approvalEvents := approvalEvents } :
              Kernels.SafetyEvidence) sSt)
          tSt (linearIngested cfg act grants lSt) bSt pbSt := by
  rw [pureCommit_deny_no_decide_commit _ _ hdeny]
  unfold ingestAll commitInstsFor linearIngested
  cases hc : cfg.consensus <;>
  cases hk : cfg.calibration <;>
  cases hl : cfg.linear <;>
  cases hp : cfg.principals <;>
  all_goals
    simp only [List.map_append,
      apply_ite (List.map (fun i : CommitInst => i.ingestPhase act)),
      List.map_cons, List.map_nil] <;>
    simp [CommitInst.ingestPhase]

/-- **NO BUDGET SPEND on any-kernel deny at the deployed registry**: whenever
    the budget section is non-empty (B registered), the committed registry
    contains the budget instance with state EXACTLY `bSt` — byte-identical
    counters. -/
theorem registry_deny_no_budget_spend (cfg : TrustedConfig) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState)
    (act : CanonicalAction)
    (hdeny : (pureCommit (commitInstsFor cfg now approvalEvents votes grants
        forecasts principal? sSt tSt lSt bSt pbSt) act).1 = .deny)
    (hb : cfg.budget.isEmpty = false) :
    (⟨Kernels.budgetKernel, cfg.budget, (), bSt⟩ : CommitInst)
      ∈ (pureCommit (commitInstsFor cfg now approvalEvents votes grants
          forecasts principal? sSt tSt lSt bSt pbSt) act).2 := by
  rw [registry_deny_ingest_only cfg now approvalEvents votes grants forecasts
        principal? sSt tSt lSt bSt pbSt act hdeny]
  unfold commitInstsFor
  simp [hb]

/-- **NO PRINCIPAL-BUDGET SPEND on any-kernel deny** (V2.1): whenever the
    principals section is configured (PB registered), the committed registry
    contains the PB instance with state EXACTLY `pbSt` — every principal's
    counters byte-identical. A denied call debits no one, whoever it
    authenticated as. -/
theorem registry_deny_no_principal_budget_spend (cfg : TrustedConfig) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState)
    (act : CanonicalAction)
    (hdeny : (pureCommit (commitInstsFor cfg now approvalEvents votes grants
        forecasts principal? sSt tSt lSt bSt pbSt) act).1 = .deny)
    (pcfg : Kernels.PrincipalsConfig) (hp : cfg.principals = some pcfg) :
    (⟨Kernels.principalBudgetKernel, pcfg, principal?, pbSt⟩ : CommitInst)
      ∈ (pureCommit (commitInstsFor cfg now approvalEvents votes grants
          forecasts principal? sSt tSt lSt bSt pbSt) act).2 := by
  rw [registry_deny_ingest_only cfg now approvalEvents votes grants forecasts
        principal? sSt tSt lSt bSt pbSt act hdeny]
  unfold commitInstsFor
  simp [hp]

/-- **NO TEMPORAL OBSERVATION on any-kernel deny**: T is always registered,
    and the committed registry contains the temporal instance with state
    EXACTLY `tSt` — the executed trace gains no event. -/
theorem registry_deny_temporal_frozen (cfg : TrustedConfig) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (grants : List LinearCore.LEvent)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState)
    (act : CanonicalAction)
    (hdeny : (pureCommit (commitInstsFor cfg now approvalEvents votes grants
        forecasts principal? sSt tSt lSt bSt pbSt) act).1 = .deny) :
    (⟨Kernels.temporalKernel, cfg.temporal, (), tSt⟩ : CommitInst)
      ∈ (pureCommit (commitInstsFor cfg now approvalEvents votes grants
          forecasts principal? sSt tSt lSt bSt pbSt) act).2 := by
  rw [registry_deny_ingest_only cfg now approvalEvents votes grants forecasts
        principal? sSt tSt lSt bSt pbSt act hdeny]
  unfold commitInstsFor
  simp

/-- The deployed grants-file parser emits ONLY grant events: `.spend` cannot
    enter the evidence stream from the grants file. This is what turns "deny
    commits only the grant fold" into "deny can only GROW holdings". -/
theorem parseGrantsText_grant_only (txt : String) :
    ∀ e ∈ Host.Evidence.parseGrantsText txt,
      ∃ c n, e = LinearCore.LEvent.grant c n := by
  intro e he
  simp only [Host.Evidence.parseGrantsText, List.mem_filterMap] at he
  obtain ⟨line, _, hline⟩ := he
  split at hline
  · exact absurd hline (by simp)
  · simp only [Option.bind_eq_bind, Option.bind_eq_some_iff] at hline
    obtain ⟨cap, _, hline⟩ := hline
    obtain ⟨uses, _, hline⟩ := hline
    exact ⟨cap, uses, (Option.some_inj.mp hline).symm⟩

/-- **Grant-only ingest is EXACT addition**: folding a grant-only evidence
    list grows every capability's multiplicity by precisely its granted total
    (`LinearCore.granted`) — never a consumption. -/
theorem linear_ingest_grant_only_holds (ev : List LinearCore.LEvent)
    (st : LinearCore.LState) (cap : LinearCore.CapId)
    (hev : ∀ e ∈ ev, ∃ c n, e = LinearCore.LEvent.grant c n) :
    LinearCore.holds (Kernels.linearKernel.ingest ev st) cap
      = LinearCore.holds st cap + LinearCore.granted cap ev := by
  induction ev generalizing st with
  | nil => simp [Kernels.linearKernel, LinearCore.granted]
  | cons e rest ih =>
      obtain ⟨c, n, rfl⟩ := hev e List.mem_cons_self
      have hstep : LinearCore.step st (.grant c n) =
          (.allow, { remaining := st.remaining.insert c (LinearCore.holds st c + n) }) := rfl
      have htail : Kernels.linearKernel.ingest (LinearCore.LEvent.grant c n :: rest) st
          = Kernels.linearKernel.ingest rest
              { remaining := st.remaining.insert c (LinearCore.holds st c + n) } := by
        show (LinearCore.LEvent.grant c n :: rest).foldl
            (fun s e => (LinearCore.step s e).2) st = _
        rw [List.foldl_cons, hstep]
        rfl
      rw [htail, ih _ (fun e he => hev e (List.mem_cons_of_mem _ he))]
      by_cases hc : c = cap
      · subst hc
        have hholds : LinearCore.holds
            { remaining := st.remaining.insert c (LinearCore.holds st c + n)
              : LinearCore.LState } c = LinearCore.holds st c + n := by
          simp [LinearCore.holds]
        rw [hholds]
        simp only [LinearCore.granted, beq_self_eq_true, if_true]
        omega
      · have hbeq : (c == cap) = false := beq_false_of_ne hc
        have hholds : LinearCore.holds
            { remaining := st.remaining.insert c (LinearCore.holds st c + n)
              : LinearCore.LState } cap = LinearCore.holds st cap := by
          simp [LinearCore.holds, Std.HashMap.getElem?_insert, hbeq]
        rw [hholds]
        simp only [LinearCore.granted, hbeq, Bool.false_eq_true, if_false]
        omega

/-- **NO CAPABILITY CONSUMED on any-kernel deny, at the deployed evidence
    path**: with L configured and the grants evidence coming from the deployed
    parse (`Host.Evidence.parseGrantsText` — grant events only), the committed
    linear state's holdings can only GROW: for EVERY capability, committed
    holds ≥ pre-call holds. A deny never decreases any capability's
    multiplicity. -/
theorem registry_deny_no_capability_consumed (cfg : TrustedConfig) (now : Nat)
    (approvalEvents : List SealCore.Event)
    (votes : Consensus.Checker.Votes)
    (forecasts : List Kernels.ForecastRecord)
    (principal? : Option AuthenticatedPrincipal)
    (sSt : SealCore.State) (tSt : Kernels.TemporalState)
    (lSt : LinearCore.LState) (bSt : Kernels.BudgetState)
    (pbSt : Kernels.PBState)
    (txt : String) (act : CanonicalAction)
    (lcfg : Kernels.LinearConfig) (hl : cfg.linear = some lcfg)
    (hdeny : (pureCommit (commitInstsFor cfg now approvalEvents votes
        (Host.Evidence.parseGrantsText txt) forecasts principal? sSt tSt lSt bSt pbSt) act).1 = .deny)
    (cap : LinearCore.CapId) :
    ∃ stC,
      (⟨Kernels.linearKernel, lcfg, Host.Evidence.parseGrantsText txt, stC⟩ : CommitInst)
        ∈ (pureCommit (commitInstsFor cfg now approvalEvents votes
            (Host.Evidence.parseGrantsText txt) forecasts principal? sSt tSt lSt bSt pbSt) act).2
      ∧ LinearCore.holds lSt cap ≤ LinearCore.holds stC cap := by
  refine ⟨linearIngested cfg act (Host.Evidence.parseGrantsText txt) lSt, ?_, ?_⟩
  · rw [registry_deny_ingest_only cfg now approvalEvents votes
          (Host.Evidence.parseGrantsText txt) forecasts principal? sSt tSt lSt bSt pbSt act hdeny]
    unfold commitInstsFor
    simp [hl]
  · simp only [linearIngested, hl]
    by_cases hg : Kernels.linearKernel.gates lcfg act
    · rw [if_pos hg,
          linear_ingest_grant_only_holds _ _ _ (parseGrantsText_grant_only txt)]
      omega
    · rw [if_neg hg]

end Host

/-! ## Axiom pins — enforced at module build

The registry-level composition sits on Lean's three classical axioms at most;
no `sorryAx`, no `Lean.ofReduceBool`. -/

/-- info: 'Host.commitInstsFor' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitInstsFor
/-- info: 'Host.commitInstsFor_kernels' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitInstsFor_kernels
/-- info: 'Host.Registered.wiredAt' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.Registered.wiredAt
/-- info: 'Host.CommitInst.wired' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.CommitInst.wired
/-- info: 'Host.commitInstsFor_wiring' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitInstsFor_wiring
/-- info: 'Host.commitInstsFor_gates' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.commitInstsFor_gates
/-- info: 'Host.linearIngested' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.linearIngested
/-- info: 'Host.registry_deny_ingest_only' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registry_deny_ingest_only
/-- info: 'Host.registry_deny_no_budget_spend' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registry_deny_no_budget_spend
/-- info: 'Host.registry_deny_no_principal_budget_spend' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registry_deny_no_principal_budget_spend
/-- info: 'Host.registry_deny_temporal_frozen' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.registry_deny_temporal_frozen
/-- info: 'Host.parseGrantsText_grant_only' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.parseGrantsText_grant_only
/--
info: 'Host.linear_ingest_grant_only_holds' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.linear_ingest_grant_only_holds
/--
info: 'Host.registry_deny_no_capability_consumed' depends on axioms: [propext, Classical.choice, Quot.sound]
-/
#guard_msgs in #print axioms Host.registry_deny_no_capability_consumed
