/- SPDX-License-Identifier: Apache-2.0 -/

/-
Host.Protection — a Lean model of the protection state machine that ships in
the seal product as `spine/protection.cjs`. Every transition constructor below
cites the file and line range that implements it, read at seal commit
8b4d3bea0847841e12e1844d585b28623d4a34ac (the tree whose line numbers also
match `docs/reference/multi-tool-semantics.md`, recorded at 466be4a5).

The subject property is ATOMICITY: seal never guards a strict non-empty
subset of the declared set. In every reachable state, either the tools
actually guarded equal the declared set, or nothing is guarded.

Modelling notes, in the order the code forces them:

* The stored record admits FIVE phases (`STATES`, spine/protection.cjs:12-19
  minus STALE): UNPROTECTED, PENDING RESTART, ACTIVE, DRIFTED, BROKEN.
  STALE is a STATUS VIEW of an ACTIVE record whose lease is dead
  (spine/protection.cjs:629-640); it is never written to disk. The model
  keeps the stored phase and the lease liveness as separate fields and
  derives the six displayed state classes in `view`.
* `declared` models `state.guardTools`: the deduplicated complete request
  set written by protect (spine/protection.cjs:651, :698). `guarded` models
  the set of tools an alive proxy actually intercepts; it is written by each
  transition according to what the code does at that point, and the theorem
  is an induction over reachability — not a definition that collapses to the
  property.
* `leaseLive` models `lockOwnerIsLive(state.lease)`
  (spine/protection.cjs:558-568); `installed` models
  `state.localOverride.installed` (:335-349, :722-726), which gates
  unprotect through `assertSealOwnedLocalOverride` (:351-369).
* Refusals that write NO state (`already_protected` :658-663, live-lease
  refusals :739-741 and :779-784, `protected_server_missing` :785-788,
  ownership refusals :351-369, empty-guardTools `state_broken` :295-301 at
  :807) are not transitions and do not appear here.

The honest scope statement: this file proves the MODEL atomic. The
JavaScript in `spine/protection.cjs` is not bound to this model by anything
in this file; that binding is stage two of the lane and does not exist yet.
-/

import Mathlib.Data.Finset.Basic

namespace Host.Protection

/-- Tool names as advertised over MCP `tools/list`. The shipped code compares
JavaScript strings (spine/protection.cjs:500-501, :673, :808). -/
abbrev Tool := String

/-- The five phases the state file can carry in its `state` field.
`STATES` at spine/protection.cjs:12-19 lists six values, but STALE is never
stored: it is derived at read time (:629-640). -/
inductive Phase
  | unprotected     -- "UNPROTECTED",     spine/protection.cjs:13
  | pendingRestart  -- "PENDING RESTART", spine/protection.cjs:14
  | active          -- "ACTIVE",          spine/protection.cjs:15
  | drifted         -- "DRIFTED",         spine/protection.cjs:17
  | broken          -- "BROKEN",          spine/protection.cjs:18
deriving DecidableEq

/-- One protection record for one project/server, plus the one environment
fact (lease liveness) the status machine reads. -/
structure S where
  /-- `state.state`, the stored phase. -/
  phase : Phase
  /-- `state.guardTools`: the declared complete set (spine/protection.cjs:698,
  deduplicated at :651 and re-deduplicated on read at :300). -/
  declared : Finset Tool
  /-- The tools a live proxy actually intercepts right now. -/
  guarded : Finset Tool
  /-- `lockOwnerIsLive(state.lease)` (spine/protection.cjs:558-568). -/
  leaseLive : Bool
  /-- `state.localOverride.installed` (spine/protection.cjs:335-349, :722-726). -/
  installed : Bool

/-- The six state classes `seal status` can display (bin/seal:58-74 over
`protectionView`, spine/protection.cjs:629-640). -/
inductive View
  | unprotected | pendingRestart | active | stale | drifted | broken
deriving DecidableEq

/-- Status view: STALE is exactly an ACTIVE record whose lease is dead
(spine/protection.cjs:632-639). Every other phase displays as itself. -/
def view (s : S) : View :=
  match s.phase with
  | .unprotected    => .unprotected
  | .pendingRestart => .pendingRestart
  | .active         => if s.leaseLive then .active else .stale
  | .drifted        => .drifted
  | .broken         => .broken

/-- The inputs that drive the machine. Constructor names match the
`transitions[].event` field of docs/protection-transition-table.json. -/
inductive Ev
  /-- `seal protect SERVER TOOL...` reaching its first state write. -/
  | protectWrite (req : Finset Tool)
  /-- `claude mcp add` succeeded inside protect. -/
  | installOk
  /-- `claude mcp add` failed inside protect. -/
  | installFail
  /-- Proxy activation: every declared tool is in the observed `tools/list`. -/
  | activateOk (observed : Finset Tool)
  /-- Proxy activation: some declared tool vanished from `tools/list`. -/
  | activateVanished (observed : Finset Tool)
  /-- Proxy activation: project server digest drifted before activation. -/
  | activateDrift
  /-- Proxy activation: the configured server failed start/initialize/list. -/
  | activateListFail
  /-- A forward through a live proxy detects digest drift. -/
  | forwardDrift
  /-- Environment: the lease-holding proxy process exits. -/
  | leaseDies
  /-- `seal unprotect SERVER`. -/
  | unprotect

/-- The transition relation. EVERY constructor cites the lines of
spine/protection.cjs that implement it; a transition without a citation is a
transition the code does not make, and it is not here. -/
inductive Step : S → Ev → S → Prop
  /-- protect writes the whole deduplicated request as `guardTools` in one
  PENDING RESTART record with `lease: null` and `installed: false`
  (spine/protection.cjs:691-712; dedup :651; refusal of every prior phase
  except UNPROTECTED :658-663 is the precondition; nonempty request :652).
  Nothing is guarded yet: no proxy exists. -/
  | protectWrite {s : S} {req : Finset Tool}
      (hphase : s.phase = .unprotected) (hne : req.Nonempty) :
      Step s (.protectWrite req)
        { phase := .pendingRestart, declared := req, guarded := ∅,
          leaseLive := false, installed := false }
  /-- The `claude mcp add` install succeeded: the same record is rewritten
  with `installed: true`; phase, guardTools and lease are unchanged
  (spine/protection.cjs:714-717, :722-726). -/
  | installOk {s : S}
      (hphase : s.phase = .pendingRestart) (hinst : s.installed = false) :
      Step s .installOk { s with installed := true }
  /-- The `claude mcp add` install failed: the PENDING RESTART record just
  written is rewritten as BROKEN with a `brokenReason`; `installed` stays
  false (spine/protection.cjs:718-721). -/
  | installFail {s : S}
      (hphase : s.phase = .pendingRestart) (hinst : s.installed = false) :
      Step s .installFail { s with phase := .broken }
  /-- Activation succeeds: `activationLease` refuses a live lease (:779-784),
  requires a readable nonempty `guardTools` (:807 via :295-301), finds no
  vanished member (:808-809 with `vanishedTools` empty), and writes ACTIVE
  with a fresh lease generation (spine/protection.cjs:820-836). The proxy now
  intercepts the WHOLE declared set — the code refused every partial
  alternative (:807-819). NOTE the deliberate absence of a phase
  precondition: `activationLease` never inspects `state.state`
  (spine/protection.cjs:772-841); see disagreement D1 in the lane report. -/
  | activateOk {s : S} {observed : Finset Tool}
      (hlease : s.leaseLive = false) (hne : s.declared.Nonempty)
      (hall : s.declared ⊆ observed) :
      Step s (.activateOk observed)
        { s with phase := .active, guarded := s.declared, leaseLive := true }
  /-- Activation with a vanished member: the code collects EVERY guarded name
  missing from `tools/list`, calls `markBroken`, and refuses activation
  (spine/protection.cjs:808-819); `markBroken` writes BROKEN and clears the
  lease (:766-770). The two survivors of a three-tool set are NOT activated
  as a partial set — this constructor is the whole reason the theorem below
  is about the shipped machine and not a nicer one. -/
  | activateVanished {s : S} {observed : Finset Tool}
      (hlease : s.leaseLive = false) (hne : s.declared.Nonempty)
      (hmiss : ¬ s.declared ⊆ observed) :
      Step s (.activateVanished observed)
        { s with phase := .broken, guarded := ∅, leaseLive := false }
  /-- Activation finds the project server digest drifted: `markDrifted`
  writes DRIFTED (spine/protection.cjs:789-792, :752-756). `markDrifted`
  KEEPS the stored lease (:753 spreads `...state`); at this point the lease
  is dead (:779-784 refused a live one), so liveness stays false. -/
  | activateDrift {s : S} (hlease : s.leaseLive = false) :
      Step s .activateDrift { s with phase := .drifted, guarded := ∅ }
  /-- The configured server failed to start, initialize or answer
  `tools/list` during activation: `markBroken` writes BROKEN and clears the
  lease (spine/protection.cjs:794-805, :766-770). -/
  | activateListFail {s : S} (hlease : s.leaseLive = false) :
      Step s .activateListFail
        { s with phase := .broken, guarded := ∅, leaseLive := false }
  /-- A forward through the live proxy detects drift: `beforeForwardFromState`
  calls `markDrifted` and refuses the forward, and every later forward
  re-checks and refuses again (spine/protection.cjs:843-857, :752-756), so
  nothing is guarded any more — the proxy intercepts nothing on behalf of
  the declared set; it refuses everything. The lease is retained (:753) and
  the holding process is still alive. -/
  | forwardDrift {s : S}
      (hphase : s.phase = .active) (hlease : s.leaseLive = true) :
      Step s .forwardDrift { s with phase := .drifted, guarded := ∅ }
  /-- The lease-holding proxy process exits. No code writes state here; the
  environment changed. An ACTIVE record with a dead lease displays as STALE
  (spine/protection.cjs:632-639), and a dead proxy intercepts nothing, so
  the guarded set is empty. A later proxy with a mismatched lease generation
  also refuses every forward (:847-849). -/
  | leaseDies {s : S} (hlease : s.leaseLive = true) :
      Step s .leaseDies { s with leaseLive := false, guarded := ∅ }
  /-- `seal unprotect SERVER` removes the override and writes UNPROTECTED
  with `lease: null` (spine/protection.cjs:730-750, write at :748).
  Preconditions: the lease is not live (:739-741 refuses), and
  `assertSealOwnedLocalOverride` (:735, :351-369) requires a non-UNPROTECTED
  record whose override was installed. `guardTools` is retained as history
  (the doc's answer 4): `declared` is unchanged, and nothing is guarded. -/
  | unprotect {s : S}
      (hphase : s.phase ≠ .unprotected) (hlease : s.leaseLive = false)
      (hinst : s.installed = true) :
      Step s .unprotect
        { s with phase := .unprotected, guarded := ∅, leaseLive := false }

/-- Before the first `seal protect` there is no state file; `readState`
returns null and every view is UNPROTECTED (spine/protection.cjs:275-281,
:630). -/
def init : S :=
  { phase := .unprotected, declared := ∅, guarded := ∅,
    leaseLive := false, installed := false }

/-- The states the shipped machine can actually reach. -/
inductive Reachable : S → Prop
  | init : Reachable init
  | step {s : S} {e : Ev} {s' : S} :
      Reachable s → Step s e s' → Reachable s'

/-- The inductive invariant: a live ACTIVE record guards exactly the declared
set; every other reachable configuration guards nothing. -/
def Inv (s : S) : Prop :=
  if s.phase = Phase.active ∧ s.leaseLive = true
  then s.guarded = s.declared
  else s.guarded = ∅

theorem inv_reachable {s : S} (h : Reachable s) : Inv s := by
  induction h with
  | init => simp [Inv, init]
  | step _ hstep ih =>
    cases hstep with
    | protectWrite hphase hne => simp [Inv]
    | installOk hphase hinst =>
      simp only [Inv] at ih ⊢
      simp [hphase] at ih ⊢
      exact ih
    | installFail hphase hinst =>
      simp only [Inv] at ih ⊢
      simp [hphase] at ih ⊢
      exact ih
    | activateOk hlease hne hall => simp [Inv]
    | activateVanished hlease hne hmiss => simp [Inv]
    | activateDrift hlease => simp [Inv]
    | activateListFail hlease => simp [Inv]
    | forwardDrift hphase hlease => simp [Inv]
    | leaseDies hlease => simp [Inv]
    | unprotect hphase hlease hinst => simp [Inv]

/-- **ATOMICITY.** In every reachable state of the modelled machine, the
guarded set equals the declared set or is empty. Seal's model never guards a
strict non-empty subset of what was declared. -/
theorem guarded_atomic {s : S} (h : Reachable s) :
    s.guarded = s.declared ∨ s.guarded = ∅ := by
  have hi := inv_reachable h
  unfold Inv at hi
  split at hi
  · exact Or.inl hi
  · exact Or.inr hi

/-- The property in its negative reading: no reachable state guards a
non-empty strict subset of the declared set. -/
theorem never_partial {s : S} (h : Reachable s) :
    ¬ (s.guarded ≠ ∅ ∧ s.guarded ⊂ s.declared) := by
  rintro ⟨hne, hssub⟩
  rcases guarded_atomic h with heq | hempty
  · rw [heq] at hssub
    exact (Finset.ssubset_def.mp hssub).2 (Finset.Subset.refl _)
  · exact hne hempty

/-- Only a live ACTIVE record guards anything, and it guards the whole
declared set. -/
theorem guarded_full_when_live_active {s : S} (h : Reachable s)
    (hp : s.phase = Phase.active) (hl : s.leaseLive = true) :
    s.guarded = s.declared := by
  have hi := inv_reachable h
  unfold Inv at hi
  rwa [if_pos ⟨hp, hl⟩] at hi

/-- Everywhere else — UNPROTECTED, PENDING RESTART, STALE, DRIFTED, BROKEN —
nothing is guarded. -/
theorem guarded_empty_unless_live_active {s : S} (h : Reachable s)
    (hn : ¬ (s.phase = Phase.active ∧ s.leaseLive = true)) :
    s.guarded = ∅ := by
  have hi := inv_reachable h
  unfold Inv at hi
  rwa [if_neg hn] at hi

/-- The STALE view in particular: an ACTIVE record whose lease died displays
STALE and guards nothing. -/
theorem stale_guards_nothing {s : S} (h : Reachable s)
    (hp : s.phase = Phase.active) (hl : s.leaseLive = false) :
    view s = View.stale ∧ s.guarded = ∅ := by
  refine ⟨by simp [view, hp, hl], ?_⟩
  exact guarded_empty_unless_live_active h (by simp [hl])

end Host.Protection
