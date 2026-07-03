/- SPDX-License-Identifier: Apache-2.0 -/

import Crdt.Liveness
import Kernels.Convergence

/-!
# W2-T4 — Convergence potential: a Lyapunov function for admitted dynamics

The Convergence kernel admits only operations in the fixed proven-convergent
set (`convergentAccepts`, preserved under composition by
`Host.composed_convergent`). The semantics of those operations are the
crdt-lean join-semilattice CRDTs, whose delivery dynamics are
`Crdt.DeliverySystem` (finite fixed update pool = quiescence; monotone,
sound, fair delivery). This module adjoins the potential the wave brief asks
for: the DEFICIT — how many generated updates a replica has not yet
delivered — and proves it is a Lyapunov function for the admitted dynamics:

* `deficit_antitone` — the potential never increases;
* `deficit_strict_decrease` — delivering a genuinely NEW update strictly
  decreases it;
* `deficit_eq_zero_iff` — potential zero exactly when the replica holds the
  full update set;
* `deficit_zero_converged` — potential zero ⇒ the replica's state IS the
  converged state (the join of all updates);
* `deficit_eventually_zero` — under fairness + quiescence the potential
  reaches zero and stays there (`DeliverySystem.converges`).

HONESTY (no overclaim): the potential is non-increasing along time, NOT
strictly decreasing at every tick — delivery can stall between arrivals.
`DeliverySystem` has no per-event "accepted delivery"; deliveries are a
monotone time-indexed set, so "each accepted delivery strictly decreases V"
is modeled as delivery-of-a-new-update (`deficit_strict_decrease`).

TRUST BOUNDARY: fairness and quiescence are `DeliverySystem` HYPOTHESES —
asserted network assumptions, not theorems (crdt-lean's own discipline). The
binding "kernel-admitted op ↔ model update" is an interpretation: the kernel
proves admitted ops lie in the proven-convergent set
(`Host.composed_convergent`); the CRDC dynamics of that set live here. No
refinement of the deployed runtime to `DeliverySystem` is claimed.
-/

namespace Kernels

open Crdt

variable {ι S : Type*} [SemilatticeSup S] [OrderBot S] [DecidableEq S]

/-- **The Lyapunov potential**: the number of generated updates replica `r`
    has not yet delivered by time `t`. Quiescence (finite `allUpdates`) makes
    this a `Nat`. -/
def deficit (sys : DeliverySystem ι S) (r : ι) (t : ℕ) : ℕ :=
  (sys.allUpdates \ sys.delivered r t).card

/-- **The potential never increases** (delivery only accumulates). -/
theorem deficit_antitone (sys : DeliverySystem ι S) (r : ι) :
    Antitone (deficit sys r) := fun _ _ h =>
  Finset.card_le_card
    (Finset.sdiff_subset_sdiff (Finset.Subset.refl _) (sys.mono r h))

/-- **Delivering a genuinely new update strictly decreases the potential.** -/
theorem deficit_strict_decrease (sys : DeliverySystem ι S) (r : ι)
    {t t' : ℕ} (h : t ≤ t') {a : S} (ha : a ∈ sys.allUpdates)
    (hnew : a ∉ sys.delivered r t) (hdel : a ∈ sys.delivered r t') :
    deficit sys r t' < deficit sys r t := by
  apply Finset.card_lt_card
  rw [Finset.ssubset_iff_of_subset
    (Finset.sdiff_subset_sdiff (Finset.Subset.refl _) (sys.mono r h))]
  exact ⟨a, Finset.mem_sdiff.mpr ⟨ha, hnew⟩,
    fun hc => (Finset.mem_sdiff.mp hc).2 hdel⟩

/-- **Potential zero IS full delivery** (soundness gives the reverse
    inclusion). -/
theorem deficit_eq_zero_iff (sys : DeliverySystem ι S) (r : ι) (t : ℕ) :
    deficit sys r t = 0 ↔ sys.delivered r t = sys.allUpdates := by
  rw [deficit, Finset.card_eq_zero, Finset.sdiff_eq_empty_iff_subset]
  exact ⟨fun h => Finset.Subset.antisymm (sys.sound r t) h,
    fun h => h ▸ Finset.Subset.refl _⟩

/-- **Potential zero ⇒ converged state**: the replica's observable state is
    the join of every generated update. -/
theorem deficit_zero_converged (sys : DeliverySystem ι S) (r : ι) (t : ℕ)
    (h : deficit sys r t = 0) :
    replicaState (sys.delivered r t) = sys.convergedState := by
  rw [(deficit_eq_zero_iff sys r t).mp h, DeliverySystem.convergedState]

/-- **The potential eventually hits zero and stays there** — fairness +
    quiescence, through `DeliverySystem.converges`. -/
theorem deficit_eventually_zero (sys : DeliverySystem ι S) (r : ι) :
    ∃ T, ∀ t, T ≤ t → deficit sys r t = 0 := by
  obtain ⟨T, hT⟩ := sys.converges r
  exact ⟨T, fun t ht => (deficit_eq_zero_iff sys r t).mpr (hT t ht)⟩

/-! ## Non-vacuity: a concrete delivery system where the potential moves

One replica, one update (`true` in the `Bool` join-semilattice), delivered at
t = 1: the deficit steps 1 → 0 and the strict-decrease theorem instantiates. -/

/-- Minimal concrete delivery system: `Unit` replica, update pool `{true}`,
    delivery at t = 1. -/
def sysEx : DeliverySystem Unit Bool where
  allUpdates := {true}
  delivered := fun _ t => if t = 0 then ∅ else {true}
  mono := fun _ => by
    intro t t' hle
    by_cases ht : t = 0
    · simp [ht]
    · have ht' : t' ≠ 0 := by omega
      simp [ht, ht']
  sound := fun _ t => by
    by_cases ht : t = 0 <;> simp [ht]
  fair := fun _ a ha => ⟨1, by simpa using ha⟩

theorem sysEx_deficit_before : deficit sysEx () 0 = 1 := by decide

theorem sysEx_deficit_after : deficit sysEx () 1 = 0 := by decide

/-- The strict-decrease theorem, instantiated on the concrete system. -/
theorem sysEx_strict_decrease : deficit sysEx () 1 < deficit sysEx () 0 :=
  deficit_strict_decrease sysEx () (Nat.zero_le 1) (a := true)
    (by decide) (by decide) (by decide)

end Kernels
