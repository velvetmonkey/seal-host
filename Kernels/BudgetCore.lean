/- SPDX-License-Identifier: Apache-2.0 -/

import SealCore.Event

/-!
# BudgetCore — the monotone spend/rate gate

SealCore's latent budget-update invariant, promoted to a standalone proven
automaton: a monotone spend counter that admits a cost only while the running
total stays at or under the cap. `run_never_over_budget` is the headline —
no event sequence whatsoever can push an in-budget counter past its cap.
-/

namespace BudgetCore

structure BState where
  spent : Nat := 0
  deriving Repr

def BState.empty : BState := {}

/-- Admit `cost` iff it fits under `cap`; a blocked spend changes nothing. -/
def step (cap : Nat) (s : BState) (cost : Nat) : SealCore.Decision × BState :=
  if s.spent + cost ≤ cap then (.allow, { spent := s.spent + cost }) else (.block, s)

theorem allow_iff_within (cap : Nat) (s : BState) (cost : Nat) :
    (step cap s cost).1 = .allow ↔ s.spent + cost ≤ cap := by
  unfold step
  by_cases h : s.spent + cost ≤ cap <;> simp [h]

/-- **Over-budget denied.** A cost that would exceed the cap is blocked. -/
theorem over_budget_denied (cap : Nat) (s : BState) (cost : Nat)
    (h : cap < s.spent + cost) : (step cap s cost).1 = .block := by
  unfold step
  simp [Nat.not_le.mpr h]

/-- The counter is monotone: spending never decreases it, denial never
    changes it. -/
theorem step_monotone (cap : Nat) (s : BState) (cost : Nat) :
    s.spent ≤ ((step cap s cost).2).spent := by
  unfold step
  by_cases h : s.spent + cost ≤ cap <;> simp [h] <;> omega

/-- One step preserves the budget invariant. -/
theorem never_over_budget (cap : Nat) (s : BState) (cost : Nat)
    (h : s.spent ≤ cap) : ((step cap s cost).2).spent ≤ cap := by
  unfold step
  by_cases hc : s.spent + cost ≤ cap <;> simp [hc] <;> omega

def run (cap : Nat) (s : BState) : List Nat → BState
  | [] => s
  | cost :: rest => run cap (step cap s cost).2 rest

/-- **The budget invariant, trace form.** No sequence of attempted costs can
    push an in-budget counter past its cap — the gate enforces `spent ≤ cap`
    forever, not per call. -/
theorem run_never_over_budget (cap : Nat) (costs : List Nat) (s : BState)
    (h : s.spent ≤ cap) : (run cap s costs).spent ≤ cap := by
  induction costs generalizing s with
  | nil => exact h
  | cons cost rest ih =>
      exact ih (step cap s cost).2 (never_over_budget cap s cost h)

end BudgetCore
