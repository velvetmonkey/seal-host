/- SPDX-License-Identifier: Apache-2.0 -/

import SealCore.Event
import Std.Data.HashMap
import Std.Data.HashMap.Lemmas

/-!
# LinearCore — the capability-accounting calculus

The linear-resource fragment behind kernel L: capabilities are granted with a
finite use multiplicity and spent exactly one use at a time. This generalises
SealCore's proven one-shot-approval consumption (multiplicity 1) into a full
no-double-spend invariant: across any event trace, the allowed spends of a
capability never exceed what was granted (plus what the initial state held).

The conservation theorem `granted_plus_initial_eq_spent_plus_remaining` is the
linear-logic content: a capability is a resource, not a fact — using it twice
requires holding it twice.
-/

namespace LinearCore

/-- Capability identifier (operator-meaningful string, e.g. "deploy-key-7"). -/
abbrev CapId := String

/-- `remaining` maps a capability to its unused grant multiplicity. Absent and
    zero both mean "cannot spend". -/
structure LState where
  remaining : Std.HashMap CapId Nat := ∅
  deriving Repr

def LState.empty : LState := {}

inductive LEvent where
  | grant (cap : CapId) (uses : Nat)
  | spend (cap : CapId)
  deriving Repr

/-- How many uses of `cap` the state holds. -/
def holds (s : LState) (cap : CapId) : Nat :=
  s.remaining[cap]?.getD 0

/-- The linear automaton. A grant adds multiplicity; a spend consumes EXACTLY
    one use and blocks when none remain (fail-closed: an unknown capability is
    an exhausted one). -/
def step (s : LState) : LEvent → SealCore.Decision × LState
  | .grant cap uses =>
      (.allow, { remaining := s.remaining.insert cap (holds s cap + uses) })
  | .spend cap =>
      match holds s cap with
      | 0 => (.block, s)
      | n + 1 => (.allow, { remaining := s.remaining.insert cap n })

/-- Step equation: spending an exhausted (or never-granted) capability. -/
theorem step_spend_exhausted (s : LState) (cap : CapId) (h : holds s cap = 0) :
    step s (.spend cap) = (.block, s) := by
  simp only [step]
  rw [h]

/-- Step equation: spending a live capability. -/
theorem step_spend_live (s : LState) (cap : CapId) (n : Nat)
    (h : holds s cap = n + 1) :
    step s (.spend cap) = (.allow, { remaining := s.remaining.insert cap n }) := by
  simp only [step]
  rw [h]

/-- A spend of a never-granted or exhausted capability is blocked. -/
theorem spend_exhausted_blocked (s : LState) (cap : CapId)
    (h : holds s cap = 0) : (step s (.spend cap)).1 = .block := by
  rw [step_spend_exhausted s cap h]

/-- An allowed spend consumes exactly one use — never zero, never more. -/
theorem spend_allow_consumes (s : LState) (cap : CapId) (n : Nat)
    (h : holds s cap = n + 1) :
    (step s (.spend cap)).1 = .allow ∧ holds (step s (.spend cap)).2 cap = n := by
  rw [step_spend_live s cap n h]
  simp [holds]

/-- A spend never touches another capability's multiplicity. -/
theorem spend_preserves_other (s : LState) (cap other : CapId) (hne : cap ≠ other) :
    holds (step s (.spend cap)).2 other = holds s other := by
  cases h : holds s cap with
  | zero => rw [step_spend_exhausted s cap h]
  | succ n =>
      rw [step_spend_live s cap n h]
      simp only [holds, Std.HashMap.getElem?_insert]
      have hbeq : (cap == other) = false := beq_false_of_ne hne
      simp [hbeq]

/-- **No double spend.** A capability granted one use admits exactly one
    spend: the first is allowed, the immediate retry is blocked. SealCore's
    one-shot approval is this theorem at multiplicity 1. -/
theorem no_double_spend (s : LState) (cap : CapId) (h : holds s cap = 0) :
    let s1 := (step s (.grant cap 1)).2
    let r1 := step s1 (.spend cap)
    r1.1 = .allow ∧ (step r1.2 (.spend cap)).1 = .block := by
  intro s1 r1
  have h0 : s.remaining[cap]?.getD 0 = 0 := h
  have h1 : holds s1 cap = 1 := by
    simp [s1, step, holds, h0]
  obtain ⟨hallow, hrem⟩ := spend_allow_consumes s1 cap 0 h1
  exact ⟨hallow, spend_exhausted_blocked _ cap hrem⟩

/-! ## Trace-level conservation -/

/-- Total multiplicity granted to `cap` across a trace. -/
def granted (cap : CapId) : List LEvent → Nat
  | [] => 0
  | .grant c n :: rest => (if c == cap then n else 0) + granted cap rest
  | .spend _ :: rest => granted cap rest

/-- Run the automaton over a trace, counting the ALLOWED spends of `cap`
    (blocked spends consume nothing and count for nothing). -/
def runCount (s : LState) (cap : CapId) : List LEvent → LState × Nat
  | [] => (s, 0)
  | e :: rest =>
      let (d, s') := step s e
      let (sf, k) := runCount s' cap rest
      let hit := match e, d with
        | .spend c, .allow => if c == cap then 1 else 0
        | _, _ => 0
      (sf, hit + k)

/-- **Conservation — the linear-logic invariant.** Across any trace, what was
    granted plus what the initial state held is exactly what was spent plus
    what remains. Capabilities are neither created by spending nor destroyed
    by denial. -/
theorem granted_plus_initial_eq_spent_plus_remaining
    (es : List LEvent) (s : LState) (cap : CapId) :
    granted cap es + holds s cap =
      (runCount s cap es).2 + holds (runCount s cap es).1 cap := by
  induction es generalizing s with
  | nil => simp [granted, runCount]
  | cons e rest ih =>
      cases e with
      | grant c n =>
          have hstep : step s (.grant c n) =
              (.allow, { remaining := s.remaining.insert c (holds s c + n) }) := rfl
          by_cases hc : c = cap
          · subst hc
            have hholds : holds { remaining := s.remaining.insert c (holds s c + n) : LState } c
                = holds s c + n := by
              simp [holds]
            have hrest := ih { remaining := s.remaining.insert c (holds s c + n) : LState }
            rw [hholds] at hrest
            simp only [granted, runCount, hstep, beq_self_eq_true, if_true]
            omega
          · have hbeq : (c == cap) = false := beq_false_of_ne hc
            have hholds : holds { remaining := s.remaining.insert c (holds s c + n) : LState } cap
                = holds s cap := by
              simp [holds, Std.HashMap.getElem?_insert, hbeq]
            have hrest := ih { remaining := s.remaining.insert c (holds s c + n) : LState }
            rw [hholds] at hrest
            simp only [granted, runCount, hstep, hbeq, Bool.false_eq_true, if_false]
            omega
      | spend c =>
          cases hh : holds s c with
          | zero =>
              have hstep := step_spend_exhausted s c hh
              have hrest := ih s
              simp only [granted, runCount, hstep]
              omega
          | succ n =>
              have hstep := step_spend_live s c n hh
              by_cases hc : c = cap
              · subst hc
                have hholds : holds { remaining := s.remaining.insert c n : LState } c = n := by
                  simp [holds]
                have hrest := ih { remaining := s.remaining.insert c n : LState }
                rw [hholds] at hrest
                simp only [granted, runCount, hstep, beq_self_eq_true, if_true]
                omega
              · have hbeq : (c == cap) = false := beq_false_of_ne hc
                have hholds : holds { remaining := s.remaining.insert c n : LState } cap
                    = holds s cap := by
                  simp [holds, Std.HashMap.getElem?_insert, hbeq]
                have hrest := ih { remaining := s.remaining.insert c n : LState }
                rw [hholds] at hrest
                simp only [granted, runCount, hstep, hbeq, Bool.false_eq_true, if_false]
                omega

/-- **No over-spend, trace form.** The allowed spends of a capability never
    exceed its grants plus the initial holding. -/
theorem spends_le_grants (es : List LEvent) (s : LState) (cap : CapId) :
    (runCount s cap es).2 ≤ granted cap es + holds s cap := by
  have := granted_plus_initial_eq_spent_plus_remaining es s cap
  omega

end LinearCore
