/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Classify
import Seal.PolicyV2Theorems

/-!
# Policy rule-overlap resolution — fail-closed and order-independent

**The question this module answers.** What happens when a policy defines the
same tool twice, with different modes? `Seal.classifyToolCall` is NOT
first-match: it evaluates EVERY rule against the call and resolves the full
decision list with `Seal.resolveRuleDecisions`. This module characterises that
resolution, quantified over arbitrary decision lists and arbitrary rule
overlap:

1. **Deny wins** (`blocking_element_denies`, `classify_blocking_rule_denies`,
   `deny_mode_rule_wins`): if ANY matching rule blocks (flat deny or invalid
   guard target), the outcome is `defaultDeny`, whatever else matched and in
   whatever order.
2. **Ambiguity is fail-closed** (`conflicting_guards_ambiguous`,
   `conflicting_guards_deny`, `classify_conflicting_guards_deny`): two guard
   decisions with DIFFERENT targets can never produce `guarded`; absent a
   blocking rule the outcome is exactly
   `defaultDeny "ambiguous guard target"`.
3. **Order-independence at the outcome level** (`resolve_perm_toEvent`,
   `classify_perm_toEvent`): permuting the decision list (respectively the
   policy's rule list) never changes the resulting `SealCore.Event` — the
   constructor (`defaultDeny` / `guarded` / `benign`) and, in the guarded
   case, the target hash.

**Granularity — load-bearing honesty note.** The `SealCore.Event` inside a
`HostEvent` structurally carries no strings; the human-readable reason string
travels in the separate `targetText` field. That string IS order-dependent by
construction: `firstBlocking?` reports the FIRST blocking reason, and the
guarded branch reports the first guard's text. So "permutation preserves the
whole `HostEvent`" is FALSE, and `reason_string_is_order_dependent` below
exhibits the counterexample rather than omitting the caveat. The theorems
therefore quantify over `(·).toEvent` — exactly the security-relevant outcome
and nothing weaker.

Proved from a seal-host module ABOUT the frozen `mcp-seal` definitions;
`Seal/Classify.lean` itself is not modified. Builds on the pointwise cases in
`Seal/PolicyV2Theorems.lean` (nil, singleton allow, allow+guard, and the
`firstBlocking?`-hypothesis-shaped `blocking_decision_dominates`); the results
here are the quantified, order-free generalisations.
-/

namespace Host.PolicyOverlap

open Lean SealCore Seal

/-- A rule decision that forces the blocking branch of
    `resolveRuleDecisions`: a flat deny or an invalid (missing-target) guard. -/
def isBlocking : RuleDecision → Bool
  | .deny _ => true
  | .invalid _ => true
  | _ => false

/-- `firstBlocking?` fires exactly when SOME element of the list blocks —
    the existential, order-free characterisation of the blocking branch. -/
theorem firstBlocking?_isSome_iff (l : List RuleDecision) :
    (firstBlocking? l).isSome ↔ ∃ d ∈ l, isBlocking d := by
  induction l with
  | nil => simp [firstBlocking?]
  | cons d rest ih =>
    cases d with
    | deny reason => simp [firstBlocking?, isBlocking]
    | invalid reason => simp [firstBlocking?, isBlocking]
    | allow => simpa [firstBlocking?, isBlocking] using ih
    | guard target text => simpa [firstBlocking?, isBlocking] using ih

/-! ## Target 1 — deny wins, quantified over the whole list -/

/-- **Deny wins.** If ANY decision in the list blocks, resolution yields the
    `defaultDeny` outcome — irrespective of what else is present or in what
    order. Lifts `Seal.blocking_decision_dominates` from a `firstBlocking?`
    hypothesis to a bare existential. -/
theorem blocking_element_denies {l : List RuleDecision}
    (h : ∃ d ∈ l, isBlocking d) :
    (resolveRuleDecisions l).toEvent = .defaultDeny := by
  obtain ⟨reason, hfb⟩ :=
    Option.isSome_iff_exists.mp ((firstBlocking?_isSome_iff l).mpr h)
  rw [blocking_decision_dominates hfb]
  rfl

/-- Reason-carrying form of `blocking_element_denies`: some blocking reason is
    reported. WHICH reason depends on list order (see
    `reason_string_is_order_dependent`). -/
theorem blocking_element_denies_reason {l : List RuleDecision}
    (h : ∃ d ∈ l, isBlocking d) :
    ∃ reason, resolveRuleDecisions l = .event .defaultDeny reason := by
  obtain ⟨reason, hfb⟩ :=
    Option.isSome_iff_exists.mp ((firstBlocking?_isSome_iff l).mpr h)
  exact ⟨reason, blocking_decision_dominates hfb⟩

/-! ## Target 2 — conflicting guard targets are fail-closed -/

/-- Membership transport into `guardDecisions`. -/
theorem guard_mem_guardDecisions {l : List RuleDecision}
    {target : TargetHash} {text : String}
    (h : .guard target text ∈ l) : (target, text) ∈ guardDecisions l :=
  List.mem_filterMap.mpr ⟨.guard target text, h, rfl⟩

/-- `sameGuardTarget`, order-free: it holds iff every guard in the whole
    (cons-shaped) list carries the head's target. Uses `TargetHash = Digest256`
    deriving `LawfulBEq`, so `==` coincides with `=`. -/
theorem sameGuardTarget_iff (first : TargetHash × String)
    (rest : List (TargetHash × String)) :
    sameGuardTarget first rest = true ↔ ∀ x ∈ rest, x.1 = first.1 := by
  simp [sameGuardTarget, List.all_eq_true]

/-- **Ambiguity is fail-closed, exact form.** Absent any blocking decision,
    two guards with DIFFERENT targets resolve to exactly
    `defaultDeny "ambiguous guard target"` — never `guarded`. This is the
    quantified answer to "the same tool defined twice with conflicting
    targets"; `Seal.ambiguous_guard_targets_block` is the two-element
    instance. -/
theorem conflicting_guards_ambiguous {l : List RuleDecision}
    (hnb : firstBlocking? l = none)
    {t₁ t₂ : TargetHash} {s₁ s₂ : String}
    (h₁ : .guard t₁ s₁ ∈ l) (h₂ : .guard t₂ s₂ ∈ l) (hne : t₁ ≠ t₂) :
    resolveRuleDecisions l = .event .defaultDeny "ambiguous guard target" := by
  have hm₁ := guard_mem_guardDecisions h₁
  have hm₂ := guard_mem_guardDecisions h₂
  cases hg : guardDecisions l with
  | nil => rw [hg] at hm₁; cases hm₁
  | cons first rest =>
    rw [hg] at hm₁ hm₂
    have hfalse : sameGuardTarget first rest = false := by
      cases hval : sameGuardTarget first rest
      · rfl
      · exfalso
        have hall : ∀ x ∈ first :: rest, x.1 = first.1 := by
          intro x hx
          rcases List.mem_cons.mp hx with hEq | hRest
          · rw [hEq]
          · exact (sameGuardTarget_iff first rest).mp hval x hRest
        exact hne ((hall (t₁, s₁) hm₁).trans (hall (t₂, s₂) hm₂).symm)
    simp [resolveRuleDecisions, hnb, hg, hfalse]

/-- **Ambiguity is fail-closed, outcome form.** Two guards with different
    targets anywhere in the list force the `defaultDeny` outcome (either some
    blocking reason fired first, or the ambiguous-guard deny did). -/
theorem conflicting_guards_deny {l : List RuleDecision}
    {t₁ t₂ : TargetHash} {s₁ s₂ : String}
    (h₁ : .guard t₁ s₁ ∈ l) (h₂ : .guard t₂ s₂ ∈ l) (hne : t₁ ≠ t₂) :
    (resolveRuleDecisions l).toEvent = .defaultDeny := by
  cases hnb : firstBlocking? l with
  | some reason => rw [blocking_decision_dominates hnb]; rfl
  | none => rw [conflicting_guards_ambiguous hnb h₁ h₂ hne]; rfl

/-! ## Target 3 — order-independence of the security-relevant outcome -/

/-- Pairwise target agreement — the permutation-invariant reformulation of
    `sameGuardTarget`. -/
def agreeOnTarget (guards : List (TargetHash × String)) : Prop :=
  ∀ x ∈ guards, ∀ y ∈ guards, x.1 = y.1

theorem sameGuardTarget_iff_agree (first : TargetHash × String)
    (rest : List (TargetHash × String)) :
    sameGuardTarget first rest = true ↔ agreeOnTarget (first :: rest) := by
  rw [sameGuardTarget_iff]
  constructor
  · intro h x hx y hy
    have hx' : x.1 = first.1 := by
      rcases List.mem_cons.mp hx with hEq | hRest
      · rw [hEq]
      · exact h x hRest
    have hy' : y.1 = first.1 := by
      rcases List.mem_cons.mp hy with hEq | hRest
      · rw [hEq]
      · exact h y hRest
    exact hx'.trans hy'.symm
  · intro h x hx
    exact h x (List.mem_cons_of_mem first hx) first List.mem_cons_self

/-- **Order-independence.** Permuting the decision list never changes the
    resulting `SealCore.Event`: the outcome constructor
    (`defaultDeny`/`guarded`/`benign`) and, in the guarded case, the target
    hash. NOT claimed for the full `HostEvent`: the reason string is genuinely
    order-dependent — see `reason_string_is_order_dependent`. -/
theorem resolve_perm_toEvent {l₁ l₂ : List RuleDecision} (h : l₁.Perm l₂) :
    (resolveRuleDecisions l₁).toEvent = (resolveRuleDecisions l₂).toEvent := by
  have hfbIff : (firstBlocking? l₁).isSome ↔ (firstBlocking? l₂).isSome := by
    rw [firstBlocking?_isSome_iff, firstBlocking?_isSome_iff]
    exact ⟨fun ⟨d, hd, hb⟩ => ⟨d, h.mem_iff.mp hd, hb⟩,
           fun ⟨d, hd, hb⟩ => ⟨d, h.mem_iff.mpr hd, hb⟩⟩
  cases hfb₁ : firstBlocking? l₁ with
  | some r₁ =>
    obtain ⟨r₂, hfb₂⟩ :=
      Option.isSome_iff_exists.mp (hfbIff.mp (by rw [hfb₁]; rfl))
    rw [blocking_decision_dominates hfb₁, blocking_decision_dominates hfb₂]
    rfl
  | none =>
    have hfb₂ : firstBlocking? l₂ = none := by
      cases hfb₂ : firstBlocking? l₂ with
      | none => rfl
      | some r =>
        have : (firstBlocking? l₁).isSome := hfbIff.mpr (by rw [hfb₂]; rfl)
        rw [hfb₁] at this
        cases this
    have hperm : (guardDecisions l₁).Perm (guardDecisions l₂) := h.filterMap _
    cases hg₁ : guardDecisions l₁ with
    | nil =>
      have hg₂ : guardDecisions l₂ = [] := by
        rw [hg₁] at hperm
        exact hperm.symm.eq_nil
      have hallow : hasExplicitAllow l₁ = hasExplicitAllow l₂ := by
        rw [Bool.eq_iff_iff]
        unfold hasExplicitAllow
        simp only [List.any_eq_true]
        exact ⟨fun ⟨x, hx, hp⟩ => ⟨x, h.mem_iff.mp hx, hp⟩,
               fun ⟨x, hx, hp⟩ => ⟨x, h.mem_iff.mpr hx, hp⟩⟩
      simp [resolveRuleDecisions, hfb₁, hfb₂, hg₁, hg₂, hallow]
    | cons f₁ r₁ =>
      cases hg₂ : guardDecisions l₂ with
      | nil =>
        rw [hg₁, hg₂] at hperm
        cases hperm.eq_nil
      | cons f₂ r₂ =>
        rw [hg₁, hg₂] at hperm
        by_cases hag : agreeOnTarget (f₁ :: r₁)
        · have hag₂ : agreeOnTarget (f₂ :: r₂) := fun x hx y hy =>
            hag x (hperm.mem_iff.mpr hx) y (hperm.mem_iff.mpr hy)
          have hs₁ : sameGuardTarget f₁ r₁ = true :=
            (sameGuardTarget_iff_agree f₁ r₁).mpr hag
          have hs₂ : sameGuardTarget f₂ r₂ = true :=
            (sameGuardTarget_iff_agree f₂ r₂).mpr hag₂
          have hheads : f₁.1 = f₂.1 :=
            hag f₁ List.mem_cons_self
                f₂ (hperm.mem_iff.mpr List.mem_cons_self)
          simp [resolveRuleDecisions, hfb₁, hfb₂, hg₁, hg₂, hs₁, hs₂,
                HostEvent.toEvent, hheads]
        · have hag₂ : ¬ agreeOnTarget (f₂ :: r₂) := fun hcon =>
            hag fun x hx y hy =>
              hcon x (hperm.mem_iff.mp hx) y (hperm.mem_iff.mp hy)
          have hs₁ : sameGuardTarget f₁ r₁ = false := by
            cases hval : sameGuardTarget f₁ r₁
            · rfl
            · exact absurd ((sameGuardTarget_iff_agree f₁ r₁).mp hval) hag
          have hs₂ : sameGuardTarget f₂ r₂ = false := by
            cases hval : sameGuardTarget f₂ r₂
            · rfl
            · exact absurd ((sameGuardTarget_iff_agree f₂ r₂).mp hval) hag₂
          simp [resolveRuleDecisions, hfb₁, hfb₂, hg₁, hg₂, hs₁, hs₂]

/-- **Honesty gate, exhibited.** Permutation does NOT preserve the whole
    `HostEvent`: `firstBlocking?` reports the FIRST blocking reason, so the
    reason string genuinely depends on list order. The order-independence
    theorems above are stated at `(·).toEvent` granularity precisely because
    this stronger statement is false. -/
theorem reason_string_is_order_dependent :
    resolveRuleDecisions [.deny "left", .deny "right"] ≠
      resolveRuleDecisions [.deny "right", .deny "left"] := by
  intro hcon
  have hleft : resolveRuleDecisions [.deny "left", .deny "right"] =
      .event .defaultDeny "left" := rfl
  have hright : resolveRuleDecisions [.deny "right", .deny "left"] =
      .event .defaultDeny "right" := rfl
  rw [hleft, hright] at hcon
  injection hcon with _ htext
  exact absurd htext (by decide)

/-! ## Target 4 — lifted to `classifyToolCall` over the policy rule list -/

/-- Deny wins at the policy level: if ANY rule in the policy evaluates to a
    blocking decision for this call, classification yields the `defaultDeny`
    outcome — regardless of every other rule. -/
theorem classify_blocking_rule_denies (policy : Policy) (toolName : String)
    (args : Json) {rule : ToolRule} (hmem : rule ∈ policy.tools)
    {d : RuleDecision} (heval : evaluateRule policy toolName args rule = some d)
    (hblock : isBlocking d = true) :
    (classifyToolCall policy toolName args).toEvent = .defaultDeny :=
  blocking_element_denies ⟨d, List.mem_filterMap.mpr ⟨rule, hmem, heval⟩, hblock⟩

/-- The evaluator's question, answered concretely: a matching `deny`-mode rule
    forces the deny outcome no matter what other rules — allow, guarded, or
    otherwise — the policy also defines for the same tool. -/
theorem deny_mode_rule_wins (policy : Policy) (toolName : String) (args : Json)
    {rule : ToolRule} (hmem : rule ∈ policy.tools)
    (hname : rule.name = toolName) (hmatch : matchRule rule args = true)
    (hmode : rule.mode = .deny) :
    (classifyToolCall policy toolName args).toEvent = .defaultDeny := by
  refine classify_blocking_rule_denies policy toolName args hmem
    (d := .deny s!"flat deny: {toolName}") ?_ rfl
  simp [evaluateRule, evaluateRuleWithMeta, evaluateRuleWithContext,
    hname, hmatch, hmode]

/-- Conflicting guard targets at the policy level: two rules that both match
    the call but commit to DIFFERENT targets force the `defaultDeny` outcome.
    The same tool defined twice with disagreeing guards fails closed. -/
theorem classify_conflicting_guards_deny (policy : Policy) (toolName : String)
    (args : Json) {r₁ r₂ : ToolRule}
    (hmem₁ : r₁ ∈ policy.tools) (hmem₂ : r₂ ∈ policy.tools)
    {t₁ t₂ : TargetHash} {s₁ s₂ : String}
    (heval₁ : evaluateRule policy toolName args r₁ = some (.guard t₁ s₁))
    (heval₂ : evaluateRule policy toolName args r₂ = some (.guard t₂ s₂))
    (hne : t₁ ≠ t₂) :
    (classifyToolCall policy toolName args).toEvent = .defaultDeny :=
  conflicting_guards_deny (List.mem_filterMap.mpr ⟨r₁, hmem₁, heval₁⟩)
    (List.mem_filterMap.mpr ⟨r₂, hmem₂, heval₂⟩) hne

/-- **Order-independence of classification.** Permuting the policy's rule
    list never changes the security-relevant outcome of `classifyToolCall`
    (constructor and guarded target). Rule evaluation reads the policy only
    through `serverIdentity`, which the rule-list update leaves untouched. -/
theorem classify_perm_toEvent (policy : Policy) (tools' : List ToolRule)
    (h : policy.tools.Perm tools') (toolName : String) (args : Json) :
    (classifyToolCall policy toolName args).toEvent =
      (classifyToolCall { policy with tools := tools' } toolName args).toEvent := by
  unfold classifyToolCall
  exact resolve_perm_toEvent (h.filterMap _)

end Host.PolicyOverlap

/-! ## Axiom pins — enforced at module build -/

/-- info: 'Host.PolicyOverlap.blocking_element_denies' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.blocking_element_denies
/-- info: 'Host.PolicyOverlap.blocking_element_denies_reason' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.blocking_element_denies_reason
/-- info: 'Host.PolicyOverlap.conflicting_guards_ambiguous' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.conflicting_guards_ambiguous
/-- info: 'Host.PolicyOverlap.conflicting_guards_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.conflicting_guards_deny
/-- info: 'Host.PolicyOverlap.resolve_perm_toEvent' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.resolve_perm_toEvent
/-- info: 'Host.PolicyOverlap.reason_string_is_order_dependent' depends on axioms: [propext] -/
#guard_msgs in #print axioms Host.PolicyOverlap.reason_string_is_order_dependent
/-- info: 'Host.PolicyOverlap.classify_blocking_rule_denies' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.classify_blocking_rule_denies
/-- info: 'Host.PolicyOverlap.deny_mode_rule_wins' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.deny_mode_rule_wins
/-- info: 'Host.PolicyOverlap.classify_conflicting_guards_deny' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.classify_conflicting_guards_deny
/-- info: 'Host.PolicyOverlap.classify_perm_toEvent' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms Host.PolicyOverlap.classify_perm_toEvent
