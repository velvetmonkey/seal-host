/- SPDX-License-Identifier: Apache-2.0 -/

import Host.NonInterference
import Host.ReplayIsolation

/-!
# Two-state stateful non-interference over the composed replay seam

The composition the two base theorems could not make: ONE non-interference
theorem over a multi-request trace where BOTH the protected `ApprovalState`
(modulo declassified views) AND the durable replay store vary. This resolves
the obstruction the `ReplayIsolation` header names — generalising to two
`ApprovalState`s pulls `state.consumedNonces` in as a second replay input —
by declassifying exactly what the composed seam actually reads, and proving
the rest cannot flow.

## THE FINDING (headline, not footnote)

Composing the two results FORCES A WIDER DECLASSIFICATION than the
single-request theorem. `observe_noninterference` (T1) keeps `now`,
`publicKey` and `policyVersion` HIGH: for one request against the in-state
gate they are invisible beyond the one authorization bit. But the durable
store seam READS them — `replayNamespace` is built from
`(publicKey, targetKey, session, policyVersion)` (mcp-seal
Validation.lean:260-264) and the store is pruned by `state.now`
(Validation.lean:381-402) — and the probe's hit/miss is observable in the
decision. So in the stateful, cross-request setting these fields become
observable THROUGH THE STORE INTERACTION, and the theorem below declassifies
them (`replayView`) plus the per-request consume data (`consumeView`). The
checked counterexample `policyVersion_declassification_necessary` proves the
widening is forced, not chosen: with `authView` agreement alone (the T1
declassification) and equal stores, two states differing only in
`policyVersion` produce DIVERGENT composed decisions.

What still cannot flow (the theorem's content): `manifestDigest`, `tools`,
`approvals`, `maxApprovalTtl`, `consumedNonces`, and every other protected
field — modulo the declassified views — cannot influence the observable
decision/record trace or the observer's slice of the durable store.

## The model (STEP-0, frozen before proving)

* Observer: a session `s`. Both protected states have `session = s` (the
  observer's identity is LOW). The request stream `raws` is LOW.
* The durable store is the sole EVOLVING replay authority and threads
  through the trace (`decideConsume`, reused from `ReplayIsolation`). The
  two `ApprovalState`s are per-trace FIXED: SealV2 is pure — nothing in the
  proof core mutates `ApprovalState`; in deployment the FFI driver threads
  `consumedNonces` imperatively AS the store (mcp-seal Ffi.lean:117-120), so
  the in-state list is modelled as a fixed second replay input absorbed by
  the per-request view agreement below.
* LOW / declassified:
  - `replayView st = (publicKey, session, policyVersion, now)` — exactly the
    `replayNamespace` fields plus the prune clock, no more (pinned against
    the definition on disk, not the field list from memory);
  - per-request `consumeView raw st` — the probe/write pre-image
    `(targetKey, nonce, expiresAt)` of the validate witness;
    `consumeView.isSome` IS `authView` (bridge lemma), so this strictly
    refines the T1 declassification;
  - `storeLowEq s` — the observer's ordered store slice (`lowPart`), from
    `ReplayIsolation`.
* HIGH: everything else in both states, and other tenants' store entries.
* Observation: the per-step `(Decision, audit record)` list plus the
  observer's slice of the final store. `epoch`/`tool`/`verdicts` are
  host-supplied LOW inputs exactly as in T2 (the named
  controlled-declassification boundary for per-kernel reason/certHash).

## Theorems

* `authView_eq_consumeView_isSome` — the bridge: the new per-request view
  refines the old declassified bit.
* `leaky_probe_fails` — the STEP-0 non-triviality probe: inject ONE
  high-dependent field (`consumedNonces.length`, the named obstruction
  field) into the composed observation and non-interference is REFUTED by a
  concrete witness. The model detects leaks; the theorem below is not
  vacuous by construction.
* `stateful_step` — the interaction step (the real content): view-equal
  states over `lowPart`-equal stores produce equal decisions and
  `lowPart`-equal successor stores. Cites the actual interaction machinery:
  namespace equality from `replayView`+`consumeView`, equal-clock pruning
  via `lowPart_prune_comm`, probe determination via `any_eq_of_lowPart_eq`,
  write locality on the observer's slice.
* `stateful_noninterference_trace` — the capstone fold over any request
  list.
* `stateful_ni_nonvacuous` — non-vacuity with BOTH channels genuinely in
  play: the states differ (HIGH field), the stores differ (another tenant's
  entry), and the observation is unchanged.
* `policyVersion_declassification_necessary` — the checked counterexample
  (hypothesis form, see below): dropping `policyVersion` from the
  declassified view makes the composed NI FALSE.
* `publicKey_declassification_necessary`,
  `session_declassification_necessary`,
  `now_declassification_necessary` — the lower bound COMPLETED: the same
  counterexample shape for every remaining `replayView` field. Together
  with the capstone, `replayView` is the EXACT minimal declassification
  interface: sufficient, and per-field necessary — no strictly smaller
  declassified tuple supports the composed NI. (See the section docstring
  above the three theorems.)

## Honest non-claims and hypothesis-form scope

Single-session observer; timing / size / ordering / allocation side-channels
out of scope; Byzantine tenants out; this is the Lean model of the seam, not
the deployed Rust/TS emitters; the verdict is the intended declassified
channel; tamper-evident, not tamper-impossible. The necessity counterexample
is stated in HYPOTHESIS FORM (a concrete `validate` success is supplied as a
hypothesis rather than constructed): Ed25519 `verifySignature` is not
kernel-evaluable, the same boundary `replay_isolation_nonvacuous` states —
and `validate`'s success at the policyVersion-twisted state is likewise a
hypothesis because `ValidApproval ast state` is state-indexed (the twisted
witness exists — `validate` reads `policyVersion` only through
`nonceConsumed`, vacuous at `consumedNonces = []` — but transporting it
across the index is dependent-type bureaucracy, not content). No frozen
module is edited; the three SealV2 theorems and both base NI theorems are
untouched.
-/

namespace Host.StatefulNI

open SealV2 (RawBytes ApprovalState Decision SessionId PublicKey Nonce
  ConsumedNonce ReplayNamespace parse validate serialize serializeAstValue
  serializeTargetKey replayNamespace pruneConsumedNonces listReplayStore
  validateAndConsumeWithStore)
open Host.ReplayIsolation (lowPart storeLowEq decideConsume
  lowPart_prune_comm any_eq_of_lowPart_eq ns_session_eq_of_beq)
open Host.NonInterference (authView combinedOf)

/-- The state fields the durable replay seam actually reads, verbatim from
`replayNamespace` (publicKey, session, policyVersion) plus the prune clock
(`now`). Declassifying exactly this tuple — no more — is what the composed
theorem costs over the single-request T1. -/
def replayView (st : ApprovalState) : PublicKey × SessionId × String × Nat :=
  (st.publicKey, st.session, st.policyVersion, st.now)

/-- The per-request consume data: the probe/write pre-image of the durable
seam — the canonical target key, the approval nonce and its expiry, when the
request validates. `isSome` of this view is exactly `authView` (bridge
below), so this strictly refines the T1 declassified bit. -/
def consumeView (raw : RawBytes) (st : ApprovalState) :
    Option (String × Nonce × Nat) :=
  match parse raw with
  | none => none
  | some ast =>
      (validate ast st).map fun c =>
        (serializeTargetKey c.snd.target, c.snd.approval.nonce,
          c.snd.approval.expiresAt)

/-- **Bridge:** the new per-request view refines the old one — its success
bit IS `authView`. -/
theorem authView_eq_consumeView_isSome (raw : RawBytes) (st : ApprovalState) :
    authView raw st = (consumeView raw st).isSome := by
  cases hp : parse raw with
  | none => simp [Host.NonInterference.authView, consumeView, hp]
  | some ast =>
      cases hv : validate ast st <;>
        simp [Host.NonInterference.authView, consumeView, hp, hv]

/-- One composed observation step: the decision against the durable seam,
its audit record, and the threaded store. -/
def observeStep (epoch : Nat) (tool : String) (verdicts : List Verdict)
    (raw : RawBytes) (st : ApprovalState) (store : List ConsumedNonce) :
    (Decision × String) × List ConsumedNonce :=
  let step := decideConsume raw st store
  ((step.1, auditLine epoch tool (combinedOf step.1) verdicts raw), step.2)

/-- The observation trace: per-step (decision, record) pairs, threading the
durable store. -/
def observeTrace (epoch : Nat) (tool : String) (verdicts : List Verdict)
    (st : ApprovalState) :
    List RawBytes → List ConsumedNonce →
      List (Decision × String) × List ConsumedNonce
  | [], store => ([], store)
  | raw :: rest, store =>
      let step := observeStep epoch tool verdicts raw st store
      let tail := observeTrace epoch tool verdicts st rest step.2
      (step.1 :: tail.1, tail.2)

/-! ## STEP-0 non-triviality probe

One HIGH-dependent field — `state.consumedNonces.length`, the exact field
the composition obstruction is about — injected into the composed step. If
non-interference still held for THIS observation, the model would have
collapsed the interaction and everything below would be vacuous. It does
not hold: `leaky_probe_fails` exhibits two states satisfying EVERY
hypothesis of the composed theorem whose leaky observations differ. -/

/-- The deliberately leaky step: the composed observation plus one injected
HIGH field. Probe artifact — not part of the claimed observation model. -/
def leakyObserveStep (epoch : Nat) (tool : String) (verdicts : List Verdict)
    (raw : RawBytes) (st : ApprovalState) (store : List ConsumedNonce) :
    (Decision × String × Nat) × List ConsumedNonce :=
  let step := decideConsume raw st store
  ((step.1, auditLine epoch tool (combinedOf step.1) verdicts raw,
    st.consumedNonces.length), step.2)

/-- **The probe fires.** Two states agreeing on `replayView`, on
`consumeView` for the request, with identical stores — every hypothesis of
the composed theorem — but the leaky observation tells them apart. The
injected `consumedNonces` channel is DETECTABLE; the honest theorem below
cannot be vacuous. -/
theorem leaky_probe_fails :
    ∃ (epoch : Nat) (tool : String) (verdicts : List Verdict)
      (raw : RawBytes) (s1 s2 : ApprovalState) (store : List ConsumedNonce),
      s1.session = "s" ∧ s2.session = "s" ∧ s1 ≠ s2 ∧
      replayView s1 = replayView s2 ∧
      consumeView raw s1 = consumeView raw s2 ∧
      storeLowEq "s" store store ∧
      leakyObserveStep epoch tool verdicts raw s1 store
        ≠ leakyObserveStep epoch tool verdicts raw s2 store := by
  refine ⟨1, "t", [], "",
    ⟨"s", 0, "pk", "md", [], [], "", 300, [], 0⟩,
    ⟨"s", 0, "pk", "md", [], [], "", 300,
      [⟨⟨"pk", "tk", "s", ""⟩,
        ⟨String.ofList (List.replicate 64 'a'), by decide⟩, 0⟩], 0⟩,
    [], rfl, rfl, ?_, rfl, rfl, rfl, ?_⟩
  · intro h
    exact absurd (congrArg (fun st => st.consumedNonces.length) h) (by decide)
  · intro h
    have := congrArg (fun p => p.1.2.2) h
    exact absurd this (by decide)

/-! ## The interaction machinery -/

/-- The Allow payload of a successful validation is a function of the parsed
request alone — the state-indexed witness is discarded by serialization.
(Repackaging of `decide_allow_of_validate_isSome` at the `validate` layer.) -/
theorem serialize_validate_eq (raw : RawBytes) (ast : SealV2.AST)
    (st : ApprovalState) (c : Σ a, SealV2.ValidApproval a st)
    (hp : parse raw = some ast) (hv : validate ast st = some c) :
    serialize c = serializeAstValue ast := by
  have hd : SealV2.decide raw st = .Allow (serialize c) := by
    simp only [SealV2.decide, hp, hv]
  have hd2 := Host.NonInterference.decide_allow_of_validate_isSome raw ast st hp
    (by simp [hv])
  rw [hd] at hd2
  injection hd2

/-- **The composed step (the real content).** Two protected states agreeing
on the replay view and on this request's consume view, over stores that
agree on the observer's slice, produce the SAME decision and successor
stores that stay slice-equal — even though the states differ arbitrarily
elsewhere and the stores differ outside the slice. The proof runs through
the actual `consumedNonces`/store interaction: namespace equality assembled
from the two views, equal-clock pruning (`lowPart_prune_comm`), probe
determination on the observer's slice (`any_eq_of_lowPart_eq`), and write
locality of the consumed entry. -/
theorem stateful_step (s : SessionId) (raw : RawBytes)
    (s1 s2 : ApprovalState) (st1 st2 : List ConsumedNonce)
    (hs : s1.session = s)
    (hrv : replayView s1 = replayView s2)
    (hcv : consumeView raw s1 = consumeView raw s2)
    (hlow : storeLowEq s st1 st2) :
    (decideConsume raw s1 st1).1 = (decideConsume raw s2 st2).1 ∧
      storeLowEq s (decideConsume raw s1 st1).2 (decideConsume raw s2 st2).2 := by
  simp only [replayView, Prod.mk.injEq] at hrv
  obtain ⟨hpk, hses, hpv, hnow⟩ := hrv
  cases hp : parse raw with
  | none =>
      refine ⟨?_, ?_⟩ <;> simp only [decideConsume, hp] <;> exact hlow
  | some ast =>
      cases hv1 : validate ast s1 with
      | none =>
          have hcv2 : consumeView raw s2 = none := by
            rw [← hcv]; simp [consumeView, hp, hv1]
          have hv2 : validate ast s2 = none := by
            cases hv2 : validate ast s2 with
            | none => rfl
            | some c2 => simp [consumeView, hp, hv2] at hcv2
          refine ⟨?_, ?_⟩ <;>
            simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
              hv1, hv2] <;>
            exact hlow
      | some c1 =>
          cases hv2 : validate ast s2 with
          | none =>
              have hcv2 : consumeView raw s2 = none := by
                simp [consumeView, hp, hv2]
              rw [hcv2] at hcv
              simp [consumeView, hp, hv1] at hcv
          | some c2 =>
              -- the consume views agree componentwise
              have htrip := hcv
              simp only [consumeView, hp, hv1, hv2, Option.map,
                Option.some.injEq, Prod.mk.injEq] at htrip
              obtain ⟨htk, hn, he⟩ := htrip
              -- the probe namespace is the SAME value on both sides
              have hns : replayNamespace s1 c1.snd.target
                  = replayNamespace s2 c2.snd.target := by
                simp only [SealV2.replayNamespace,
                  SealV2.ReplayNamespace.mk.injEq]
                exact ⟨hpk, htk, hses, hpv⟩
              -- equal clocks + slice-equal stores ⇒ slice-equal pruned stores
              have hprune : lowPart s (pruneConsumedNonces s1.now st1)
                  = lowPart s (pruneConsumedNonces s2.now st2) := by
                rw [← hnow, lowPart_prune_comm, lowPart_prune_comm, hlow]
              -- the probe only reads the observer's slice
              have himp : ∀ e : ConsumedNonce,
                  (e.ns == replayNamespace s1 c1.snd.target
                    && e.nonce == c1.snd.approval.nonce) = true →
                  (e.ns.session == s) = true := by
                intro e hpe
                simp only [Bool.and_eq_true] at hpe
                have hses' := ns_session_eq_of_beq _ _ hpe.1
                have : e.ns.session = s := by
                  rw [hses']; exact hs
                simp [this]
              have hany := any_eq_of_lowPart_eq s
                (fun e => e.ns == replayNamespace s1 c1.snd.target
                  && e.nonce == c1.snd.approval.nonce)
                _ _ hprune himp
              -- both sides now case on the SAME probe bit
              cases hb : (pruneConsumedNonces s1.now st1).any
                  (fun e => e.ns == replayNamespace s1 c1.snd.target
                    && e.nonce == c1.snd.approval.nonce) with
              | true =>
                  have hb2 : (pruneConsumedNonces s2.now st2).any
                      (fun e => e.ns == replayNamespace s2 c2.snd.target
                        && e.nonce == c2.snd.approval.nonce) = true := by
                    rw [← hns, ← hn, ← hany, hb]
                  refine ⟨?_, ?_⟩ <;>
                    simp only [decideConsume, hp,
                      SealV2.validateAndConsumeWithStore, SealV2.listReplayStore,
                      hv1, hv2, hb, hb2] <;>
                    exact hlow
              | false =>
                  have hb2 : (pruneConsumedNonces s2.now st2).any
                      (fun e => e.ns == replayNamespace s2 c2.snd.target
                        && e.nonce == c2.snd.approval.nonce) = false := by
                    rw [← hns, ← hn, ← hany, hb]
                  refine ⟨?_, ?_⟩ <;>
                    simp only [decideConsume, hp,
                      SealV2.validateAndConsumeWithStore, SealV2.listReplayStore,
                      hv1, hv2, hb, hb2]
                  -- .1: Allow bytes are request-determined on both sides
                  · rw [serialize_validate_eq raw ast s1 c1 hp hv1,
                        serialize_validate_eq raw ast s2 c2 hp hv2]
                  -- .2: the SAME consumed entry lands on both slices
                  · have hentry : (⟨replayNamespace s1 c1.snd.target,
                        c1.snd.approval.nonce, c1.snd.approval.expiresAt⟩
                          : ConsumedNonce)
                        = ⟨replayNamespace s2 c2.snd.target,
                            c2.snd.approval.nonce, c2.snd.approval.expiresAt⟩ := by
                      rw [hns, hn, he]
                    have hc1 : ((replayNamespace s1 c1.snd.target).session == s)
                        = true := by
                      show (s1.session == s) = true
                      simp [hs]
                    have hc2 : ((replayNamespace s2 c2.snd.target).session == s)
                        = true := by
                      show (s2.session == s) = true
                      simp [← hses, hs]
                    simp only [storeLowEq, lowPart, List.filter_cons, hc1, hc2,
                      if_true]
                    simp only [lowPart] at hprune
                    rw [hprune, hentry]

/-- **Capstone: two-state stateful non-interference over a trace.** Along
any request list, two protected states agreeing on the replay view and on
every request's consume view, over slice-equal stores, produce the SAME
observable (decision, record) trace, and the stores stay slice-equal —
resolving the composition gap: BOTH the `ApprovalState` and the durable
store vary here. -/
theorem stateful_noninterference_trace (epoch : Nat) (tool : String)
    (verdicts : List Verdict) (s : SessionId) (s1 s2 : ApprovalState)
    (raws : List RawBytes) (st1 st2 : List ConsumedNonce)
    (hs : s1.session = s)
    (hrv : replayView s1 = replayView s2)
    (hcv : ∀ raw ∈ raws, consumeView raw s1 = consumeView raw s2)
    (hlow : storeLowEq s st1 st2) :
    (observeTrace epoch tool verdicts s1 raws st1).1
      = (observeTrace epoch tool verdicts s2 raws st2).1 ∧
      storeLowEq s (observeTrace epoch tool verdicts s1 raws st1).2
        (observeTrace epoch tool verdicts s2 raws st2).2 := by
  induction raws generalizing st1 st2 with
  | nil => exact ⟨rfl, hlow⟩
  | cons raw rest ih =>
      obtain ⟨h1, h2⟩ := stateful_step s raw s1 s2 st1 st2 hs hrv
        (hcv raw (by simp)) hlow
      obtain ⟨ht1, ht2⟩ := ih _ _ (fun r hr => hcv r (List.mem_cons_of_mem _ hr)) h2
      simp only [observeTrace, observeStep]
      exact ⟨by rw [h1, ht1], ht2⟩

/-- **Non-vacuity, with BOTH channels genuinely in play.** The states differ
(in HIGH: the TTL cap), the stores differ (another tenant's entry, outside
the observer's slice), and the observable trace and store slice are
unchanged. -/
theorem stateful_ni_nonvacuous :
    ∃ (epoch : Nat) (tool : String) (verdicts : List Verdict)
      (s1 s2 : ApprovalState) (st1 st2 : List ConsumedNonce)
      (raws : List RawBytes),
      s1 ≠ s2 ∧ st1 ≠ st2 ∧
      s1.session = "alice" ∧
      replayView s1 = replayView s2 ∧
      (∀ raw ∈ raws, consumeView raw s1 = consumeView raw s2) ∧
      storeLowEq "alice" st1 st2 ∧
      (observeTrace epoch tool verdicts s1 raws st1).1
        = (observeTrace epoch tool verdicts s2 raws st2).1 ∧
      storeLowEq "alice" (observeTrace epoch tool verdicts s1 raws st1).2
        (observeTrace epoch tool verdicts s2 raws st2).2 := by
  refine ⟨1, "t", [],
    ⟨"alice", 0, "pk", "md", [], [], "", 300, [], 0⟩,
    ⟨"alice", 0, "pk", "md", [], [], "", 301, [], 0⟩,
    [],
    [⟨⟨"pkB", "db write 1 md {}", "bob", "v1"⟩,
      ⟨String.ofList (List.replicate 64 'a'), by decide⟩, 10⟩],
    [""], ?_, ?_, rfl, rfl, ?_, ?_, ?_, ?_⟩
  · intro h
    exact absurd (congrArg SealV2.ApprovalState.maxApprovalTtl h) (by decide)
  · intro h
    exact absurd (congrArg List.length h) (by decide)
  · intro raw hr
    simp only [List.mem_singleton] at hr
    subst hr
    rfl
  · show lowPart "alice" [] = lowPart "alice" [_]
    rw [lowPart, lowPart, List.filter_cons]
    rw [show ((("bob" : SessionId) == ("alice" : SessionId))) = false from by decide]
    simp
  · rfl
  · show lowPart "alice" [] = lowPart "alice" [_]
    rw [lowPart, lowPart, List.filter_cons]
    rw [show ((("bob" : SessionId) == ("alice" : SessionId))) = false from by decide]
    simp

/-! ## The obstruction, checked -/

/-- Derived-`BEq` reflexivity for replay namespaces (String fields only). -/
theorem ns_beq_refl (n : ReplayNamespace) : (n == n) = true := by
  obtain ⟨a, b, c, d⟩ := n
  show (a == a && (b == b && (c == c && d == d))) = true
  simp

/-- `Nonce` `BEq` reflexivity (value-projection instance). -/
theorem nonce_beq_refl (n : Nonce) : (n == n) = true := by
  show (n.value == n.value) = true
  simp

/-- Appending a character changes a string. -/
theorem string_ne_append_x (s : String) : s ≠ s ++ "x" := by
  intro h
  have hlen := congrArg String.length h
  simp [String.length_append] at hlen
  exact absurd hlen (by decide)

/-- **The checked counterexample: `policyVersion` MUST be declassified.**
The naive composition — T1's `authView` agreement alone, over EQUAL stores —
is FALSE for the composed seam: any concrete validation success yields a
policyVersion-twisted twin state that agrees with the original on `authView`
for the request (both validate), yet the two composed decisions DIVERGE on a
store seeded with the original's consumed entry: the original's probe hits
its own namespace (deny), the twin's namespace differs in exactly the
`policyVersion` component (allow). Hypothesis form per the module docstring:
the twisted validation success and its consume-data agreement are supplied
as hypotheses (Ed25519 is not kernel-evaluable; the witness is
state-indexed). -/
theorem policyVersion_declassification_necessary
    (raw : RawBytes) (ast : SealV2.AST) (s1 : ApprovalState)
    (c1 : Σ a, SealV2.ValidApproval a s1)
    (c2 : Σ a, SealV2.ValidApproval a
      { s1 with policyVersion := s1.policyVersion ++ "x" })
    (hp : parse raw = some ast)
    (hv1 : validate ast s1 = some c1)
    (hv2 : validate ast { s1 with policyVersion := s1.policyVersion ++ "x" }
      = some c2) :
    authView raw s1
      = authView raw { s1 with policyVersion := s1.policyVersion ++ "x" } ∧
    ∃ st : List ConsumedNonce,
      storeLowEq s1.session st st ∧
      (decideConsume raw s1 st).1
        ≠ (decideConsume raw
            { s1 with policyVersion := s1.policyVersion ++ "x" } st).1 := by
  refine ⟨?_, ⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
    s1.now⟩ :: [], rfl, ?_⟩
  · -- both validate: the T1 declassified bit agrees
    simp [Host.NonInterference.authView, hp, hv1, hv2]
  · -- the seeded entry survives its own prune and hits its own probe …
    have hself : ((⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
        s1.now⟩ : ConsumedNonce).ns == replayNamespace s1 c1.snd.target
          && (⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
            s1.now⟩ : ConsumedNonce).nonce == c1.snd.approval.nonce) = true := by
      simp [ns_beq_refl, nonce_beq_refl]
    -- … but the twin's namespace differs in the policyVersion component
    have hmiss : ((⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
        s1.now⟩ : ConsumedNonce).ns ==
          replayNamespace { s1 with policyVersion := s1.policyVersion ++ "x" }
            c2.snd.target) = false := by
      show ((s1.publicKey == s1.publicKey
        && (serializeTargetKey c1.snd.target == serializeTargetKey c2.snd.target
        && (s1.session == s1.session
        && (s1.policyVersion == s1.policyVersion ++ "x")))) = false)
      have : (s1.policyVersion == s1.policyVersion ++ "x") = false := by
        rw [beq_eq_false_iff_ne]
        exact string_ne_append_x _
      simp [this]
    have hprune1 : pruneConsumedNonces s1.now
        [(⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
          s1.now⟩ : ConsumedNonce)]
        = [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩] := by
      simp [SealV2.pruneConsumedNonces]
    intro hcontra
    -- reduce both composed decisions and read off Block ≠ Allow
    have h1 : (decideConsume raw s1
        [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩]).1
        = Decision.Block := by
      simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
        SealV2.listReplayStore, hv1, hprune1, List.any_cons, List.any_nil,
        hself, Bool.or_false]
    have h2 : (decideConsume raw
        { s1 with policyVersion := s1.policyVersion ++ "x" }
        [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩]).1
        = Decision.Allow (serialize c2) := by
      simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
        SealV2.listReplayStore, hv2, hprune1, List.any_cons, List.any_nil,
        hmiss, Bool.false_and, Bool.or_false]
    rw [h1, h2] at hcontra
    exact SealV2.Decision.noConfusion hcontra

/-! ## The lower bound, completed: `replayView` is EXACTLY minimal

Probe verdict, recorded before the proofs: all four declassified fields are
NECESSARY — no tightening is available, and `replayView` + the capstone are
therefore untouched by this section (the additive-only case).

With the three theorems below, every component of
`replayView = (publicKey, session, policyVersion, now)` carries a checked
state-twist counterexample in the exact shape of
`policyVersion_declassification_necessary`: two states agreeing on
`authView` for the request (the T1 declassification — both validate, by
hypothesis), over the SAME store seeded with the original's consumed entry,
whose composed decisions DIVERGE. Together with the capstone
(`stateful_noninterference_trace`, sufficiency), this characterizes
`replayView` as the EXACT minimal declassification interface of the
composed replay seam: declassifying the tuple suffices for trace NI, and
dropping ANY single field falsifies it. No strictly smaller declassified
tuple supports stateful non-interference.

Mechanism per field: `publicKey`, `session`, `policyVersion` are the 1st,
3rd, and 4th components of `replayNamespace` — twisting any one of them
makes the twin's probe MISS the entry the original's probe HITS (deny vs
allow). `now` is not in the namespace but is the PRUNE CLOCK: a seeded
entry with `expiresAt = s1.now` survives the original's prune and hits
(deny), while a twin one tick later prunes it away and allows — prune is
not symmetric once the store is non-empty.

Witness-existence notes (hypothesis form, per the module boundary): the
twisted validation success `hv2` is a hypothesis in all three. For
`session` and `now` the twin's HIGH fields (its approvals) can carry the
twisted-session / longer-expiry approval, so the witness exists modulo
state-indexed transport — the same bureaucracy note as the landed theorem.
For `publicKey` the hypothesis additionally names the Ed25519 boundary
itself: `validate` reads `publicKey` through the non-kernel-evaluable
`verifySignature`, exactly the boundary `replay_isolation_nonvacuous`
states.

Receipt-sufficiency relation: this is the witness-refinement thesis at the
NI layer — `replayView ∪ consumeView` is the minimal field set that must be
visible to replay an authorization decision across a session, the same
"smallest tuple that carries the claim" shape as `witness-check` / v2's
`args_hash` at the receipt layer. -/

/-- **`publicKey` MUST be declassified.** Same shape as
`policyVersion_declassification_necessary`, with the namespace mismatch in
the FIRST component: the twin's probe namespace differs in exactly
`publicKey`, so the original's seeded entry hits (deny) while the twin
misses (allow). Hypothesis form; note the twisted validation hypothesis
here leans on the named Ed25519 boundary (`verifySignature` reads
`publicKey` and is not kernel-evaluable). -/
theorem publicKey_declassification_necessary
    (raw : RawBytes) (ast : SealV2.AST) (s1 : ApprovalState)
    (c1 : Σ a, SealV2.ValidApproval a s1)
    (c2 : Σ a, SealV2.ValidApproval a
      { s1 with publicKey := s1.publicKey ++ "x" })
    (hp : parse raw = some ast)
    (hv1 : validate ast s1 = some c1)
    (hv2 : validate ast { s1 with publicKey := s1.publicKey ++ "x" }
      = some c2) :
    authView raw s1
      = authView raw { s1 with publicKey := s1.publicKey ++ "x" } ∧
    ∃ st : List ConsumedNonce,
      storeLowEq s1.session st st ∧
      (decideConsume raw s1 st).1
        ≠ (decideConsume raw
            { s1 with publicKey := s1.publicKey ++ "x" } st).1 := by
  refine ⟨?_, ⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
    s1.now⟩ :: [], rfl, ?_⟩
  · simp [Host.NonInterference.authView, hp, hv1, hv2]
  · have hself : ((⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
        s1.now⟩ : ConsumedNonce).ns == replayNamespace s1 c1.snd.target
          && (⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
            s1.now⟩ : ConsumedNonce).nonce == c1.snd.approval.nonce) = true := by
      simp [ns_beq_refl, nonce_beq_refl]
    have hmiss : ((⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
        s1.now⟩ : ConsumedNonce).ns ==
          replayNamespace { s1 with publicKey := s1.publicKey ++ "x" }
            c2.snd.target) = false := by
      show ((s1.publicKey == s1.publicKey ++ "x"
        && (serializeTargetKey c1.snd.target == serializeTargetKey c2.snd.target
        && (s1.session == s1.session
        && (s1.policyVersion == s1.policyVersion)))) = false)
      have : (s1.publicKey == s1.publicKey ++ "x") = false := by
        rw [beq_eq_false_iff_ne]
        exact string_ne_append_x _
      simp [this]
    have hprune1 : pruneConsumedNonces s1.now
        [(⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
          s1.now⟩ : ConsumedNonce)]
        = [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩] := by
      simp [SealV2.pruneConsumedNonces]
    intro hcontra
    have h1 : (decideConsume raw s1
        [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩]).1
        = Decision.Block := by
      simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
        SealV2.listReplayStore, hv1, hprune1, List.any_cons, List.any_nil,
        hself, Bool.or_false]
    have h2 : (decideConsume raw
        { s1 with publicKey := s1.publicKey ++ "x" }
        [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩]).1
        = Decision.Allow (serialize c2) := by
      simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
        SealV2.listReplayStore, hv2, hprune1, List.any_cons, List.any_nil,
        hmiss, Bool.false_and, Bool.or_false]
    rw [h1, h2] at hcontra
    exact SealV2.Decision.noConfusion hcontra

/-- **`session` MUST be declassified.** Same shape, mismatch in the THIRD
namespace component. The twin's approvals are HIGH, so a twisted-session
approval exists modulo the state-indexed transport (the landed bureaucracy
note); its validation success is the usual hypothesis. -/
theorem session_declassification_necessary
    (raw : RawBytes) (ast : SealV2.AST) (s1 : ApprovalState)
    (c1 : Σ a, SealV2.ValidApproval a s1)
    (c2 : Σ a, SealV2.ValidApproval a
      { s1 with session := s1.session ++ "x" })
    (hp : parse raw = some ast)
    (hv1 : validate ast s1 = some c1)
    (hv2 : validate ast { s1 with session := s1.session ++ "x" }
      = some c2) :
    authView raw s1
      = authView raw { s1 with session := s1.session ++ "x" } ∧
    ∃ st : List ConsumedNonce,
      storeLowEq s1.session st st ∧
      (decideConsume raw s1 st).1
        ≠ (decideConsume raw
            { s1 with session := s1.session ++ "x" } st).1 := by
  refine ⟨?_, ⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
    s1.now⟩ :: [], rfl, ?_⟩
  · simp [Host.NonInterference.authView, hp, hv1, hv2]
  · have hself : ((⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
        s1.now⟩ : ConsumedNonce).ns == replayNamespace s1 c1.snd.target
          && (⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
            s1.now⟩ : ConsumedNonce).nonce == c1.snd.approval.nonce) = true := by
      simp [ns_beq_refl, nonce_beq_refl]
    have hmiss : ((⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
        s1.now⟩ : ConsumedNonce).ns ==
          replayNamespace { s1 with session := s1.session ++ "x" }
            c2.snd.target) = false := by
      show ((s1.publicKey == s1.publicKey
        && (serializeTargetKey c1.snd.target == serializeTargetKey c2.snd.target
        && (s1.session == s1.session ++ "x"
        && (s1.policyVersion == s1.policyVersion)))) = false)
      have : (s1.session == s1.session ++ "x") = false := by
        rw [beq_eq_false_iff_ne]
        exact string_ne_append_x _
      simp [this]
    have hprune1 : pruneConsumedNonces s1.now
        [(⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
          s1.now⟩ : ConsumedNonce)]
        = [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩] := by
      simp [SealV2.pruneConsumedNonces]
    intro hcontra
    have h1 : (decideConsume raw s1
        [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩]).1
        = Decision.Block := by
      simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
        SealV2.listReplayStore, hv1, hprune1, List.any_cons, List.any_nil,
        hself, Bool.or_false]
    have h2 : (decideConsume raw
        { s1 with session := s1.session ++ "x" }
        [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩]).1
        = Decision.Allow (serialize c2) := by
      simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
        SealV2.listReplayStore, hv2, hprune1, List.any_cons, List.any_nil,
        hmiss, Bool.false_and, Bool.or_false]
    rw [h1, h2] at hcontra
    exact SealV2.Decision.noConfusion hcontra

/-- **`now` MUST be declassified — prune is not symmetric on a seeded
store.** The prune clock is not a namespace component, so the twist works
through EXPIRY instead: the seeded entry carries `expiresAt = s1.now`; the
original's prune keeps it (`now ≤ expiresAt`) and the probe hits (deny);
the twin, one tick later, prunes it away and the probe misses (allow). The
twin's validation success at the later clock is the usual hypothesis (its
HIGH approvals can carry a longer-expiry approval). -/
theorem now_declassification_necessary
    (raw : RawBytes) (ast : SealV2.AST) (s1 : ApprovalState)
    (c1 : Σ a, SealV2.ValidApproval a s1)
    (c2 : Σ a, SealV2.ValidApproval a { s1 with now := s1.now + 1 })
    (hp : parse raw = some ast)
    (hv1 : validate ast s1 = some c1)
    (hv2 : validate ast { s1 with now := s1.now + 1 } = some c2) :
    authView raw s1 = authView raw { s1 with now := s1.now + 1 } ∧
    ∃ st : List ConsumedNonce,
      storeLowEq s1.session st st ∧
      (decideConsume raw s1 st).1
        ≠ (decideConsume raw { s1 with now := s1.now + 1 } st).1 := by
  refine ⟨?_, ⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
    s1.now⟩ :: [], rfl, ?_⟩
  · simp [Host.NonInterference.authView, hp, hv1, hv2]
  · have hself : ((⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
        s1.now⟩ : ConsumedNonce).ns == replayNamespace s1 c1.snd.target
          && (⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
            s1.now⟩ : ConsumedNonce).nonce == c1.snd.approval.nonce) = true := by
      simp [ns_beq_refl, nonce_beq_refl]
    have hprune1 : pruneConsumedNonces s1.now
        [(⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
          s1.now⟩ : ConsumedNonce)]
        = [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩] := by
      simp [SealV2.pruneConsumedNonces]
    have hprune2 : pruneConsumedNonces (s1.now + 1)
        [(⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce,
          s1.now⟩ : ConsumedNonce)] = [] := by
      simp [SealV2.pruneConsumedNonces]
    intro hcontra
    have h1 : (decideConsume raw s1
        [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩]).1
        = Decision.Block := by
      simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
        SealV2.listReplayStore, hv1, hprune1, List.any_cons, List.any_nil,
        hself, Bool.or_false]
    have h2 : (decideConsume raw { s1 with now := s1.now + 1 }
        [⟨replayNamespace s1 c1.snd.target, c1.snd.approval.nonce, s1.now⟩]).1
        = Decision.Allow (serialize c2) := by
      simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
        SealV2.listReplayStore, hv2, hprune2, List.any_nil]
    rw [h1, h2] at hcontra
    exact SealV2.Decision.noConfusion hcontra

end Host.StatefulNI
