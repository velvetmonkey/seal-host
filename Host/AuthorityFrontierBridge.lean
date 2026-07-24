/- SPDX-License-Identifier: Apache-2.0 -/

import Crdt.AuthorityFrontier
import Host.StatefulNI

/-!
# SealV2 ↔ AuthoritySystem: the applicability bridge

The abstract no-double-spend theorem
(`Crdt.AuthorityFrontier.authority_frontier_card_le_one`, crdt-lean) applied
to SealV2's REAL single-use nonce model: replicas of the deployed gate's
durable replay store, judging the same validated approval, instantiate the
abstract `AuthoritySystem` — all four named laws discharged against the
actual definitions (`validateAndConsumeWithStore`, `listReplayStore`,
`replayNamespace`, `pruneConsumedNonces`), not a re-model.

## THE SCOPE SENTENCE (load-bearing — do not round up)

The transferred claim is: **at most one disconnected replica can be able to
consume a given approval CONCURRENTLY, within the approval's TTL window,
provided the deployment maintains at-most-once receipts.** It is NOT
"provably single-use for all time": SealV2 approvals expire, and
`validateAndConsumeWithStore` prunes expired entries before its replay
probe, so an entry that has aged out no longer blocks a re-consume — that
is SealV2's TTL semantics, faithfully preserved here. Accordingly
`receipts` counts DOMAINS that have consumed (a set that only grows), not
consume events over time.

## The mapping

* failure domain `d : D` — a replica of the durable replay store
  (`List ConsumedNonce`, the `listReplayStore` reference store: exactly the
  structure the deployed FFI threads through the gate, mcp-seal
  Ffi.lean:117);
* the approval — the nonce of one fixed validated request (`c0`, with
  `validate ast st = some c0` supplied as a hypothesis — the family's
  sanctioned hypothesis-form boundary: Ed25519 is not kernel-evaluable and
  the `ValidApproval` witness is state-indexed);
* a completed consume receipt at `d` — `d`'s replica containing an entry
  for the approval's replay namespace and nonce, i.e. a successful
  `validateAndConsumeWithStore` write;
* `live c d` — DERIVED, and it is SealV2's own enablement: the gate call
  `validateAndConsumeWithStore` SUCCEEDING on `d`'s local replica;
* `disconnected` — distinct replicas never sync (the partition model:
  merging IS the coordination whose necessity the theorem establishes).

## What the corollaries say

`sealv2_no_disconnected_double_availability`: if every reachable replica
family carries at most one consumed domain, then two distinct replicas are
never both able to consume the approval. `sealv2_frontier_card_le_one`:
the live frontier of the replica model has cardinality ≤ 1 under that
safety. Contrapositive reading: uncoordinated replicas of the seal replay
store cannot maintain at-most-once — coordination-free double-spend cannot
be excluded without breaking one of the four named laws (e.g. quorum
breaks `disconnected`; store synchronization breaks the partition model's
premise).

## Honest non-claims

Hypothesis-form validation (see above); ONE fixed (state, request) per
instance — replicas of the same gate judging the same approval; the
reference `listReplayStore` (the deployed FFI's store), not arbitrary
`ReplayStoreOps σ` backends; a Lean model of the gate, not the Rust/TS
emitters; no cryptographic unforgeability, Byzantine safety, durability,
or liveness claims — all inherited from the parent bricks' disclaimers
(crdt-lean AuthorityFrontier; Host/StatefulNI). The TTL scope sentence
above governs every downstream restatement of this result.
-/

namespace Host.AuthorityFrontierBridge

open SealV2 (ApprovalState AST ConsumedNonce ValidApproval
  validateAndConsumeWithStore listReplayStore replayNamespace
  pruneConsumedNonces validate)
open Crdt.AuthorityFrontier (AuthoritySystem Safe frontier
  no_disconnected_double_availability authority_frontier_card_le_one)
open Host.StatefulNI (ns_beq_refl nonce_beq_refl)

variable (st : ApprovalState) (ast : AST)
  (c0 : Σ a, ValidApproval a st)

/-- One gate call against a single replica: SealV2's real consume seam. -/
def bridgeConsume (s : List ConsumedNonce) :
    Option (List ConsumedNonce × Σ a, ValidApproval a st) :=
  validateAndConsumeWithStore listReplayStore s ast st

/-- The approval's replay namespace. -/
def bridgeNs : SealV2.ReplayNamespace := replayNamespace st c0.snd.target

/-- The receipt predicate: an entry consuming OUR approval. -/
def isReceipt (e : ConsumedNonce) : Bool :=
  e.ns == bridgeNs st c0 && e.nonce == c0.snd.approval.nonce

/-- The consumed entry the gate writes on success. -/
def bridgeEntry : ConsumedNonce :=
  { ns := bridgeNs st c0, nonce := c0.snd.approval.nonce,
    expiresAt := c0.snd.approval.expiresAt }

/-- Characterization of the gate call on a replica, from the real
definition: deny exactly on a live replay hit in the PRUNED store; on
allow, the consumed entry is prepended to the pruned store and the checked
witness is the fixed `c0`. -/
theorem bridgeConsume_eq (hv : validate ast st = some c0)
    (s : List ConsumedNonce) :
    bridgeConsume st ast s =
      if (pruneConsumedNonces st.now s).any (isReceipt st c0) = true
      then none
      else some (bridgeEntry st c0 :: pruneConsumedNonces st.now s, c0) := by
  cases hb : (pruneConsumedNonces st.now s).any (isReceipt st c0) with
  | true =>
      have hb' : (pruneConsumedNonces st.now s).any
          (fun e => e.ns == replayNamespace st c0.snd.target
            && e.nonce == c0.snd.approval.nonce) = true := by
        simpa [isReceipt, bridgeNs] using hb
      simp [bridgeConsume, SealV2.validateAndConsumeWithStore, hv,
        SealV2.listReplayStore, hb']
  | false =>
      have hb' : (pruneConsumedNonces st.now s).any
          (fun e => e.ns == replayNamespace st c0.snd.target
            && e.nonce == c0.snd.approval.nonce) = false := by
        simpa [isReceipt, bridgeNs] using hb
      simp only [bridgeConsume, SealV2.validateAndConsumeWithStore, hv,
        SealV2.listReplayStore, hb', Bool.false_eq_true, if_false,
        bridgeEntry, bridgeNs]

variable {D : Type} [DecidableEq D] [Fintype D]

/-- Replica-family configurations: one durable store per failure domain. -/
abbrev BridgeConfig (D : Type) := D → List ConsumedNonce

/-- Reachability from a parametric initial replica family, closed under
single-replica consume steps. -/
inductive BridgeReach (init : BridgeConfig D) : BridgeConfig D → Prop
  | init : BridgeReach init init
  | step {c : BridgeConfig D} {d : D}
      {r : List ConsumedNonce × Σ a, ValidApproval a st} :
      BridgeReach init c → bridgeConsume st ast (c d) = some r →
      BridgeReach init (Function.update c d r.1)

/-- **The SealV2 replica instance of the abstract `AuthoritySystem`.**
Every field is SealV2's real seam; every law is proved against the real
definitions (the probe of this brick — see module doc). -/
def SealReplicaSystem (hv : validate ast st = some c0)
    (init : BridgeConfig D) : AuthoritySystem D where
  Config := BridgeConfig D
  reachable := BridgeReach st ast init
  step c d c' := ∃ r, bridgeConsume st ast (c d) = some r ∧
    c' = Function.update c d r.1
  receipts c := Finset.univ.filter (fun d => (c d).any (isReceipt st c0) = true)
  live c d := (bridgeConsume st ast (c d)).isSome
  disconnected _ d₁ d₂ := d₁ ≠ d₂
  step_live c d h := by
    obtain ⟨r, hr⟩ := Option.isSome_iff_exists.mp h
    exact ⟨Function.update c d r.1, r, hr, rfl⟩
  step_reachable c d c' hreach hs := by
    obtain ⟨r, hr, rfl⟩ := hs
    exact BridgeReach.step hreach hr
  receipts_step c d c' hs := by
    obtain ⟨r, hr, rfl⟩ := hs
    -- pin the successful write's shape against the real definition
    rw [bridgeConsume_eq st ast c0 hv (c d)] at hr
    by_cases hb : (pruneConsumedNonces st.now (c d)).any (isReceipt st c0) = true
    · rw [if_pos hb] at hr; exact absurd hr (by simp)
    · rw [if_neg hb] at hr
      have hr1 : r.1 = bridgeEntry st c0 :: pruneConsumedNonces st.now (c d) := by
        have := Option.some.inj hr
        exact congrArg Prod.fst this.symm
      apply Finset.ext
      intro x
      simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_insert]
      by_cases hx : x = d
      · subst hx
        rw [Function.update_self, hr1]
        simp only [List.any_cons]
        have hself : isReceipt st c0 (bridgeEntry st c0) = true := by
          simp [isReceipt, bridgeEntry, ns_beq_refl, nonce_beq_refl]
        simp [hself]
      · rw [Function.update_of_ne hx]
        simp [hx]
  frozen_live c d₁ d₂ c₁ hne hs h := by
    obtain ⟨r, _, rfl⟩ := hs
    simpa [Function.update_of_ne (Ne.symm hne)] using h

/-- **Transfer corollary 1.** If every reachable replica family carries at
most one consumed domain (operational safety, judged on stored receipts
alone), then two DISTINCT replicas are never BOTH able to consume the same
approval. A visible application of the abstract amalgamation theorem — no
re-proof. -/
theorem sealv2_no_disconnected_double_availability
    (hv : validate ast st = some c0) (init : BridgeConfig D)
    (hsafe : Safe (SealReplicaSystem st ast c0 hv init))
    {c : BridgeConfig D} (hreach : BridgeReach st ast init c) {d₁ d₂ : D}
    (hne : d₁ ≠ d₂) :
    ¬((bridgeConsume st ast (c d₁)).isSome ∧
      (bridgeConsume st ast (c d₂)).isSome) :=
  no_disconnected_double_availability (SealReplicaSystem st ast c0 hv init)
    hsafe hreach hne hne

/-- **Transfer corollary 2 (the headline).** Under the same safety, the
live authority frontier of the SealV2 replica model — the set of replicas
on which the gate call would succeed — has cardinality at most one. -/
theorem sealv2_frontier_card_le_one
    (hv : validate ast st = some c0) (init : BridgeConfig D)
    (hsafe : Safe (SealReplicaSystem st ast c0 hv init))
    {c : BridgeConfig D} (hreach : BridgeReach st ast init c) :
    (frontier (SealReplicaSystem st ast c0 hv init) c).card ≤ 1 :=
  authority_frontier_card_le_one (SealReplicaSystem st ast c0 hv init)
    hsafe hreach (fun _ _ hne => hne)

/-! ## Sufficiency on the seam — a SECOND deployment shape, with `Safe` PROVEN

**Framing (load-bearing — do not misread as a weakening or as discharging
the corollaries above):** the two necessity corollaries above are about the
SHARED-state replica family (every replica holds the same `ApprovalState`
and can validate the approval); their `hsafe` hypothesis stays exactly as
it is — for that deployment shape, safety is an operational obligation, not
a theorem. This section adds a **different deployment shape** where safety
IS a theorem: the single-delivery deployment. Nothing above is weakened,
nothing above is discharged; a new shape is added beside it.

**The probe, recorded first (kernel-checked below):**

* Layer-D laws (a)–(c) — empty-init receipts, step-requires-live, generated
  reachability — all discharge cleanly on the landed instance
  (`SealReplicaGenerated`).
* Pruning (d) is invisible to the sufficiency induction: `receipts_step`
  (already landed) absorbs it — the consume write always prepends a
  matching entry and `isReceipt` is expiry-blind.
* **The literal goal — `SealedSenders` over the landed shared-state
  instance with empty init — is REFUTED**
  (`sealv2_shared_not_sealed_senders`): with validation fixed by `hv`, the
  gate call has exactly ONE failure mode, a replay hit, i.e. a receipt in
  the store (`bridgeConsume_eq`). So `¬live ⟺ receipt-in-store`: **SealV2's
  replay-store vocabulary has no disable-without-consume** — a sender can
  only be sealed by carrying a receipt, contradicting `init_receipts = ∅`;
  at the empty start every replica is live. The store cannot carry the
  seal.
* **The deployed carrier that CAN:** validation itself.
  `validateAndConsumeWithStore` is fail-closed on `validate = none`
  (`bridgeConsume_sealed_none`), so a replica whose `ApprovalState` cannot
  validate the approval is never live, on ANY store, at any configuration.

**The single-delivery deployment (`SealReplicaSystemP`):** per-replica
`ApprovalState`s (`stf : D → ApprovalState`); the signed approval is
delivered to exactly ONE replica `d₀` (`hv₀`); every other replica's state
does not validate it (`hsealed`) — it never received the approval, or the
approval does not bind to its session. That non-designated replicas fail
validation is exactly CutWorld's disable-in-the-past and crdt-lean's
`SealedSenders`, carried by the deployed gate's own fail-closed validation
seam rather than by a store entry. It is also precisely where the necessity
theorem says coordination must live: the coordination is performed at
handoff/delivery time, by giving the approval to one replica.

For this shape, `Safe` is PROVEN (`sealv2_partitioned_safe`, via crdt-lean's
`sealed_senders_safe`), and the two corollaries re-state with the `hsafe`
hypothesis replaced by the checkable delivery condition `hsealed`
(`sealv2_no_disconnected_double_availability'`,
`sealv2_frontier_card_le_one'`).

**Honest scope:** sufficiency only — no converse is claimed at any level
(the abstract witnesses `wSeq` / `SeqSystem` in crdt-lean already refute
it); ONE fixed approval per instance; the TTL scope sentence above governs
this section unchanged (`st.now` is one temporal snapshot per instance);
hypothesis-form validation as in the landed bridge; a Lean model of the
gate, not the Rust/TS emitters. -/

section Sufficiency

open Crdt.AuthorityFrontier (GeneratedAuthoritySystem SealedSenders
  sealed_senders_safe)

/-- The landed shared-state instance, from empty stores, carries the
Layer-D generated structure: empty initial receipts, steps only from
enablement, reachability generated by `BridgeReach`'s recursor. (The
unsafe multi-replica deployment satisfies ALL these laws — they smuggle in
no safety.) -/
def SealReplicaGenerated (hv : validate ast st = some c0) :
    GeneratedAuthoritySystem D where
  toAuthoritySystem := SealReplicaSystem st ast c0 hv (fun _ => [])
  init := fun _ => []
  init_reachable := BridgeReach.init
  init_receipts := by
    simp [SealReplicaSystem]
  step_requires_live c d c' hs := by
    obtain ⟨r, hr, _⟩ := hs
    exact Option.isSome_iff_exists.mpr ⟨r, hr⟩
  reachable_generated P hinit hstep c hc := by
    induction hc with
    | init => exact hinit
    | @step c d r hprev hcons ih => exact hstep c d _ hprev ih ⟨r, hcons, rfl⟩

/-- Every replica of the shared-state family is live at the empty start:
nothing is pruned from `[]`, nothing hits the replay probe, the consume
succeeds. -/
theorem shared_all_live_at_init (hv : validate ast st = some c0) (d : D) :
    (SealReplicaSystem st ast c0 hv (fun _ => [])).live (fun _ => []) d := by
  show (bridgeConsume st ast []).isSome
  rw [bridgeConsume_eq st ast c0 hv []]
  simp [SealV2.pruneConsumedNonces]

/-- **The kernel-checked no-go (the probe's verdict).** Over the landed
shared-state instance with empty initial stores, `SealedSenders` is
unsatisfiable as soon as two replicas exist: every replica is live at the
reachable start. The seal has no store-level carrier — with validation
fixed, the only blocker `validateAndConsumeWithStore` knows is a receipt. -/
theorem sealv2_shared_not_sealed_senders (hv : validate ast st = some c0)
    {d₁ d₂ : D} (hne : d₁ ≠ d₂) :
    ¬ SealedSenders (SealReplicaGenerated (D := D) st ast c0 hv) := by
  rintro ⟨e, hseal⟩
  by_cases h1 : d₁ = e
  · exact hseal _ BridgeReach.init d₂ (h1 ▸ Ne.symm hne)
      (shared_all_live_at_init st ast c0 hv d₂)
  · exact hseal _ BridgeReach.init d₁ h1
      (shared_all_live_at_init st ast c0 hv d₁)

/-- A replica whose state cannot validate the approval is never able to
consume it, on any store: `validateAndConsumeWithStore` is fail-closed on
validation failure. This is the deployed carrier of the seal. -/
theorem bridgeConsume_sealed_none {st' : ApprovalState}
    (hnone : validate ast st' = none) (s : List ConsumedNonce) :
    bridgeConsume st' ast s = none := by
  simp [bridgeConsume, SealV2.validateAndConsumeWithStore, hnone]

variable (stf : D → ApprovalState) (d₀ : D)
  (cap0 : Σ a, ValidApproval a (stf d₀))

/-- Reachability for the per-replica-state family: each replica judges the
approval against ITS OWN `ApprovalState`. -/
inductive BridgeReachP (stf : D → ApprovalState) (ast : AST)
    (init : BridgeConfig D) : BridgeConfig D → Prop
  | init : BridgeReachP stf ast init init
  | step {c : BridgeConfig D} {d : D}
      {r : List ConsumedNonce × Σ a, ValidApproval a (stf d)} :
      BridgeReachP stf ast init c → bridgeConsume (stf d) ast (c d) = some r →
      BridgeReachP stf ast init (Function.update c d r.1)

/-- **The single-delivery replica instance.** Same consume seam, same
receipt observer (the ONE approval's namespace and nonce, fixed at `d₀`'s
state), but per-replica `ApprovalState`s: `d₀` validates the approval
(`hv₀`), no other replica does (`hsealed`). Every law is proved against
the real definitions, exactly as in the landed instance. -/
def SealReplicaSystemP (hv₀ : validate ast (stf d₀) = some cap0)
    (hsealed : ∀ d, d ≠ d₀ → validate ast (stf d) = none)
    (init : BridgeConfig D) : AuthoritySystem D where
  Config := BridgeConfig D
  reachable := BridgeReachP stf ast init
  step c d c' := ∃ r, bridgeConsume (stf d) ast (c d) = some r ∧
    c' = Function.update c d r.1
  receipts c := Finset.univ.filter
    (fun d => (c d).any (isReceipt (stf d₀) cap0) = true)
  live c d := (bridgeConsume (stf d) ast (c d)).isSome
  disconnected _ d₁ d₂ := d₁ ≠ d₂
  step_live c d h := by
    obtain ⟨r, hr⟩ := Option.isSome_iff_exists.mp h
    exact ⟨Function.update c d r.1, r, hr, rfl⟩
  step_reachable c d c' hreach hs := by
    obtain ⟨r, hr, rfl⟩ := hs
    exact BridgeReachP.step hreach hr
  receipts_step c d c' hs := by
    obtain ⟨r, hr, rfl⟩ := hs
    by_cases hd : d = d₀
    · subst hd
      rw [bridgeConsume_eq (stf d) ast cap0 hv₀ (c d)] at hr
      by_cases hb : (pruneConsumedNonces (stf d).now (c d)).any
          (isReceipt (stf d) cap0) = true
      · rw [if_pos hb] at hr; exact absurd hr (by simp)
      · rw [if_neg hb] at hr
        have hr1 : r.1 = bridgeEntry (stf d) cap0 ::
            pruneConsumedNonces (stf d).now (c d) := by
          have := Option.some.inj hr
          exact congrArg Prod.fst this.symm
        apply Finset.ext
        intro x
        simp only [Finset.mem_filter, Finset.mem_univ, true_and,
          Finset.mem_insert]
        by_cases hx : x = d
        · subst hx
          rw [Function.update_self, hr1]
          simp only [List.any_cons]
          have hself : isReceipt (stf x) cap0 (bridgeEntry (stf x) cap0) = true := by
            simp [isReceipt, bridgeEntry, ns_beq_refl, nonce_beq_refl]
          simp [hself]
        · rw [Function.update_of_ne hx]
          simp [hx]
    · rw [bridgeConsume_sealed_none ast (hsealed d hd) (c d)] at hr
      exact absurd hr (by simp)
  frozen_live c d₁ d₂ c₁ hne hs h := by
    obtain ⟨r, _, rfl⟩ := hs
    simpa [Function.update_of_ne (Ne.symm hne)] using h

/-- The single-delivery instance carries the generated structure from
empty stores. -/
def SealReplicaGeneratedP (hv₀ : validate ast (stf d₀) = some cap0)
    (hsealed : ∀ d, d ≠ d₀ → validate ast (stf d) = none) :
    GeneratedAuthoritySystem D where
  toAuthoritySystem := SealReplicaSystemP ast stf d₀ cap0 hv₀ hsealed (fun _ => [])
  init := fun _ => []
  init_reachable := BridgeReachP.init
  init_receipts := by
    simp [SealReplicaSystemP]
  step_requires_live c d c' hs := by
    obtain ⟨r, hr, _⟩ := hs
    exact Option.isSome_iff_exists.mpr ⟨r, hr⟩
  reachable_generated P hinit hstep c hc := by
    induction hc with
    | init => exact hinit
    | @step c d r hprev hcons ih => exact hstep c d _ hprev ih ⟨r, hcons, rfl⟩

/-- The single-delivery deployment IS a sealed-senders system: every
non-designated replica fails validation, hence is never live, at every
configuration — the deployed shadow of `CutWorld.SealedHandoff`. -/
theorem sealed_delivery_sealed_senders
    (hv₀ : validate ast (stf d₀) = some cap0)
    (hsealed : ∀ d, d ≠ d₀ → validate ast (stf d) = none) :
    SealedSenders (SealReplicaGeneratedP ast stf d₀ cap0 hv₀ hsealed) := by
  refine ⟨d₀, fun c _ d hd hlive => ?_⟩
  have hlive' : (bridgeConsume (stf d) ast (c d)).isSome = true := hlive
  rw [bridgeConsume_sealed_none ast (hsealed d hd) (c d)] at hlive'
  exact absurd hlive' (by simp)

/-- **Safety, PROVEN — no `hsafe` hypothesis.** In the single-delivery
deployment, every reachable replica family carries at most one consumed
domain: receipts start empty and only `d₀` can ever step. Via crdt-lean's
`sealed_senders_safe` (Layer D). -/
theorem sealv2_partitioned_safe
    (hv₀ : validate ast (stf d₀) = some cap0)
    (hsealed : ∀ d, d ≠ d₀ → validate ast (stf d) = none) :
    Safe (SealReplicaSystemP ast stf d₀ cap0 hv₀ hsealed (fun _ => [])) :=
  sealed_senders_safe _ (sealed_delivery_sealed_senders ast stf d₀ cap0 hv₀ hsealed)

/-- **Transfer corollary 1, `Safe` discharged.** In the single-delivery
deployment, two distinct replicas are never both able to consume the
approval — from the delivery condition alone. -/
theorem sealv2_no_disconnected_double_availability'
    (hv₀ : validate ast (stf d₀) = some cap0)
    (hsealed : ∀ d, d ≠ d₀ → validate ast (stf d) = none)
    {c : BridgeConfig D} (hreach : BridgeReachP stf ast (fun _ => []) c)
    {d₁ d₂ : D} (hne : d₁ ≠ d₂) :
    ¬((bridgeConsume (stf d₁) ast (c d₁)).isSome ∧
      (bridgeConsume (stf d₂) ast (c d₂)).isSome) :=
  no_disconnected_double_availability
    (SealReplicaSystemP ast stf d₀ cap0 hv₀ hsealed (fun _ => []))
    (sealv2_partitioned_safe ast stf d₀ cap0 hv₀ hsealed) hreach hne hne

/-- **Transfer corollary 2, `Safe` discharged.** The live frontier of the
single-delivery deployment has cardinality at most one — from the delivery
condition alone. -/
theorem sealv2_frontier_card_le_one'
    (hv₀ : validate ast (stf d₀) = some cap0)
    (hsealed : ∀ d, d ≠ d₀ → validate ast (stf d) = none)
    {c : BridgeConfig D} (hreach : BridgeReachP stf ast (fun _ => []) c) :
    (frontier (SealReplicaSystemP ast stf d₀ cap0 hv₀ hsealed (fun _ => [])) c).card ≤ 1 :=
  authority_frontier_card_le_one
    (SealReplicaSystemP ast stf d₀ cap0 hv₀ hsealed (fun _ => []))
    (sealv2_partitioned_safe ast stf d₀ cap0 hv₀ hsealed) hreach
    (fun _ _ hne => hne)

end Sufficiency

/-! ## The third shape: mesh-coordinated replicas over the SHARED store

**Probe verdict (recorded before the proofs): it COMPOSES — by product.**
The load-bearing question was whether an external coordination fact can
attach to the shared-store system so the composition satisfies
`SealedSenders` where the bare store provably cannot
(`sealv2_shared_not_sealed_senders`), without the store's replay
vocabulary re-obstructing. It can, because the obstruction was never about
attachment: the no-go says the STORE's only non-liveness is a receipt. The
mesh's liveness vocabulary is free — so the composed system's enablement is
the CONJUNCTION `store-live ∧ mesh-live`, and the seal rides the mesh
conjunct, which the store never constrains.

**The exact interface the mesh must expose** (the sharp finding): a
`GeneratedAuthoritySystem D` over the SAME failure domains satisfying
`SealedSenders` — uniform never-liveness of every non-designated domain at
every mesh-reachable configuration. That is precisely the predicate the
landed no-go proves the shared store structurally cannot carry (its only
way to make a domain non-live is a receipt, which contradicts empty-start
generation). The mesh CAN carry it because its `live` field is
unconstrained by the replay seam.

**The composed system (`SealReplicaMeshSystem`):** configurations are
pairs (replica store family, mesh configuration); a consume step at `d`
fires the REAL gate call on `d`'s store AND a mesh step at `d` (the gate
call spends the mesh grant); enablement is the conjunction; receipts are
the STORE receipts (safety is still judged on the gate's own consumed
entries); disconnection is disconnection in BOTH layers. Every store-side
law is the landed proof unchanged; every mesh-side law is `M`'s law.

**What transfers:** if the mesh satisfies `SealedSenders` (hypothesis
`hM` — establishable upstream by crdt-lean's coordination discipline),
the composition does too (`mesh_sealed_senders`, via the reachability
projection `meshReach_snd`), hence is Safe (`sealv2_mesh_safe`) — the
`hsafe` obligation discharged for the mesh-coordinated deployment. The
composition is what neither brick has alone: the store contributes the
real consume seam and replay dedup; the mesh contributes the seal.

**Kill-line:** without the mesh fact the same shared store fails the
predicate — `sealv2_shared_not_sealed_senders` is the standing witness.
Non-vacuity is concrete: `TokenMesh` (the minimal mesh: one domain holds
the grant) satisfies `SealedSenders` non-vacuously, and on the composed
system the designated holder is GENUINELY live at the empty start
(`mesh_holder_live_at_init`) — the composition does not seal everyone.

**Deployment meaning + CutWorld relation:** this names the
mesh-coordinated fleet over shared/replicated approval state — every
replica could validate the approval, but a coordination layer (a token
service, a sealed-handoff CRDT, a leader lease within the TTL window)
designates the single consumer. The mesh fact is `CutWorld.SealedHandoff`
one more level up: the disable-in-the-causal-past becomes the mesh's
never-granting of non-holders, carried by the coordination layer instead
of by store entries (which the no-go forbids) or by validation partition
(the single-delivery shape). All landed scope governs: TTL window, one
approval per instance, hypothesis-form validation, model-level. -/

section Composition

open Crdt.AuthorityFrontier (GeneratedAuthoritySystem SealedSenders
  sealed_senders_safe)

/-- Reachability of the composed system: empty stores + the mesh's initial
configuration; a step fires the real gate call on one replica's store AND
a mesh step at the same domain. -/
inductive MeshReach (st : ApprovalState) (ast : AST)
    (M : GeneratedAuthoritySystem D) :
    BridgeConfig D × M.Config → Prop
  | init : MeshReach st ast M (fun _ => [], M.init)
  | step {p : BridgeConfig D × M.Config} {d : D}
      {r : List ConsumedNonce × Σ a, ValidApproval a st} {m' : M.Config} :
      MeshReach st ast M p → bridgeConsume st ast (p.1 d) = some r →
      M.step p.2 d m' →
      MeshReach st ast M (Function.update p.1 d r.1, m')

/-- **The mesh-coordinated shared-store instance.** The store side is the
landed `SealReplicaSystem` seam verbatim; the mesh side is `M`'s own
structure; enablement and steps are the conjunction/product. Receipts are
the STORE receipts — safety is still judged on the gate's consumed
entries. -/
def SealReplicaMeshSystem (hv : validate ast st = some c0)
    (M : GeneratedAuthoritySystem D) : AuthoritySystem D where
  Config := BridgeConfig D × M.Config
  reachable := MeshReach st ast M
  step p d p' := (∃ r, bridgeConsume st ast (p.1 d) = some r ∧
      p'.1 = Function.update p.1 d r.1) ∧ M.step p.2 d p'.2
  receipts p := Finset.univ.filter
    (fun d => (p.1 d).any (isReceipt st c0) = true)
  live p d := (bridgeConsume st ast (p.1 d)).isSome ∧ M.live p.2 d
  disconnected p d₁ d₂ := d₁ ≠ d₂ ∧ M.disconnected p.2 d₁ d₂
  step_live p d h := by
    obtain ⟨hs, hm⟩ := h
    obtain ⟨r, hr⟩ := Option.isSome_iff_exists.mp hs
    obtain ⟨m', hm'⟩ := M.step_live p.2 d hm
    exact ⟨(Function.update p.1 d r.1, m'), ⟨r, hr, rfl⟩, hm'⟩
  step_reachable p d p' hreach hs := by
    obtain ⟨⟨r, hr, h1⟩, h2⟩ := hs
    have hp' : p' = (Function.update p.1 d r.1, p'.2) := by
      exact Prod.ext h1 rfl
    rw [hp']
    exact MeshReach.step hreach hr h2
  receipts_step p d p' hs := by
    obtain ⟨⟨r, hr, h1⟩, _⟩ := hs
    rw [bridgeConsume_eq st ast c0 hv (p.1 d)] at hr
    by_cases hb : (pruneConsumedNonces st.now (p.1 d)).any (isReceipt st c0) = true
    · rw [if_pos hb] at hr; exact absurd hr (by simp)
    · rw [if_neg hb] at hr
      have hr1 : r.1 = bridgeEntry st c0 :: pruneConsumedNonces st.now (p.1 d) := by
        have := Option.some.inj hr
        exact congrArg Prod.fst this.symm
      apply Finset.ext
      intro x
      simp only [Finset.mem_filter, Finset.mem_univ, true_and, Finset.mem_insert]
      by_cases hx : x = d
      · subst hx
        rw [h1, Function.update_self, hr1]
        simp only [List.any_cons]
        have hself : isReceipt st c0 (bridgeEntry st c0) = true := by
          simp [isReceipt, bridgeEntry, ns_beq_refl, nonce_beq_refl]
        simp [hself]
      · rw [h1, Function.update_of_ne hx]
        simp [hx]
  frozen_live p d₁ d₂ p₁ hdis hs h := by
    obtain ⟨hne, hmdis⟩ := hdis
    obtain ⟨⟨r, hr, h1⟩, h2⟩ := hs
    obtain ⟨hstore, hmesh⟩ := h
    refine ⟨?_, M.frozen_live p.2 d₁ d₂ p₁.2 hmdis h2 hmesh⟩
    rw [h1, Function.update_of_ne (Ne.symm hne)]
    exact hstore

/-- The composed instance carries the generated structure: empty stores +
`M.init`, generated reachability, conjunction-gated steps. -/
def SealReplicaMeshGenerated (hv : validate ast st = some c0)
    (M : GeneratedAuthoritySystem D) : GeneratedAuthoritySystem D where
  toAuthoritySystem := SealReplicaMeshSystem st ast c0 hv M
  init := (fun _ => [], M.init)
  init_reachable := MeshReach.init
  init_receipts := by
    simp [SealReplicaMeshSystem]
  step_requires_live p d p' hs := by
    obtain ⟨⟨r, hr, _⟩, h2⟩ := hs
    exact ⟨Option.isSome_iff_exists.mpr ⟨r, hr⟩,
      M.step_requires_live p.2 d p'.2 h2⟩
  reachable_generated P hinit hstep p hp := by
    induction hp with
    | init => exact hinit
    | @step p d r m' hprev hcons hmst ih =>
        exact hstep p d _ hprev ih ⟨⟨r, hcons, rfl⟩, hmst⟩

/-- A composed-reachable configuration's mesh component is mesh-reachable:
the projection that lets `M`'s `SealedSenders` fact speak about every
composed configuration. -/
theorem meshReach_snd (M : GeneratedAuthoritySystem D)
    {p : BridgeConfig D × M.Config} (hp : MeshReach st ast M p) :
    M.reachable p.2 := by
  induction hp with
  | init => exact M.init_reachable
  | @step p d r m' _ _ hmst ih => exact M.step_reachable p.2 d m' ih hmst

/-- **The seal rides the mesh.** If the coordination layer satisfies
`SealedSenders`, so does the composition: composed liveness includes mesh
liveness, and the mesh component of every composed-reachable configuration
is mesh-reachable. The store conjunct never re-obstructs — it is not
consulted. -/
theorem mesh_sealed_senders (hv : validate ast st = some c0)
    (M : GeneratedAuthoritySystem D) (hM : SealedSenders M) :
    SealedSenders (SealReplicaMeshGenerated st ast c0 hv M) := by
  obtain ⟨d₀, hseal⟩ := hM
  exact ⟨d₀, fun p hp d hd hlive =>
    hseal p.2 (meshReach_snd st ast M hp) d hd hlive.2⟩

/-- **Safety, discharged for the mesh-coordinated deployment.** The shared
durable store, plus a mesh coordination fact, is Safe — at most one replica
ever holds a consumed entry for the approval — with no `hsafe` hypothesis:
the composition of seal's consume seam and crdt-lean's coordination spine,
which neither carries alone. -/
theorem sealv2_mesh_safe (hv : validate ast st = some c0)
    (M : GeneratedAuthoritySystem D) (hM : SealedSenders M) :
    Safe (SealReplicaMeshSystem st ast c0 hv M) :=
  sealed_senders_safe _ (mesh_sealed_senders st ast c0 hv M hM)

/-- Token-mesh reachability: grant consumption only ever happens at the
designated holder. -/
inductive TokenReach (d₀ : D) : Finset D → Prop
  | init : TokenReach d₀ ∅
  | step {m : Finset D} : TokenReach d₀ m → TokenReach d₀ (insert d₀ m)

/-- **The minimal witness mesh:** one domain holds the grant, forever;
consuming records it. Satisfies every `AuthoritySystem` and generated law;
`SealedSenders` holds non-vacuously (the holder IS live). -/
def TokenMesh (d₀ : D) : GeneratedAuthoritySystem D where
  Config := Finset D
  reachable := TokenReach d₀
  step m d m' := d = d₀ ∧ m' = insert d m
  receipts m := m
  live _ d := d = d₀
  disconnected _ d₁ d₂ := d₁ ≠ d₂
  step_live m d h := ⟨insert d m, h, rfl⟩
  step_reachable m d m' hr hs := by
    obtain ⟨rfl, rfl⟩ := hs
    exact TokenReach.step hr
  receipts_step m d m' hs := hs.2
  frozen_live _ _ _ _ _ _ h := h
  init := ∅
  init_reachable := TokenReach.init
  init_receipts := rfl
  step_requires_live _ _ _ hs := hs.1
  reachable_generated P hinit hstep m hm := by
    induction hm with
    | init => exact hinit
    | @step m hprev ih => exact hstep m d₀ (insert d₀ m) hprev ih ⟨rfl, rfl⟩

/-- The token mesh is a sealed-senders system, non-vacuously. -/
theorem tokenMesh_sealed_senders (d₀ : D) :
    SealedSenders (TokenMesh d₀) :=
  ⟨d₀, fun _ _ d hd h => hd h⟩

/-- **Non-vacuity of the composition:** on the token-mesh composition the
designated holder is GENUINELY live at the empty start — its gate call
succeeds and it holds the grant. The composition seals the others, not
everyone. -/
theorem mesh_holder_live_at_init (hv : validate ast st = some c0) (d₀ : D) :
    (SealReplicaMeshSystem st ast c0 hv (TokenMesh d₀)).live
      (fun _ => [], (∅ : Finset D)) d₀ :=
  ⟨shared_all_live_at_init st ast c0 hv d₀, rfl⟩

/-- **The concrete discharged deployment:** shared store + token mesh is
Safe, outright. -/
theorem sealv2_token_mesh_safe (hv : validate ast st = some c0) (d₀ : D) :
    Safe (SealReplicaMeshSystem st ast c0 hv (TokenMesh d₀)) :=
  sealv2_mesh_safe st ast c0 hv (TokenMesh d₀) (tokenMesh_sealed_senders d₀)

end Composition

end Host.AuthorityFrontierBridge
