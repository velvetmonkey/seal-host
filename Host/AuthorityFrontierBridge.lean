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
  the `ValidCapability` witness is state-indexed);
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

open SealV2 (ApprovalState AST ConsumedNonce ValidCapability
  validateAndConsumeWithStore listReplayStore replayNamespace
  pruneConsumedNonces validate)
open Crdt.AuthorityFrontier (AuthoritySystem Safe frontier
  no_disconnected_double_availability authority_frontier_card_le_one)
open Host.StatefulNI (ns_beq_refl nonce_beq_refl)

variable (st : ApprovalState) (ast : AST)
  (c0 : Σ a, ValidCapability a st)

/-- One gate call against a single replica: SealV2's real consume seam. -/
def bridgeConsume (s : List ConsumedNonce) :
    Option (List ConsumedNonce × Σ a, ValidCapability a st) :=
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
      {r : List ConsumedNonce × Σ a, ValidCapability a st} :
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

end Host.AuthorityFrontierBridge
