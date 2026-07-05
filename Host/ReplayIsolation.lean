/- SPDX-License-Identifier: Apache-2.0 -/

import SealV2.DecideTheorems

/-!
# Cross-session replay isolation over the durable store seam σ

**Scope: cross-session isolation over the durable store seam σ, per-request
state fixed.** Fix an observer session `s`, ONE `ApprovalState` with
`state.session = s`, and the request stream; only the external replay store
varies. Two stores that agree on the observer's projection (`lowPart s` —
the entries whose consumed-nonce namespace belongs to `s`) produce the SAME
decision trace and stay `lowPart`-equal forever: other tenants' nonce spends
(different sessions in the shared durable store) can neither flip the
observer's decisions nor leak into the observer's slice of the store.

## The model (STEP-0, frozen)

* `lowPart s entries` — the observer's ordered projection of the store:
  `entries.filter (fun e => e.ns.session == s)`.
* `storeLowEq s st1 st2` — equality of ordered projections.
* `decideConsume raw state st` — one gate step against the durable seam:
  `parse`, then `validateAndConsumeWithStore listReplayStore`; on ANY deny
  the ORIGINAL store `st` is returned unpruned (deny writes nothing); on
  allow the updated store (entry consumed) is returned.
* Single-state by design: the theorem does NOT generalise to two
  `ApprovalState`s — that would pull `state.consumedNonces` in as an
  unmodeled second replay input. The in-state nonce list is part of the
  per-request state, held fixed; the varying object is the durable seam.

## Theorems

* `ns_eq_implies_session_eq` — a store entry that BEq-matches the
  observer's replay namespace lives in the observer's session (derived-BEq
  decomposition, proved once).
* `store_lowEq_step` — ONE step: `lowPart`-equal stores give the same
  `Decision` and `lowPart`-equal successor stores. The `contains?` probe
  reads only the `s`-projection (its predicate forces the namespace to
  match, hence the session); `pruneExpired` is a time-only filter that
  commutes with `lowPart`; `insertConsumed` prepends the SAME
  `s`-namespaced entry on both sides.
* `replay_isolation_trace` — the fold: equal decision traces and
  `storeLowEq` preserved along any request list (induction on the step).
* `replay_isolation_nonvacuous` — non-vacuity at the `contains?` layer:
  the SAME nonce spent by ANOTHER tenant (different namespace) is invisible
  to the observer's probe (`.ok false`) and lies outside `lowPart s`. The
  spending tenant's own-probe block is NOT evaluated concretely (the
  derived `BEq` on the nested-inductive `AST` inside `Target` is
  WF-compiled, not kernel-reducible — see the theorem docstring); no live
  kernel Allow witness is attempted: Ed25519 `verifySignature` is not
  kernel-evaluable.
* `listReplayStore_namespaceLocal` — the reference store satisfies three
  structural locality laws: `contains?` reads only namespace-matching
  entries; `insertConsumed` prepends exactly the given entry;
  `pruneExpired` is the order-preserving namespace-blind time filter.

## Honesty

This does NOT compose with the non-interference theorem T1
(`Host/NonInterference.lean`): under a FIXED per-request state the
Allow-bytes half of any such composition is rfl-equal — there is no content
there. The real content here is the isolation step lemma and its trivial
induction. The frozen `mcp-seal` package is untouched.
-/

namespace Host.ReplayIsolation

open SealV2 (RawBytes ApprovalState Decision SessionId Nonce Target
  ReplayNamespace ConsumedNonce ReplayStoreOps parse validate serialize
  validateAndConsumeWithStore listReplayStore replayNamespace
  pruneConsumedNonces)

/-- The observer's ordered projection of the durable store: the entries
whose consumed-nonce namespace belongs to session `s`. -/
def lowPart (s : SessionId) (entries : List ConsumedNonce) : List ConsumedNonce :=
  entries.filter (fun e => e.ns.session == s)

/-- Two stores agree on everything the observer session can see. -/
def storeLowEq (s : SessionId) (st1 st2 : List ConsumedNonce) : Prop :=
  lowPart s st1 = lowPart s st2

/-- One gate step against the durable store seam. Deny (parse failure,
validation failure, replay hit) returns the ORIGINAL store unpruned — a
denied request writes nothing. Allow returns the store with the nonce
consumed. -/
def decideConsume (raw : RawBytes) (state : ApprovalState)
    (st : List ConsumedNonce) : Decision × List ConsumedNonce :=
  match parse raw with
  | none => (.Block, st)
  | some ast =>
      match validateAndConsumeWithStore listReplayStore st ast state with
      | none => (.Block, st)
      | some (st', checked) => (.Allow (serialize checked), st')

/-- The decision trace of a request list, threading the store. -/
def decideTrace (state : ApprovalState) :
    List RawBytes → List ConsumedNonce → List Decision × List ConsumedNonce
  | [], st => ([], st)
  | raw :: rest, st =>
      let step := decideConsume raw state st
      let tail := decideTrace state rest step.2
      (step.1 :: tail.1, tail.2)

/-- Derived-BEq decomposition, proved once: BEq-equal replay namespaces have
equal sessions. (The derived `BEq` on `ReplayNamespace` is the right-nested
conjunction of field comparisons; `SessionId` is a `String`, whose BEq is
lawful.) -/
theorem ns_session_eq_of_beq (n m : ReplayNamespace)
    (h : (n == m) = true) : n.session = m.session := by
  obtain ⟨a, b, c, d⟩ := n
  obtain ⟨a', b', c', d'⟩ := m
  have h' : (a == a' && (b == b' && (c == c' && d == d'))) = true := h
  simp only [Bool.and_eq_true] at h'
  exact eq_of_beq h'.2.2.1

/-- A store entry that BEq-matches the observer's replay namespace lives in
the observer's session. -/
theorem ns_eq_implies_session_eq (s : SessionId) (state : ApprovalState)
    (target : Target) (hs : state.session = s) (e : ConsumedNonce)
    (h : (e.ns == replayNamespace state target) = true) : e.ns.session = s := by
  rw [ns_session_eq_of_beq _ _ h]
  exact hs

/-- Pruning is time-only, hence namespace-blind: it commutes with the
observer projection. -/
theorem lowPart_prune_comm (s : SessionId) (now : Nat)
    (entries : List ConsumedNonce) :
    lowPart s (pruneConsumedNonces now entries)
      = pruneConsumedNonces now (lowPart s entries) := by
  unfold lowPart pruneConsumedNonces
  rw [List.filter_filter, List.filter_filter]
  exact List.filter_congr fun e _ => Bool.and_comm _ _

/-- An `any` whose predicate only fires on `s`-namespaced entries is
determined by the `s`-projection. -/
theorem any_eq_of_lowPart_eq (s : SessionId) (p : ConsumedNonce → Bool)
    (l1 l2 : List ConsumedNonce) (hlow : lowPart s l1 = lowPart s l2)
    (himp : ∀ e, p e = true → (e.ns.session == s) = true) :
    l1.any p = l2.any p := by
  have hpt : (fun e => (e.ns.session == s) && p e) = p := funext fun e => by
    cases hp : p e with
    | true => simp [himp e hp]
    | false => simp
  have h1 : ∀ l : List ConsumedNonce, l.any p = (lowPart s l).any p := fun l => by
    rw [lowPart, List.any_filter, hpt]
  rw [h1 l1, h1 l2, hlow]

/-- **The isolation step.** With the observer's per-request state fixed,
`lowPart`-equal stores produce the same decision and `lowPart`-equal
successor stores: the gate reads and writes only the observer's slice of
the durable seam. -/
theorem store_lowEq_step (s : SessionId) (raw : RawBytes)
    (state : ApprovalState) (st1 st2 : List ConsumedNonce)
    (hs : state.session = s) (hlow : storeLowEq s st1 st2) :
    (decideConsume raw state st1).1 = (decideConsume raw state st2).1 ∧
      storeLowEq s (decideConsume raw state st1).2
        (decideConsume raw state st2).2 := by
  cases hp : parse raw with
  | none =>
      refine ⟨?_, ?_⟩ <;> simp only [decideConsume, hp] <;> exact hlow
  | some ast =>
      cases hv : validate ast state with
      | none =>
          refine ⟨?_, ?_⟩ <;>
            simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore, hv] <;>
            exact hlow
      | some checked =>
          have hprune : lowPart s (pruneConsumedNonces state.now st1)
              = lowPart s (pruneConsumedNonces state.now st2) := by
            rw [lowPart_prune_comm, lowPart_prune_comm, hlow]
          have himp : ∀ e : ConsumedNonce,
              (e.ns == replayNamespace state checked.snd.target
                && e.nonce == checked.snd.approval.nonce) = true →
              (e.ns.session == s) = true := by
            intro e hpe
            simp only [Bool.and_eq_true] at hpe
            have := ns_eq_implies_session_eq s state checked.snd.target hs e hpe.1
            simp [this]
          have hany := any_eq_of_lowPart_eq s _ _ _ hprune himp
          cases hb : (pruneConsumedNonces state.now st1).any
              (fun e => e.ns == replayNamespace state checked.snd.target
                && e.nonce == checked.snd.approval.nonce) with
          | true =>
              have hb2 : (pruneConsumedNonces state.now st2).any
                  (fun e => e.ns == replayNamespace state checked.snd.target
                    && e.nonce == checked.snd.approval.nonce) = true := by
                rw [← hany]; exact hb
              refine ⟨?_, ?_⟩ <;>
                simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
                  SealV2.listReplayStore, hv, hb, hb2] <;>
                exact hlow
          | false =>
              have hb2 : (pruneConsumedNonces state.now st2).any
                  (fun e => e.ns == replayNamespace state checked.snd.target
                    && e.nonce == checked.snd.approval.nonce) = false := by
                rw [← hany]; exact hb
              refine ⟨?_, ?_⟩ <;>
                simp only [decideConsume, hp, SealV2.validateAndConsumeWithStore,
                  SealV2.listReplayStore, hv, hb, hb2]
              -- .2: same entry prepended to both pruned stores
              have hlp : lowPart s _ = lowPart s _ := hprune
              simp only [storeLowEq, lowPart, List.filter_cons]
              simp only [lowPart] at hprune
              rw [hprune]

/-- **Cross-session replay isolation (trace form).** Along any request list,
stores that agree on the observer's projection yield the SAME decision trace
and stay projection-equal. Other tenants' spends in the shared durable store
cannot flip the observer's decisions. -/
theorem replay_isolation_trace (s : SessionId) (state : ApprovalState)
    (raws : List RawBytes) (st1 st2 : List ConsumedNonce)
    (hs : state.session = s) (hlow : storeLowEq s st1 st2) :
    (decideTrace state raws st1).1 = (decideTrace state raws st2).1 ∧
      storeLowEq s (decideTrace state raws st1).2 (decideTrace state raws st2).2 := by
  induction raws generalizing st1 st2 with
  | nil => exact ⟨rfl, hlow⟩
  | cons raw rest ih =>
      obtain ⟨h1, h2⟩ := store_lowEq_step s raw state st1 st2 hs hlow
      obtain ⟨ht1, ht2⟩ := ih _ _ h2
      simp only [decideTrace]
      exact ⟨by rw [h1, ht1], ht2⟩

/-- The reference probe, as its underlying Bool — a generic `rfl` equation
used to evaluate concrete witnesses without fighting elaborator
transparency. -/
theorem listReplayStore_contains_eq (entries : List ConsumedNonce)
    (ns : ReplayNamespace) (nonce : Nonce) :
    listReplayStore.contains? entries ns nonce =
      .ok (entries.any (fun e => e.ns == ns && e.nonce == nonce)) := rfl

/-- **Non-vacuity, at the `contains?` layer.** The SAME nonce spent by
ANOTHER tenant — same durable store, different namespace (different session
and key) — is invisible to the observer's replay probe (`.ok false`) and
absent from the observer's projection (`lowPart s = []`): a cross-tenant
spend cannot block the observer. Stated at the `contains?` layer per the
brief; no live kernel Allow witness is attempted (Ed25519 signature
verification is not kernel-evaluable), and the spending tenant's own-probe
block (`.ok true` on its own namespace) is not evaluated concretely (the
hypothesis form sanctioned by the brief). Since mcp-seal e36fc98,
`ReplayNamespace` carries the target as its canonical STRING key
(`targetKey`), so the namespace `BEq` is over `String`s only — the old
nested-`AST` derived-`BEq` reducibility trap no longer sits on this path;
the witness literals here use a plain string key accordingly. -/
theorem replay_isolation_nonvacuous :
    ∃ (s : SessionId) (other : ConsumedNonce) (ns : ReplayNamespace)
      (nonce : Nonce),
      ns.session = s ∧ other.ns.session ≠ s ∧ other.nonce = nonce ∧
      lowPart s [other] = [] ∧
      listReplayStore.contains? [other] ns nonce = .ok false := by
  refine ⟨"alice",
    ⟨⟨"pkB", "db write 1 md {}", "bob", "v1"⟩,
      ⟨String.ofList (List.replicate 64 'a'), by decide⟩, 10⟩,
    ⟨"pkA", "db write 1 md {}", "alice", "v1"⟩,
    ⟨String.ofList (List.replicate 64 'a'), by decide⟩,
    rfl, by decide, rfl, ?_, ?_⟩
  · show lowPart "alice" [_] = []
    rw [lowPart, List.filter_cons]
    rw [show ((("bob" : SealV2.SessionId) == ("alice" : SealV2.SessionId))) = false from by decide]
    simp
  · rw [listReplayStore_contains_eq]
    exact congrArg Except.ok (by decide)

/-- The three structural locality laws of the reference store: the replay
probe reads only namespace-matching entries; insertion prepends exactly the
given entry; pruning is the order-preserving, namespace-blind time filter. -/
structure NamespaceLocal (ops : ReplayStoreOps (List ConsumedNonce)) : Prop where
  contains_reads_ns : ∀ entries ns nonce,
    ops.contains? entries ns nonce =
      .ok ((entries.filter (fun e => e.ns == ns)).any (fun e => e.nonce == nonce))
  insert_prepends : ∀ entries e, ops.insertConsumed entries e = .ok (e :: entries)
  prune_time_filter : ∀ entries now,
    ops.pruneExpired entries now = .ok (pruneConsumedNonces now entries)

/-- The reference `List` store satisfies the locality laws. -/
theorem listReplayStore_namespaceLocal : NamespaceLocal listReplayStore where
  contains_reads_ns entries ns nonce := by
    simp only [SealV2.listReplayStore, List.any_filter]
  insert_prepends _ _ := rfl
  prune_time_filter _ _ := rfl

end Host.ReplayIsolation
