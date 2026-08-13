/- SPDX-License-Identifier: Apache-2.0 -/

/-!
# A6 cross-restart durability, as an ordering property

`CLAIMS.md` (A6) closes cross-restart replay durability for the host's
Ed25519 signed-token production channel on operational evidence. Since the
G2 two-phase burn (ruled by Ben 2026-08-06) the production order is:
`rust/src/a3.rs::reserve_nonce` durably HOLDS the nonce in SQLite
(`rust/src/replay_store.rs`, WAL + `synchronous=FULL`) before the approval
reaches Lean; the burn is durably COMMITTED (`A3Filter::commit_nonce`) only
at RECORDED — after the authorization-decision receipt persists — and
strictly before the child forward; startup recovery commits a hold only when
an exact matching RECORDED receipt nonce exists, reclaims holds with no such
receipt, and refuses malformed or missing hold state. This module makes the durability argument itself
formal: it models the ORDER of store-write, acknowledgement and process
termination — not SQLite — states the property the claim needs, and proves
exactly which hypotheses the storage layer must supply. In this model
`commit` maps to the production COMMIT at RECORDED and `ack` to the child
forward; the pre-Lean reservation and its startup reclaim are host-layer
machinery BELOW this model's abstraction and are covered by the Rust crash
suite (`rust/tests/host_path.rs`, G2 T1-T4), not by these theorems.

## The model

An abstract token store run is a trace of events over an opaque token type:

* `Ev.commit b t` — the store ACCEPTS token `t` (the check-and-record step,
  production `commit_reservation` at RECORDED returning `true`). The flag `b`
  records whether the write was persistent at the moment the call returned:
  `b = true` is what `synchronous=FULL` buys (WAL fsynced before COMMIT
  returns); `b = false` models a lazily-synced commit that the process may
  outlive.
* `Ev.ack t` — the host acknowledges `t`: the approved effect is released
  downstream (production: the single child forward). Only a token accepted
  in the CURRENT process epoch and not yet acknowledged can be acknowledged
  (`pending`).
* `Ev.reject t` — a re-presented token is refused; no state changes.
* `Ev.crash` — process termination at an arbitrary point, immediately
  followed by restart: volatile state is lost, durable state survives.

State is three lists: `durable` (survives crash), `volatile` (rows the live
connection can read but that die with the process), `pending` (accepted in
this epoch, acknowledgement not yet emitted — process memory). The store
check reads `visible = durable ++ volatile`: a live SQLite connection sees
its own un-synced commits, which is why an UNDURABLE store still passes
single-epoch tests — the failure only exists across a crash.

## Headline results

* `ack_at_most_once` — per-token at-most-once acknowledgement across any
  number of crashes, given only that every accepting write OF THAT TOKEN
  was durable-on-return.
* `no_reack_after_restart` — the claim's exact shape: acknowledged before
  termination ⇒ not acknowledged again after restart.
* `recorded_token_not_acked_after_restart` — the write-then-crash-before-ack
  case is FAIL-CLOSED: a durably recorded token is never acknowledged in any
  later epoch (at-most-once, not exactly-once: an approval can be paid for
  and never delivered).
* `no_reack_fails_without_durability` — counter-model: with one volatile
  commit (`b = false`) the same token is acknowledged in two epochs. This is
  the double-acknowledgement A6 rules out, and it shows the durability
  hypothesis — the `synchronous=FULL` configuration — is load-bearing, not
  decorative.

## Hypotheses (what the storage layer must provide)

* **H1 durability-on-return** — an accepting write is persistent before the
  accept call returns (`Ev.commit true`; SQLite `synchronous=FULL` + WAL).
  The counter-model shows the property fails without it.
* **H2 write-ahead-of-ack** — acknowledgement only via `pending`, entered at
  commit: the durable record precedes the release (the host forwards to the
  child only after `commit_reservation` commits at RECORDED).
* **H3 atomic check-and-record** — `Step.commit` requires the token absent
  from `visible`: insert-if-absent under the store's uniqueness constraint
  (`nonces` PRIMARY KEY).
* **H4 one ack per accept** — `Step.ack` consumes `pending`: one boolean
  return per accept call, forwarded at most once.
* **H5 crash semantics** — termination erases `volatile` and `pending`,
  never `durable`: the database file outlives the process; rows are not
  deleted. Production prunes only EXPIRED rows; the model has no clock, so
  the result is scoped to a token's TTL window.

## What this does NOT cover

* **Store substitution (residual A7)** — the model assumes the `durable`
  list the restarted process reads is the one the dead process wrote.
  Binding a store INSTANCE is proved unachievable at the application layer
  and is ruled an accepted limitation (council `5c3845e7`); nothing here
  shrinks that residual.
* **The legacy control-file and interactive demo channels** — in-memory
  replay state, explicitly outside the A6 claim, outside this model.
* **Refinement to the deployed binary** — that `rusqlite` + SQLite under
  `synchronous=FULL` actually implements `Ev.commit true`, and that the OS
  honours fsync, is the TCB. This module proves the ordering discipline
  correct GIVEN that contract; it does not prove SQLite.
* **Expiry** — no TTL in the model; re-acceptance of an expired-and-pruned
  nonce is by design and out of scope.
* **Concurrency** — one presenter at a time (A4's host `Mutex`); traces are
  sequential.
-/

namespace DurabilityA6

/-- One event of a store run over opaque tokens `τ`. -/
inductive Ev (τ : Type) where
  /-- The store accepts `t`; `durable = true` iff the write is persistent at
  the moment the accept returns (H1, `synchronous=FULL`). -/
  | commit (durable : Bool) (t : τ)
  /-- The approval for `t` is released to the kernel. -/
  | ack (t : τ)
  /-- A re-presented token is refused. -/
  | reject (t : τ)
  /-- Process termination at an arbitrary point, then restart. -/
  | crash
deriving DecidableEq, Repr

/-- Store-run state. `durable` survives a crash; `volatile` is what only the
live process can see (un-synced rows); `pending` is accepted-not-yet-acked
process memory. -/
structure St (τ : Type) where
  durable : List τ
  volatile : List τ
  pending : List τ
deriving DecidableEq, Repr

/-- What the store's uniqueness check reads: a live connection sees durable
rows AND its own not-yet-persistent rows. -/
def visible (s : St τ) : List τ := s.durable ++ s.volatile

/-- The empty store: first process epoch, nothing recorded. -/
def init : St τ := ⟨[], [], []⟩

variable {τ : Type} [DecidableEq τ]

/-- One transition. The constructors ARE hypotheses H2-H5; H1 is the `b`
flag on `commit`, left free here and assumed by the theorems. -/
inductive Step : St τ → Ev τ → St τ → Prop
  /-- Accept `t`: only if absent from `visible` (H3). Durable iff `b` (H1);
  enters `pending` (H2). -/
  | commit {s : St τ} {b : Bool} {t : τ} (hfresh : t ∉ visible s) :
      Step s (.commit b t)
        { durable := if b then t :: s.durable else s.durable
          volatile := if b then s.volatile else t :: s.volatile
          pending := t :: s.pending }
  /-- Acknowledge `t`: only from `pending`, consuming it (H2, H4). -/
  | ack {s : St τ} {t : τ} (hpend : t ∈ s.pending) :
      Step s (.ack t) { s with pending := s.pending.filter fun u => decide (u ≠ t) }
  /-- Refuse a token the store already sees. No state change. -/
  | reject {s : St τ} {t : τ} (hdup : t ∈ visible s) :
      Step s (.reject t) s
  /-- Terminate and restart: volatile and pending die, durable survives (H5). -/
  | crash {s : St τ} :
      Step s .crash { durable := s.durable, volatile := [], pending := [] }

/-- Executions: `Reach s0 es s` iff the event list `es` (oldest first) drives
the machine from `s0` to `s`. -/
inductive Reach (s0 : St τ) : List (Ev τ) → St τ → Prop
  | nil : Reach s0 [] s0
  | snoc {es : List (Ev τ)} {s' s'' : St τ} {e : Ev τ} :
      Reach s0 es s' → Step s' e s'' → Reach s0 (es ++ [e]) s''

/-- How many times `t` is acknowledged in a trace. -/
def ackCount (t : τ) : List (Ev τ) → Nat
  | [] => 0
  | .ack u :: es => (if u = t then 1 else 0) + ackCount t es
  | .commit _ _ :: es => ackCount t es
  | .reject _ :: es => ackCount t es
  | .crash :: es => ackCount t es

theorem ackCount_append (t : τ) (l r : List (Ev τ)) :
    ackCount t (l ++ r) = ackCount t l + ackCount t r := by
  induction l with
  | nil => simp [ackCount]
  | cons e es ih => cases e <;> simp [ackCount, ih] <;> omega

/-- Durable rows are never lost: no step removes from `durable`. (H5.) -/
theorem Step.durable_mono {s s' : St τ} {e : Ev τ} (h : Step s e s') :
    ∀ t, t ∈ s.durable → t ∈ s'.durable := by
  cases h with
  | @commit b u _ => intro t ht; cases b <;> simp_all
  | ack _ => exact fun _ ht => ht
  | reject _ => exact fun _ ht => ht
  | crash => exact fun _ ht => ht

/-- A durably committed token is in the durable store from then on. -/
theorem mem_durable_of_commit {s0 s : St τ} {es : List (Ev τ)} {t : τ}
    (h : Reach s0 es s) (hc : Ev.commit true t ∈ es) : t ∈ s.durable := by
  induction h with
  | nil => cases hc
  | @snoc es s' s'' e hr hstep ih =>
    rcases List.mem_append.mp hc with hin | hlast
    · exact hstep.durable_mono t (ih hin)
    · have he : e = Ev.commit true t := (List.mem_singleton.mp hlast).symm
      subst he
      cases hstep with
      | commit _ => simp

/-- The per-token safety invariant, under H1 for THIS token only
(`Ev.commit false t ∉ es`: every accepting write of `t` was durable when it
returned). Conjuncts: an acked token is durably recorded; pending tokens are
durably recorded; `t` is acked at most once; a pending token has never been
acked. -/
theorem invariant {t : τ} {es : List (Ev τ)} {s : St τ}
    (h : Reach init es s) (hdur : Ev.commit false t ∉ es) :
    (1 ≤ ackCount t es → t ∈ s.durable)
      ∧ (t ∈ s.pending → t ∈ s.durable)
      ∧ ackCount t es ≤ 1
      ∧ (t ∈ s.pending → ackCount t es = 0) := by
  induction h with
  | nil => simp [init, ackCount]
  | @snoc es s' s'' e hr hstep ih =>
    have hdurL : Ev.commit false t ∉ es :=
      fun hm => hdur (List.mem_append.mpr (.inl hm))
    have hdurR : e ≠ Ev.commit false t :=
      fun he => hdur (List.mem_append.mpr (.inr (he ▸ List.mem_singleton.mpr rfl)))
    obtain ⟨ih1, ih2, ih3, ih4⟩ := ih hdurL
    cases hstep with
    | @commit b u hfresh =>
      have hfd : u ∉ s'.durable := fun hm => hfresh (List.mem_append.mpr (.inl hm))
      have hcnt : ackCount t (es ++ [Ev.commit b u]) = ackCount t es := by
        rw [ackCount_append]; rfl
      refine ⟨?_, ?_, ?_, ?_⟩
      · intro hc
        rw [hcnt] at hc
        have := ih1 hc
        cases b <;> simp_all
      · intro hp
        rcases List.mem_cons.mp hp with heq | hp'
        · -- t is the freshly accepted token: its commit must be durable.
          subst heq
          cases b with
          | false => exact absurd rfl hdurR
          | true => simp
        · have := ih2 hp'
          cases b <;> simp_all
      · rw [hcnt]; exact ih3
      · intro hp
        rw [hcnt]
        rcases List.mem_cons.mp hp with heq | hp'
        · -- fresh token: were it ever acked it would already be durable,
          -- contradicting the freshness check.
          subst heq
          rcases Nat.eq_zero_or_pos (ackCount t es) with h0 | h1
          · exact h0
          · exact absurd (ih1 h1) hfd
        · exact ih4 hp'
    | @ack u hpend =>
      have hcnt : ackCount t (es ++ [Ev.ack u])
          = ackCount t es + (if u = t then 1 else 0) := by
        rw [ackCount_append]; simp [ackCount]
      refine ⟨?_, ?_, ?_, ?_⟩
      · intro hc
        by_cases hut : u = t
        · exact ih2 (hut ▸ hpend)
        · rw [hcnt] at hc; simp [hut] at hc; exact ih1 hc
      · intro hp
        exact ih2 (List.mem_filter.mp hp).1
      · rw [hcnt]
        by_cases hut : u = t
        · have h0 : ackCount t es = 0 := ih4 (hut ▸ hpend)
          simp [hut, h0]
        · simp [hut]; exact ih3
      · intro hp
        have hp' := List.mem_filter.mp hp
        have hne : ¬(u = t) := by
          have h2 := hp'.2
          simp only [decide_eq_true_eq] at h2
          exact fun h => h2 h.symm
        rw [hcnt, if_neg hne, Nat.add_zero]
        exact ih4 hp'.1
    | @reject u hdup =>
      have hcnt : ackCount t (es ++ [Ev.reject u]) = ackCount t es := by
        rw [ackCount_append]; rfl
      exact ⟨fun hc => ih1 (hcnt ▸ hc), ih2, hcnt ▸ ih3, fun hp => hcnt ▸ ih4 hp⟩
    | crash =>
      have hcnt : ackCount t (es ++ [Ev.crash]) = ackCount t es := by
        rw [ackCount_append]; rfl
      exact ⟨fun hc => ih1 (hcnt ▸ hc), by simp, hcnt ▸ ih3, by simp⟩

/-- **A6, at-most-once form.** In any execution from the empty store — with
any number of crash/restart boundaries anywhere in the trace — a token whose
accepting writes were all durable-on-return (H1) is acknowledged at most
once. H2-H5 are carried by the transition relation itself. -/
theorem ack_at_most_once {t : τ} {es : List (Ev τ)} {s : St τ}
    (h : Reach init es s) (hdur : Ev.commit false t ∉ es) :
    ackCount t es ≤ 1 :=
  (invariant h hdur).2.2.1

/-- Global-hypothesis form: if EVERY write in the trace is durable-on-return,
every token is acknowledged at most once. -/
theorem ack_at_most_once_of_durableWrites {es : List (Ev τ)} {s : St τ}
    (h : Reach init es s) (hdw : ∀ u : τ, Ev.commit false u ∉ es) (t : τ) :
    ackCount t es ≤ 1 :=
  ack_at_most_once h (hdw t)

/-- A token that is durably recorded and not pending can never be
acknowledged in the remainder of ANY execution — regardless of whether later
writes are durable. Durable rows only grow (H5), the freshness check (H3)
blocks re-acceptance, and `ack` needs `pending` (H2/H4). -/
theorem sealed_token_stays_sealed {t : τ} {s1 s2 : St τ} {es : List (Ev τ)}
    (h : Reach s1 es s2) (hd : t ∈ s1.durable) (hp : t ∉ s1.pending) :
    ackCount t es = 0 ∧ t ∈ s2.durable ∧ t ∉ s2.pending := by
  induction h with
  | nil => exact ⟨rfl, hd, hp⟩
  | @snoc es s' s'' e hr hstep ih =>
    obtain ⟨ihc, ihd, ihp⟩ := ih
    cases hstep with
    | @commit b u hfresh =>
      have hne : u ≠ t := fun he =>
        hfresh (List.mem_append.mpr (.inl (he ▸ ihd)))
      refine ⟨?_, ?_, ?_⟩
      · rw [ackCount_append, ihc]; rfl
      · cases b <;> simp_all
      · intro hmem
        rcases List.mem_cons.mp hmem with heq | h'
        · exact hne heq.symm
        · exact ihp h'
    | @ack u hpend =>
      have hne : u ≠ t := fun he => ihp (he ▸ hpend)
      refine ⟨?_, ihd, ?_⟩
      · rw [ackCount_append, ihc]; simp [ackCount, hne]
      · exact fun hmem => ihp (List.mem_filter.mp hmem).1
    | reject _ =>
      exact ⟨by rw [ackCount_append, ihc]; rfl, ihd, ihp⟩
    | crash =>
      exact ⟨by rw [ackCount_append, ihc]; rfl, ihd, by simp⟩

/-- **A6, the claim's shape.** If a token was acknowledged before
termination (and its accepting writes were durable-on-return, H1), then
after restart it is never acknowledged again — in the immediate next epoch
or any later one, `es2` being arbitrary. -/
theorem no_reack_after_restart {t : τ} {es1 es2 : List (Ev τ)}
    {s1 s1' s2 : St τ}
    (h1 : Reach init es1 s1) (hdur : Ev.commit false t ∉ es1)
    (hacked : 1 ≤ ackCount t es1)
    (hcrash : Step s1 .crash s1')
    (h2 : Reach s1' es2 s2) :
    ackCount t es2 = 0 := by
  have hd : t ∈ s1.durable := (invariant h1 hdur).1 hacked
  cases hcrash with
  | crash => exact (sealed_token_stays_sealed h2 hd (by simp)).1

/-- **Crash BETWEEN write and acknowledgement is fail-closed.** Any durably
recorded token — acknowledged or not — is never acknowledged after the
restart. So a crash between the store write and the ack loses the approval
rather than doubling it: at-most-once, not exactly-once. -/
theorem recorded_token_not_acked_after_restart {t : τ} {es1 es2 : List (Ev τ)}
    {s1 s1' s2 : St τ}
    (h1 : Reach init es1 s1) (hc : Ev.commit true t ∈ es1)
    (hcrash : Step s1 .crash s1')
    (h2 : Reach s1' es2 s2) :
    ackCount t es2 = 0 := by
  have hd : t ∈ s1.durable := mem_durable_of_commit h1 hc
  cases hcrash with
  | crash => exact (sealed_token_stays_sealed h2 hd (by simp)).1

/-! ## The counter-model: H1 is load-bearing

One volatile commit (`Ev.commit false`) — a store whose accept returns
before the write is persistent, i.e. `synchronous=FULL` absent — admits the
exact execution A6 forbids: accept, acknowledge, crash, and the SAME token
is accepted and acknowledged again, because the restarted store never saw
the first write. The live-connection `volatile` row is what made epoch one
look correct from inside. -/

/-- Epoch one of the counter-model: volatile accept, then ack. -/
def counterEpoch : List (Ev Nat) := [.commit false 0, .ack 0]

/-- Without H1, a token is acknowledged before termination AND acknowledged
again after restart: the double-acknowledgement, in exactly the shape
`no_reack_after_restart` forbids under H1. The trace is minimal — drop the
`commit false` and no constructor can rebuild it. -/
theorem no_reack_fails_without_durability :
    ∃ (s1 s1' s2 : St Nat),
      Reach init counterEpoch s1 ∧
      Step s1 .crash s1' ∧
      Reach s1' counterEpoch s2 ∧
      Ev.commit false 0 ∈ counterEpoch ∧
      1 ≤ ackCount 0 counterEpoch := by
  refine ⟨⟨[], [0], []⟩, ⟨[], [], []⟩, ⟨[], [0], []⟩, ?_, ?_, ?_, by decide, by decide⟩
  · show Reach init (([] ++ [.commit false 0]) ++ [.ack 0]) ⟨[], [0], []⟩
    exact .snoc (.snoc .nil (.commit (by decide))) (.ack (by decide))
  · exact Step.crash
  · show Reach ⟨[], [], []⟩ (([] ++ [.commit false 0]) ++ [.ack 0]) ⟨[], [0], []⟩
    exact .snoc (.snoc .nil (.commit (by decide))) (.ack (by decide))

/-- The durable channel is live: the at-most-once bound is reached, not
vacuous. A durable accept and its single acknowledgement form a valid
execution with `ackCount = 1`. -/
theorem durable_ack_nonvacuous :
    ∃ s : St Nat,
      Reach init [Ev.commit true 0, Ev.ack 0] s ∧
      ackCount 0 [Ev.commit true 0, Ev.ack 0] = 1 := by
  refine ⟨⟨[0], [], []⟩, ?_, by decide⟩
  show Reach init (([] ++ [.commit true 0]) ++ [.ack 0]) ⟨[0], [], []⟩
  exact .snoc (.snoc .nil (.commit (by decide))) (.ack (by decide))

/-! Axiom footprint, pinned: every headline result sits on
`{propext, Quot.sound}` alone — no `sorryAx`, no `Lean.ofReduceBool`
(`native_decide`), not even `Classical.choice`. Drift fails the build. -/

/-- info: 'DurabilityA6.ack_at_most_once' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms ack_at_most_once

/--
info: 'DurabilityA6.ack_at_most_once_of_durableWrites' depends on axioms: [propext, Quot.sound]
-/
#guard_msgs in #print axioms ack_at_most_once_of_durableWrites

/-- info: 'DurabilityA6.no_reack_after_restart' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms no_reack_after_restart

/--
info: 'DurabilityA6.recorded_token_not_acked_after_restart' depends on axioms: [propext, Quot.sound]
-/
#guard_msgs in #print axioms recorded_token_not_acked_after_restart

/-- info: 'DurabilityA6.sealed_token_stays_sealed' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms sealed_token_stays_sealed

/--
info: 'DurabilityA6.no_reack_fails_without_durability' depends on axioms: [propext, Quot.sound]
-/
#guard_msgs in #print axioms no_reack_fails_without_durability

/-- info: 'DurabilityA6.durable_ack_nonvacuous' depends on axioms: [propext, Quot.sound] -/
#guard_msgs in #print axioms durable_ack_nonvacuous

end DurabilityA6
