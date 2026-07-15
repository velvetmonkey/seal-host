/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Record

/-!
# W2-T1 — Timed record admissibility: freshness, ordering, replay (WAVE 2)

L1 CORE (`Host.Record`) proves the decision log is an append-only,
tamper-evident hash chain. This module adjoins TIME to that record: each entry
carries the producing step's logical-clock reading and a nonce, and an
admissibility gate enforces, in the model:

* **freshness** — an accepted entry sits within bound `δ` of its producing
  step's clock (`admitted_within_bound`); a `δ`-stale entry is inadmissible
  (`stale_clock_inadmissible`);
* **ordering** — an entry older than the newest logged entry is inadmissible
  (`regressed_clock_inadmissible`); admissible appends keep the log
  clock-sorted (`admit_preserves_clock_mono`). Index ordering itself is
  structural on `List` (cons order) — the clock discipline is the novel
  ordered content;
* **replay** — a repeated nonce is inadmissible (`replayed_nonce_inadmissible`);
  admissible appends keep the nonce set duplicate-free
  (`admit_preserves_nonce_nodup`).

The chain spine is INHERITED, not re-proved: a timed log renders into the L1
`Log` through an entry encoder (`render`), `head_after_append` lifts
definitionally (`timed_head_after_append`), and `tamper_evident` lifts under
one NEW named assumption **A-ENC** — injectivity of the entry encoder
(`timed_tamper_evident`). Same discipline as A-CR/A-GEN: structure
machine-checked, primitive property a named TCB assumption.

TRUST BOUNDARY (stated loud): `now` is the host's MONOTONE LOGICAL clock —
the same source that feeds `SafetyEvidence.now`. Nothing here claims
wall-clock truth. Wall clock, nonce GENERATION (uniqueness at the source),
and runtime freshness enforcement (A3: nonce/replay/TTL, `rust/src/a3.rs`)
remain TCB, exactly as named in `Ffi.lean`. This module is the Lean-side
freshness discipline OF THE RECORD, complementing A3, not replacing it.
The deployed encoder `TimedEntry.line` is demonstration-grade: A-ENC is NOT
discharged for it (JSON string escaping is not proven injective) — mirroring
the FNV-1a honesty note on `chainHash` (`Host/Record.lean`).
-/

namespace Host.Record

open SealCore  -- `Hash := UInt64`, as in `Host.Record`

/-- One timed record entry: the audit payload (what `Host.auditLine` emits for
    one mediated decision, including its `request_sha256` commitment to the
    judged line), the producing step's logical-clock reading, and a nonce. -/
structure TimedEntry where
  payload : String
  clock   : Nat
  nonce   : Nat
  deriving Repr, DecidableEq

/-- The timed decision log, MOST-RECENT-FIRST (mirrors `Log`). -/
abbrev TimedLog := List TimedEntry

/-- Clock of the newest entry; 0 on the empty log, so every first entry
    trivially satisfies the no-regression conjunct. -/
def latestClock : TimedLog → Nat
  | [] => 0
  | e :: _ => e.clock

/-- The nonces the log has consumed. -/
def nonces (log : TimedLog) : List Nat := log.map (·.nonce)

/-- Admissibility of appending `e` when the producing step's clock reads
    `now`, at freshness bound `δ`: the entry is not from the future, within
    `δ` of the producing step, does not regress the log's clock, and does not
    replay a consumed nonce. -/
def admissible (δ now : Nat) (log : TimedLog) (e : TimedEntry) : Bool :=
  decide (e.clock ≤ now) && decide (now ≤ e.clock + δ)
    && decide (latestClock log ≤ e.clock)
    && decide (e.nonce ∉ nonces log)

/-- Gated append: the entry goes in iff it is admissible. -/
def admit (δ now : Nat) (log : TimedLog) (e : TimedEntry) : Option TimedLog :=
  if admissible δ now log e then some (e :: log) else none

/-- Clock monotonicity of a most-recent-first timed log: every older entry's
    clock is ≤ every newer entry's clock. -/
def ClockMono (log : TimedLog) : Prop :=
  log.Pairwise (fun a b => b.clock ≤ a.clock)

/-- **(a) FRESHNESS.** Every accepted entry sits within `δ` of its producing
    step's clock: not from the future, and not older than `now - δ`. -/
theorem admitted_within_bound (δ now : Nat) (log : TimedLog) (e : TimedEntry)
    (log' : TimedLog) (h : admit δ now log e = some log') :
    e.clock ≤ now ∧ now ≤ e.clock + δ := by
  unfold admit at h
  split at h
  · rename_i hadm
    simp only [admissible, Bool.and_eq_true, decide_eq_true_eq] at hadm
    exact ⟨hadm.1.1.1, hadm.1.1.2⟩
  · exact absurd h (by simp)

/-- **(b) STALENESS.** An entry whose clock is more than `δ` behind the
    producing step is inadmissible — whatever the log contents. -/
theorem stale_clock_inadmissible (δ now : Nat) (log : TimedLog) (e : TimedEntry)
    (hstale : e.clock + δ < now) : admit δ now log e = none := by
  have hb : admissible δ now log e = false := by
    have : ¬ (now ≤ e.clock + δ) := by omega
    simp [admissible, this]
  simp [admit, hb]

/-- **(b') NO CLOCK REGRESSION.** An entry older than the newest logged entry
    is inadmissible: the record never travels backwards in logical time. -/
theorem regressed_clock_inadmissible (δ now : Nat) (log : TimedLog)
    (e : TimedEntry) (hreg : e.clock < latestClock log) :
    admit δ now log e = none := by
  have hb : admissible δ now log e = false := by
    have : ¬ (latestClock log ≤ e.clock) := by omega
    simp [admissible, this]
  simp [admit, hb]

/-- **(c) NO REPLAY.** An entry reusing a consumed nonce is inadmissible. -/
theorem replayed_nonce_inadmissible (δ now : Nat) (log : TimedLog)
    (e : TimedEntry) (hmem : e.nonce ∈ nonces log) :
    admit δ now log e = none := by
  have hb : admissible δ now log e = false := by
    simp [admissible, hmem]
  simp [admit, hb]

/-- **(d) ORDER PRESERVATION.** Admissible appends keep the log clock-sorted:
    the no-regression conjunct is checked only against the newest entry, but
    sortedness of the rest carries it to the whole log. -/
theorem admit_preserves_clock_mono (δ now : Nat) (log : TimedLog)
    (e : TimedEntry) (log' : TimedLog)
    (hmono : ClockMono log) (h : admit δ now log e = some log') :
    ClockMono log' := by
  unfold admit at h
  split at h
  · rename_i hadm
    injection h with h'
    subst h'
    simp only [admissible, Bool.and_eq_true, decide_eq_true_eq] at hadm
    have hle : latestClock log ≤ e.clock := hadm.1.2
    refine List.Pairwise.cons ?_ hmono
    intro b hb
    cases log with
    | nil => cases hb
    | cons p rest =>
      cases hb with
      | head => exact hle
      | tail _ hbrest =>
        have hbp : b.clock ≤ p.clock :=
          (List.pairwise_cons.mp hmono).1 b hbrest
        have hpe : p.clock ≤ e.clock := hle
        omega
  · exact absurd h (by simp)

/-- **(d') NONCE UNIQUENESS PRESERVATION.** Admissible appends keep the
    consumed-nonce list duplicate-free. -/
theorem admit_preserves_nonce_nodup (δ now : Nat) (log : TimedLog)
    (e : TimedEntry) (log' : TimedLog)
    (hnodup : (nonces log).Nodup) (h : admit δ now log e = some log') :
    (nonces log').Nodup := by
  unfold admit at h
  split at h
  · rename_i hadm
    injection h with h'
    subst h'
    simp only [admissible, Bool.and_eq_true, decide_eq_true_eq] at hadm
    have hfresh : e.nonce ∉ nonces log := hadm.2
    have hcons : nonces (e :: log) = e.nonce :: nonces log := rfl
    rw [hcons, List.nodup_cons]
    exact ⟨hfresh, hnodup⟩
  · exact absurd h (by simp)

/-! ## Chain-spine inheritance (INHERITED from L1 CORE, not re-proved) -/

/-- Render a timed log into the `Log` the L1 hash chain commits, through an
    entry encoder. -/
def render (enc : TimedEntry → String) (log : TimedLog) : Log := log.map enc

/-- INHERITED APPEND-ONLY: `head_after_append` (L1 CORE) at `enc e` —
    committing a timed entry extends the chain over the unchanged prior head.
    Definitional, no assumption. -/
theorem timed_head_after_append (H : Hash → String → Hash) (genesis : Hash)
    (enc : TimedEntry → String) (log : TimedLog) (e : TimedEntry) :
    rollingHead H genesis (render enc (e :: log))
      = H (rollingHead H genesis (render enc log)) (enc e) := rfl

/-- An injective map reflects list equality. Local helper for the
    tamper-evidence lift (no Mathlib in this tree). -/
private theorem map_inj_list {α β : Type} (f : α → β)
    (hf : ∀ a b, f a = f b → a = b) :
    ∀ l₁ l₂ : List α, l₁.map f = l₂.map f → l₁ = l₂
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | a :: l₁, b :: l₂, h => by
      simp only [List.map_cons, List.cons.injEq] at h
      rw [hf a b h.1, map_inj_list f hf l₁ l₂ h.2]

/-- INHERITED TAMPER-EVIDENCE, lifted to timed logs: under A-CR + A-GEN
    (exactly the L1 CORE assumptions) plus **A-ENC** — injectivity of the
    entry encoder — equal chain heads over rendered timed logs force equal
    timed logs. Any insert, reorder, clock edit, nonce edit, or payload
    mutation changes the head. -/
theorem timed_tamper_evident (H : Hash → String → Hash) (genesis : Hash)
    (hinj : ∀ a b p q, H a p = H b q → a = b ∧ p = q)   -- A-CR : collision-resistance
    (hgen : ∀ a p, H a p ≠ genesis)                      -- A-GEN: fresh genesis
    (enc : TimedEntry → String)
    (henc : ∀ e₁ e₂, enc e₁ = enc e₂ → e₁ = e₂)          -- A-ENC: injective encoder
    (t₁ t₂ : TimedLog)
    (hhead : rollingHead H genesis (render enc t₁)
           = rollingHead H genesis (render enc t₂)) :
    t₁ = t₂ :=
  map_inj_list enc henc t₁ t₂
    (tamper_evident H genesis hinj hgen (render enc t₁) (render enc t₂) hhead)

/-- The deployed entry encoder: one-line JSON. **Demonstration-grade** —
    A-ENC is NOT discharged for it (string escaping of `payload` is not
    proven injective); production discharges A-ENC with a length-prefixed or
    canonically-escaped encoding. Mirrors the `chainHash` honesty note. -/
def TimedEntry.line (e : TimedEntry) : String :=
  s!"\{\"clock\":{e.clock},\"nonce\":{e.nonce},\"payload\":\"{e.payload}\"}"

/-! ## Non-vacuity: the gate is live on both sides

Build-gated `#guard` tests (kernel-cheap Nat/List evaluation; a failing guard
fails the build, no axiom introduced). Each rejection exemplar is chosen so
EXACTLY ONE conjunct fails — the values around it satisfy the other three, so
each guard witnesses its own conjunct being load-bearing. -/

/-- Witness entries. -/
def wEntry0 : TimedEntry := { payload := "audit-0", clock := 5, nonce := 10 }
def wEntry1 : TimedEntry := { payload := "audit-1", clock := 7, nonce := 11 }

-- admissible: clock 7 ≤ now 7 ≤ 7+3; no regression (5 ≤ 7); nonce 11 fresh.
#guard admissible 3 7 [wEntry0] wEntry1 = true
#guard admit 3 7 [wEntry0] wEntry1 = some [wEntry1, wEntry0]
-- δ-stale ONLY: 7+3 < 12; not future (7 ≤ 12), no regression (5 ≤ 7), nonce fresh.
#guard admissible 3 12 [wEntry0] { payload := "stale", clock := 7, nonce := 12 } = false
#guard admit 3 12 [wEntry0] { payload := "stale", clock := 7, nonce := 12 } = none
-- clock regression ONLY: 6 < 7 = latestClock; fresh (7 ≤ 6+3), nonce fresh.
#guard admissible 3 7 [wEntry1, wEntry0] { payload := "regress", clock := 6, nonce := 12 } = false
-- nonce replay ONLY: 11 already consumed; fresh (8 ≤ 9 ≤ 8+3), no regression (7 ≤ 8).
#guard admissible 3 9 [wEntry1, wEntry0] { payload := "replay", clock := 8, nonce := 11 } = false

/-- The admitted witness log is clock-sorted — the invariant the preservation
    theorem maintains is inhabited. -/
theorem wLog_clock_mono : ClockMono [wEntry1, wEntry0] := by
  unfold ClockMono
  simp [List.pairwise_cons, wEntry0, wEntry1]

/-- ... and its consumed-nonce list is duplicate-free. -/
theorem wLog_nonce_nodup : (nonces [wEntry1, wEntry0]).Nodup := by
  simp [nonces, List.nodup_cons, wEntry0, wEntry1]

end Host.Record
