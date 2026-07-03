/- SPDX-License-Identifier: Apache-2.0 -/

import Host.RecordTemporal
import Mathlib.Data.Nat.Digits.Lemmas

/-!
# W2-T1 hardening — A-ENC discharged: the canonical entry encoder

`Host/RecordTemporal.lean` inherits L1 tamper-evidence to timed logs under
A-CR + A-GEN (the standard crypto TCB) PLUS one extra named assumption,
**A-ENC** (entry-encoder injectivity), undischarged for the demonstration-
grade JSON encoder `TimedEntry.line`. A-ENC is the only non-cryptographic
assumption in that chain — and it is pure-Lean dischargeable. This module
discharges it:

* `TimedEntry.encCanonical` — a length-prefixed, delimiter-safe encoder:
  decimal digit blocks (`Nat.digits 10`, rendered through `Nat.digitChar`)
  for the payload length, clock, and nonce, separated by `'|'`. The payload's
  extent is pinned by its length prefix, so the payload bytes may contain
  `'|'` (or anything else) freely — no escaping, hence no escaping hazard.
  A `Nat` renders little-endian with `0 ↦ []`; blocks are delimiter-bounded,
  so the empty block is unambiguous. Injectivity is what this encoder is
  for; human readability is not.
* `TimedEntry.encCanonical_injective` — injectivity BY CONSTRUCTION, proved
  by structural list surgery: the digit blocks contain no separator
  (first-separator splitting, `sep_split`), digit rendering is injective
  (`Nat.ofDigits_digits` round-trip), and the payload splits off by its
  length (`List.append_inj`). No crypto, no enumeration.
* `timed_tamper_evident_canonical` — `timed_tamper_evident` instantiated at
  `encCanonical`: the SAME conclusion with NO encoder assumption. The only
  remaining assumptions are A-CR + A-GEN — exactly the landed L1 crypto TCB.

`TimedEntry.line` is untouched and remains demonstration-grade; this module
is additive.
-/

namespace Host.Record

open SealCore

/-- Little-endian decimal digit block of a `Nat` (`[]` for `0`; blocks are
    always delimiter-bounded downstream, so the empty block is unambiguous). -/
def digitChars (n : Nat) : List Char := (Nat.digits 10 n).map Nat.digitChar

/-- `Nat.digitChar` is injective below the base. Ten-by-ten case check. -/
theorem digitChar_lt10_inj :
    ∀ d₁ < 10, ∀ d₂ < 10, Nat.digitChar d₁ = Nat.digitChar d₂ → d₁ = d₂ := by
  decide

/-- No decimal digit renders as the separator. -/
theorem digitChar_lt10_ne_bar : ∀ d < 10, Nat.digitChar d ≠ '|' := by decide

/-- The separator never occurs inside a digit block. -/
theorem bar_notMem_digitChars (n : Nat) : '|' ∉ digitChars n := by
  intro hmem
  obtain ⟨d, hd, hdc⟩ := List.mem_map.mp hmem
  exact digitChar_lt10_ne_bar d (Nat.digits_lt_base (by norm_num) hd) hdc

/-- Rendering digit lists (entries < 10) through `Nat.digitChar` is
    injective. -/
theorem map_digitChar_inj : ∀ (l₁ l₂ : List Nat),
    (∀ d ∈ l₁, d < 10) → (∀ d ∈ l₂, d < 10) →
    l₁.map Nat.digitChar = l₂.map Nat.digitChar → l₁ = l₂
  | [], [], _, _, _ => rfl
  | [], _ :: _, _, _, h => by simp at h
  | _ :: _, [], _, _, h => by simp at h
  | a :: l₁, b :: l₂, h₁, h₂, h => by
      simp only [List.map_cons, List.cons.injEq] at h
      rw [digitChar_lt10_inj a (h₁ a List.mem_cons_self) b
          (h₂ b List.mem_cons_self) h.1,
        map_digitChar_inj l₁ l₂ (fun d hd => h₁ d (List.mem_cons_of_mem _ hd))
          (fun d hd => h₂ d (List.mem_cons_of_mem _ hd)) h.2]

/-- The digit block determines the number (`Nat.ofDigits_digits` round-trip). -/
theorem digitChars_inj {n₁ n₂ : Nat} (h : digitChars n₁ = digitChars n₂) :
    n₁ = n₂ := by
  have hdig : Nat.digits 10 n₁ = Nat.digits 10 n₂ :=
    map_digitChar_inj _ _ (fun d hd => Nat.digits_lt_base (by norm_num) hd)
      (fun d hd => Nat.digits_lt_base (by norm_num) hd) h
  have := congrArg (Nat.ofDigits 10) hdig
  rwa [Nat.ofDigits_digits, Nat.ofDigits_digits] at this
  -- `Nat.ofDigits 10 : List ℕ → ℕ` here; both sides collapse to `nᵢ`.

/-- **First-separator splitting.** If two separator-free prefixes are each
    followed by the separator, equal concatenations force equal prefixes and
    equal tails. -/
theorem sep_split : ∀ (xs ys as bs : List Char), '|' ∉ xs → '|' ∉ ys →
    xs ++ '|' :: as = ys ++ '|' :: bs → xs = ys ∧ as = bs
  | [], [], _, _, _, _, h => by
      simp only [List.nil_append, List.cons.injEq] at h
      exact ⟨rfl, h.2⟩
  | [], y :: ys, as, bs, _, hy, h => by
      simp only [List.nil_append, List.cons_append, List.cons.injEq] at h
      exact absurd (List.mem_cons.mpr (Or.inl h.1)) hy
  | x :: xs, [], as, bs, hx, _, h => by
      simp only [List.cons_append, List.nil_append, List.cons.injEq] at h
      exact absurd (List.mem_cons.mpr (Or.inl h.1.symm)) hx
  | x :: xs, y :: ys, as, bs, hx, hy, h => by
      simp only [List.cons_append, List.cons.injEq] at h
      obtain ⟨hxy, hrest⟩ :=
        sep_split xs ys as bs (fun hm => hx (List.mem_cons_of_mem _ hm))
          (fun hm => hy (List.mem_cons_of_mem _ hm)) h.2
      exact ⟨by rw [h.1, hxy], hrest⟩

/-- **The canonical entry encoder** (FROZEN, W2-T1 hardening): length-prefixed
    payload, then delimited decimal blocks for clock and nonce. Injective by
    construction — no escaping, no hazard. -/
def TimedEntry.encCanonical (e : TimedEntry) : String :=
  String.ofList (digitChars e.payload.length ++ '|' ::
    (e.payload.toList ++ '|' :: (digitChars e.clock ++ '|' :: digitChars e.nonce)))

/-- **A-ENC, DISCHARGED** (FROZEN, W2-T1 hardening): the canonical encoder is
    injective. Pure structural reasoning — separator-free digit blocks split
    uniquely at the first separator, the length prefix splits the payload off
    by `List.append_inj`, and digit rendering round-trips through
    `Nat.ofDigits_digits`. -/
theorem TimedEntry.encCanonical_injective :
    Function.Injective TimedEntry.encCanonical := by
  intro e₁ e₂ h
  have hlist := congrArg String.toList h
  rw [TimedEntry.encCanonical, TimedEntry.encCanonical, String.toList_ofList,
    String.toList_ofList] at hlist
  obtain ⟨hlen, hrest⟩ := sep_split _ _ _ _
    (bar_notMem_digitChars _) (bar_notMem_digitChars _) hlist
  have hL : e₁.payload.length = e₂.payload.length := digitChars_inj hlen
  have hLdata : e₁.payload.toList.length = e₂.payload.toList.length := by
    rw [String.length_toList, String.length_toList, hL]
  obtain ⟨hpayl, hrest₂⟩ := List.append_inj hrest hLdata
  have hrest₃ : digitChars e₁.clock ++ '|' :: digitChars e₁.nonce
      = digitChars e₂.clock ++ '|' :: digitChars e₂.nonce := by
    injection hrest₂
  obtain ⟨hclk, hnon⟩ := sep_split _ _ _ _
    (bar_notMem_digitChars _) (bar_notMem_digitChars _) hrest₃
  have hp : e₁.payload = e₂.payload := String.toList_injective hpayl
  have hc : e₁.clock = e₂.clock := digitChars_inj hclk
  have hn : e₁.nonce = e₂.nonce := digitChars_inj hnon
  cases e₁; cases e₂; simp_all

/-- **TIMED TAMPER-EVIDENCE, UNCONDITIONAL IN THE ENCODER** (FROZEN, W2-T1
    hardening): `timed_tamper_evident` at the canonical encoder. Equal chain
    heads over canonically rendered timed logs force equal timed logs, under
    A-CR + A-GEN alone — exactly the landed L1 crypto TCB. A-ENC is gone:
    discharged by `TimedEntry.encCanonical_injective`, not assumed. -/
theorem timed_tamper_evident_canonical (H : Hash → String → Hash) (genesis : Hash)
    (hinj : ∀ a b p q, H a p = H b q → a = b ∧ p = q)   -- A-CR : collision-resistance
    (hgen : ∀ a p, H a p ≠ genesis)                      -- A-GEN: fresh genesis
    (t₁ t₂ : TimedLog)
    (hhead : rollingHead H genesis (render TimedEntry.encCanonical t₁)
           = rollingHead H genesis (render TimedEntry.encCanonical t₂)) :
    t₁ = t₂ :=
  timed_tamper_evident H genesis hinj hgen TimedEntry.encCanonical
    (fun _ _ h => TimedEntry.encCanonical_injective h) t₁ t₂ hhead

/-! ## Non-vacuity: distinctness is live in every field

Build-gated `#guard` tests (compiler evaluator; a failing guard fails the
build). Each field difference alone produces a distinct encoding; equal
entries encode equal; and the delimiter-hazard exhibit — a payload containing
separators and digits — cannot fake field boundaries past the length prefix. -/

#guard TimedEntry.encCanonical { payload := "a", clock := 1, nonce := 2 }
    == TimedEntry.encCanonical { payload := "a", clock := 1, nonce := 2 }
#guard TimedEntry.encCanonical { payload := "a", clock := 1, nonce := 2 }
    != TimedEntry.encCanonical { payload := "b", clock := 1, nonce := 2 }
#guard TimedEntry.encCanonical { payload := "a", clock := 1, nonce := 2 }
    != TimedEntry.encCanonical { payload := "a", clock := 3, nonce := 2 }
#guard TimedEntry.encCanonical { payload := "a", clock := 1, nonce := 2 }
    != TimedEntry.encCanonical { payload := "a", clock := 1, nonce := 3 }
-- delimiter-hazard exhibit: '|' and digits inside the payload
#guard TimedEntry.encCanonical { payload := "a|1", clock := 2, nonce := 3 }
    != TimedEntry.encCanonical { payload := "a", clock := 1, nonce := 2 }
#guard TimedEntry.encCanonical { payload := "1|2|3", clock := 4, nonce := 5 }
    != TimedEntry.encCanonical { payload := "1", clock := 2, nonce := 3 }

end Host.Record
