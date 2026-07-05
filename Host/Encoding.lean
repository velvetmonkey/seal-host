/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Hash
import Batteries.Data.Nat.Digits

/-!
# Injectivity of the canonical part-list encoding (netstring framing)

`Seal.encodeParts` (mcp-seal-dev @ e36fc98) frames each part `s` as
`<decimal charCount>:<s>` and concatenates. This module proves the framing is
INJECTIVE over `List String` — `encodeParts_injective` — by unique decoding:

* the decimal length prefix contains no `':'`
  (`Nat.isDigit_of_mem_toDigits`, Batteries), so the FIRST `':'` delimits it
  (`append_sep_inj`);
* decimal rendering is injective (`digitsVal_toDigits`: fold the digits back,
  a left inverse of `Nat.toDigits 10`), so equal prefixes mean equal lengths;
* equal lengths split the remainder exactly (`List.append_inj`), and the
  chain recurses (`chain_inj`).

Kernel proof only: no `native_decide`, no new axioms. This is the structural
half of the unconditional capability theorem in `Host/CapabilityAdequacy`:
it moves the entire collision surface of `Seal.stableHashParts` out of the
ENCODING (now provably collision-free) and into the fixed-width
`stableHashString` compression, where it is named A-CR.
-/

namespace Host.Encoding

/-! ## Decimal digits: value fold, injectivity, and the no-colon fact -/

/-- Fold a digit string back to its value — a left inverse of
    `Nat.toDigits 10` (proved below), which is all injectivity needs. -/
def digitsVal (cs : List Char) : Nat :=
  cs.foldl (fun a c => a * 10 + (c.toNat - 48)) 0

theorem digitChar_val (d : Nat) (h : d < 10) : (Nat.digitChar d).toNat - 48 = d := by
  match d, h with
  | 0, _ => decide
  | 1, _ => decide
  | 2, _ => decide
  | 3, _ => decide
  | 4, _ => decide
  | 5, _ => decide
  | 6, _ => decide
  | 7, _ => decide
  | 8, _ => decide
  | 9, _ => decide

/-- `digitsVal` is a left inverse of decimal rendering. -/
theorem digitsVal_toDigits (n : Nat) : digitsVal (Nat.toDigits 10 n) = n := by
  induction n using Nat.strongRecOn with
  | _ n ih =>
    by_cases h : n < 10
    · rw [Nat.toDigits_of_lt_base h]
      show 0 * 10 + ((Nat.digitChar n).toNat - 48) = n
      rw [digitChar_val n h]
      omega
    · have h10 : 10 ≤ n := Nat.le_of_not_lt h
      have hq : 0 < n / 10 := Nat.div_pos h10 (by decide)
      have hd : n % 10 < 10 := Nat.mod_lt _ (by decide)
      have hstep := Nat.toDigits_append_toDigits (b := 10) (n := n / 10)
        (d := n % 10) (by decide) hq hd
      rw [Nat.toDigits_of_lt_base hd, Nat.div_add_mod n 10] at hstep
      rw [← hstep]
      show digitsVal (Nat.toDigits 10 (n / 10) ++ [Nat.digitChar (n % 10)]) = n
      unfold digitsVal
      rw [List.foldl_append]
      show (Nat.toDigits 10 (n / 10)).foldl _ 0 * 10
          + ((Nat.digitChar (n % 10)).toNat - 48) = n
      have hihq : digitsVal (Nat.toDigits 10 (n / 10)) = n / 10 :=
        ih (n / 10) (Nat.div_lt_self (by omega) (by decide))
      unfold digitsVal at hihq
      rw [hihq, digitChar_val (n % 10) hd]
      have := Nat.div_add_mod n 10
      omega

/-- Decimal rendering is injective. -/
theorem toDigits_ten_inj {m n : Nat}
    (h : Nat.toDigits 10 m = Nat.toDigits 10 n) : m = n := by
  have hm := digitsVal_toDigits m
  rw [h, digitsVal_toDigits n] at hm
  exact hm.symm

/-- No decimal digit character is the frame separator `':'`. -/
theorem toDigits_ne_colon {n : Nat} {c : Char}
    (hc : c ∈ Nat.toDigits 10 n) : c ≠ ':' := by
  have hd := Nat.isDigit_of_mem_toDigits (by decide) (by decide) hc
  intro h
  rw [h] at hd
  exact absurd hd (by decide)

/-! ## The separator split: the first `':'` is unambiguous -/

/-- If neither prefix contains the separator, `as ++ ':' :: r₁ = bs ++ ':' :: r₂`
    splits componentwise: the FIRST separator occurrence pins the boundary. -/
theorem append_sep_inj {as bs r₁ r₂ : List Char}
    (ha : ∀ c ∈ as, c ≠ ':') (hb : ∀ c ∈ bs, c ≠ ':')
    (h : as ++ ':' :: r₁ = bs ++ ':' :: r₂) : as = bs ∧ r₁ = r₂ := by
  induction as generalizing bs with
  | nil =>
    cases bs with
    | nil =>
      simp only [List.nil_append] at h
      exact ⟨rfl, (List.cons.inj h).2⟩
    | cons b bt =>
      simp only [List.nil_append, List.cons_append] at h
      exact absurd (List.cons.inj h).1.symm (hb b (List.mem_cons_self ..))
  | cons a at' ih =>
    cases bs with
    | nil =>
      simp only [List.nil_append, List.cons_append] at h
      exact absurd (List.cons.inj h).1 (ha a (List.mem_cons_self ..))
    | cons b bt =>
      simp only [List.cons_append] at h
      obtain ⟨hab, ht⟩ := List.cons.inj h
      obtain ⟨h1, h2⟩ := ih
        (fun c hc => ha c (List.mem_cons_of_mem _ hc))
        (fun c hc => hb c (List.mem_cons_of_mem _ hc)) ht
      exact ⟨by rw [hab, h1], h2⟩

/-! ## The frame chain over `List Char` -/

/-- One netstring frame, at the character level. -/
def frameChars (s : String) : List Char :=
  Nat.toDigits 10 s.length ++ ':' :: s.toList

/-- The whole encoding, at the character level. -/
def chain : List String → List Char
  | [] => []
  | s :: t => frameChars s ++ chain t

theorem chain_cons (s : String) (t : List String) :
    chain (s :: t) = Nat.toDigits 10 s.length ++ ':' :: (s.toList ++ chain t) := by
  simp [chain, frameChars, List.append_assoc]

/-- **Unique decode.** The frame chain is injective. -/
theorem chain_inj : ∀ l₁ l₂ : List String, chain l₁ = chain l₂ → l₁ = l₂ := by
  intro l₁
  induction l₁ with
  | nil =>
    intro l₂ h
    cases l₂ with
    | nil => rfl
    | cons s t =>
      rw [chain_cons] at h
      cases hds : Nat.toDigits 10 s.length with
      | nil => rw [hds] at h; exact absurd h (by simp [chain])
      | cons c cs => rw [hds] at h; exact absurd h (by simp [chain])
  | cons s₁ t₁ ih =>
    intro l₂ h
    cases l₂ with
    | nil =>
      rw [chain_cons] at h
      cases hds : Nat.toDigits 10 s₁.length with
      | nil => rw [hds] at h; exact absurd h (by simp [chain])
      | cons c cs => rw [hds] at h; exact absurd h (by simp [chain])
    | cons s₂ t₂ =>
      rw [chain_cons, chain_cons] at h
      obtain ⟨hdig, hrest⟩ := append_sep_inj
        (fun c hc => toDigits_ne_colon hc) (fun c hc => toDigits_ne_colon hc) h
      have hlen : s₁.length = s₂.length := toDigits_ten_inj hdig
      have hlen' : s₁.toList.length = s₂.toList.length := by
        rw [String.length_toList, String.length_toList, hlen]
      obtain ⟨hs, ht⟩ := List.append_inj hrest hlen'
      rw [String.toList_inj.mp hs, ih t₂ ht]

/-! ## Transfer to `Seal.encodeParts` -/

theorem foldl_append_toList (L : List String) (acc : String) :
    (L.foldl (· ++ ·) acc).toList = acc.toList ++ (L.map String.toList).flatten := by
  induction L generalizing acc with
  | nil => simp
  | cons s t ih =>
    show (t.foldl (· ++ ·) (acc ++ s)).toList = _
    rw [ih (acc ++ s), String.toList_append]
    simp [List.append_assoc]

theorem empty_toList : ("" : String).toList = [] := by decide

theorem join_toList (L : List String) :
    (String.join L).toList = (L.map String.toList).flatten := by
  show (L.foldl (· ++ ·) "").toList = _
  rw [foldl_append_toList, empty_toList, List.nil_append]

/-- One frame's characters are exactly `frameChars`. -/
theorem frame_toList (s : String) :
    (toString s.length ++ ":" ++ s).toList = frameChars s := by
  rw [String.toList_append, String.toList_append]
  show (Nat.repr s.length).toList ++ (":" : String).toList ++ s.toList = _
  show (String.ofList (Nat.toDigits 10 s.length)).toList
      ++ (":" : String).toList ++ s.toList = _
  rw [String.toList_ofList]
  have hcolon : (":" : String).toList = [':'] := by decide
  rw [hcolon, frameChars, List.append_assoc]
  rfl

theorem map_frame_flatten (l : List String) :
    (l.map (String.toList ∘ fun s => toString s.length ++ ":" ++ s)).flatten
      = chain l := by
  induction l with
  | nil => rfl
  | cons s t ih =>
    rw [List.map_cons, List.flatten_cons, ih]
    show (toString s.length ++ ":" ++ s).toList ++ chain t = chain (s :: t)
    rw [frame_toList]
    rfl

theorem encodeParts_toList (l : List String) :
    (Seal.encodeParts l).toList = chain l := by
  show (String.join (l.map fun s => toString s.length ++ ":" ++ s)).toList = chain l
  rw [join_toList, List.map_map, map_frame_flatten]

/-- **The encoding is injective** (netstring framing, unique decode). The
    entire collision surface of `Seal.stableHashParts` is therefore the
    fixed-width `stableHashString` compression, not the encoding. -/
theorem encodeParts_injective : Function.Injective Seal.encodeParts := by
  intro l₁ l₂ h
  apply chain_inj
  rw [← encodeParts_toList, ← encodeParts_toList, h]

end Host.Encoding
