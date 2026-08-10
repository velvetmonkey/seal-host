/- SPDX-License-Identifier: Apache-2.0 -/

/-!
# Unpaired UTF-16 surrogate escapes on the raw wire

`Lean.Json.parse` (toolchain `Lean/Data/Json/Parser.lean:60-70`) substitutes
U+FFFD for an unpaired `\uD800`–`\uDFFF` escape and accepts the string, while
a strict conformant reader (serde_json among them) rejects the same bytes and
other deployed readers extract the raw surrogate — the witnessed A2 class (a)
decoupling (`docs/A2-DIVERGENCE-CLASSIFICATION.md` rows 10–18,
`docs/V31-DOWNSTREAM-PARSER-AGREEMENT.md`). The judged `CanonicalAction` then
contains U+FFFD where the forwarded bytes carry the surrogate escape: the
kernel judges one event, the child may execute another.

This guard refuses the class pre-parse, on the raw line bytes, in the style of
`Seal.JsonUtil.wireKeysSafe`: a total scan, no `Json.parse`, no `partial`.

## Shape of the scan

A two-mode recursive descent over the character list (`scan false` outside
string literals, `scan true` inside), consuming escape sequences whole. Inside
a string:

* `\uXXXX` with `XXXX` four hex digits reading as a HIGH surrogate
  (`D800`–`DBFF`) must be followed IMMEDIATELY by `\uYYYY` with `YYYY` a LOW
  surrogate (`DC00`–`DFFF`); anything else — a non-escape character, a simple
  escape, a second high surrogate, a non-surrogate escape, an incomplete
  escape, the closing quote, end of line — is an unpaired surrogate: unsafe.
* `\uXXXX` reading as a LOW surrogate with no preceding high surrogate escape
  is unpaired: unsafe.
* Every other escape (`\n`, `\"`, `\\`, `\u0041`, …) and every ordinary
  character is transparent (the transparency THEOREMS below).

An INCOMPLETE `\u` escape (fewer than four hex digits) is NOT this class: it
is malformed JSON on every reader, `Lean.Json.parse` refuses it, and the line
routes exactly as before this guard. The scanner treats the dangling `u` as an
escaped character and rescans the remainder.

## The exclusion obligation

A predicate that also catches ordinary text is not a fix, it is an outage. The
exclusion is stated and PROVEN as `unsafe_implies_surrogate_escape`: whenever
`wireSurrogatesSafe s = false`, the raw characters of `s` literally contain
the six-character substring `\uXXXX` with `XXXX` hex-reading into
`D800`–`DFFF` (`containsSurrogateEscape`, an independent positional spec that
never inspects string/escape context). Contrapositive
(`safe_of_no_surrogateEscape`): a line without those six raw bytes — all
ordinary traffic — is UNTOUCHED by this guard. The transparency lemmas sharpen
this inside the surrogate-carrying class: a VALID surrogate pair, a
non-surrogate `\u` escape, and every simple escape are consumed with no effect
on the verdict, so a line is refused only through an escape that hex-reads
into the surrogate range and fails to pair.
-/

namespace Host.SurrogateEscapes

/-- Hex digit value, both cases, in the JSON `\u` escape alphabet. -/
def hexVal? (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c ∧ c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

/-- The value of a four-hex-digit escape body, or `none` if any character is
    not a hex digit. -/
def hex4? (c1 c2 c3 c4 : Char) : Option Nat :=
  match hexVal? c1, hexVal? c2, hexVal? c3, hexVal? c4 with
  | some a, some b, some c, some d => some (((a * 16 + b) * 16 + c) * 16 + d)
  | _, _, _, _ => none

/-- UTF-16 high (leading) surrogate code unit. -/
def isHighSurrogate (v : Nat) : Bool := 0xD800 ≤ v ∧ v ≤ 0xDBFF

/-- UTF-16 low (trailing) surrogate code unit. -/
def isLowSurrogate (v : Nat) : Bool := 0xDC00 ≤ v ∧ v ≤ 0xDFFF

/-- Any UTF-16 surrogate code unit. -/
def isSurrogate (v : Nat) : Bool := isHighSurrogate v || isLowSurrogate v

/-- The two-mode scan. `scan false l`: outside a string literal, looking for
    an opening quote. `scan true l`: inside a string literal. Returns `true`
    exactly when an unpaired surrogate escape is found. Total: every recursive
    call consumes at least one character. -/
def scan : Bool → List Char → Bool
  | false, '"' :: rest => scan true rest
  | false, _ :: rest => scan false rest
  | false, [] => false
  | true, '\\' :: 'u' :: c1 :: c2 :: c3 :: c4 :: rest =>
      (match hex4? c1 c2 c3 c4 with
       | some v =>
           if isHighSurrogate v then
             match rest with
             | '\\' :: 'u' :: d1 :: d2 :: d3 :: d4 :: rest' =>
                 (match hex4? d1 d2 d3 d4 with
                  | some w => if isLowSurrogate w then scan true rest' else true
                  | none => true)
             | _ => true
           else if isLowSurrogate v then true
           else scan true rest
       | none =>
           -- Not four hex digits: no complete escape here. Rescan from the
           -- first body character (hex digits are never `\` or `"`, so the
           -- two consumed characters are inert).
           scan true (c1 :: c2 :: c3 :: c4 :: rest))
  | true, '\\' :: _ :: rest => scan true rest
  | true, '"' :: rest => scan false rest
  | true, _ :: rest => scan true rest
  | true, [] => false
termination_by _ l => l.length

/-- **The class-(a) pre-parse predicate.** `true` iff the raw wire line
    carries no unpaired UTF-16 surrogate escape inside a string literal.
    Decidable and total; runs before `Json.parse` in `Host.classifyLine`. -/
def wireSurrogatesSafe (s : String) : Bool :=
  !scan false s.toList

/-! ## The independent positional spec

`containsSurrogateEscape` is deliberately DUMBER than the scanner: it knows
nothing about string literals, escape consumption, or pairing. It asks only
whether the six raw characters `\uXXXX` with a surrogate hex value occur
contiguously anywhere in the list. The exclusion theorem lower-bounds every
refusal by this spec. -/

/-- The list BEGINS with `\uXXXX`, `XXXX` four hex digits whose value is a
    UTF-16 surrogate code unit. -/
def surrogateEscapeHead : List Char → Bool
  | '\\' :: 'u' :: c1 :: c2 :: c3 :: c4 :: _ =>
      (match hex4? c1 c2 c3 c4 with
       | some v => isSurrogate v
       | none => false)
  | _ => false

/-- Some suffix of the list begins with a surrogate escape: the six raw
    characters occur as a contiguous substring. -/
def containsSurrogateEscape : List Char → Bool
  | [] => false
  | c :: rest => surrogateEscapeHead (c :: rest) || containsSurrogateEscape rest

/-- Substring containment is preserved by prepending a character. -/
theorem contains_cons (c : Char) {l : List Char}
    (h : containsSurrogateEscape l = true) :
    containsSurrogateEscape (c :: l) = true := by
  simp [containsSurrogateEscape, h]

/-- A list that begins with a surrogate escape contains one. -/
theorem contains_of_head : ∀ {l : List Char},
    surrogateEscapeHead l = true → containsSurrogateEscape l = true
  | [], h => by simp [surrogateEscapeHead] at h
  | c :: rest, h => by simp [containsSurrogateEscape, h]

/-- **Exclusion, scanner level.** If the scan reports unsafe — from either
    mode — the six raw characters of a surrogate escape are literally present
    in the input. -/
theorem scan_surrogate (mode : Bool) (l : List Char) :
    scan mode l = true → containsSurrogateEscape l = true := by
  fun_induction scan mode l with
  | case1 rest ih => -- false, '"' :: rest
      intro h; exact contains_cons _ (ih h)
  | case2 c rest _ ih => -- false, other char
      intro h; exact contains_cons _ (ih h)
  | case3 => -- false, []
      intro h; exact absurd h (by simp [scan])
  | case4 c1 c2 c3 c4 v hv hhigh d1 d2 d3 d4 rest' w hw hlow ih =>
      -- high surrogate escape, paired with a low escape: recursion
      intro _
      exact contains_of_head (by simp [surrogateEscapeHead, hv, isSurrogate, hhigh])
  | case5 c1 c2 c3 c4 v hv hhigh d1 d2 d3 d4 rest' w hw hlow =>
      -- high surrogate escape, follower escape not low: head is a surrogate
      intro _
      exact contains_of_head (by simp [surrogateEscapeHead, hv, isSurrogate, hhigh])
  | case6 c1 c2 c3 c4 v hv hhigh d1 d2 d3 d4 rest' hw =>
      -- high surrogate escape, follower escape body not hex
      intro _
      exact contains_of_head (by simp [surrogateEscapeHead, hv, isSurrogate, hhigh])
  | case7 c1 c2 c3 c4 rest v hv hhigh hrest =>
      -- high surrogate escape, no follower escape at all
      intro _
      exact contains_of_head (by simp [surrogateEscapeHead, hv, isSurrogate, hhigh])
  | case8 c1 c2 c3 c4 rest v hv hhigh hlow =>
      -- lone low surrogate escape
      intro _
      exact contains_of_head
        (by simp [surrogateEscapeHead, hv, isSurrogate, hlow])
  | case9 c1 c2 c3 c4 rest v hv hhigh hlow ih =>
      -- non-surrogate \u escape: recursion on rest
      intro h
      exact contains_cons _ (contains_cons _ (contains_cons _ (contains_cons _
        (contains_cons _ (contains_cons _ (ih h))))))
  | case10 c1 c2 c3 c4 rest hv ih =>
      -- incomplete escape body: rescan from first body character
      intro h
      exact contains_cons _ (contains_cons _ (ih h))
  | case11 e rest _ ih => -- simple escape
      intro h
      exact contains_cons _ (contains_cons _ (ih h))
  | case12 rest ih => -- closing quote
      intro h; exact contains_cons _ (ih h)
  | case13 c rest _ _ _ ih => -- ordinary in-string char
      intro h; exact contains_cons _ (ih h)
  | case14 => -- true, []
      intro h; exact absurd h (by simp [scan])

/-- **THE EXCLUSION THEOREM.** A line this guard refuses literally contains
    the six raw characters `\uXXXX` with `XXXX` hex-reading into the UTF-16
    surrogate range `D800`–`DFFF`. The guard can fire on NOTHING ELSE. -/
theorem unsafe_implies_surrogateEscape (s : String)
    (h : wireSurrogatesSafe s = false) :
    containsSurrogateEscape s.toList = true := by
  have hs : scan false s.toList = true := by
    have := congrArg Bool.not h
    simpa [wireSurrogatesSafe] using this
  exact scan_surrogate false s.toList hs

/-- Contrapositive, the operational reading: ordinary traffic — any line in
    which the six raw bytes of a surrogate escape never occur — is ACCEPTED by
    this guard, unconditionally. -/
theorem safe_of_no_surrogateEscape (s : String)
    (h : containsSurrogateEscape s.toList = false) :
    wireSurrogatesSafe s = true := by
  cases hw : wireSurrogatesSafe s with
  | true => rfl
  | false => exact absurd (unsafe_implies_surrogateEscape s hw) (by simp [h])

/-! ## Transparency lemmas — what the scanner consumes WITHOUT effect

These sharpen the exclusion inside the surrogate-carrying class: a valid
surrogate pair, a non-surrogate `\u` escape, and every simple escape are
verdict-neutral. A refusal can therefore only arise from a surrogate-valued
escape that fails to pair. -/

/-- A VALID surrogate pair (high escape immediately followed by low escape) is
    transparent: the scan continues after it with no effect on the verdict.
    Well-formed astral-plane text (`\uD834\uDD1E` and kin) is never refused. -/
theorem scan_pair_transparent (c1 c2 c3 c4 d1 d2 d3 d4 : Char)
    (rest : List Char) (v w : Nat)
    (hv : hex4? c1 c2 c3 c4 = some v) (hhigh : isHighSurrogate v = true)
    (hw : hex4? d1 d2 d3 d4 = some w) (hlow : isLowSurrogate w = true) :
    scan true ('\\' :: 'u' :: c1 :: c2 :: c3 :: c4 ::
               '\\' :: 'u' :: d1 :: d2 :: d3 :: d4 :: rest)
      = scan true rest := by
  simp [scan, hv, hhigh, hw, hlow]

/-- A non-surrogate `\u` escape (`\u0041`, `\u1234`, …) is transparent. -/
theorem scan_uescape_transparent (c1 c2 c3 c4 : Char) (rest : List Char)
    (v : Nat) (hv : hex4? c1 c2 c3 c4 = some v)
    (hns : isSurrogate v = false) :
    scan true ('\\' :: 'u' :: c1 :: c2 :: c3 :: c4 :: rest)
      = scan true rest := by
  have hh : isHighSurrogate v = false := by
    cases hb : isHighSurrogate v with
    | false => rfl
    | true => simp [isSurrogate, hb] at hns
  have hl : isLowSurrogate v = false := by
    cases hb : isLowSurrogate v with
    | false => rfl
    | true => simp [isSurrogate, hb] at hns
  rw [scan.eq_def]
  simp [hv, hh, hl]

/-- A simple escape (`\n`, `\"`, `\\`, `\t`, …: anything but `u`) is
    transparent. In particular `\"` does NOT close the string and `\\` does
    not open an escape. -/
theorem scan_simple_escape_transparent (e : Char) (rest : List Char)
    (he : e ≠ 'u') :
    scan true ('\\' :: e :: rest) = scan true rest := by
  rw [scan.eq_def]
  split
  all_goals try simp_all
  all_goals
    rename_i hall _ heq
    exact absurd heq.2.symm (hall e rest heq.1.symm)

/-- An ordinary in-string character (not `\`, not `"`) is transparent. -/
theorem scan_char_transparent (c : Char) (rest : List Char)
    (hb : c ≠ '\\') (hq : c ≠ '"') :
    scan true (c :: rest) = scan true rest := by
  rw [scan.eq_def]
  split
  all_goals simp_all

/-! ## Elaboration-time controls (the concrete-string discipline:
`String` functions do not kernel-reduce on this toolchain, so per-line facts
are build-gated `#guard`s — a flip fails the build). -/

-- The nine recorded class-(a) vectors, raw (envelope-free) forms:
#guard wireSurrogatesSafe "[\"\\uDADA\"]" = false
#guard wireSurrogatesSafe "[\"\\uD888\\u1234\"]" = false
#guard wireSurrogatesSafe "[\"\\uD800\\n\"]" = false
#guard wireSurrogatesSafe "[\"\\uDd1ea\"]" = false
#guard wireSurrogatesSafe "[\"\\uD800\\uD800\\n\"]" = false
#guard wireSurrogatesSafe "[\"\\ud800\"]" = false
#guard wireSurrogatesSafe "[\"\\ud800abc\"]" = false
#guard wireSurrogatesSafe "[\"\\uDd1e\\uD834\"]" = false
#guard wireSurrogatesSafe "[\"\\uDFAA\"]" = false

-- Positive controls: ordinary traffic is untouched.
#guard wireSurrogatesSafe "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"SELECT 1\"}}}"
#guard wireSurrogatesSafe "[\"\\uD834\\uDD1E\"]"          -- valid pair (𝄞)
#guard wireSurrogatesSafe "[\"\\udbff\\udfff\"]"          -- valid pair, lowercase
#guard wireSurrogatesSafe "[\"\\u0041\\u1234\\uFFFF\"]"   -- non-surrogate escapes
#guard wireSurrogatesSafe "[\"\\n\\\"\\\\\\t\"]"          -- simple escapes
#guard wireSurrogatesSafe "[\"uD800 D800 \\\\uD800\"]"    -- surrogate TEXT, no escape
#guard wireSurrogatesSafe "not json at all"
#guard wireSurrogatesSafe "[\"\\uD8\"]"                    -- incomplete escape: not this class

end Host.SurrogateEscapes
