/- SPDX-License-Identifier: Apache-2.0 -/

/-!
# Container nesting depth on the raw wire

A2 class (c): `Lean.Json.parse` (a partial-recursive parser with no depth
bound) accepts arbitrarily deep container nesting, while a downstream reader
enforces a recursion limit — serde_json rejects at depth 128
(`i_structure_500_nested_arrays`, `docs/A2-DIVERGENCE-CLASSIFICATION.md`
row 9). A line the host judges as an act can therefore be rejected outright
by the child's reader, or truncate other readers' stacks: the judged event
and the executed event decouple exactly as in class (a).

This guard bounds the nesting of the WHOLE wire line at
`maxNestingDepth = 128` — the serde_json default recursion limit, the
shallowest limit among the recorded downstream readers. Same shape as
`Seal.JsonUtil.wireDigitsSafe`: a total fold, string-literal aware (a `[` or
`{` inside a string does not nest), escape-aware (`\"` does not close a
string), no parse.

Exclusion is definitional and pinned by `wireDepthSafe_iff`: the guard fires
iff the maximum bracket nesting outside string literals exceeds the bound.
Ordinary traffic sits at depth ≤ 10; the fixed `tools/call` envelope
contributes exactly 2 (`{"jsonrpc":…,"params":{…}}`) plus the arguments'
own nesting.
-/

namespace Host.NestingDepth

/-- serde_json's default recursion limit — the shallowest depth bound among
    the recorded downstream readers. -/
def maxNestingDepth : Nat := 128

/-- Character-scan state for the bracket-depth guard. -/
structure DepthScan where
  /-- Currently inside a string literal. -/
  inString : Bool := false
  /-- The previous character was an unconsumed backslash inside a string. -/
  escaped : Bool := false
  /-- Current container nesting depth. -/
  depth : Nat := 0
  /-- Maximum depth reached so far. -/
  worst : Nat := 0
  deriving Repr

/-- One character step of the depth scan: tracks string-literal and escape
    state so brackets inside strings never count, and folds `{`/`[` and
    `}`/`]` into the running and worst depth. -/
def depthScanStep (st : DepthScan) (c : Char) : DepthScan :=
  if st.inString then
    if st.escaped then { st with escaped := false }
    else if c == '\\' then { st with escaped := true }
    else if c == '"' then { st with inString := false }
    else st
  else if c == '"' then { st with inString := true }
  else if c == '{' || c == '[' then
    let d := st.depth + 1
    { st with depth := d, worst := Nat.max st.worst d }
  else if c == '}' || c == ']' then
    { st with depth := st.depth - 1 }
  else st

/-- The maximum container nesting depth reached outside string literals. -/
def worstDepth (s : String) : Nat :=
  (s.toList.foldl depthScanStep {}).worst

/-- **The class-(c) pre-parse predicate.** `true` iff the raw line's container
    nesting outside string literals never exceeds `maxNestingDepth`. -/
def wireDepthSafe (s : String) : Bool :=
  worstDepth s ≤ maxNestingDepth

/-- **Exclusion, definitionally.** The guard refuses a line IFF its maximum
    raw-wire nesting depth exceeds the pinned bound — nothing else about the
    line is consulted. -/
theorem wireDepthSafe_iff (s : String) :
    wireDepthSafe s = true ↔ worstDepth s ≤ maxNestingDepth := by
  simp [wireDepthSafe]

/-- A line with no `{` or `[` outside string literals is never refused: its
    worst depth is 0. Stated via the scan invariant that only openers raise
    `worst`. -/
theorem wireDepthSafe_of_worst_zero (s : String)
    (h : worstDepth s = 0) : wireDepthSafe s = true := by
  simp [wireDepthSafe, h]

/-! ## Elaboration-time controls (concrete strings are `#guard`-pinned; they
do not kernel-reduce on this toolchain). -/

-- Boundary: exactly 128 accepted, 129 refused.
#guard wireDepthSafe
  (String.ofList (List.replicate 128 '[' ++ List.replicate 128 ']'))
#guard !wireDepthSafe
  (String.ofList (List.replicate 129 '[' ++ List.replicate 129 ']'))

-- The recorded class-(c) vector shape (row 9), envelope-free:
#guard !wireDepthSafe
  (String.ofList (List.replicate 500 '[' ++ List.replicate 500 ']'))

-- Ordinary traffic untouched; brackets inside strings do not nest.
#guard wireDepthSafe "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"sql\":\"SELECT 1\"}}}"
#guard wireDepthSafe "{\"a\":\"[[[[[[ not nesting \\\" ]]]]\"}"
#guard worstDepth "{\"a\":[{\"b\":[1,2,[3]]}]}" == 5

end Host.NestingDepth
