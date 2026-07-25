/- SPDX-License-Identifier: Apache-2.0 -/

import UnicodeBasic

/-!
# Unicode-canonical object-key identity on the raw wire

Swift's `String` equality is Unicode-canonical equality, and Foundation's JSON
readers materialise objects in `Dictionary<String, ...>`. Two literal JSON
keys can therefore be distinct to Lean but one key to a downstream Swift
child. This scanner rejects only an actual duplicate under canonical
equivalence. It does not reject a key merely for containing non-ASCII text.

Unicode canonical equivalence is equality after canonical decomposition and
canonical combining-class ordering (NFD). `UnicodeBasic` supplies complete
Unicode 17 canonical decompositions (including Hangul) and combining classes.
-/

namespace Host.UnicodeKeys

/-- Insert one combining character into an already canonically ordered
    reversed prefix. Reversed order is descending by combining class; inserting
    before an equal class preserves the original order after the final reverse.
    A class-zero starter is the boundary of the current combining sequence. -/
private def insertCombiningRev (c : Char) : List Char → List Char
  | [] => [c]
  | x :: xs =>
      let cc := Unicode.getCanonicalCombiningClass c
      let xcc := Unicode.getCanonicalCombiningClass x
      if xcc = 0 ∨ xcc ≤ cc then c :: x :: xs
      else x :: insertCombiningRev c xs

/-- Add one already-decomposed character to a reversed NFD accumulator. -/
private def addOrderedRev (rev : List Char) (c : Char) : List Char :=
  if Unicode.getCanonicalCombiningClass c = 0 then c :: rev
  else insertCombiningRev c rev

/-- Unicode Normalization Form D, sufficient and exact for testing canonical
    equivalence. `getCanonicalDecomposition` returns the complete canonical
    decomposition of one scalar; the second fold orders combining characters
    across scalar/decomposition boundaries. -/
def nfd (s : String) : String :=
  let rev := s.toList.foldl (fun acc c =>
    (Unicode.getCanonicalDecomposition c).toList.foldl addOrderedRev acc) []
  String.ofList rev.reverse

private inductive KeyFrame where
  | obj (seenNfd : List String) (expectKey : Bool)
  | arr

private structure KeyScan where
  stack : List KeyFrame := []
  inString : Bool := false
  escaped : Bool := false
  isKey : Bool := false
  buf : List Char := []
  bad : Bool := false

/-- Mirror the existing raw-wire key scanner, but store NFD key identities.
    Escaped keys are refused here too, although the preceding `wireKeysSafe`
    check already refuses them before this guard is reached. -/
private def keyScanStep (st : KeyScan) (c : Char) : KeyScan :=
  if st.bad then st
  else if st.inString then
    if st.escaped then { st with escaped := false }
    else if c == '\\' then
      if st.isKey then { st with bad := true }
      else { st with escaped := true }
    else if c == '"' then
      if st.isKey then
        let keyNfd := nfd (String.ofList st.buf.reverse)
        match st.stack with
        | .obj seen _ :: rest =>
            if seen.contains keyNfd then { st with bad := true }
            else { st with
              inString := false
              isKey := false
              buf := []
              stack := .obj (keyNfd :: seen) false :: rest }
        | _ => { st with bad := true }
      else { st with inString := false }
    else if st.isKey then { st with buf := c :: st.buf }
    else st
  else if c == '"' then
    let isKey := match st.stack with
      | .obj _ expectKey :: _ => expectKey
      | _ => false
    { st with inString := true, isKey, buf := [] }
  else if c == '{' then { st with stack := .obj [] true :: st.stack }
  else if c == '[' then { st with stack := .arr :: st.stack }
  else if c == '}' then
    match st.stack with
    | .obj _ _ :: rest => { st with stack := rest }
    | _ => { st with bad := true }
  else if c == ']' then
    match st.stack with
    | .arr :: rest => { st with stack := rest }
    | _ => { st with bad := true }
  else if c == ',' then
    match st.stack with
    | .obj seen _ :: rest => { st with stack := .obj seen true :: rest }
    | _ => st
  else
    st

/-- `true` exactly when the scanner sees no two literal object keys with the
    same Unicode canonical identity (and no escaped key/structural anomaly).
    Distinct non-ASCII keys remain accepted. -/
def wireKeysSafe (s : String) : Bool :=
  !(s.toList.foldl keyScanStep {}).bad

end Host.UnicodeKeys
