/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import Seal.Classify
import SealV2.Parser

/-!
Line-oriented measurement harness for the `canonicalL0` availability study.

Each argument names a UTF-8 text file containing one candidate wire message
per line.  The executable emits one TSV record per input line:

    file  1-based-line  v1  canonical  interesting  JSON-quoted-input

The final field is JSON-quoted so tabs, control characters, and non-ASCII
content remain unambiguous in the evidence file.
-/

open Lean

private structure Counts where
  total : Nat := 0
  v1Some : Nat := 0
  canonicalNone : Nat := 0
  interesting : Nat := 0

private def classifyPair (line : String) : Bool × Bool :=
  let trimmed := line.trimAscii.toString
  let v1 :=
    match Json.parse trimmed with
    | .error _ => false
    | .ok json => (Seal.toolsCall? json).isSome
  let canonical := (SealV2.parse trimmed).isSome
  (v1, canonical)

private def someNone (b : Bool) : String :=
  if b then "some" else "none"

private def boolText (b : Bool) : String :=
  if b then "true" else "false"

private def measureFile (path : String) : IO Counts := do
  let lines ← IO.FS.lines path
  let mut counts : Counts := {}
  for index in [:lines.size] do
    let line := lines[index]!
    let (v1, canonical) := classifyPair line
    let interesting := v1 && !canonical
    counts := {
      total := counts.total + 1
      v1Some := counts.v1Some + (if v1 then 1 else 0)
      canonicalNone := counts.canonicalNone + (if canonical then 0 else 1)
      interesting := counts.interesting + (if interesting then 1 else 0)
    }
    IO.println <| String.intercalate "\t" [
      path,
      toString (index + 1),
      someNone v1,
      someNone canonical,
      boolText interesting,
      (Json.str line).compress
    ]
  IO.eprintln <| String.intercalate "\t" [
    "SUMMARY",
    path,
    s!"total={counts.total}",
    s!"v1_some={counts.v1Some}",
    s!"canonical_none={counts.canonicalNone}",
    s!"interesting={counts.interesting}"
  ]
  pure counts

def main (args : List String) : IO UInt32 := do
  if args.isEmpty then
    IO.eprintln "usage: l0_liveness_measure <one-wire-message-per-line-file>..."
    pure 2
  else
    let mut aggregate : Counts := {}
    for path in args do
      let counts ← measureFile path
      aggregate := {
        total := aggregate.total + counts.total
        v1Some := aggregate.v1Some + counts.v1Some
        canonicalNone := aggregate.canonicalNone + counts.canonicalNone
        interesting := aggregate.interesting + counts.interesting
      }
    IO.eprintln <| String.intercalate "\t" [
      "AGGREGATE",
      s!"total={aggregate.total}",
      s!"v1_some={aggregate.v1Some}",
      s!"canonical_none={aggregate.canonicalNone}",
      s!"interesting={aggregate.interesting}"
    ]
    pure 0
