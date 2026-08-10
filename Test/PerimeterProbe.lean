/- SPDX-License-Identifier: Apache-2.0 -/

import Host.PassthroughPerimeter

/-! # Passthrough-perimeter control (runnable SHOW)

The perimeter theorems (`Host/PassthroughPerimeter.lean`) are proved in the
kernel, but `Lean.Json.parse` is `partial` so the kernel cannot EVALUATE a
concrete line's class. This executable does — it runs the compiled router
and the widened `wrun` over a corpus and enforces, at runtime, the property
the brief asks for a control on:

* **RED** (exit non-zero) if any message INSIDE S (`inPerimeter`) is ever
  forwarded to the child undecided (a `fwdEv` in its widened trace) or is
  not decided at all (no `decideEv`). This is the invariant a regression in
  `classifyLine` would break.
* It also asserts the escaping witnesses (malformed JSON, BOM-prefixed JSON,
  `"TOOLS/CALL"`, the JSON-RPC batch array) ARE forwarded undecided — the
  live hole is real, not hypothetical — and that the monster-exponent line
  is refused. A regression that silently started mediating (or refusing)
  those would also go RED, so the control pins the perimeter from both
  sides.

Same corpus is build-gated by the `#guard`s in the perimeter module; this is
the standalone, exit-status form. -/

open Host.Perimeter Host.Channel

/-- Corpus: (label, line, expected class) where class ∈ {"S","R","escape"}. -/
def corpus : List (String × String × String) :=
  [ ("strict tools/call (S)", mediatedWitness, "S"),
    ("malformed JSON", malformedWitness, "escape"),
    ("BOM-prefixed JSON", bomWitness, "escape"),
    ("TOOLS/CALL spelling", misspelledWitness, "escape"),
    ("JSON-RPC batch array", batchWitness, "escape"),
    ("monster exponent", monsterExponentWitness, "R") ]

/-- The class a line actually lands in, by the byte predicates. -/
def actualClass (line : String) : String :=
  if inPerimeter line then "S"
  else if refusedClass line then "R"
  else "escape"

/-- Does the widened run forward this line child-bound (a `fwdEv`)? -/
def isForwarded (line : String) : Bool :=
  (wrun sealAdapter blockGate [line]).2.contains (WEv.fwdEv line)

/-- Does the widened run decide this line (a `decideEv`)? -/
def isDecided (line : String) : Bool :=
  (wrun sealAdapter blockGate [line]).2.any
    (fun e => match e with | WEv.decideEv _ _ => true | _ => false)

def main : IO UInt32 := do
  let mut red := 0
  for (label, line, want) in corpus do
    let got := actualClass line
    let fwd := isForwarded line
    let dec := isDecided line
    -- Class agreement:
    if got != want then
      IO.println s!"RED  {label}: class {got}, expected {want}"
      red := red + 1
    -- The load-bearing control: an S member must be DECIDED and NEVER
    -- forwarded undecided.
    if got == "S" then
      if fwd then
        IO.println s!"RED  {label}: message INSIDE S was FORWARDED undecided"
        red := red + 1
      else if !dec then
        IO.println s!"RED  {label}: message INSIDE S was not decided"
        red := red + 1
      else
        IO.println s!"ok   {label}: inside S, decided, not forwarded"
    -- The escaping side: the hole is real (forwarded, no decision).
    else if got == "escape" then
      if fwd && !dec then
        IO.println s!"ok   {label}: escapes S, forwarded undecided (the hole)"
      else
        IO.println s!"RED  {label}: expected forwarded-undecided, got fwd={fwd} dec={dec}"
        red := red + 1
    -- The refused side: blocked, not forwarded, not decided.
    else
      if !fwd && !dec then
        IO.println s!"ok   {label}: refused, not forwarded"
      else
        IO.println s!"RED  {label}: expected refused, got fwd={fwd} dec={dec}"
        red := red + 1
  if red == 0 then
    IO.println "perimeter control: GREEN — every S member mediated, every witnessed escape forwarded undecided"
    return 0
  else
    IO.println s!"perimeter control: RED — {red} violation(s)"
    return 1
