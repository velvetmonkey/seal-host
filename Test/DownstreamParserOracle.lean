/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Canonical

open Lean Host

private def observation (line : String) : Json :=
  match classifyLine line with
  | .passthrough =>
      Json.mkObj [("class", Json.str "Passthrough")]
  | .refuse =>
      Json.mkObj [("class", Json.str "Refuse")]
  | .act action =>
      Json.mkObj [
        ("class", Json.str "Act"),
        ("tool", Json.str action.tool),
        ("arguments", action.argsJson),
        ("arguments_compress", Json.str action.argsJson.compress)
      ]

def main (args : List String) : IO UInt32 := do
  let [path] := args
    | IO.eprintln "usage: downstream_parser_oracle <terminator-stripped-wire-file>"
      return 2
  let line ← IO.FS.readFile (System.FilePath.mk path)
  IO.println (observation line).compress
  return 0
