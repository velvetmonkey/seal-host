/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser
import Seal.Classify
import Host.Action

namespace Host

open Lean

/-- How the host treats one wire line.

    Routing (is this a `tools/call`?) follows the V1 host byte-for-byte:
    `Lean.Json.parse` + `Seal.toolsCall?`. The SealV2 verified parser is then a
    strictly fail-closed gate on top: a line V1 routing recognises as a
    `tools/call` but the canonical parser rejects is blocked rather than
    mediated. Everything that is not a `tools/call` passes through untouched,
    exactly as in V1. -/
inductive LineClass where
  | passthrough
  | act (a : CanonicalAction)

private def jsonId (json : Json) : Json :=
  (json.getObjVal? "id").toOption.getD Json.null

/-- Route a wire line. A `tools/call` (recognised by the V1 `Lean.Json` view,
    byte-identical to the mcp-seal host) is mediated; the SealV2 canonical
    parse is attached as `ast?` when it succeeds (audit + the byte form an
    approval commits to) and is `none` otherwise — it never blocks a call.
    Non-`tools/call` lines pass through untouched. -/
def classifyLine (line : String) : LineClass :=
  let trimmed := line.trimAscii.toString
  match Json.parse trimmed with
  | .error _ => .passthrough
  | .ok json =>
      match Seal.toolsCall? json with
      | none => .passthrough
      | some (toolName, toolArgs) =>
          .act {
            tool := toolName
            argsJson := toolArgs
            ast? := SealV2.parse trimmed
            raw := line
            requestId := jsonId json
          }

end Host
