/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser
import Seal.Classify
import Host.Action

namespace Host

open Lean

/-- How the host treats one wire line.

    Routing (is this a `tools/call`?) follows the V1 host byte-for-byte:
    `Lean.Json.parse` + `Seal.toolsCall?`. This host runs the COMPATIBLE
    profile: the SealV2 canonical parse is attached as `ast?` for audit only
    and does NOT gate the call. A `tools/call` the canonical parser rejects is
    still mediated on the V1 `Lean.Json` view with `ast? = none`; it is never
    silently blocked on canonical-reject. (A strict `canonical-l0` profile, in
    which canonical-reject BLOCKS and every forward carries a canonical parse
    witness, is a separate mode tracked in `CLAIMS.md` and
    `SEAL-MEDIATION-PROFILE-L0`; it is not implemented in this file.)
    Everything that is not a `tools/call` passes through untouched, exactly as
    in V1. -/
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
