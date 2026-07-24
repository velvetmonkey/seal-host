/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser
import Seal.Classify
import Seal.JsonUtil
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
  /-- Fail-closed refusal: a wire line the host will not parse because it
      carries an unsafe wire form. It is neither forwarded (never a bypass)
      nor passed through (never fail-open); `stepRoute` routes it to `.block`. -/
  | refuse

private def jsonId (json : Json) : Json :=
  (json.getObjVal? "id").toOption.getD Json.null

/-- Route a wire line. A `tools/call` (recognised by the V1 `Lean.Json` view,
    byte-identical to the mcp-seal host) is mediated; the SealV2 canonical
    parse is attached as `ast?` when it succeeds (audit + the byte form an
    approval commits to) and is `none` otherwise — it never blocks a call.
    Non-`tools/call` lines pass through untouched. -/
def classifyLine (line : String) : LineClass :=
  let trimmed := line.trimAscii.toString
  -- Fail closed BEFORE `Json.parse` on a pathological numeric literal: a wire
  -- number with a monster decimal exponent makes `Json.parse` evaluate
  -- `10^exponent` and abort (native `.so` + Lean interpreter) while the
  -- emscripten wasm degrades to passthrough — the Lane C divergence. Refusing
  -- here fails closed IDENTICALLY in every lane (all run this guard): the line
  -- is neither aborted on nor passed through. (Seal.JsonUtil.wireNumbersSafe.)
  if !Seal.JsonUtil.wireNumbersSafe trimmed then
    .refuse
  else
  -- Duplicate-key mediation gate: `Json.parse` collapses duplicate object
  -- keys last-wins, but a downstream tool parser may disagree (first-wins/
  -- reject) — a divergence no post-parse check can see. A line whose RAW
  -- text carries a duplicate (or escaped) object key is a HARD refusal.
  -- (Seal.JsonUtil.wireKeysSafe)
  if !Seal.JsonUtil.wireKeysSafe trimmed then
    .refuse
  else
  -- Stage-A pinned integer bound: >18 significant mantissa digits in an
  -- unquoted number would diverge from the Stage-C i64 byte twin; fail closed
  -- here instead. (Seal.JsonUtil.wireDigitsSafe)
  if !Seal.JsonUtil.wireDigitsSafe trimmed then
    .refuse
  else
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

/-- **Fail-closed classification.** A wire line the pre-parse number guard
    rejects (a pathological numeric literal) classifies as `.refuse` — NEVER
    `.passthrough` (so it is never passed through unmediated, the fail-OPEN the
    emscripten wasm exhibited) and never `.act` (it is not parsed, so
    `Json.parse` never evaluates `10^exponent` and never aborts, the native/
    interpreter fail-CLOSED crash). Both failure directions closed, identically
    in every lane. -/
theorem classifyLine_refuse_of_unsafe (line : String)
    (h : Seal.JsonUtil.wireNumbersSafe line.trimAscii.toString = false) :
    classifyLine line = .refuse := by
  simp only [classifyLine, h, Bool.not_false, if_true]

end Host
