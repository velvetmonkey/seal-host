/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser
import Seal.Classify
import Host.Action
import Host.JsonWire

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
  -- All presenter-controlled JSON crosses the one shared seven-guard boundary
  -- before `Json.parse`. Any failed guard is a hard, fail-closed refusal.
  if !Host.JsonWire.safe trimmed then
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
  simp [classifyLine, Host.JsonWire.safe, h]

/-! ### The other raw-wire guards, proven the same way

The theorem above existed for `wireNumbersSafe` alone. The duplicate-key,
Unicode-equivalent-key and significant-digit guards were added on 2026-07-24 and
2026-07-25 with TESTS but WITHOUT the matching theorems, so three of the four
pre-parse refusals were asserted only by tests while their sibling was proven.
The binary64-agreement guard follows the same pattern below.

Each is stated UNCONDITIONALLY on its own guard: an earlier guard failing also
yields `.refuse`, so the conclusion holds either way and the theorem need not
assume the earlier guards passed. That is the honest shape, because it says
"this line is refused" rather than "this line is refused provided nothing else
refused it first".
-/

/-- A raw line carrying a duplicate or escaped object key is refused, whatever
    the other guards say. This is the mediation bypass closed on 2026-07-24:
    `Json.parse` collapses duplicates last-wins while a downstream parser may
    read first-wins, a divergence no post-parse check can see. -/
theorem classifyLine_refuse_of_unsafe_keys (line : String)
    (h : Seal.JsonUtil.wireKeysSafe line.trimAscii.toString = false) :
    classifyLine line = .refuse := by
  simp [classifyLine, Host.JsonWire.safe, h]

/-- A raw line carrying two keys that are DISTINCT byte sequences but share a
    Unicode canonical identity is refused. A Foundation/Swift reader keys its
    dictionary on canonical equivalence, so those collide downstream while
    surviving the byte-level duplicate check. -/
theorem classifyLine_refuse_of_unsafe_unicode_keys (line : String)
    (h : Host.UnicodeKeys.wireKeysSafe line.trimAscii.toString = false) :
    classifyLine line = .refuse := by
  simp [classifyLine, Host.JsonWire.safe, h]

/-- A raw line whose mantissa exceeds the pinned significant-digit bound is
    refused, rather than parsed into a value that would diverge from the
    Stage-C i64 byte twin. -/
theorem classifyLine_refuse_of_unsafe_digits (line : String)
    (h : Seal.JsonUtil.wireDigitsSafe line.trimAscii.toString = false) :
    classifyLine line = .refuse := by
  simp [classifyLine, Host.JsonWire.safe, h]

/-- A raw line carrying an unquoted number outside binary64 round-trip
    agreement is refused before parsing, so the exact Lean reading can never
    be approved and forwarded to a downstream binary64 reader that disagrees. -/
theorem classifyLine_refuse_of_unsafe_agreement (line : String)
    (h : Seal.JsonUtil.wireNumbersAgreementSafe
      line.trimAscii.toString = false) :
    classifyLine line = .refuse := by
  simp [classifyLine, Host.JsonWire.safe, h]

/-- A raw line carrying an unpaired UTF-16 surrogate escape is refused: the
    substituted (U+FFFD) event is never judged, so the witnessed downstream
    decoupling of A2 class (a) has no forwarded line left to act on. -/
theorem classifyLine_refuse_of_unsafe_surrogates (line : String)
    (h : Host.SurrogateEscapes.wireSurrogatesSafe line.trimAscii.toString = false) :
    classifyLine line = .refuse := by
  simp [classifyLine, Host.JsonWire.safe, h]

/-- A raw line nesting deeper than the pinned downstream depth bound is
    refused — A2 class (c): never judged here while rejected there. -/
theorem classifyLine_refuse_of_unsafe_depth (line : String)
    (h : Host.NestingDepth.wireDepthSafe line.trimAscii.toString = false) :
    classifyLine line = .refuse := by
  simp [classifyLine, Host.JsonWire.safe, h]

end Host
