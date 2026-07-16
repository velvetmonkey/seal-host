/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealCore
import Kernels.LinearCore
import Kernels.Calibration
import Consensus.Checker
import Seal.JsonUtil

/-!
Pure evidence parsers, shared by the Lean stdio host (`Host.Main` gatherers)
and the FFI surface (`Ffi`) so both transports feed kernels through exactly
the same parsing. All fail-closed: a line or record that fails to parse
simply does not exist (which can only shrink quorums/grants/windows, never
extend them).

Every parse is gated by `Seal.JsonUtil.wireNumbersSafe` first: an evidence
line carrying a pathological numeric literal (a monster decimal exponent that
would make `Json.parse` evaluate `10^exponent` and abort) is dropped, exactly
as an unparseable line is — fail-closed, never an abort, identical in every
compiled lane.
-/

namespace Host.Evidence

open Lean

/-- Parse an evidence line only if its numbers are safe; a pathological numeric
    literal drops the line (fail-closed) rather than aborting `Json.parse`. -/
private def parseSafe (line : String) : Option Json :=
  if Seal.JsonUtil.wireNumbersSafe line then (Json.parse line).toOption else none

private def nonEmptyLines (text : String) : List String :=
  text.splitOn "\n" |>.map (·.trimAscii.toString) |>.filter (!·.isEmpty)

/-- Votes file lines: `{"acceptor": <nat>, "value": "<string>"}`. -/
def parseVotesText (text : String) : Consensus.Checker.Votes :=
  nonEmptyLines text |>.filterMap fun line =>
    match parseSafe line with
    | none => none
    | some j => do
        let acceptor ← (j.getObjVal? "acceptor").toOption.bind (·.getNat?.toOption)
        let value ← (j.getObjVal? "value").toOption.bind (·.getStr?.toOption)
        some (acceptor, value)

/-- Grants file lines: `{"cap": "<id>", "uses": <nat>}`. -/
def parseGrantsText (text : String) : List LinearCore.LEvent :=
  nonEmptyLines text |>.filterMap fun line =>
    match parseSafe line with
    | none => none
    | some j => do
        let cap ← (j.getObjVal? "cap").toOption.bind (·.getStr?.toOption)
        let uses ← (j.getObjVal? "uses").toOption.bind (·.getNat?.toOption)
        some (LinearCore.LEvent.grant cap uses)

/-- Forecast records: `{"confidence": <num in [0,1]>, "outcome": 0|1}`. -/
def parseForecastsText (text : String) : List Kernels.ForecastRecord :=
  nonEmptyLines text |>.filterMap fun line =>
    match parseSafe line with
    | none => none
    | some j => do
        let confidence ← (j.getObjVal? "confidence").toOption.bind fun v =>
          match v with
          | .num n => some n.toFloat
          | _ => none
        let outcome ← (j.getObjVal? "outcome").toOption.bind (·.getNat?.toOption)
        if outcome == 0 || outcome == 1 then
          some { confidence, outcome := outcome == 1 }
        else
          none

private def jsonToNat? (j : Json) : Option Nat :=
  match j with
  | .num n => (toString n).toNat?
  | .str s => s.toNat?
  | _ => none

private def jsonToTargetHash? (j : Json) : Option SealCore.TargetHash :=
  match j with
  | .str s => SealCore.Sha256.Digest256.parseHex? s
  | _ => none

/-- Convert approval records (JSON array of `{"target": "<64 lowercase hex>", "issuedAt"?: <ms>}`)
    into SealCore approval events, mirroring `Seal.Channel.parseApprovalRecord`
    deadline semantics exactly: `deadline = min(issuedAt, now) + ttlMs`, so a
    record can only ever make a ticket expire SOONER than `now + ttlMs`. -/
def approvalEventsFromJson (j : Json) (now ttlMs : Nat) : List SealCore.Event :=
  match j.getArr? with
  | .error _ => []
  | .ok arr =>
      arr.toList.filterMap fun r => do
        let target ← (r.getObjVal? "target").toOption.bind jsonToTargetHash?
        let issuedAt := (r.getObjVal? "issuedAt").toOption.bind jsonToNat?
        let base := min (issuedAt.getD now) now
        some (SealCore.Event.approval target (base + ttlMs))

end Host.Evidence
