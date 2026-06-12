/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser
import Seal.Policy
import Seal.JsonUtil
import Kernels.Temporal

namespace Host

open Lean
open Seal.JsonUtil

/-- The host's one trusted config: signed, epoch-stamped, one section per
    kernel. `safety` is the V1 policy shape (kernel S); `temporal` is the LTL
    safety-policy list (kernel T), absent section = no temporal constraints. -/
structure TrustedConfig where
  epoch : Nat
  safety : Seal.Policy
  temporal : List Kernels.TemporalPolicy

private def parseStringList (json : Json) : Except String (List String) := do
  let arr ← json.getArr?
  arr.toList.mapM (fun j => j.getStr?)

private def parseTemporalPolicy (json : Json) : Except String Kernels.TemporalPolicy := do
  let name ← getObjString json "name"
  let kind ← getObjString json "type"
  if kind != "no_after" then
    throw s!"unsupported temporal policy type: {kind}"
  let trigger ← parseStringList (← json.getObjVal? "trigger")
  let forbidden ← parseStringList (← json.getObjVal? "forbidden")
  pure { name, trigger, forbidden }

def parseTemporalSection (json : Json) : Except String (List Kernels.TemporalPolicy) := do
  match ← getObjValOpt json "temporal" with
  | none => pure []
  | some section_ =>
      let policiesJson ← (← section_.getObjVal? "policies").getArr?
      policiesJson.toList.mapM parseTemporalPolicy

/-- Stub signature scheme, byte-compatible with the SealV2 approval stub
    (`SealV2.Validation.verifySignature`): the signature commits to the exact
    payload bytes. G6 swaps this for real Ed25519 over the same bytes. -/
def verifyConfigSignature (publicKey payload signature : String) : Bool :=
  signature == s!"stub-ed25519:{publicKey}:{payload}"

/-- Pure, fail-closed config check. The payload must
    1. carry a signature binding it to the trusted public key,
    2. be accepted by the SealV2 verified canonical parser (one canonical
       byte-form, no parser differential on the trusted input), and
    3. parse to an epoch ≥ 1 plus a well-formed `safety` policy section.
    The epoch lives INSIDE the signed payload, so it cannot be tampered with
    independently of the signature. Any failure is an error — never a default. -/
def checkTrustedConfig (publicKey payload signature : String) :
    Except String TrustedConfig := do
  if !verifyConfigSignature publicKey payload signature then
    throw "config signature verification failed"
  if (SealV2.parse payload).isNone then
    throw "config payload is not canonical (SealV2 parse rejected it)"
  let json ← Json.parse payload
  let epoch ← (← json.getObjVal? "epoch").getNat?
  if epoch == 0 then
    throw "config epoch must be ≥ 1"
  let safetyJson ← json.getObjVal? "safety"
  let safety ← Seal.parsePolicyJson safetyJson
  let temporal ← parseTemporalSection json
  pure { epoch, safety, temporal }

/-- Load and verify the signed config envelope:
    `{"payload": "<canonical JSON>", "signature": "stub-ed25519:<pk>:<payload>"}`.
    Fail-closed: any failure aborts the host before it touches stdio. -/
def loadTrustedConfig (path : System.FilePath) (publicKey : String) :
    IO TrustedConfig := do
  let text ← IO.FS.readFile path
  let result : Except String TrustedConfig := do
    let envelope ← Json.parse text
    let payload ← getObjString envelope "payload"
    let signature ← getObjString envelope "signature"
    checkTrustedConfig publicKey payload signature
  match result with
  | .ok config => pure config
  | .error err => throw <| IO.userError s!"trusted config rejected: {err}"

end Host
