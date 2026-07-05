/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser
import SealV2.Crypto
import Seal.Policy
import Seal.JsonUtil
import Kernels.Temporal
import Kernels.Consensus
import Kernels.Convergence
import Kernels.Calibration
import Kernels.Linear
import Kernels.Budget

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
  consensus : Option Kernels.ConsensusConfig
  convergence : Kernels.ConvergenceConfig
  calibration : Option Kernels.CalibrationConfig
  linear : Option Kernels.LinearConfig
  budget : Kernels.BudgetConfig

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

def parseConsensusSection (json : Json) : Except String (Option Kernels.ConsensusConfig) := do
  match ← getObjValOpt json "consensus" with
  | none => pure none
  | some section_ =>
      let rosterJson ← (← section_.getObjVal? "roster").getArr?
      let roster ← rosterJson.toList.mapM (fun j => j.getNat?)
      let votesFile := System.FilePath.mk (← getObjString section_ "votes_file")
      let highStakes ← parseStringList (← section_.getObjVal? "high_stakes")
      pure (some { roster, votesFile, highStakes })

def parseConvergenceSection (json : Json) : Except String Kernels.ConvergenceConfig := do
  match ← getObjValOpt json "convergence" with
  | none => pure []
  | some section_ =>
      let toolsJson ← (← section_.getObjVal? "tools").getArr?
      toolsJson.toList.mapM fun j => do
        let tool ← getObjString j "tool"
        let opArg ← getObjString j "op_arg"
        pure { tool, opArg := splitPath opArg : Kernels.ReplicatedTool }

def parseCalibrationSection (json : Json) :
    Except String (Option Kernels.CalibrationConfig) := do
  match ← getObjValOpt json "calibration" with
  | none => pure none
  | some section_ =>
      let enabled ← match ← getObjValOpt section_ "enabled" with
        | some v => v.getBool?
        | none => pure false
      let deltaNum ← (← section_.getObjVal? "delta_num").getNat?
      let deltaDen ← (← section_.getObjVal? "delta_den").getNat?
      if deltaNum == 0 || deltaDen ≤ deltaNum then
        throw "calibration delta must satisfy 0 < delta < 1"
      let minSamples ← (← section_.getObjVal? "min_samples").getNat?
      let recordsFile ← getObjString section_ "records_file"
      let gatedTools ← parseStringList (← section_.getObjVal? "gated_tools")
      pure (some { enabled, deltaNum, deltaDen, minSamples, gatedTools,
                   recordsFile := System.FilePath.mk recordsFile })

def parseLinearSection (json : Json) : Except String (Option Kernels.LinearConfig) := do
  match ← getObjValOpt json "linear" with
  | none => pure none
  | some section_ =>
      let grantsFile := System.FilePath.mk (← getObjString section_ "grants_file")
      let toolsJson ← (← section_.getObjVal? "tools").getArr?
      let tools ← toolsJson.toList.mapM fun j => do
        let tool ← getObjString j "tool"
        let capArg ← getObjString j "cap_arg"
        pure { tool, capArg := splitPath capArg : Kernels.LinearTool }
      pure (some { grantsFile, tools })

def parseBudgetSection (json : Json) : Except String Kernels.BudgetConfig := do
  match ← getObjValOpt json "budget" with
  | none => pure []
  | some section_ =>
      let budgetsJson ← (← section_.getObjVal? "budgets").getArr?
      budgetsJson.toList.mapM fun j => do
        let name ← getObjString j "name"
        let cap ← (← j.getObjVal? "cap").getNat?
        let tools ← parseStringList (← j.getObjVal? "tools")
        let costArg ← match ← getObjValOpt j "cost_arg" with
          | some v => pure (some (splitPath (← v.getStr?)))
          | none => pure none
        pure { name, cap, tools, costArg : Kernels.BudgetSpec }

/-- Real Ed25519 verification for the trusted config envelope. The config
    signing key is a startup trust root, separate from approval-token keys.
    The signature covers the exact `payload` string bytes carried by the
    envelope; no normalized or reserialized substitute is verified. -/
def verifyConfigSignature (publicKey payload signature : String) : Bool :=
  match SealV2.hexDecode? publicKey, SealV2.hexDecode? signature with
  | some pk, some sig => SealV2.ed25519Verify pk payload.toUTF8 sig
  | _, _ => false

/-- Parse the already-authenticated config payload. This does NOT verify
    signatures and is therefore not a trust boundary by itself; real loaders
    must call `checkTrustedConfig` / `checkEnvelope` first. It is factored out
    so the conformance model oracle can initialise from a harness-trusted
    payload without executing the `@[extern]` Ed25519 leaf in the interpreter. -/
def parseCanonicalConfigPayload (payload : String) :
    Except String TrustedConfig := do
  if (SealV2.parse payload).isNone then
    throw "config payload is not canonical (SealV2 parse rejected it)"
  let json ← Json.parse payload
  let epoch ← (← json.getObjVal? "epoch").getNat?
  if epoch == 0 then
    throw "config epoch must be ≥ 1"
  let safetyJson ← json.getObjVal? "safety"
  let safety ← Seal.parsePolicyJson safetyJson
  let temporal ← parseTemporalSection json
  let consensus ← parseConsensusSection json
  let convergence ← parseConvergenceSection json
  let calibration ← parseCalibrationSection json
  let linear ← parseLinearSection json
  let budget ← parseBudgetSection json
  pure { epoch, safety, temporal, consensus, convergence, calibration, linear, budget }

/-- Pure, fail-closed config check. The payload must
    1. carry a real Ed25519 signature binding it to the trusted public key,
    2. be accepted by the SealV2 verified canonical parser (one canonical
       byte-form, no parser differential on the trusted input), and
    3. parse to an epoch ≥ 1 plus a well-formed `safety` policy section.
    The epoch lives INSIDE the signed payload, so it cannot be tampered with
    independently of the signature. Any failure is an error — never a default. -/
def checkTrustedConfig (publicKey payload signature : String) :
    Except String TrustedConfig := do
  let config ← parseCanonicalConfigPayload payload
  if !verifyConfigSignature publicKey payload signature then
    throw "config signature verification failed"
  pure config

/-- Pure envelope check:
    `{"payload": "<canonical JSON>", "signature": "<ed25519 signature hex>"}`.
    The config public key is a startup trust root and is not read from the
    envelope it authenticates. -/
def checkEnvelope (text publicKey : String) : Except String TrustedConfig := do
  let envelope ← Json.parse text
  let payload ← getObjString envelope "payload"
  let signature ← getObjString envelope "signature"
  checkTrustedConfig publicKey payload signature

/-- Load and verify the signed config envelope. Fail-closed: any failure
    aborts the host before it touches stdio. -/
def loadTrustedConfig (path : System.FilePath) (publicKey : String) :
    IO TrustedConfig := do
  let text ← IO.FS.readFile path
  match checkEnvelope text publicKey with
  | .ok config => pure config
  | .error err => throw <| IO.userError s!"trusted config rejected: {err}"

end Host
