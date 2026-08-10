/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.EffectEnvelope

/-!
Live Phase-M Rust/Lean signed-shape lane. This file contains no expected
bytes: it runs the actual `SealV2.Effect.effectMessage` encoder and prints
named observations for the Rust integration test to compare directly.
-/

open SealV2
open SealV2.Effect

private def canonicalJson (raw : String) : String :=
  match Lean.Json.parse raw with
  | .ok value => value.compress
  | .error error => panic! s!"invalid metadata test JSON: {error}"

private def claim (metadata : MetaValue) (requestState : RequestState)
    (inputResponses : InputResponses) : EffectClaim :=
  {
    resource := "shell_exec"
    action := "run"
    args := "{\"command\":\"echo controlled\"}"
    metadata
    requestState
    inputResponses
  }

private def envelope (effectClaim : EffectClaim) : EffectEnvelope :=
  {
    keyId := "mrtr-control"
    nonce := ByteArray.mk (Array.range 32 |>.map UInt8.ofNat)
    issuedAt := 10
    expiresAt := 120
    line := "{}"
    adapterType := "mcp"
    adapterVersion := "2026-07-28"
    session := "mrtr-control"
    policyVersion := "mrtr-control-policy"
    effect := some effectClaim
  }

private def authority : ByteArray :=
  ByteArray.mk (Array.range 32 |>.map fun i => UInt8.ofNat (160 + i))

private def observations : List (String × EffectClaim) :=
  [
    ("requestState.left", claim
      .absent
      (.present "{\"opaque\":{\"ignoredSemantics\":[1,null,false],\"token\":\"state-a\"},\"sibling\":\"retained\"}")
      .absent),
    ("requestState.right", claim
      .absent
      (.present "{\"opaque\":{\"ignoredSemantics\":[1,null,false],\"token\":\"state-b\"},\"sibling\":\"retained\"}")
      .absent),
    ("inputResponses.left", claim .absent .absent
      (.present "{\"confirm\":{\"action\":\"accept\",\"content\":true},\"extension\":[\"one\",\"two\"],\"survey\":{\"score\":5}}")),
    ("inputResponses.right", claim .absent .absent
      (.present "{\"confirm\":{\"action\":\"decline\",\"content\":false},\"extension\":[\"one\",\"two\"],\"survey\":{\"score\":5}}")),
    ("metadata.left", claim (.present (canonicalJson "{\"trace\":\"meta-a\",\"attempt\":1}")) .absent .absent),
    ("metadata.right", claim (.present (canonicalJson "{\"trace\":\"meta-b\",\"attempt\":1}")) .absent .absent),
    ("metadata.absent", claim .absent .absent .absent),
    ("metadata.present-empty", claim (.present (canonicalJson "{}")) .absent .absent),
    ("metadata.present-null", claim (.present (canonicalJson "null")) .absent .absent),
    ("metadata.present-bool", claim (.present (canonicalJson "true")) .absent .absent),
    ("metadata.present-number", claim (.present (canonicalJson "42")) .absent .absent),
    ("metadata.present-string", claim (.present (canonicalJson "\"str\"")) .absent .absent),
    ("metadata.present-array", claim
      (.present (canonicalJson "[{\"z\":1,\"a\":2}]")) .absent .absent),
    ("metadata.with-requestState", claim
      (.present (canonicalJson "{\"trace\":\"co-present\"}"))
      (.present "{\"opaque\":\"state\"}") .absent),
    ("requestState.absent", claim .absent .absent .absent),
    ("requestState.present-empty", claim .absent (.present "{}") .absent),
    ("requestState.present-null", claim .absent (.present "null") .absent),
    ("inputResponses.absent", claim .absent .absent .absent),
    ("inputResponses.present-empty", claim .absent .absent (.present "{}")),
    ("inputResponses.present-null", claim .absent .absent (.present "null")),
    ("both.present", claim
      .absent
      (.present "{\"opaque\":\"state\"}")
      (.present "{\"confirm\":{\"action\":\"accept\"},\"extension\":{\"retained\":true}}"))
  ]

def main : IO Unit := do
  for (name, effectClaim) in observations do
    IO.println s!"{name} {bytesToHex (effectMessage authority (envelope effectClaim))}"
