/- SPDX-License-Identifier: Apache-2.0 -/

import SealV2.EffectEnvelope

/-!
Live Phase-M Rust/Lean signed-shape lane. This file contains no expected
bytes: it runs the actual `SealV2.Effect.effectMessage` encoder and prints
named observations for the Rust integration test to compare directly.
-/

open SealV2
open SealV2.Effect

private def claim (requestState : RequestState)
    (inputResponses : InputResponses) : EffectClaim :=
  {
    resource := "shell_exec"
    action := "run"
    args := "{\"command\":\"echo controlled\"}"
    metadata := .absent
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
      (.present "{\"opaque\":{\"ignoredSemantics\":[1,null,false],\"token\":\"state-a\"},\"sibling\":\"retained\"}")
      .absent),
    ("requestState.right", claim
      (.present "{\"opaque\":{\"ignoredSemantics\":[1,null,false],\"token\":\"state-b\"},\"sibling\":\"retained\"}")
      .absent),
    ("inputResponses.left", claim .absent
      (.present "{\"confirm\":{\"action\":\"accept\",\"content\":true},\"extension\":[\"one\",\"two\"],\"survey\":{\"score\":5}}")),
    ("inputResponses.right", claim .absent
      (.present "{\"confirm\":{\"action\":\"decline\",\"content\":false},\"extension\":[\"one\",\"two\"],\"survey\":{\"score\":5}}")),
    ("requestState.absent", claim .absent .absent),
    ("requestState.present-empty", claim (.present "{}") .absent),
    ("requestState.present-null", claim (.present "null") .absent),
    ("inputResponses.absent", claim .absent .absent),
    ("inputResponses.present-empty", claim .absent (.present "{}")),
    ("inputResponses.present-null", claim .absent (.present "null")),
    ("both.present", claim
      (.present "{\"opaque\":\"state\"}")
      (.present "{\"confirm\":{\"action\":\"accept\"},\"extension\":{\"retained\":true}}"))
  ]

def main : IO Unit := do
  for (name, effectClaim) in observations do
    IO.println s!"{name} {bytesToHex (effectMessage authority (envelope effectClaim))}"
