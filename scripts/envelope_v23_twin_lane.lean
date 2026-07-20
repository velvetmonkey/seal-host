/- SPDX-License-Identifier: Apache-2.0 -/
import Lean.Data.Json
import SealV2.EffectEnvelope

/-!
V2.3 twin lane: encode every vector in the shared corpus
(`rust/tests/envelope_v23_twin.rs` reads the same file) with the REAL Lean
spec encoder `SealV2.Effect.effectMessage` and print one lowercase hex line
per vector, in corpus order. Any divergence from the Rust encoder is a
byte-twin break.

Run: `lean --run scripts/envelope_v23_twin_lane.lean rust/tests/vectors/envelope_v23_twin_corpus.json`

IMPORT CAVEAT (honest): seal-host's pinned `mcp-seal` package rev predates
`SealV2.EffectEnvelope`, so `lake env lean` cannot resolve this import from
the in-repo package graph today. Until the pin advances past mcp-seal-dev
`9452f32`, this lane needs `LEAN_PATH` pointing at a built mcp-seal-dev
checkout (and its batteries/aesop packages). The Rust side therefore also
checks a frozen Lean-generated expectation file so CI has coverage without
this lane; see `rust/tests/envelope_v23_twin.rs` for the full story.
-/

open Lean SealV2.Effect

def hexVal (c : Char) : Option Nat :=
  if '0' ≤ c ∧ c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c ∧ c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else none

def hexToBytes (s : String) : Option ByteArray := Id.run do
  let cs := s.toList.toArray
  if cs.size % 2 ≠ 0 then return none
  let mut out := ByteArray.empty
  let mut i := 0
  while h : i < cs.size do
    let some hi := hexVal cs[i] | return none
    let some lo := hexVal cs[i + 1]! | return none
    out := out.push (UInt8.ofNat (hi * 16 + lo))
    i := i + 2
  return some out

def getStr (j : Json) (k : String) : Except String String := do
  (← j.getObjVal? k).getStr?

def getNat (j : Json) (k : String) : Except String Nat := do
  (← j.getObjVal? k).getNat?

def envelopeOfJson (v : Json) : Except String (ByteArray × EffectEnvelope) := do
  let authorityHex ← getStr v "authority_hex"
  let some authority := hexToBytes authorityHex
    | .error "bad authority_hex"
  let line ← getStr v "line"
  let e ← v.getObjVal? "envelope"
  let some nonce := hexToBytes (← getStr e "nonce_hex")
    | .error "bad nonce_hex"
  let adapter ← e.getObjVal? "adapter"
  -- `effect: null` and an all-empty effect object are the same wire value:
  -- three empty frames (the Rust encoder's `Option` is JSON surface only).
  let effectJson ← e.getObjVal? "effect"
  let (res, act, args) ←
    if effectJson.isNull then pure ("", "", "")
    else do
      pure (← getStr effectJson "resource", ← getStr effectJson "action",
        ← getStr effectJson "args")
  pure (authority, {
    keyId := ← getStr e "key_id"
    nonce := nonce
    issuedAt := ← getNat e "issued_at"
    line := line
    adapterType := ← getStr adapter "type"
    adapterVersion := ← getStr adapter "version"
    session := ← getStr e "session"
    effectResource := res
    effectAction := act
    effectArgs := args
    idempotencyKey := ← getStr e "idempotency_key"
    policyVersion := ← getStr e "policy_version"
    onBehalfOf := ← getStr e "on_behalf_of"
    parentCapabilityRef := ← getStr e "parent_capability_ref"
    revocationSubject := ← getStr e "revocation_subject"
    audience := ← getStr e "audience"
    causalityToken := ← getStr e "causality_token"
    expiresAt := ← getNat e "expires_at" })

def main (argv : List String) : IO UInt32 := do
  let [path] := argv
    | IO.eprintln "usage: lean --run envelope_v23_twin_lane.lean <corpus.json>"
      return 2
  let text ← IO.FS.readFile path
  let corpus ← match Json.parse text with
    | .ok j => pure j
    | .error e => IO.eprintln s!"corpus is not JSON: {e}"; return 1
  let vectors ← match corpus.getObjVal? "vectors" >>= Json.getArr? with
    | .ok a => pure a
    | .error e => IO.eprintln s!"corpus has no vectors array: {e}"; return 1
  for v in vectors do
    match envelopeOfJson v with
    | .ok (authority, e) => IO.println (bytesToHex (effectMessage authority e))
    | .error err =>
        let name := ((v.getObjVal? "name" >>= Json.getStr?).toOption).getD "?"
        IO.eprintln s!"vector {name}: {err}"
        return 1
  return 0
