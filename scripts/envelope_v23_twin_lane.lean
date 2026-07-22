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

Stage B2: the corpus shape is the RECONCILED `seal.effect/v2` envelope
(mcp-seal-dev `4f39f20`) — killed seats gone (revocation_subject included),
expires_at/policy_version rescued and mandatory, and the F3 claim is
Option-encoded with a signed presence byte: `effect: null` and an all-empty
effect object are now DIFFERENT wire values.

Resolution: the manifest pins `mcp-seal` at `4f39f20` (Stage B2), so
`lake env lean` resolves `SealV2.EffectEnvelope` from the in-repo package
graph and `rust/tests/envelope_v23_twin.rs` runs this lane LIVE by default
(Ben's Stage B acceptance addition, 2026-07-22). `LEAN_PATH` can still be
pointed at an out-of-graph built mcp-seal-dev checkout via
`SEAL_V23_SPEC_LEAN_PATH`. The frozen expectation file remains as a fast
hermetic layer, anchored to the spec repo's `#guard_msgs` pin.
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
  -- PORTED 2026-07-25 from the `seal.effect/v1` shape to `seal.effect/v2`.
  --
  -- The Stage B2 reconciliation (mcp-seal-dev `4f39f20`) removed
  -- `idempotency_key`, `on_behalf_of`, `parent_capability_ref`,
  -- `revocation_subject`, `audience` and `causality_token` from
  -- `EffectEnvelope` entirely, while retaining mandatory `expires_at` and
  -- `policy_version`. This lane therefore reads exactly the signed v2 shape.
  --
  -- ONE SEMANTIC CHANGE, DELIBERATE, DO NOT "SIMPLIFY" IT BACK:
  -- under v1 `effect: null` and an all-empty effect object encoded IDENTICALLY
  -- (three empty frames), and the old comment here said so. Under v2 `effect`
  -- is `Option EffectClaim` with a signed presence byte: `none` encodes `0x00`,
  -- `some` encodes `0x01` followed by three frames. So null and `{"resource":
  -- "","action":"","args":""}` now produce DIFFERENT signed bytes. Mapping an
  -- empty object to `none` would silently re-merge two cases the v2 format
  -- deliberately separates, which is exactly the kind of collapse the presence
  -- byte exists to prevent. Null maps to `none`; any object maps to `some`,
  -- empty strings included.
  let effectJson ← e.getObjVal? "effect"
  let effect : Option EffectClaim ←
    if effectJson.isNull then pure none
    else do
      pure (some {
        resource := ← getStr effectJson "resource"
        action := ← getStr effectJson "action"
        args := ← getStr effectJson "args" })
  pure (authority, {
    keyId := ← getStr e "key_id"
    nonce := nonce
    issuedAt := ← getNat e "issued_at"
    expiresAt := ← getNat e "expires_at"
    line := line
    adapterType := ← getStr adapter "type"
    adapterVersion := ← getStr adapter "version"
    session := ← getStr e "session"
    policyVersion := ← getStr e "policy_version"
    effect := effect })

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
