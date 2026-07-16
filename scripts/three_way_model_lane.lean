/- SPDX-License-Identifier: Apache-2.0 -/
import Ffi

/-!
MODEL lane runner for the three-way differential (rust/tests/three_way.rs).

Evaluates the REAL Lean decision core (`Ffi.modelStep`) in the Lean INTERPRETER
via `#eval` under `lake env lean` — the same Lean source the theorems govern,
never a re-implementation. The harness diffs this against the compiled native
`.so` and the pinned emscripten wasm to test that both compiles preserve the
proven decisions + audit bytes on the generated corpus.

R6 boundary (same as scripts/model_oracle.lean): the interpreter cannot execute
the `@[extern]` Ed25519 config-signature leaf, so this lane initialises from the
harness-trusted payload via `modelInitFromTrustedPayload`. Native/wasm lanes
initialise from the signed envelope and verify real signatures.

Corpus protocol (shared with scripts/three_way_wasm_lane.mjs and the native
in-process lane): one compact-JSON step input per line; the literal control
line `#REINIT` re-initialises a FRESH session (steps are stateful) and emits NO
output line. Real step inputs always start with `{`.

Differences from scripts/model_oracle.lean (which is a pinned evidence producer
and stays untouched): `#REINIT` handling, and output is STREAMED to the out
file per line instead of accumulated (soak-scale corpora).

Run:
  SEAL_CONF_PAYLOAD=<payload-file> \
    SEAL_CONF_CORPUS=<step-inputs.jsonl> SEAL_CONF_OUT=<outputs.jsonl> \
    lake env lean scripts/three_way_model_lane.lean
-/

open Ffi

#eval show IO Unit from do
  let payloadPath := (← IO.getEnv "SEAL_CONF_PAYLOAD").getD ""
  let corpusPath := (← IO.getEnv "SEAL_CONF_CORPUS").getD ""
  let outPath := (← IO.getEnv "SEAL_CONF_OUT").getD ""
  let payload ← IO.FS.readFile payloadPath
  let initOk : IO Bool := do
    let initOut ← modelInitFromTrustedPayload payload
    if (initOut.splitOn "\"ok\":true").length == 1 then
      IO.eprintln s!"three_way_model_lane: init failed: {initOut}"
      pure false
    else
      pure true
  if !(← initOk) then
    return ()
  let corpus ← IO.FS.readFile corpusPath
  let h ← IO.FS.Handle.mk outPath IO.FS.Mode.write
  for line in corpus.splitOn "\n" do
    let input := line.trimAscii.toString
    if input.isEmpty then
      continue
    if input == "#REINIT" then
      if !(← initOk) then
        return ()
      continue
    h.putStr ((← modelStep input) ++ "\n")
  h.flush
