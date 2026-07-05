/- SPDX-License-Identifier: Apache-2.0 -/
import Ffi

/-!
Conformance-bridge MODEL oracle.

Evaluates the REAL Lean decision core (`Ffi.modelStep`) in the Lean INTERPRETER
via a `#eval` under `lake env lean`. It is NOT the compiled `.so` and NOT a
reimplementation — it is the same Lean source the theorems govern, run through
Lean's own evaluator. The bridge diffs this against the compiled native artifact
to test that codegen preserves the proven decisions + audit bytes on the corpus.

R6 boundary: the interpreter cannot execute the `@[extern]` Ed25519 config
signature leaf, so MODEL initialises from a harness-trusted payload via
`modelInitFromTrustedPayload`. Native/WASM/deployed oracles still initialise
from the signed envelope and verify real signatures; R6 signature behavior is
covered by dedicated startup/config tests, not by this interpreted oracle.

Run (args + corpus via env/file so no `main`/CLI/stdin plumbing is needed —
`#eval` under `lake env lean` does not receive the process stdin):
  SEAL_CONF_PAYLOAD=<payload-file> \
    SEAL_CONF_CORPUS=<step-inputs.jsonl> SEAL_CONF_OUT=<outputs.jsonl> \
    lake env lean scripts/model_oracle.lean
-/

open Ffi

#eval show IO Unit from do
  let payloadPath := (← IO.getEnv "SEAL_CONF_PAYLOAD").getD ""
  let corpusPath := (← IO.getEnv "SEAL_CONF_CORPUS").getD ""
  let outPath := (← IO.getEnv "SEAL_CONF_OUT").getD ""
  let payload ← IO.FS.readFile payloadPath
  let initOut ← modelInitFromTrustedPayload payload
  if (initOut.splitOn "\"ok\":true").length == 1 then
    IO.eprintln s!"model_oracle: init failed: {initOut}"
  else
    let corpus ← IO.FS.readFile corpusPath
    let mut out : String := ""
    for line in corpus.splitOn "\n" do
      let input := line.trimAscii.toString
      if !input.isEmpty then
        out := out ++ (← modelStep input) ++ "\n"
    -- Write to a file (not stdout) so elaboration diagnostics can never
    -- contaminate the model output stream.
    IO.FS.writeFile outPath out
