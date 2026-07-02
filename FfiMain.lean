/- SPDX-License-Identifier: Apache-2.0 -/
import Ffi

/-- Entry point for the `ffi_shared` exe target (linked with `-shared` to
    produce the self-contained `.so`). Kept in its own module so `Ffi` itself
    exports no root `main`, leaving the interpreter-run conformance oracle
    (`scripts/model_oracle.lean`) free to define its own. -/
def main : IO Unit := pure ()
