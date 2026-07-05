# Trusted Computing Base

Seal keeps the proof boundary small, but deployment still has a TCB.

## Trusted for the proof story

- The Lean kernel and the stated axiom footprint.
- The theorem statements and axiom gates in the Lean repositories.
- The SHA-256 target-commitment assumption A-CR.

## Trusted for deployment

- The Rust, wasm, JavaScript, Node, browser, and emscripten toolchains that build and run artifacts.
- The operating system, filesystem permissions, process isolation, clocks, and networking.
- Approval providers, signing keys, control files, and operators.
- MCP hosts and downstream tools honoring the mediated path.
- CI and release processes that pin and distribute artifacts.

## Checked, not trusted blindly

- Artifact SHA-256 pins.
- Conformance bridge outputs over the corpus.
- Receipt re-derivation in the browser and CLI.
- Record-chain heads and tamper-evidence checks.
