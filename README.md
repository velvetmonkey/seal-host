# seal-host

**PRIVATE pre-award — do not push to any public remote yet.** Per the ARIA Track 1 bid commitment, the specification layer (kernel theorem statements, the composition theorem statement, `THREAT_MODEL`, `TCB`) is to be published openly ahead of submission and the full proof sources at grant kickoff; only the implementation (host, registry, harness) is retained under the 12-month commercialisation clawback.

Verified Agent Kernels: one fail-closed MCP host, many verified kernels. Each
kernel is a verified `decide()` grounded in a sorry-free, axiom-clean Lean
library. The host owns MCP stdio transport, the SealV2 canonical parser
service, a signed epoch-stamped trusted config, and a kernel registry that
combines verdicts fail-closed (allow iff every gating kernel allows).

Spec: `tech/projects/seal/seal-host-kernel-buildout-plan.md` (vault).
Public math bricks are consumed as Lake dependencies (mcp-seal, crdt-lean,
temporal-logic-lean, consensus-lean, calibration-lean); the novel IP — host,
kernel interface, registry, composition theorem, harness — lives only here.

## Status

- **G1**: host + `Kernel = {name, gates, decide}` + Safety Seal kernel
  (S) lifted from SealCore, behaviour unchanged; registry skeleton; signed
  epoch'd trusted-config loader (stub signature; Ed25519 lands in G6).
- **G2–G5**: kernels T (temporal monitor), C (consensus quorum), V
  (convergence), K (calibration, experimental flag), L (linear capability
  accounting, proven in-repo), B (budget/rate, proven in-repo); composition
  theorem (`Host/Composition.lean`).
- **G6 (this)**: Rust FFI host (`rust/`) — stdio transport + swappable
  approval back-channel (control-file / Ed25519 signed token / interactive
  TTY) + A3 nonce/replay/TTL, calling the Lean verified core through
  `libsealffi.so` (`scripts/build_ffi_so.sh`); property-based differential
  conformance harness on the seam. The deployed target commitment is SHA-256;
  FNV `auditHashParts` remains only a per-cert/demo hash, not the target or
  record commitment. **FFI grows the TCB — see
  `TCB.md`.**
- **W2 closeout**: single-request non-interference
  (`Host.NonInterference.observe_noninterference`), cross-session replay
  isolation (`Host.ReplayIsolation.replay_isolation_trace`), and deployed
  adapter O1/O2 + non-vacuity (`Host.Channel.deployed_O1`,
  `Host.Channel.deployed_O2`, `Host.Channel.deployed_nonvacuous`) are landed
  as Lean model theorems. Binary correspondence remains the finite-corpus
  conformance bridge, not a theorem.
- G7: see the build plan.

## Rust host build

```sh
lake build Ffi               # compile the Lean core
scripts/build_ffi_so.sh      # link libsealffi.so (self-contained + leanshared)
cd rust && cargo build && cargo test
python3 test/integration/test_host_rs.py
.lake/build/bin/../../rust/target/debug/seal-host-rs \
  --config trusted.json --pubkey <pk> \
  [--channel file|ed25519|interactive] -- <server-cmd> ...
```

## Layout

- `Host/` — kernel interface (`Kernel.lean`), canonical parse service
  (`Canonical.lean`, SealV2-backed, fail-closed), trusted-config loader
  (`Config.lean`), registry + fail-closed combinator (`Registry.lean`), audit
  certs (`Audit.lean`), MCP stdio loop (`Main.lean`).
- `Kernels/` — the seven kernel modules shipped in-repo: `Safety.lean` (kernel S,
  a pure lift of the mcp-seal V1 decision path — `SealCore.step` +
  `Seal.classifyToolCall`, unchanged), `Temporal.lean`,
  `Consensus.lean`/`ConsensusBytes.lean`,
  `Convergence.lean`/`ConvergencePotential.lean`, `Calibration.lean`,
  `Linear.lean`/`LinearCore.lean`, and `Budget.lean`/`BudgetCore.lean`.
- `Test/` — `Axioms.lean` (axiom gate: {propext, Classical.choice, Quot.sound}
  only), `HostUnit.lean` (pure unit tests).
- `test/integration/` — stdio regression suite ported from mcp-seal.
- `test/tools/sign_config.py` — wraps a config payload in the signed envelope.

## Build and test

```sh
lake build                                   # also runs Test/Axioms #print axioms
lake exe axiom_check
lake exe host_unit_tests
python3 test/integration/test_host.py
```

Run the host:

```sh
python3 test/tools/sign_config.py payload.json <pubkey> > trusted.json
.lake/build/bin/seal-host --config trusted.json --pubkey <pubkey> -- <server-cmd> ...
```

## Gate (every goal)

`lake build` clean; `#print axioms` on every decision-bearing def and imported
theorem = `{propext, Classical.choice, Quot.sound}` only (no `sorryAx`, no
`Lean.ofReduceBool`); CI runs `lake build`, `lake exe axiom_check`, and greps the
axiom-check output for those forbidden axioms; zero behaviour regression on the
mcp-seal SealCore suite.
