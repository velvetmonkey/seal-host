# seal-host

**PRIVATE. Do not push to any remote.**

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

- **G1 (this)**: host + `Kernel = {name, gates, decide}` + Safety Seal kernel
  (S) lifted from SealCore, behaviour unchanged; registry skeleton; signed
  epoch'd trusted-config loader (stub signature; Ed25519 lands in G6).
- G2–G7: see the build plan.

## Layout

- `Host/` — kernel interface (`Kernel.lean`), canonical parse service
  (`Canonical.lean`, SealV2-backed, fail-closed), trusted-config loader
  (`Config.lean`), registry + fail-closed combinator (`Registry.lean`), audit
  certs (`Audit.lean`), MCP stdio loop (`Main.lean`).
- `Kernels/` — `Safety.lean`: kernel S, a pure lift of the mcp-seal V1
  decision path (`SealCore.step` + `Seal.classifyToolCall`, unchanged).
- `Test/` — `Axioms.lean` (axiom gate: {propext, Classical.choice, Quot.sound}
  only), `HostUnit.lean` (pure unit tests).
- `test/integration/` — stdio regression suite ported from mcp-seal.
- `test/tools/sign_config.py` — wraps a config payload in the signed envelope.

## Build and test

```sh
lake build                                   # also runs Test/Axioms #print axioms
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
`Lean.ofReduceBool`); zero behaviour regression on the mcp-seal SealCore suite.
