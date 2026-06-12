# Trusted Computing Base

What must be correct (beyond the Lean kernel checking the proofs) for the
seal-host guarantees to hold, per deployment shape.

## Shape 1 — Lean stdio sidecar (`.lake/build/bin/seal-host`)

The cleanest assurance story. Trusted:

- the Lean compiler + runtime (compiles the proven `decide` we run);
- the thin IO layer in `Host/Main.lean` (stdio relay, file reads, clock) —
  every decision it routes on comes from proven code;
- OS file permissions on the trusted config, approval/votes/grants/forecast
  files (origin assumption A-origin);
- the stub config signature (G1–G5): commits to exact bytes but is not
  cryptographic until the Ed25519 swap.

## Shape 2 — Rust FFI host (`rust/`, G6)

**FFI grows the TCB. This is a deliberate, documented trade of assurance
for deployability.** Everything in Shape 1, plus:

- the C ABI seam: `lean.rs` marshalling (string in/out), Lean runtime
  initialisation ordering, refcount handling;
- the Rust transport (`main.rs`): it must actually route the bytes the way
  Lean's verdict says — a transport bug here can bypass mediation without
  falsifying any Lean theorem. Mitigation: the transport never parses wire
  lines for routing (Lean's `seal_host_classify`/`seal_host_step` is the
  single authority) and never forwards on a broken seam (fail-closed on any
  unparseable step output);
- the JSON marshalling of evidence across the seam (`serde_json` on the
  Rust side, `Lean.Json` on the Lean side);
- the approval back-channel providers (`providers.rs`): control-file,
  Ed25519 signed token (real cryptography — `ed25519-dalek` is trusted),
  interactive TTY. Providers mint records; they never decide;
- A3 (`a3.rs`): nonce replay set, TTL freshness, future-skew rejection, and
  the wall clock itself. The Lean kernels prove properties *given* the `now`
  and the evidence the host hands them — A3 is exactly the host-side state
  and clock the proofs assume;
- the differential conformance harness (`rust/tests/differential.rs`) pins
  the residual wire-parser gap: property-based agreement between the Rust
  serde_json wire view and the Lean canonical parser on what gets mediated,
  with zero bypass cases. This is evidence, not proof — stated as a trusted
  relationship, never claimed eliminated.

## Unchanged by either shape

- The classifier-completeness, target-parser-equivalence, approval-origin
  and out-of-band-effects residuals from the mcp-seal threat model.
- Mediation is at the MCP boundary only; in-process orchestrator calls are
  out of scope by design.
