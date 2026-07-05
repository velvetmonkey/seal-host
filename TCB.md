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
- the config-signing trust root (`--pubkey`) and the existing Ed25519 leaf
  (`SealV2.ed25519Verify` / vendored TweetNaCl) that verifies the exact
  trusted-config payload bytes. This key is separate from approval-token keys.

## Shape 2 — Rust FFI host (`rust/`, G6)

**FFI grows the TCB. This is a deliberate, documented trade of assurance
for deployability.** Everything in Shape 1, plus:

- the C ABI seam: `lean.rs` marshalling (string in/out), Lean runtime
  initialisation ordering, refcount handling. Hardened (see RUST_BRIDGE.md):
  strings cross by exact byte length (interior-NUL safe), strict UTF-8, and
  every seam failure is a typed `SeamError` that can only refuse; Lean
  panics terminate the process (`lean_set_exit_on_panic` +
  `LEAN_ABORT_ON_PANIC`) instead of returning a routable default —
  empirically pinned by `rust/tests/panic_probe.rs`;
- the Rust transport (`main.rs`): it must actually route the bytes the way
  Lean's verdict says — a transport bug here can bypass mediation without
  falsifying any Lean theorem. Mitigation: the transport never parses wire
  lines for routing (Lean's `seal_host_classify`/`seal_host_step` is the
  single authority), forwards the client's bytes VERBATIM on allow, and
  never forwards on a broken seam. The kernel-output → action translation
  lives in `rust/src/route.rs` as total functions where `Forward` is
  unconstructible without an exact kernel verdict; the binary and the tests
  run the same functions, and the property is proptested plus pinned by the
  full-binary oracle in `rust/tests/host_path.rs`;
- the JSON marshalling of evidence across the seam (`serde_json` on the
  Rust side, `Lean.Json` on the Lean side);
- the approval back-channel providers (`providers.rs`): control-file,
  Ed25519 signed token (real cryptography over exact `ApprovalRecord` JSON
  payload bytes — `ed25519-dalek` is trusted), interactive TTY. Providers mint
  records; they never decide;
- A3 (`a3.rs`) plus the replay store (`replay_store.rs`): nonce replay set,
  SQLite durable nonce persistence for the Ed25519 signed-token production
  channel, TTL freshness, future-skew rejection, and the wall clock itself.
  SQLite runs with WAL and `synchronous=FULL`; the nonce insert is
  write-ahead before an approval reaches Lean. The Lean kernels prove
  properties *given* the `now` and the evidence the host hands them — A3 is
  exactly the host-side state and clock the proofs assume. The legacy
  control-file/interactive demo channels keep in-memory replay state only.
- the differential conformance harness (`rust/tests/differential.rs`) pins
  the residual wire-parser gap: property-based agreement between the Rust
  serde_json wire view and the Lean canonical parser on what gets mediated
  (including the full obfuscation disguise corpus), with zero bypass cases;
  the one known representational difference (numbers beyond f64: Lean
  mediates, serde can't parse — fail-closed direction) is pinned as its own
  test. This is evidence, not proof — stated as a trusted relationship,
  never claimed eliminated.

**Not mediated, loudly:** responses are relayed verbatim from the guarded
server to the client (request-effects are mediated, response egress is not),
and routing assumes a strict child parser (a lenient child that executes a
line strict JSON rejects is outside the contract). Both are limitations of
the claim — see "What seal does NOT claim" in RUST_BRIDGE.md; never restate
the guarantee as "nothing leaks".

## Unchanged by either shape

- The classifier-completeness, target-parser-equivalence, approval-origin
  and out-of-band-effects residuals from the mcp-seal threat model.
- Mediation is at the MCP boundary only; in-process orchestrator calls are
  out of scope by design.
