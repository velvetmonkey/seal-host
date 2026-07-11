# seal-host

The deployable MCP host that puts the proven Seal rulebook between an agent and real tools. **Role:** The guard at the door.

![Lean](https://img.shields.io/badge/Lean-4.28.0-blue)
![Rust](https://img.shields.io/badge/Rust-host-orange)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

<!-- truthbox:begin -->
> **Runtime profile: `compatible`.** Strict `canonical-l0` is proved and modelled, not the deployed route yet.
> **Claim:** policy-covered request-effects recognised by the compatible MCP boundary require a matching live human approval and an allowing Lean kernel verdict; seam failures block; every decision emits replayable evidence.
> **Non-claim:** the deployed host is not proved end to end, and canonical parser rejection is not currently the runtime gate. Host `ApprovalRecord` tokens are a separate signed channel from the v2 canonical approval tuple.
<!-- truthbox:end -->
> Map: [EVALUATOR-START.md](https://github.com/velvetmonkey/seal/blob/main/EVALUATOR-START.md) · profile detail: [PROFILE.md](PROFILE.md).

This is the thing you actually run. An agent's tool calls pass through seal-host; the guarded ones stop at the door until a human has approved that exact request, and every decision walks away with a receipt. The Lean kernel decides what's allowed; the Rust host you deploy runs that decision byte-for-byte and records it. The proof says what the guard must do. The conformance tests show this host does exactly that.

## What happens when an agent tries to use a production tool

The Rust host receives MCP traffic and forwards ordinary traffic unchanged. When a guarded `tools/call` arrives, it gathers approval records, filters them for freshness and replay, and calls the Lean kernel through the FFI surface. A matching approval routes the original call forward. No match returns a JSON-RPC error before the downstream tool sees anything.

The host also writes records. The production record chain uses SHA-256. Per-kernel `certHash` values remain the legacy UInt64 audit seals; they are not the target commitment and they are not the record-chain commitment.

## For evaluators and auditors

Seal's proof story is intentionally narrow. The Lean theorems cover the mediation kernel and selected model properties. The binaries and browser artifacts are connected to that proof by reproducible conformance tests, not by a theorem about every compiled instruction.

Start with the family [claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) (one table: proven / tested / assumed / not claimed), then [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md) for theorem names and file locations, [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the byte-identity claim, and [docs/TCB.md](docs/TCB.md) for what remains trusted.

Mandatory non-claims (canonical copy: [docs/LIMITATIONS.md](docs/LIMITATIONS.md)):

<!-- claims:begin -->
- Seal proves properties of the mediation KERNEL, not of the whole deployed system.
- Seal does NOT prove SHA-256 collision resistance in Lean; it is a named, scoped cryptographic assumption (A-CR).
- The deployed Rust / wasm / JS are NOT proven bug-free; they are tied to the proof by byte-exact conformance testing over a corpus, not for every possible input.
- Seal guarantees AUTHORIZATION match, not INTENT match: if a human approves a malicious-but-valid request, Seal will execute it.
- Seal does NOT prevent compromise of hosts, browsers, build systems, keys, operators, or downstream tools.
- Seal's audit chain is tamper-EVIDENT, not tamper-IMPOSSIBLE.
- Seal does NOT make the AI smarter or prevent hallucinations; it stops an unapproved effect.
- Axiom footprint {propext, Classical.choice, Quot.sound} is the minimal classical fragment; no extra axioms.
<!-- claims:end -->

## Beyond mediation: the receipt is not a covert channel

The audit record does not leak the protected state. `observe_noninterference` (see [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md)) proves, machine-checked, that any two `ApprovalState`s agreeing on the single authorized bit for a request produce byte-identical decisions **and** byte-identical audit records. Secrets in the state, other sessions' approvals, the public key, consumed nonces, policy version, TTL caps, the clock, cannot flow into what an observer of the gate sees, except through that one declassified authorization bit (Goguen-Meseguer conditional non-interference). The record chain is tamper-evident under an injective hash step (`Host.Record.tamper_evident`).

**Cross-session, too.** The single-request guarantee extends across a session (`stateful_noninterference_trace`). Over a whole request trace, with both the protected `ApprovalState` **and** the durable replay store varying, the observable decision-plus-record trace reveals nothing about internal policy or other tenants beyond the entitled per-step verdicts.

The honest boundary, stated not buried: the stateful guarantee declassifies **more** than the single-request one. The namespace fields it must expose to route replay, `publicKey`, `session`, `policyVersion`, and the prune clock, become observable across a session (`policyVersion_declassification_necessary` proves this widening is forced, not sloppy). What stays hidden: the deep secrets, `manifestDigest`, tools, approvals, `maxApprovalTtl`, `consumedNonces`. So: single-request hides all but the one auth bit; cross-session additionally reveals the namespace fields and the clock, and nothing deeper.

Boundary (stated, not hidden): these are **model-level** non-interference results over `SealV2.decide` and `Host.auditLine` (single-request `observe_noninterference`; cross-session `stateful_noninterference_trace` + `replay_isolation_trace`). They do not cover timing or size side-channels, or a deployment that routes `ApprovalState`-derived data into a host `reason` string (that flow is outside the theorem). Axiom footprint `{propext, Classical.choice, Quot.sound}`.

## Verify in five minutes

```sh
lake build
lake exe axiom_check
lake exe sha256_selfcheck
scripts/build_ffi_so.sh
cd rust && cargo test
cd .. && node scripts/conformance_bridge.mjs --wasm
```

To run the host, build the Lean core and start `rust/target/debug/seal-host-rs` with a signed config and a child MCP server. See `docs/ARCHITECTURE.md` and `docs/CONFORMANCE.md` before deploying.

## The Seal family

_All Seal-family repositories are currently private; these links resolve only for authorised evaluators._

- [seal](https://github.com/velvetmonkey/seal): the private umbrella story, product map, and evaluator path.
- [mcp-seal-dev](https://github.com/velvetmonkey/mcp-seal-dev): The rulebook, proven.
- [seal-host](https://github.com/velvetmonkey/seal-host): The guard at the door.
- [seal-check](https://github.com/velvetmonkey/seal-check): Don't trust. Verify.
- [seal-live-demo](https://github.com/velvetmonkey/seal-live-demo): Watch it work.
- [seal-assurance-kit](https://github.com/velvetmonkey/seal-assurance-kit): Check your own boundary.
- [witness-check](https://github.com/velvetmonkey/witness-check): The sufficiency analyzer. (private/proprietary)
- [seal-verify-action](https://github.com/velvetmonkey/seal-verify-action): Gate receipts in CI.

## Documentation

- [What Seal is NOT](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/WHAT-SEAL-IS-NOT.md) — read this first (private kit repo)
- [Family claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) · [family architecture map](https://github.com/velvetmonkey/seal/blob/main/docs/ARCHITECTURE.md) (private umbrella)
- [Deployment: install to first PASS/FAIL](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/DEPLOYMENT.md) (private kit repo)
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/THREAT-MODEL.md)
- [Assumptions](docs/ASSUMPTIONS.md)
- [Proof reference](docs/PROOF-REFERENCE.md)
- [Conformance](docs/CONFORMANCE.md)
- [Trusted computing base](docs/TCB.md)
- [Glossary](docs/GLOSSARY.md)
- [Limitations](docs/LIMITATIONS.md)
- [Security policy](SECURITY.md)

## License

Apache-2.0. See [LICENSE](LICENSE).
