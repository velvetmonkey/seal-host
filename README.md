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

**Seal is the approval gateway for agentic tool use: it lets agents read and reason, but forces every protected external effect through an exact, recorded, checkable approval boundary.** When an AI agent tries to use a real tool over MCP (send money, delete a record, call an external service), Seal stands in the way and asks one question: did a human explicitly approve *this exact request*? No matching approval, no action. Every decision is written into a tamper-evident record you can check yourself. What makes Seal different from other guardrails: the core mediation rules aren't just tested, they're machine-checked theorems in Lean 4. The same decision logic then runs byte-for-byte in the Rust host you deploy, in the browser, and in the checker, each verified against that one proven rulebook.

That is the product line in one sentence: prove the rulebook, then check every body that runs it. Seal is built around MCP because MCP is where agent intent becomes an external effect. The proof says what the kernel must do; the conformance tests show that the Rust, wasm, and JavaScript artifacts used by the product family emit the same decisions and records over the shared corpus.

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
