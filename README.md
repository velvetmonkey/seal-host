# seal-host

[![CI](https://github.com/velvetmonkey/seal-host/actions/workflows/ci.yml/badge.svg)](https://github.com/velvetmonkey/seal-host/actions/workflows/ci.yml)
[![Golden Path](https://github.com/velvetmonkey/seal-host/actions/workflows/golden-path.yml/badge.svg)](https://github.com/velvetmonkey/seal-host/actions/workflows/golden-path.yml)

**Stops the unapproved prod action before it ever reaches your real MCP server.**

An agent calls a guarded tool (drop table, send money, rm -rf). Without a matching human approval for that exact target, seal-host blocks it. The call never reaches the child. With the ticket, it flows. Every decision — allow or refuse — is written as a tamper-evident authorization decision.

One command shows the full loop over a fake ledger in seconds (block with 64-hex target, signed approval via CLI, action or explicit refused, side-effect or audit).

The proof story (Lean kernel, TCB, non-interference) comes after you have watched it work.

To wire the host into Claude Code, Claude Desktop, Cursor, or VS Code and run
the real destructive SQLite sandbox, start with [CONFIG.md](CONFIG.md).

## Quick start

One-time build first (`bash scripts/build_all.sh`: Lean core → FFI `.so` → Rust host). Budget it honestly: the Rust host compiles in **~45s warm** (measured: `cargo build --release`, 44.2s on this box); the dominant cost is the first cold `lake build` of the Lean core, which pulls the toolchain and can run tens of minutes on a fresh machine. After that the loop is instant. From a fresh checkout, run:

```bash
bash scripts/build_all.sh && bash scripts/showcase.sh
```

## What the showcase proves

**30-second showcase (one command, zero external setup)**

What you see:
- `BLOCK: ... "approval required: <64-hex>"`
- CLI signs target-bound record
- On allow: `SYNTHETIC_LEDGER_ACTION ... (committed via approval)`
- On deny: host emits `approval refused (signed decline...)` (not a timeout)
- `=== PASS ===`

Distinct targets, real Ed25519 signed channel, explicit refused path, full audit lines. The synthetic ledger is the fake guarded tool — pure demo, no setup.

(Delegates to shipped demo/see_the_loop.py with LD paths. Setup in DEPLOY.md.)

The rest of this page (and DEPLOY.md) tells you how to stand it in front of a real MCP server.

![Lean](https://img.shields.io/badge/Lean-4.28.0-blue)
![Rust](https://img.shields.io/badge/Rust-host-orange)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

<!-- truthbox:begin -->
> **Runtime profile: `compatible`.** Strict `canonical-l0` is proved and modelled, not the deployed route yet.
> **Claim:** policy-covered request-effects recognised by the compatible MCP boundary require a matching live human approval and an allowing Lean kernel verdict; seam failures block; every decision emits replayable evidence.
> **Non-claim:** the deployed host is not proved end to end, and canonical parser rejection is not currently the runtime gate. Host `ApprovalRecord` tokens are a separate signed channel from the v2 kernel-defined approval tuple. “Canonical” in Seal names the pinned kernel byte rule, not RFC 8785/JCS.
<!-- truthbox:end -->
> Map: [EVALUATOR-START.md](https://github.com/velvetmonkey/seal/blob/main/EVALUATOR-START.md) · profile detail: [PROFILE.md](PROFILE.md).

**Dogfood it (real approval channel, you are the human)**

The showcase scripts one signer. These three demos put *you* in the loop on the real Ed25519 token channel — no mocks, raw host output, exit code follows the actual decision:

```bash
python3 demo/dogfood_cli.py          # host BLOCKS; you sign in another terminal → the identical call FLOWS
python3 demo/dogfood_failclosed.py   # signed DENY + a tampered token → both stay blocked, fully automated
TELEGRAM_BOT_TOKEN=… SEAL_TG_ALLOWED=<id> python3 demo/dogfood_telegram.py   # tap Approve on your phone
```

Each prints the raw `approval required: <64-hex>` block and the raw second response (`SYNTHETIC_LEDGER_ACTION … committed via approval`, or an explicit refusal). `dogfood_failclosed.py` is one-command and needs no human; `dogfood_telegram.py` exits 2 with 3-step BotFather setup if no bot token is set — nothing is mocked.

**Prove the authorization decision (5-minute cold-reviewer walkthrough)**

The showcase shows the *decision*; this shows the *evidence is tamper-evident*. One command, no external setup:

```bash
bash scripts/receipt_demo.sh
```

A destructive `db.execute` is BLOCKED by the real Lean-verified gate, the decisions are sealed into a SHA-256 hash-chain, the intact chain VERIFIES, and then the script mutates and reorders entries to show both are REJECTED. This is the concrete instance of the machine-checked `Host.Record.tamper_evident` theorem. Real output (this machine):

```
VERIFY OK: 3 entries, chain intact.
VERIFY FAIL: entry 1 — recorded head does not match recomputed chain.  ✓ mutation REJECTED.
VERIFY FAIL: entry 0 — recorded head does not match recomputed chain.  ✓ reorder REJECTED
RECEIPT DEMO PASSED
```

## What happens when an agent tries to use a production tool

<!-- TODO(asset, shot #5, PROMO-GRADE): real terminal GIF (asciinema) of the full loop —
     guarded db.execute BLOCKED with the 64-hex target commitment visible, human appends the
     approval line, the identical call passes, authorization-decision JSON line printed. Capture from the
     docs/DEPLOY.md walkthrough. Do NOT fake or mock this capture. -->
<!-- TODO(asset, shot #6, AI-generatable): clean diagram — agent → seal-host (guard) →
     real MCP server, approval channel as side input, authorization decision as output. Cleaner render of
     the ASCII art in docs/DEPLOY.md. -->

The Rust host receives MCP traffic and forwards ordinary traffic unchanged. When a guarded `tools/call` arrives, it gathers approval records, filters them for freshness and replay, and calls the Lean kernel through the FFI surface. A matching approval routes the original call forward. No match returns a JSON-RPC error before the downstream tool sees anything.

The host also writes records. The production record chain uses SHA-256. Per-kernel `certHash` values remain the legacy UInt64 audit seals; they are not the target commitment and they are not the record-chain commitment.

## For evaluators and auditors

Seal's proof story is intentionally narrow. The Lean theorems cover the mediation kernel and selected model properties. The binaries and browser artifacts are connected to that proof by reproducible conformance tests, not by a theorem about every compiled instruction.

Start with the family [claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) (one table: proven / tested / assumed / not claimed), then [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md) for theorem names and file locations, [docs/CONFORMANCE.md](docs/CONFORMANCE.md) for the byte-identity claim, and [docs/TCB.md](docs/TCB.md) for what remains trusted.

This repo also carries the distributed transfer: the coordination-free no-double-spend impossibility (proven abstractly in [crdt-lean](https://github.com/velvetmonkey/crdt-lean)) applied to the gate model's real consume seam as a TTL-scoped instance — within the approval's TTL window, per concurrent replica, never "single-use forever" (`Host.AuthorityFrontierBridge`; see [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md) and the family [authorization mesh](https://github.com/velvetmonkey/seal/blob/main/docs/AUTHORIZATION-MESH.md)).

Mandatory non-claims (canonical copy: [docs/LIMITATIONS.md](docs/LIMITATIONS.md)):

<!-- claims:begin -->
- Seal proves properties of the mediation KERNEL, not of the whole deployed system.
- Seal does NOT prove SHA-256 collision resistance in Lean; it is a named, scoped cryptographic assumption (A-CR).
- The deployed Rust / wasm / JS are NOT proven bug-free; they are tied to the proof by byte-exact conformance testing over a corpus, not for every possible input.
- Seal guarantees AUTHORIZATION match, not INTENT match: if a human approves a malicious-but-valid request, Seal will execute it.
- Seal does NOT prevent compromise of hosts, browsers, build systems, keys, operators, or downstream tools.
- Seal's audit chain is tamper-EVIDENT, not tamper-IMPOSSIBLE.
- Seal does NOT make the AI smarter or prevent hallucinations; it stops an unapproved effect.
- The `{propext, Classical.choice, Quot.sound}` axiom-footprint claim is scoped to theorem names imported and pinned by `Test/Axioms.lean`; it is not repository-wide (see “Proof build-wire residual” in the canonical limitations document).
<!-- claims:end -->

## Beyond mediation: the authorization decision is not a covert channel

Machine-checked non-interference: any two approval states that agree on the single authorized bit for a request produce byte-identical decisions **and** byte-identical audit records — for one request (`observe_noninterference`) and across a whole session trace with the durable replay store varying (`stateful_noninterference_trace`). The record chain is tamper-evident under an injective hash step (`Host.Record.tamper_evident` — notably an **axiom-free** theorem: collision resistance and genesis freshness enter as explicit hypotheses, not axioms).

Boundary, stated not hidden: these are **model-level** results over `SealV2.decide` and `Host.auditLine`; the cross-session guarantee necessarily declassifies the replay-routing namespace fields (`publicKey`, `session`, `policyVersion`, and the prune clock — `policyVersion_declassification_necessary` proves that widening is forced, not sloppy), and timing/size side-channels are out of scope. Theorem-by-theorem detail, including exactly what stays hidden: [docs/PROOF-REFERENCE.md](docs/PROOF-REFERENCE.md).

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
- [seal-verify-action](https://github.com/velvetmonkey/seal-verify-action): Gate authorization decisions in CI.

## Documentation

- **[Deploy: stand the gate up in front of your own agent](docs/DEPLOY.md)** — clone → build → first blocked call → approve → authorization decision
- **[Operate the V1 core](docs/OPERATIONS.md)** — authenticated health/readiness, retention, rotation, secrets, and replay recovery
- [What Seal is NOT](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/WHAT-SEAL-IS-NOT.md) — read this first (private kit repo)
- [Family claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md) · [family architecture map](https://github.com/velvetmonkey/seal/blob/main/docs/ARCHITECTURE.md) (private umbrella)
- [Authorization-decision evidence deployment (assurance kit): install to first PASS/FAIL](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/DEPLOYMENT.md) (private kit repo)
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
