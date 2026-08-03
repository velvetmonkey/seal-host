# Threat model — seal-host

The seal-host is a **provably-correct policy monitor over the MCP-visible slice
of an agent's behaviour**. It is not a proven-safe agent. This document states
what it defends, against whom, where the boundary sits, and what is explicitly
out of scope.

## Adversary

A **compromised or prompt-injected agent**: the LLM-driven orchestrator and any
tool outputs it ingests are untrusted. A poisoned source, an injected
instruction, or a confused-deputy chain may cause the agent to *attempt* any
MCP `tools/call` — destructive, exfiltrating, out-of-order, over-budget,
unilateral, or divergent. The adversary controls the wire content the agent
emits; it does **not** control the host, the trusted config, the approval
keys, or the OS file permissions.

Out of the adversary model: an attacker with write access to the trusted
config / approval keys / control files (that is the OS-permission origin
assumption below), and an attacker who bypasses MCP entirely (the
MCP-boundary-only assumption below).

The opt-in health/readiness listener is separately treated as hostile network
input. It defaults to loopback, requires bearer authentication before the
socket is opened, accepts at most 8 KiB, and exposes fixed status responses
only. Its Rust implementation is tested, not covered by the Lean mediation
proof.

## What the host enforces (the seven invariants)

Each is a kernel grounded in a sorry-free, axiom-clean Lean theorem; the host
runs every gating kernel and **combines fail-closed (allow iff every gating
kernel allows)**. Composition is itself proven invariant-preserving
(`Host/Composition.lean`: `and_combinator_preserves_invariants`).

| Kernel | Stops | Proof anchor |
|---|---|---|
| **S** safety | prompt-injected destructive/exfil call without an un-mintable, target-bound, one-shot human approval | `SealCore.no_allow_guarded_without_matching_approval_in_state` |
| **T** temporal | replay-after-revoke, out-of-order sequence attacks (each call legal, the order not) | `Temporal.monitor_sound`, `gateTrace_sealSafe` |
| **C** consensus | single compromised approver, rogue node, silent roster swap on high-stakes actions | `Consensus.Checker.agreement` |
| **V** convergence | divergent / last-writer-wins writes to replicated state | `Crdt.converged_states_agree`, `Crdt.ORSet.add_wins` |
| **K** calibration (experimental) | overconfident-model auto-actions on an uncalibrated forecaster | `ProbabilityTheory.hasCondSubgaussianMGF_of_mem_Icc` |
| **L** linear | approval / capability double-spend, one-shot replay | `LinearCore.no_double_spend`, `spends_le_grants` |
| **B** budget | runaway spend, rate-flood, quota evasion | `BudgetCore.run_never_over_budget` |

## Boundary assumptions (where the proof stops)

These are the trusted relationships the proofs *assume*; they are stated, not
claimed eliminated.

1. **Classifier boundary.** The host decides on the policy's classification of
   each `tools/call`. The policy must capture the dangerous calls: a
   destructive action the policy does not classify as guarded is not gated.
   Completeness of the policy is the operator's burden; the host proves only
   that *what the policy classifies as guarded* is enforced without bypass.
   In the deployed `compatible` profile, classification reads exactly
   `name` and `arguments` within `params`; every other member of `params` is
   outside policy matching and every kernel verdict and, on a forward, is sent
   to the child verbatim (`.lake/packages/mcp-seal/Seal/Classify.lean:278-288`,
   `rust/src/main.rs:527`, `:1559`).

2. **OS-permission origin.** The trusted config (signed), the approval/votes/
   grants/forecast files, and the approval keys are trusted inputs. Their
   integrity rests on OS file permissions and (for signed channels) on key
   secrecy. An adversary who controls the config-signing key, approval keys, or
   host startup arguments is outside the model. The config envelope uses real
   Ed25519 over the exact trusted-config payload bytes, verified by the
   existing `SealV2.ed25519Verify` leaf; the startup `--pubkey` is the named
   config-signing trust root and is not read from the config it verifies. The
   separate host approval back-channel can use real Ed25519 (`ed25519-dalek`)
   over exact `ApprovalRecord` JSON payload bytes. The SealV2 kernel-defined token
   path signs `(target, session, issuedAt, expiry, nonce)` bytes in
   `mcp-seal-dev`. These are three distinct signing channels and keys.

3. **MCP-boundary-only.** Mediation happens at the MCP `tools/call` boundary.
   In-process orchestrator calls, side effects the agent reaches without
   going through MCP (direct shell, cached handles, network), and tool effects
   not surfaced as MCP calls are **out of scope by design**. The host is a
   boundary monitor, not a sandbox.

4. **Parser/translation residual.** The shared SealV2 parser closes
   the parser-differential *on the seal side*: a kernel-admitted line has the
   one byte form defined by `SealV2.serializeAstValue`, the form an approval
   signature commits to. "Canonical" here names the kernel rule, not RFC
   8785/JCS; its known divergences and the host's cross-implementation
   containment are documented in
   [`docs/CANONICAL-BYTE-CONTRACT.md`](docs/CANONICAL-BYTE-CONTRACT.md). The residual gap
   between the upstream server's wire parser and the Seal kernel-defined view is a
   per-server trusted-translation assumption, pinned (not eliminated) by the
   G6 property-based differential conformance harness
   (`rust/tests/differential.rs`). The kernel-defined parser is an audit/signing
   aid, **not** a traffic filter — legitimate multiline/Unicode arguments are
   mediated on the value view, not refused.

5. **Host-trusted clock & freshness (A3).** The Lean kernels prove their
   properties *given* the `now` and the evidence the host supplies. Nonce
   replay rejection, TTL expiry and clock-skew rejection are enforced
   host-side (`rust/src/a3.rs`) before any record reaches a kernel. For the
   Ed25519 signed-token production channel, accepted nonces are durably
   inserted into SQLite before forwarding to Lean, so replay state survives a
   process restart. The SQLite store uses WAL plus `synchronous=FULL`; the
   local crash test covers close/reopen process restart, not power-loss
   certification. The legacy control-file channel remains demo-only and does
   not claim cross-restart replay protection.

## Fail-closed posture

Every uncertainty resolves to **deny**:

- no kernel gated a call → deny (empty-verdict fail-closed, `combine_empty_deny`);
- any gating kernel denies → deny (`combine_deny_of_member`);
- malformed evidence (unparseable vote/grant/forecast line, missing field) →
  the record does not exist, which can only shrink a quorum/grant/window;
- rejected trusted config at startup → the host exits before mediating a
  single line;
- a broken FFI seam (unparseable step output) → the Rust transport never
  forwards.

The honest ceiling: **safety only, no liveness** (Schneider). The host can
refuse a bad action; it cannot promise a good one ever runs. Claims are scoped
to "provably-correct policy monitor over the MCP-visible slice," never
"proven-safe agent."

## TCB

The trusted computing base differs by deployment shape (Lean stdio sidecar vs
Rust FFI host); see `TCB.md`. The FFI host trades a larger TCB (C ABI,
transport, marshalling, providers, clock) for deployability; the stdio sidecar
remains the cleanest assurance story.

## Demonstration

`demo/run_g7.py` exercises the model end-to-end: a poisoned-source destructive
call blocked (S), an out-of-order replay blocked (T), a single-signer
high-stakes action gated on quorum (C), a divergent write refused (V), an
over-budget call denied (B), and a human (Ed25519-signed) approval unlocking a
legitimate retry through a swappable back-channel — audit certificates emitted
throughout — then the whole host placed in front of a real LangGraph agent
(the canary compliance pipeline) mediating its live vault writes.
