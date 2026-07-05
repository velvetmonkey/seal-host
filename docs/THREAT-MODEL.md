# Threat Model

## Assets

- Human approval authority.
- MCP tool calls that can create external effects.
- Target commitments and approval records.
- Decision receipts and audit chains.
- Kernel and artifact provenance.

## Adversaries

- An AI agent that is mistaken, manipulated, or trying to route around policy.
- Prompt-injection content that influences the agent's tool request.
- A user or integration that presents stale, malformed, or mismatched approvals.
- A reviewer who needs to detect tampered receipts or record chains.

## In scope

- Blocking guarded MCP effects unless an approval matches the exact target commitment.
- One-shot approval consumption at the kernel boundary.
- Fail-closed handling for missing or malformed approval data.
- Tamper-evident records for decisions that are emitted.
- Corpus-based conformance among the model and deployed artifacts.

## Out of scope

- Seal proves properties of the mediation KERNEL, not of the whole deployed system.
- Seal does NOT prove SHA-256 collision resistance in Lean; it is a named, scoped cryptographic assumption (A-CR).
- The deployed Rust / wasm / JS are NOT proven bug-free; they are tied to the proof by byte-exact conformance testing over a corpus, not for every possible input.
- Seal guarantees AUTHORIZATION match, not INTENT match: if a human approves a malicious-but-valid request, Seal will execute it.
- Seal does NOT prevent compromise of hosts, browsers, build systems, keys, operators, or downstream tools.
- Seal's audit chain is tamper-EVIDENT, not tamper-IMPOSSIBLE.
- Seal does NOT make the AI smarter or prevent hallucinations; it stops an unapproved effect.
- Axiom footprint {propext, Classical.choice, Quot.sound} is the minimal classical fragment; no extra axioms.
