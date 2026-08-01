# Limitations

These limits are part of the Seal claim. They are not footnotes.

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

## Proof build-wire residual

**As of 2026-08-01:** `lake exe axiom_check` does not import the theorem-bearing
modules `Host.CanonicalL0Liveness`, `Host.DurabilityA6`,
`Host.EgressPerimeter`, `Host.EgressStrength`, `Host.PolicyOverlap`, or
`Host.StrictPerimeter`. Any inline theorem checks, axiom pins, and
compiler-evaluated guards in those modules are not exercised by that release
gate until the modules are added to the `Test/Axioms.lean` import closure.
