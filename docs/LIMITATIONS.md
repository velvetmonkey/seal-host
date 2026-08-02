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

## Canonical JSON non-claim

Seal does not claim RFC 8785/JCS conformance. “Canonical” in theorem, type,
field, and profile names means the deterministic byte rule defined by the
pinned kernel or by the specifically named host serializer. The signed effect
boundary now rejects every present effect for which the actual Rust and Lean
canonical fields are not byte-identical; it does not rewrite data and does not
make either renderer standards-conformant. The exact rules, the U+0008/U+0009/
U+000C, number, and property-order divergences, and the separate arguments,
config, approval-record, and receipt contracts are in
[`CANONICAL-BYTE-CONTRACT.md`](CANONICAL-BYTE-CONTRACT.md).

## Proof build-wire residual

**As of 2026-08-01, after the wiring work:** five of the six modules named in
the earlier version of this residual are now in the `Test/Axioms.lean` import
closure and are built by release CI. Verified in run `30693805679`, whose build
log contains `Built` lines for `Host.DurabilityA6`, `Host.EgressPerimeter`,
`Host.EgressStrength`, `Host.PolicyOverlap` and `Host.StrictPerimeter`, along
with the newer `Host.SpawnSeam` and `Host.AuditSeam`.

**One module remains outside the wire, and this is a ruling, not an oversight.**
`Host.CanonicalL0Liveness` was DROPPED FROM THE RELEASE CLAIM by Ben on
2026-08-01. Its kernel reduction measured 6.0 GiB RSS and 1h51m CPU on
2026-07-31, which the release pipeline will not carry. Nothing in the public
claim surface asserts that its theorems are built or axiom-checked. The source
remains in the tree and remains visible in every generated proof inventory as
`reserved=1`, so the exclusion is stated rather than silent.

`scripts/proof_inventory.py` fails the build with `ORPHAN PROOF MODULE` for any
other theorem-bearing `Host/` source that is not in the closure.
