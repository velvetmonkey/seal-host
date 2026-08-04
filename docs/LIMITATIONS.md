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

**As of 2026-08-05 (source walk of the `Test.Axioms` import closure on
`88f5e92` tip):** of 53 theorem-bearing modules in the tracked tree, 51 are
inside the closure. The five Host modules that a 2026-08-01 residual once named
as excluded — `Host.DurabilityA6`, `Host.EgressPerimeter`,
`Host.EgressStrength`, `Host.PolicyOverlap`, `Host.StrictPerimeter` — are direct
imports of `Test/Axioms.lean` (wired `4eb6bb4`) and are built under
`lake exe axiom_check`. CI run `30693805679` (workflow `ci.yml`, not
`release.yml`) already carried `Built` lines for those five plus
`Host.SpawnSeam` and `Host.AuditSeam`.

**Two theorem-bearing modules remain outside the `Test.Axioms` closure.** Both
are permanent exclusions under the repo-wide G1 gate
(`scripts/proof_reach.py` → CI `control_33`), not silent oversights. G1's stop
condition is zero `ORPHANED` rows; excluded modules appear as `EXCLUDED` with
the reasons below.

1. **`Host.CanonicalL0Liveness` — a ruling, not an oversight.** DROPPED FROM
   THE RELEASE CLAIM by Ben on 2026-08-01. Its kernel reduction measured 6.0 GiB
   RSS and 1h51m CPU on 2026-07-31, which the release pipeline will not carry.
   Nothing in the public claim surface asserts that its theorems are built or
   axiom-checked. The source remains in the tree and remains visible in every
   generated proof inventory as `reserved=1` / `EXCLUDED`, so the exclusion is
   stated rather than silent. `scripts/proof_inventory.py` fails the build with
   `ORPHAN PROOF MODULE` for any *other* theorem-bearing `Host/` source that is
   not in the closure; `scripts/proof_reach.py` fails on any non-excluded
   `ORPHANED` module repo-wide.

2. **`Test.A2DivergenceClassification` — permanent exclusion, not an axiom pin.**
   Theorem-bearing since 2026-07-30 (`b5f6ad8`). Classification criterion and
   unasserted `#print axioms` for A2 parser divergence; not part of the
   axiom-footprint claim. It is imported by nothing on a default target, has
   no executable root, and is addressable only through the non-default `Test.+`
   library glob — so it is not in the `Test.Axioms` closure and is not
   axiom-gated by `lake exe axiom_check`. CI builds it every run as
   `control_16` (`lake build Test.A2DivergenceClassification`); that build is
   a compile-time guard, not an axiom pin (seven `#print axioms` lines, zero
   `#guard_msgs`). The G1 gate names it here as `EXCLUDED` so the public
   sentence matches the `Test.Axioms` census (51/53) and the exclusion is not
   silent.

The workflow-build inventory measures a separate, broader wire. Of the same 53
theorem-bearing modules, 52 are in the transitive source-import closure of a
concrete `lake test`, `lake build`, or `lake exe` command in a checked-in GitHub
Actions workflow. It gives no credit to a Lake target merely because it is
declared. Under this measure `Test.A2DivergenceClassification` is reached
because CI explicitly runs `lake build Test.A2DivergenceClassification`; only
`Host.CanonicalL0Liveness` remains outside the wire, reported as `EXCEPTED=1`
under the ruling above.

`scripts/proof_inventory.py` fails the build with `ORPHAN PROOF MODULE` for any
other theorem-bearing module outside the workflow-derived closures. It also
fails closed on any import it cannot resolve and on circular local imports.
