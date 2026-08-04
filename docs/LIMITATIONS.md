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

**As of 2026-08-04:** the repository contains 53 modules with explicit
`theorem`/`lemma` commands. Of those, 52 are in the transitive source-import
closure of a `lake test`, `lake build`, or `lake exe` command **declared in
[`proof-build-targets.toml`](../proof-build-targets.toml)**. This definition
deliberately gives no credit to a Lake target merely because it is declared in
`lakefile.toml`. In particular, `Test.A2DivergenceClassification` is reached
because `ci.yml`'s `control_16` is declared to run `lake build
Test.A2DivergenceClassification`, while the `Ffi` and `Test` library globs do
not confer reachability by themselves.

**Read the claim precisely, because it is narrower than it looks.** The
manifest is a set of *assertions by a maintainer* that CI runs those 27
commands. It is not a derivation from the workflow text, and deliberately so:
whether a line of shell will actually run depends on runner secrets, event
payloads, matrix expansion and scripts the workflow shells out to, none of
which is a function of the text. A predicate over the text that *granted*
reachability would have to guess on that undecidable middle, and a wrong "yes"
is invisible — `echo lake build X` and `lake build X` are one keystroke apart.

So the workflow text is read only in the opposite direction. Every declared row
must still correspond to a command in shell **command position**, at the named
job and step, under the recorded `guard`; a row that fails that check confers
nothing and fails the build. Any live command-position `lake` invocation that
no row declares also fails the build. Neither check can make the gate pass.
A row's `guard` field records verbatim what the invocation is conditional on
(a step `if:`, a shell branch, or nothing), so a conditional build is visible
rather than silently counted or silently dropped.

**What this still does not establish.** That the declared commands ran, that
their jobs were scheduled, that `continue-on-error: true` did not swallow a
failure, or that the builds succeeded. Those are facts about a CI run, and the
honest way to get them is for CI to emit a record of what it invoked and for
this gate to consume that record. That is not implemented here.

**One module remains outside the wire, and this is a ruling, not an oversight.**
`Host.CanonicalL0Liveness` was DROPPED FROM THE RELEASE CLAIM by Ben on
2026-08-01. Its kernel reduction measured 6.0 GiB RSS and 1h51m CPU on
2026-07-31, which the release pipeline will not carry. Nothing in the public
claim surface asserts that its theorems are built or axiom-checked. The source
remains in the tree and remains visible in every generated proof inventory as
`EXCEPTED=1`, with this reason, so the exclusion is stated rather than silent.

`scripts/proof_inventory.py` fails the build with `ORPHAN PROOF MODULE` for any
other theorem-bearing module outside the declared closures. It also fails
closed on any import it cannot resolve, on circular local imports, on a
declared row the workflow no longer supports, and on a `lake` invocation no row
declares. Its errors are the only thing that gates: read `$?`, not the printed
counters, which are all zero when the instrument cannot produce an inventory.
