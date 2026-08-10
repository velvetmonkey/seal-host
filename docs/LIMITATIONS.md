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

## Release provenance non-claims

GitHub artifact attestations are unavailable for this user-owned private
repository. The replacement release provenance uses a Sigstore keyless
ephemeral key certified for the GitHub Actions release-workflow OIDC identity.
It proves only that this workflow identity signed the listed SHA-256 byte
bindings. It does not establish an independently controlled human or
organisation key, and it does not prove uncompromised repository/tag control,
GitHub Actions, Sigstore services, runners, compilers, dependencies, or source.
It also does not prove reproducibility, hermeticity, source-to-binary
correspondence, or that a Lean theorem applies to compiled bytes. The full
signed non-claim set and verification command are in
[`RELEASE-PROVENANCE.md`](RELEASE-PROVENANCE.md).

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
   stated rather than silent. `scripts/proof_reach.py` fails on any
   non-excluded `ORPHANED` module repo-wide.

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
theorem-bearing modules, 52 are in the transitive source-import closure of one
of 21 `lake test`, `lake build`, or `lake exe` commands **declared in
[`proof-build-targets.toml`](../proof-build-targets.toml) with `push_main =
true`, whose workflow trigger admits an unconditional push to the default
branch**. It gives no credit to a Lake target merely because it is declared in
`lakefile.toml`. Under this measure
`Test.A2DivergenceClassification` is reached because `ci.yml`'s `control_16` is
declared to run `lake build Test.A2DivergenceClassification`; only
`Host.CanonicalL0Liveness` remains outside the wire, reported as `EXCEPTED=1`
under the ruling above.

**Read the workflow-build claim precisely, because it is narrower than it
looks.** The manifest contains 24 maintainer assertions about commands in CI.
Three are not credited for the default-branch push inventory: the manual-only
`public-export.yml:export:control_14` and the two tag-only declarations
`release.yml:build:control_19` and `release.yml:build:control_09`. They remain
declared with `push_main = false` and named as `TRIGGER-EXCEPTED`, with the
trigger reason, rather than disappearing. Widening either workflow's `on:` text
cannot change that manifest assertion or restore credit.

The manifest is not a derivation from workflow text: whether shell actually
runs depends on runner secrets, event payloads, matrix expansion and invoked
scripts. The workflow text is therefore read only in the refuting direction.
Every declared row must correspond to a command in shell command position at
the named job and step, under its recorded `guard`; a row that fails that check
confers nothing and fails the build. Any live command-position `lake` invocation
that no row declares also fails the build. Neither check can make the gate pass.
A workflow trigger that does not admit a push to `main` likewise removes that
row's credit. Trigger evaluation is a closed world with three outcomes:
`FIRES`, `DOES NOT FIRE`, and `NOT UNDERSTOOD`.

**The `on:` block is read as YAML, not as text.** Until 2026-08-04 the reader
matched indentation as literal string prefixes — two spaces for an event key,
four for a filter key, six for a list item — which made the gate reject valid
workflows over whitespace it had never documented and GitHub does not care
about. A branch list written as a block sequence at four spaces instead of six
matched no prefix, so the filter collected nothing and was reported as *empty*
about a filter plainly containing `main`; quoting the top-level key as `"on":`,
the standard answer to yamllint's default `truthy` warning, read as no trigger
at all. Both now parse. So do anchors and aliases, which GitHub has supported
since 2025-09-18, and any indentation YAML itself permits. This costs the gate
a dependency on PyYAML, which `ci.yml` provisions explicitly; if it is missing
the gate refuses to run rather than reporting coverage it could not check.

Reading real YAML widens what parses, so the closed world is enforced above the
parser instead. Event names are closed over GitHub's documented vocabulary of
35, and each event's configuration keys over that event's documented set, both
transcribed from the machine-readable workflow schema. The distinction that
draws is the load-bearing one: a key that is **not an event name** — `defaults`,
say — makes the workflow file invalid, so it runs on nothing, and refusing it is
correct rather than over-strict; an event name this gate does not *interpret* is
merely another way for the workflow to start, and since `on:` is a disjunction
it cannot withdraw the push being judged. So `merge_group`, `workflow_call` and
a configured `pull_request` leave the push verdict intact, while an unrecognised
key at any depth does not.

Only `push` is interpreted. Its implemented fields are `branches`,
`branches-ignore`, `tags`, `tags-ignore`, `paths`, and `paths-ignore`; ref
filters implement literal characters, `*`/`**`, and ordered `!` negation in
positive `branches`/`tags` lists. A `schedule` is still checked to be a sequence
of `cron` mappings whose five fields are `*` or one range-valid integer.
Duplicate keys are refused at every level rather than resolved last-one-wins,
as PyYAML's own constructor would; so are explicit YAML tags, merge keys,
multi-document files, non-string keys, and alias graphs that are cyclic or that
expand past a fixed bound. Any other event, field, configuration, value shape,
or syntax is `NOT UNDERSTOOD`: every declaration in that workflow loses credit,
every row is printed as `TRIGGER-NOT-UNDERSTOOD`, and the gate exits non-zero.
Uncertainty is never read as liveness.

Because YAML whitespace is space and tab only, characters that merely look like
whitespace — U+00A0 and its relatives — remain scalar data and are refused as
unsupported pattern characters rather than trimmed to a name that matches.

A `paths`- or `paths-ignore`-filtered push is conditional on a changed-file set,
so it is not an unconditional push-to-main witness. Either filter produces
`DOES NOT FIRE` for this inventory and removes the workflow's credit; the gate
does not guess which files a future push will touch.
A row's `guard` field records verbatim what the invocation is conditional on
(a step `if:`, a shell branch, or nothing), so a conditional build is visible
rather than silently counted or silently dropped.

This does not establish that the declared commands ran, their jobs were
scheduled, `continue-on-error: true` did not swallow a failure, or the builds
succeeded. Those are facts about a CI run, not the workflow text.

`scripts/proof_inventory.py` fails the build with `ORPHAN PROOF MODULE` for any
other theorem-bearing module outside the declared closures. It also fails
closed on any import it cannot resolve, on circular local imports, on a
declared row the workflow no longer supports, and on a `lake` invocation no row
declares. Its errors are the only thing that gates: read `$?`, not the printed
counters, which are all zero when the instrument cannot produce an inventory.
