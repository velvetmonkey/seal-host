# seal-host mediation profiles

`seal-host` runs one of two mediation profiles. The deployed default is
`compatible`. This file states which profile is live, what each proves, and
where the trust boundary sits.

## Deployed: `compatible`

The deployed `Ffi.stepImpl` path routes by `stepRoute` (`Host/Canonical.lean`).
It recognises MCP `tools/call` requests through the runtime JSON view, routes
the decision through the Lean kernel, blocks seam failures fail-closed, and
records replayable evidence. The v2 canonical parse is attached as **audit
data**, not as a routing gate.

**Claim.** For policy-covered request-effects recognised by the compatible MCP
boundary, forwarding requires a matching live human approval and an allowing
Lean kernel verdict. Seam failures block. Every decision emits replayable
evidence.

**Non-claim.** The whole deployed host is not proved, and canonical parser
rejection is not currently the runtime gate.

## Proved, not deployed: `canonical-l0`

The strict `canonical-l0` profile (`Host/CanonicalL0.lean`) is an additive
proof-layer profile: a mediated call whose canonical parse fails routes to
`.block` for every kernel input, and every forward carries a canonical parse
witness. `stepRouteP .compatible = stepRoute` holds by `rfl`; the strict
profile is proved separately and is **not** wired into the deployed host. It is
the first funded hardening milestone, not a pre-decision patch.

## The honest split

The theorem proves the mediation rulebook. The deployed host is trusted runtime
glue around that rulebook, constrained by fail-closed routing and checked by
byte-exact conformance over a labelled corpus, not by a proof of the compiler,
OS, or transport. We publish the remaining profile and runtime gap because
hiding it would weaken the assurance case.

See the family map in
[EVALUATOR-START.md](https://github.com/velvetmonkey/seal/blob/main/EVALUATOR-START.md).
