<!-- SPDX-License-Identifier: Apache-2.0 -->

# Policy assurance boundary

This document separates two states that must not be conflated. The audited v1
baseline below was pinned at `mcp-seal-dev` revision `872ac50`. Policy-v2 is
implemented and proved in the sibling core source, but is not a deployed feature
until the immutable promotion gate passes.

**Kernel pin (authoritative, one commit).** As of the 7-kernel DX surface,
`seal-host` builds against a single authoritative `mcp-seal-dev` commit —
`cc79c86691ca25b728c9cc1968d07cacb09cd39e` — and every pin names it:
`lakefile.toml`, `lake-manifest.json`, and this document. It is a descendant
of and supersedes `6bbadbc7` (the pathological-number fail-closed fix, which
itself superseded the drifted `872ac50`/`88168e1`/`fe51d91` references) and
additionally carries `Seal.parsePolicyBundle` — the policy-v2 7-kernel config
vocabulary the host's `Host.ofBundle` now consumes. Moving the *deployed*
production pin to `cc79c86` is a separate step gated to Monkey's frisk +
merge; this reconciles the source-of-truth wording, not the production
deploy.

**Audit date:** 2026-07-12 (baseline); pin reconciled 2026-07-16.  
**Scope:** the policy-evaluation path deployed by `seal-host-rs`, before policy-v2.

## Bottom line

Current match and target evaluation already run in Lean, not in Rust. The
deployed path is:

```text
signed envelope
  → Lean checkEnvelope / parseCanonicalConfigPayload
  → Lean classifyLine / Seal.toolsCall?
  → Lean classifyToolCall
       every rule evaluated → resolveRuleDecisions
       → matchRule
       → evalTargetParts
       → stableHashParts(tool :: target parts)
  → proven SealCore approval automaton
  → Lean kernel composition / stepRoute
  → trusted FFI and Rust byte routing
```

Policy-v2 should therefore extend `Seal.Policy` and `Seal.Classify` inside
Lean. Implementing predicates or precedence in Rust would move authoritative
policy meaning out of the current core and enlarge the TCB.

## Proven core versus trusted glue

| Stage | Current implementation | Assurance status |
|---|---|---|
| Config signature and canonical payload check | Lean `Host.Config.checkEnvelope` / `checkTrustedConfig`; Ed25519 extern | Parsing and rejection are in Lean. The cryptographic leaf, key provision and exact loaded native code remain trusted. |
| MCP recognition | Lean `Host.classifyLine` using `Lean.Json.parse` and `Seal.toolsCall?` | `step_forward_non_bypass` provides a parse/recognition witness for forwarded calls. The deployed profile is compatible JSON, not strict canonical L0. |
| Rule selection | Lean `Seal.classifyToolCall` | Not first-match: every rule is evaluated and `Seal.resolveRuleDecisions` resolves the full decision list; unknown tools and no-match cases default to deny. `Host.PolicyOverlap` contains source theorems for blocking-rule dominance (`classify_blocking_rule_denies`, `deny_mode_rule_wins`), conflicting-target denial (`conflicting_guards_ambiguous`, `classify_conflicting_guards_deny`), security-relevant permutation invariance (`classify_perm_toEvent`), and order-dependent reason strings (`reason_string_is_order_dependent`). That module is a direct import of `Test/Axioms.lean` (since `4eb6bb4`), so its inline `#guard_msgs` axiom pins run under `lake exe axiom_check`. No theorem characterizes author intent. |
| Match evaluation | Lean `Seal.matchRule` | `always` or case-insensitive substring matching over one argument path. Missing/non-scalar paths do not match and therefore deny. No semantic parser is implied. |
| Target evaluation | Lean `Seal.evalTargetParts` and `stableHashParts` | Missing target fields deny. The commitment is SHA-256 over tool plus configured literal/argument parts. There is no current theorem that the selected parts are adequate for every intended effect. |
| Approval decision | Lean `SealCore.step` | Default deny, exact-target separation, expiry and one-shot consumption are proved in `SealCore.Safety`. |
| Multi-kernel composition | Lean `Host.dispatch`, `combineVerdicts`, `stepRoute` | `combine_allow_iff`, `combine_deny_of_member`, `composed_non_bypass`, and `step_forward_non_bypass` prove fail-closed AND composition over the pure decision. |
| Evidence gathering and state | Rust providers/A3 plus Lean `IO.Ref` session state | Trusted IO boundary. Theorems do not establish that files, clocks, votes or grants supplied by Rust are authentic or complete. A3 has executable tests and separate replay-store models, not an end-to-end proof of the Rust provider. |
| Native FFI and byte routing | `Ffi.lean`, `rust/src/lean.rs`, `rust/src/route.rs`, `rust/src/main.rs` | Trusted compilation, ABI, marshalling and OS IO. The three-way property differential (`rust/tests/three_way.rs`) binds a large seeded corpus to model/native/wasm behavior byte-for-byte every CI run; this is evidence over the cases tried, not universal equivalence. The routing-preservation seam split is stated in the `lean.rs` / `route.rs` module docs: the pure result→route mapping (`route_of_step_output`, `route_of_classify`) is pinned exhaustively (`differential.rs::every_seam_error_variant_fails_closed`); the raw-pointer marshalling in `lean.rs` stays trusted glue. |
| Receipt assembly and persistence | Rust decision-receipt producer | Trusted additive producer. Receipt verification independently re-derives decision bytes; `host_identity` identifies native artifacts but does not close Lane C equivalence. Sink failure is fail-closed. |

## What the present theorems establish

- `SealCore.default_deny_never_allowed`: the default-deny event cannot allow.
- `SealCore.guarded_allow_iff_live` and
  `no_allow_guarded_without_matching_approval_in_state`: a guarded target
  allows exactly when the same target has a live approval.
- `SealCore.approval_binds_to_target`: approval for one target is not live for
  a distinct target.
- `SealCore.consumed_approval_not_live`: successful use consumes the approval.
- `SealCore.expired_not_live`: an expired approval cannot authorize.
- `Host.combine_allow_iff`: composed ALLOW means a non-empty gate set and every
  applicable gate allowed.
- `Host.composed_non_bypass`: if classification produced guarded target `t`
  and composition allowed, the safety state held a live approval for `t`.
- `Host.step_forward_non_bypass`: a forward has a recognized `tools/call`
  witness and all gating verdicts are ALLOW.
- `Host.registry_deny_ingest_only` (with `Host.pureCommit_deny_of_member` and
  the per-kernel corollaries): on ANY kernel's deny, the full 7-kernel
  registry — bound to the deployed selection by `commitInstsFor_kernels` ≡
  `Ffi.activeKernels` — commits only the spec-allowed ingests: no budget
  spend, no linear capability consumed (holds can only grow —
  `registry_deny_no_capability_consumed`, `parseGrantsText_grant_only`), no
  temporal trace event; only Safety's approval fold and Linear's grant fold
  move, and the theorem says so.
- `Host.dispatch_plan`: the dispatch loop's three per-call accumulations —
  the `phase1Held` verdicts it combines, its unconditional ingest writes, and
  its allow-only held replay — equal `pureCommit`'s components, stated in the
  loop's own vocabulary. (Until `dispatch_spelled` this was spoken in the
  loop's VOCABULARY but proven over pure expressions shaped like the loop;
  the next entry makes it literal.)
- `Host.dispatch_spelled` (Host/DispatchSpelled.lean): the deployed
  `Host.dispatch` `do`-block — `mut` accumulators, `for` loop, queued held
  writes, allow-only replay — IS the explicit recursion `dispatchGo`,
  program equality in `IO` by list induction over core's
  `LawfulMonad (EStateM ε σ)`, with the opaque `IO.Ref` get/set as abstract
  leaves on both sides. This pins the desugaring, the accumulator order, the
  CONTENT AND ORDER of the queued held writes (one `set st2` per gating
  instance, registry order) and that they replay exactly on a combined
  allow. `dispatchGo_cons_pure_gather` + `registryFor_gather_pure` then
  discharge gather execution for the deployed registry: every `registryFor`
  gather is a pure constant, so executing it is the monad law `pure_bind`.
  `registryFor_reader_invariance` pins that the registry's state slots
  depend on nothing but the session's four named refs.
- `Ffi.stepImpl_spelled` (Ffi.lean, file-local — `stepImpl` is private):
  one mediation step IS the pure `stepPlanFor` wrapped around its two IO
  leaves (`sessionRef.get`, `dispatch`) — which input field feeds which
  parser, the single judged `line` binding, the fail-closed
  uninitialised/unsafe-number/bad-parse/refuse branches, and that the
  dispatched registry is `registryFor` at exactly the marshalled values.
- `Ffi.registryFor_kernels_nodup` (with `activeKernels_nodup`): no config
  registers a kernel twice — no double ingest, no double verdict, at most
  one registry instance per stateful session ref. (Previously nothing pinned
  this: a duplicated instance would have passed every existing theorem.)

The load-bearing qualifier is **after classification produced a guarded
target**. These theorems do not prove that a policy author selected the right
operations or bound every effect-relevant parameter.

## What is not proved yet

- Per-caller / per-principal (multi-tenant) policy. Kernels key on tool-set /
  capability-id, never on the caller; on the stdio topology caller identity is a
  proven no-go (`stdio_no_caller_authentication`, `Host/ReceiptIdentity.lean`).
  The honest design path (signed principal envelope over stdio, opaque
  `AuthenticatedPrincipal`, `principal_from_auth_not_request` +
  `principal_budget_isolation`) is specified in `docs/V2.1-PRINCIPAL-DIMENSION.md`.
- That substring matching captures an author’s intended SQL, shell, URL,
  GitHub or filesystem operation. Prefix/substring matching is not parsing.
- That the current first-rule selection matches author expectations when rules
  overlap.
- An explicit-ALLOW origin property; current policy has only `guarded` and
  `deny`, with no safe-allow language.
- Deny/guard precedence or monotonicity for a compositional rule language.
- Target adequacy: changing every effect-relevant argument changes the target.
  Existing target-separation theorems assume distinct target hashes; they do
  not prove the policy constructed distinct hashes for distinct effects.
- Universal native-versus-wasm equivalence. Conformance covers a finite
  corpus only — the 15-case bridge plus the three-way property differential's
  large seeded corpus (25,000 CI cases, soak on demand), byte-identical
  native ≡ wasm ≡ model. This is the open Lane C gap: strong, continuously
  re-checked evidence ("no known divergence under N cases per run"), not a
  proof. The differential surfaced one real divergence and it is now CLOSED:
  an adversarial JSON number with a ~10-digit decimal exponent used to abort
  the native `.so` and the Lean interpreter (`Nat.pow` limit) while the
  emscripten wasm passed through, but the fail-closed number guard
  (`Seal.JsonUtil.wireNumbersSafe`, `Host.pathological_never_forwards`) now
  makes every lane `block` it byte-identically, regression-pinned by
  `three_way.rs::pathological_number_fails_closed_all_lanes`. True closure of
  the residual (unfound) gap needs a verified compiler / source equivalence
  proof, out of scope by magnitude.
- The dispatch IO shell around `dispatch_plan` — now REDUCED to its opaque
  core. Four of its former trusted-by-inspection items are theorems (see
  "What the present theorems establish"): the `for`/`do` desugaring and
  `mut` accumulators, the structure of the held replay (queued-write content,
  order, allow-only execution), gather execution at the deployed registry,
  and `stepImpl`'s marshalling (`dispatch_spelled`, `stepImpl_spelled` and
  companions; the wiring of `commitInstsFor` against `registryFor` was
  already proven: `commitInstsFor_wiring` + `commitInstsFor_gates` on top of
  `commitInstsFor_kernels`). What REMAINS trusted is exactly this, and each
  item names why Lean cannot close it:
  * **`IO.Ref` value semantics.** `ST.Prim.Ref.get`/`set`/`mkRef` are
    `opaque` extern constants in Lean core (`Init/System/ST.lean`) — that a
    get returns the ref's current value, a set updates it, and `mkRef`
    allocates fresh has NOTHING to unfold. A "proof" would mean axiomatising
    an IO.Ref model, which manufactures theorems without content; refused.
    This is the irreducible core of "snapshot faithfulness" and of the held
    writes actually LANDING when replayed.
  * **Typed-runtime trust covers ref distinctness.** The five session refs
    carry pairwise-distinct state types (`SealCore.State`, `TemporalState`,
    `LState`, `BudgetState`, `Unit` — Ffi.lean), so cross-kernel aliasing
    through the typed API is a type error, not a runtime possibility; each
    stateful kernel appears at most once (`registryFor_kernels_nodup`); the
    one deliberately shared ref (`unitRef`, C/V/K) has `State = Unit`, where
    every read and write is `()`. The residue is only that the Lean
    runtime/FFI respects types — the standing compiler/runtime trust, not a
    dispatch-specific assumption.
  * **The export wrapper.** `unsafeBaseIO`/`catchExceptions` above
    `stepImpl`: any IO exception renders `errJson` (blocked); state-wise an
    exception between the unconditional ingest writes and the allow replay
    leaves exactly the deny-shape state (ingests committed, held decides
    not) — fail-closed degradation by construction, trusted because
    exceptions live in opaque IO.
  * **Session lifecycle.** `initFromConfig` REPLACES the session with five
    fresh refs (re-init is state reset by construction); the exports are not
    thread-safe and the Rust host serialises calls (Ffi.lean header). The
    interpreter oracle (`modelStep`/`modelInitFromTrustedPayload`) bypasses
    only signature verification and is not the deployed path.
  Evidence backing this residue: the three-way property differential
  (25,000 seeded cases per CI run, model ≡ native ≡ wasm byte-for-byte —
  and the model oracle runs the SAME `stepImpl` the export wraps), the host
  unit tests, and the Lane C status above.
- An end-to-end proof through Rust routing, provider authenticity, filesystem
  persistence, compiler/codegen, dynamic loading, or OS behavior.

## Scan and adequacy status

The audit initially found `seal scan` and `seal adequacy` as JavaScript-only
checks. The first formal bricks now exist, with the remaining executable seams
kept explicit.

- **Scan has finite-manifest soundness in Lean.** `Seal.scan_pass_sound` proves
  that every supplied entry annotated mutating is non-benign when the checker
  passes, and `scan_pass_no_orphan_allow` covers explicit ALLOW rules. It does
  not prove the manifest complete or its effect annotations correct. The
  shipped JavaScript policy-v2 mirror is not yet theorem-bound.
- **Adequacy has a proved Lean executable checker.** `check_sound`,
  `check_implies_finite_witness_computable`, and
  `collision_refutes_aggregator` connect the checker to witness refinement.
  The JavaScript CLI agrees with that oracle over corpus C; the JS
  implementation itself is not formally verified.

Policy-v2 must make the Lean evaluator authoritative for scan. The formal
target for scan is coverage completeness relative to an explicit pinned
manifest and effect classification. The formal target for adequacy is finite
soundness: if the executable checker passes, the declared separation holds in
that finite model; on failure it returns a valid collision witness.

## Policy-v2 implementation and remaining promotion

1. **Implemented in Lean source:** explicit `allow`, `guard`, and `deny`; no
   match remains deny.
2. **Implemented and proved:** deterministic deny/guard/allow precedence,
   explicit-ALLOW origin, deny/guard monotonicity, ambiguous-target blocking,
   and canonical full-argument pre-image sensitivity.
3. **Native compatibility probe passed:** conditional allow, default deny,
   deny dominance, server+tool+full-arguments target binding, mismatch
   rejection, one-shot replay, and authorization-labelled receipts.
4. **Still gated:** publish an immutable core revision, clean-build the host
   and public wasm from it, repin every consumer, then require one explicit
   policy ALLOW receipt to verify and tamper-fail across browser, CLI and CI.

The executable checklist and the strict distinction between a local probe and
a release are in [`POLICY-V2-PROMOTION.md`](POLICY-V2-PROMOTION.md).
