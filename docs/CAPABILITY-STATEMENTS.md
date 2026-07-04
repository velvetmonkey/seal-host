<!-- SPDX-License-Identifier: Apache-2.0 -->

# CAPABILITY-STATEMENTS — ocap/delegation-safety scoping (ARIA S6)

**Status: SCOPING DRAFT for the design council. One frozen candidate
statement, no proof. The CONCLUSION is locked; hypothesis plumbing may flex
at council; the conclusion may not.** Wave-2 discipline applies to the
eventual proof module (build bar in §6). Nothing in this document edits any
existing theorem; `.lake/packages/mcp-seal` is untouched.

All symbols below are verbatim-bound to the live tree and were
`#check`-probed to bind and typecheck (including decidability of the
adequacy side-condition) on 2026-07-05.

---

## 1. The frozen property + candidate statement

**Prose (frozen).** Every allowed guarded action traces to a held, live
approval whose minted target hash equals the action's resolved target hash
(already landed — §3). And whenever the deployment's target part-list
universe is *hash-adequate*, the authorizing approval's minted part-list
EQUALS the action's resolved part-list: **a capability authorizes exactly
the action it was minted for, never a neighbor.** This is
no-ambient-authority + no-confused-deputy specialized to the seam the
deployed broker actually crosses — the collapse from structural targets to
`UInt64` hashes.

**Candidate Lean statement (conclusion LOCKED = `pa = pg`):**

```lean
/-- The deployment's part-list universe is hash-adequate: the deployed
    FNV-1a-64 target hash is injective ON THIS UNIVERSE. Decidable for any
    finite `U` — discharged per policy by `decide`. -/
def Adequate (U : List (List String)) : Prop :=
  ∀ pa ∈ U, ∀ pg ∈ U,
    Seal.stableHashParts pa = Seal.stableHashParts pg → pa = pg

theorem approval_authorizes_only_its_target
    (U : List (List String)) (hadq : Adequate U)
    (pa pg : List String) (hpa : pa ∈ U) (hpg : pg ∈ U)
    (now deadline : Nat)
    (hlive : SealCore.live
      { approved := (∅ : Std.HashMap SealCore.Hash Nat).insert
          (Seal.stableHashParts pa) deadline }
      (Seal.stableHashParts pg) now = true) :
    pa = pg
```

Notes: `Seal.stableHashParts : List String → SealCore.Hash`
(`Seal/Hash.lean:16`, namespace `Seal`, NOT `Seal.Hash`); the
single-approval state literal mirrors the landed
`SealCore.approval_binds_to_target` pattern (its generalization is council
question Q3). Expected proof shape: contrapositive of
`approval_binds_to_target` gives hash equality from liveness; `hadq` lifts
it to part-list equality. Small — the value is in the STATEMENT +
per-deployment adequacy discharge, not proof difficulty.

## 2. Authority map (recon, live-symbol-bound)

* **Minting (TCB):** Rust providers (`rust/src/providers.rs`) mint
  `ApprovalRecord { target: u64, … }` via control-file / Ed25519
  signed-token / TTY. `rust/src/a3.rs` freshness-filters every record
  (nonce-once per session, TTL, +5s future-skew, wall clock) before Lean
  sees it — `A3Filter`, fail-closed.
* **Checking (deployed path):** `Ffi.stepImpl` (`Ffi.lean:190`,
  string-in/string-out seam) → `Seal.classifyToolCall` resolves the call to
  `stableHashParts (toolName :: evalTargetParts rule.target args)`
  (`Seal/Classify.lean:32-51` — this is where the `literal`/`argPath`
  target-part split lives) → `SealCore.step`/`live`
  (`SealCore/Automaton.lean:20`): a **hash-keyed** `Std.HashMap
  Hash Nat` lookup. The deployed broker compares `UInt64` hashes.
* **Value model (SealV2):** `validate`/`ValidCapability`
  (`SealV2/Validation.lean:272-309`) compares full `Target` STRUCTS
  (`approval.target == target`, derived BEq over all fields including
  `arguments : AST`; `targetFor`:226 copies request fields whole). Used by
  the SealAdapter / NI / replay proofs.
* **The seam:** the two layers meet only at `stableHashParts`. FNV-1a-64 is
  NOT collision resistant; a collision between two distinct resolvable
  part-lists is precisely a confused deputy in the deployed broker.
* **Delegation/attenuation: NO PRIMITIVE EXISTS** (grep-confirmed across
  the package and Host). Approvals are minted for one fully-instantiated
  target and matched by equality; nothing narrows, chains, or re-mints.
  "Attenuation-only delegation" would formalize a mechanism the broker does
  not have — rejected as the target, recorded here as a scope finding.
* **Signature:** `SealV2.SignatureVerified` (`Validation.lean:191`) is a
  Prop over `verifySignature`, which is a `stub-ed25519:` string match in
  the model; real Ed25519 (`ed25519-dalek`) is Rust TCB.

## 3. Subsumption verdict vs the landed slate

**Already landed (hash-level tracing + separation — cite, do not re-prove):**

| landed theorem | what it gives |
|---|---|
| `SealCore.no_allow_guarded_without_matching_approval_in_state` | allow ⇒ live (authority tracing at one step) |
| `SealCore.approval_binds_to_target` | hash≠ ⇒ not live (separation) |
| `SealCore.confused_deputy_blocks_from_single_other_approval` | the step-level refusal exemplar |
| `SealCore.consumed_approval_not_live` / `fresh_approval_live` / `expired_not_live` | one-shot + freshness discipline |
| `SealV2.decide_emit_unique` | value-level: every Allow carries a `ValidCapability` witness (held, session-bound, target-equal approval) |

**Novel residual (the theorem to ship):** the **hash→value lift** — nothing
landed says hash-equality implies part-list equality, because
unconditionally it is FALSE (FNV collisions exist). The candidate makes it
true under the decidable `Adequate U` side-condition and ships the
per-policy discharge. NI (state secrecy), ReplayIsolation (store
isolation), DeployedAdapter O1∧O2 (channel mediation) are orthogonal — none
speak to authority binding across the hash seam.

**Convergence note:** `seal-assurance-kit` just gained
`seal adequacy check` / `seal adequacy find-collision` (labels.json) — the
operational JS probe of exactly this property. The Lean theorem is its
formal half; the kit tool is the deployment-side discharge/refutation
procedure. One property, two enforcement points.

## 4. Trust boundary (loud)

**Stays TCB (assumed, not proven):** grant-token unforgeability (Ed25519,
`providers.rs`; model uses the stub); the wall clock, nonce replay set,
TTL, and skew (`a3.rs`); the C ABI seam + JSON marshalling (`Ffi.lean`,
`lean.rs`); OS permissions on config/approval files.

**The model PROVES:** authority tracing (allow ⇒ held live approval,
landed) and — new — the adequacy-conditional binding (held approval for
`pa` authorizes an action resolving to `pg` only if `pa = pg`).

**Explicitly NOT assumed:** collision resistance of FNV-1a-64. That is the
point: the statement replaces an unavailable cryptographic assumption with
a decidable, per-deployment, kernel-checked injectivity condition on the
finite universe the deployment actually uses.

## 5. Non-vacuity plan (build-gated exemplars)

1. **Held cap authorizes its target:** `fresh_approval_live` + a `step`
   allow on the same hash — concrete universe entry, `decide`/`rfl`.
2. **Not-held refused:** instance of `approval_binds_to_target` at two
   concrete distinct part-lists from the exemplar universe.
3. **Cross-approval refusal:** cite the landed
   `confused_deputy_blocks_from_single_other_approval` (already the
   refusal witness; re-witnessing optional, council Q5).
4. **Adequacy discharge:** `Adequate U₀` for a concrete small universe
   `U₀` by `decide` (decidability instance probe-confirmed). Council Q5:
   `U₀` = the shipped demo policy's actual part-lists (ties the theorem to
   the deployment) vs synthetic.
5. **Delegated-beyond-parent refused:** **N/A — no delegation primitive**
   (scope finding, §2). Stated, not silently dropped.
6. Witness hygiene: everything at the SealCore/hash layer —
   kernel-evaluable (short strings, FNV). Avoid anything touching
   `Target.arguments : AST` equality (derived BEq on the nested inductive
   is WF-compiled, not kernel-reducible — known gotcha).

## 6. Build bar (must match Wave-2)

Green bare `lake build` (gate closure); axioms exactly
`[propext, Classical.choice, Quot.sound]` per pinned theorem (observed
footprints pinned if lighter, per repo precedent); zero `sorry`; zero
`native_decide`; per-theorem `#guard_msgs in #print axioms` pins; module
wired via `Test/Axioms.lean` import like every Wave module. Proposed home:
`Host/CapabilityAdequacy.lean` (council Q4).

## 7. Open questions for the design council (settle BEFORE the freeze)

* **Q1 — universe source.** `U` as an explicit input list (mirroring the
  kit's labels.json; recommended — matches the operational tool, keeps the
  statement decidable) vs derived from the policy as the image of
  `evalTargetParts` (args-dependent, infinite for `argPath` parts —
  requires an argument-universe cut that must itself be justified).
* **Q2 — aggregation theorem.** Ship the hash-seam lemma alone, or ALSO a
  decide-level ∃-trace statement ("every Allow names its authorizing
  approval") — the latter is largely a repackaging of
  `decide_emit_unique`/`no_allow_guarded_…`; risk: subsumption-flagged as
  low-novelty.
* **Q3 — state generality.** Single-approval state literal (as frozen,
  mirrors `approval_binds_to_target`) vs arbitrary reachable state — the
  latter needs a `live s target now = true → ∃ deadline, s.approved[target]?
  = some deadline`-style inversion (check whether SealCore exposes one;
  none surfaced in recon).
* **Q4 — module home.** `Host/CapabilityAdequacy.lean` vs `Kernels/`.
* **Q5 — exemplar universe.** Shipped demo policy's real part-lists vs
  synthetic; and whether to re-witness the cross-approval refusal at the
  new module or cite the landed lemma.
