<!-- SPDX-License-Identifier: Apache-2.0 -->

# CAPABILITY-STATEMENTS — ocap/delegation-safety scoping (ARIA S6)

**Status: LANDED.** The live proof is `Host/CapabilityAdequacy.lean`; Stage 2
repins the target commitment to SHA-256 (`SealCore.TargetHash = Digest256`)
without changing the theorem conclusions. The old finite-universe/FNV scoping
language in this note is superseded by the explicit A-CR hypothesis over
`Seal.stableHashString`.

All symbols below are verbatim-bound to the live tree and were
`#check`-probed to bind and typecheck (including the A-CR hypothesis shape)
on 2026-07-05.

---

## 1. The frozen property + landed statement

**Prose (frozen).** Every allowed guarded action traces to a held, live
approval whose minted target hash equals the action's resolved target hash
(already landed — §3). Under A-CR for the deployed target commitment, the
authorizing approval's minted part-list EQUALS the action's resolved
part-list: **a capability authorizes exactly the action it was minted for,
never a neighbor.** This is no-ambient-authority + no-confused-deputy
specialized to the seam the deployed broker actually crosses — the collapse
from structural targets to `Digest256` target commitments.

**Landed Lean statement (conclusion LOCKED = `pa = pg`):**

```lean
theorem approval_authorizes_only_its_target'
    (hACR : ∀ x y, Seal.stableHashString x = Seal.stableHashString y → x = y)
    (pa pg : List String)
    (now deadline : Nat)
    (hguard : SealCore.live
      { approved := (∅ : Std.HashMap SealCore.TargetHash Nat).insert
          (Seal.stableHashParts pa) deadline }
      (Seal.stableHashParts pg) now = true) :
    pa = pg
```

Notes: `Seal.stableHashParts : List String → SealCore.TargetHash`;
`Seal.stableHashString` is SHA-256 over `Seal.encodeParts`. The proof keeps
the hash opaque: `SealCore.approval_binds_to_target` gives target equality
from liveness, and `hACR` lifts that to part-list equality.

## 2. Authority map (recon, live-symbol-bound)

* **Minting (TCB):** Rust providers (`rust/src/providers.rs`) mint
  `ApprovalRecord { target: "<64 lowercase hex>", … }` via control-file / Ed25519
  signed-token / TTY. The host Ed25519 signed-token provider signs the exact
  `ApprovalRecord` JSON payload bytes; it is separate from the SealV2 kernel-defined
  `(target, session, issuedAt, expiry, nonce)` token path in `mcp-seal-dev`.
  `rust/src/a3.rs` freshness-filters every record (nonce-once per session, TTL,
  +5s future-skew, wall clock) before Lean sees it — `A3Filter`, fail-closed.
* **Checking (deployed path):** `Ffi.stepImpl` (`Ffi.lean:190`,
  string-in/string-out seam) → `Seal.classifyToolCall` resolves the call to
  `stableHashParts (toolName :: evalTargetParts rule.target args)`
  (`Seal/Classify.lean:32-51` — this is where the `literal`/`argPath`
  target-part split lives) → `SealCore.step`/`live`
  (`SealCore/Automaton.lean:20`): a **hash-keyed** `Std.HashMap
  TargetHash Nat` lookup. The deployed broker compares SHA-256 target digests.
  The deployed routing profile is `compatible`, not strict `canonical-l0`
  (CLAIMS.md: do not describe the deployed host as strict canonical-l0 — it is
  `compatible`; `canonical-l0` is implemented at the proof layer, not the
  deployed routing path).
* **Value model (SealV2):** `validate`/`ValidCapability`
  (`SealV2/Validation.lean:272-309`) compares full `Target` STRUCTS
  (`approval.target == target`, derived BEq over all fields including
  `arguments : AST`; `targetFor`:226 copies request fields whole). Used by
  the SealAdapter / NI / replay proofs.
* **The seam:** the two layers meet only at `stableHashParts`. The live theorem
  names the residual as A-CR over SHA-256 `stableHashString`; this is a
  cryptographic assumption, not a Lean axiom.
* **Delegation/attenuation: NO PRIMITIVE EXISTS** (grep-confirmed across
  the package and Host). Approvals are minted for one fully-instantiated
  target and matched by equality; nothing narrows, chains, or re-mints.
  "Attenuation-only delegation" would formalize a mechanism the broker does
  not have — rejected as the target, recorded here as a scope finding.
* **Signature:** `SealV2.SignatureVerified` (`Validation.lean:191`) is a
  Prop over `verifySignature`; in `mcp-seal-dev` that path calls real Ed25519
  over kernel-defined `(target, session, issuedAt, expiry, nonce)` bytes. This
  is not an RFC 8785/JCS claim; see
  [`CANONICAL-BYTE-CONTRACT.md`](CANONICAL-BYTE-CONTRACT.md). The host's
  NDJSON provider is also real Ed25519 (`ed25519-dalek`) but over exact
  `ApprovalRecord` JSON payload bytes. The trusted config envelope is a third,
  separate Ed25519 channel over exact config payload bytes, verified with the
  startup config `--pubkey`.

## 3. Subsumption verdict vs the landed slate

**Already landed (hash-level tracing + separation — cite, do not re-prove):**

| landed theorem | what it gives |
|---|---|
| `SealCore.no_allow_guarded_without_matching_approval_in_state` | allow ⇒ live (authority tracing at one step) |
| `SealCore.approval_binds_to_target` | hash≠ ⇒ not live (separation) |
| `SealCore.approval_not_transferable_across_targets` | the step-level refusal exemplar (single other approval ⇒ block) |
| `SealCore.consumed_approval_not_live` / `fresh_approval_live` / `expired_not_live` | one-shot + freshness discipline |
| `SealV2.decide_emit_unique` | value-level: every Allow carries a `ValidCapability` witness (held, session-bound, target-equal approval) |

**Novel residual (now named explicitly):** the **hash→value lift** — nothing
in Lean proves SHA-256 collision resistance. The theorem exposes that as
`hACR` over `Seal.stableHashString`; deployment makes the assumption
credible by using SHA-256 over the injective `encodeParts` bytes. NI (state
secrecy), ReplayIsolation (store isolation), GatedSinkAdapter O1∧O2 (channel
mediation) are orthogonal — none speak to authority binding across the hash
seam.

**Convergence note:** the old finite-universe adequacy probes were useful
for FNV-era scoping. The live deployment story is now the four-body
conformance chain: Lean model, native host, wasm, and JS mirrors all compute
the same SHA-256 target commitment.

## 4. Trust boundary (loud)

**Stays TCB (assumed, not proven):** grant-token unforgeability (Ed25519,
`providers.rs`, over exact `ApprovalRecord` JSON bytes); the wall clock, nonce replay set,
TTL, and skew (`a3.rs`); the C ABI seam + JSON marshalling (`Ffi.lean`,
`lean.rs`); OS permissions on config/approval files.

**The model PROVES:** authority tracing (allow ⇒ held live approval,
landed) and the A-CR-conditional binding (held approval for `pa` authorizes
an action resolving to `pg` only if `pa = pg`).

**Explicitly NOT a Lean axiom:** collision resistance of SHA-256. It remains
the named assurance-case hypothesis `hACR`; the old FNV path is confined to
`Seal.auditHashParts` for UInt64 audit/demo hashes.

## 5. Non-vacuity plan (build-gated exemplars)

1. **Held cap authorizes its target:** `fresh_approval_live` + a `step`
   allow on the same hash — concrete universe entry, `decide`/`rfl`.
2. **Not-held refused:** instance of `approval_binds_to_target` at two
   concrete distinct part-lists from the exemplar universe.
3. **Cross-approval refusal:** cite the landed
   `approval_not_transferable_across_targets` (already the
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
wired via an explicit `Test/Axioms.lean` import. This is a required acceptance
check, not a claim that every theorem-bearing module is already wired; the
current residual is recorded in `docs/LIMITATIONS.md`. Proposed home:
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
