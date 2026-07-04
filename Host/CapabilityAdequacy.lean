/- SPDX-License-Identifier: Apache-2.0 -/

import SealCore.Safety
import Seal.Hash

/-!
# Capability adequacy — a held capability authorizes ONLY its own target

The ARIA S6 ocap theorem scoped in `docs/CAPABILITY-STATEMENTS.md`
(council-settled Q1–Q5): the deployed broker authorizes by FNV-1a-64 target
hashes (`Seal.stableHashParts` → `SealCore.live`), so the only
confused-deputy channel is a hash collision between distinct resolvable
part-lists. This module proves: on any *hash-adequate* finite part-list
universe `U` (injectivity of the deployed hash on `U` — a DECIDABLE,
per-deployment side condition), a held live approval minted for part-list
`pa` authorizes an action resolving to `pg` only if `pa = pg`. The
conditional theorem ships as a DISCHARGED PAIR: `demoU_mirror_adequate`
proves the side condition by kernel `decide` at the computable hash mirror
for the shipped demo policy's real part-lists, and `demoU_adequate`
transfers it to `Adequate demoU` through the single named A-HASH-MIRROR
seam (below).

## A-MINT — the explicit mint-faithfulness assumption (TCB, loud)

The Rust minting side (`rust/src/providers.rs`) produces
`ApprovalRecord { target: u64, … }`. The theorems below speak about hashes
already inside Lean; the assumption that the MINTED `u64` equals
`Seal.stableHashParts (toolName :: approvedParts)` — same bytes, same
part-list, across the FFI seam — is a TRUST-BOUNDARY assumption, not a
theorem. It is stated here as the named, visible `MintFaithful` proposition
and consumed as an EXPLICIT HYPOTHESIS of
`minted_approval_authorizes_only_its_target`, so a reviewer sees exactly
where it enters. (It is deliberately NOT a Lean `axiom`: Rust structs are
not objects of this logic, so an axiom would either be unstatable or
vacuous; the hypothesis form is the honest formalization, and it keeps the
axiom environment clean. Operationally the assumption is exercised by the
four-bodies conformance chain and `host_path.rs`, which round-trips minted
targets through the live gate.)

## A-HASH-MIRROR — the evaluation seam (toolchain limitation, loud)

In Lean v4.28, `String.foldl` is iterator/WF-compiled: it does NOT reduce in
the kernel, and core ships no `String.foldl ↔ toList.foldl` lemma — so
`Seal.stableHashParts` (frozen, not editable) admits NO in-logic evaluation
whatsoever without `native_decide` (banned here). Consequently the council
amendment's literal `Adequate demoU := by decide` is impossible in this
toolchain. The honest resolution, following the repo's canonical-l0
precedent (dup-key: infeasible-as-theorem → `#guard`, flagged):

* `natHash`/`targetHash` — the SAME FNV-1a-64 fold over `toList`
  (structural, kernel-reducible; verified by probe).
* `demoU_mirror_adequate` — the adequacy discharge, UNCONDITIONAL, kernel
  `decide`, at the mirror.
* Four build-gated `#guard`s — compiled-evaluation evidence (the same
  semantics the deployed binary runs) that the deployed hash equals the
  mirror on every discharge-universe entry. Evidence, not theorem; adds no
  axiom to anything.
* `adequate_of_mirror` + `demoU_adequate` — the transfer to
  `Adequate demoU`, conditional on exactly that four-entry agreement, so a
  future hand-proved `String.foldl` bridge (or a toolchain that computes
  it) discharges the last hypothesis with zero restatement.

One seam, named, gated, and transfer-ready — not hidden inside a stuck
`decide`.

## The residual, loudly (do not misread the theorem)

`Seal.evalTargetParts` (`Seal/Classify.lean:32-36`) resolves `.argPath`
parts from RAW request-argument scalars, so at runtime the guarded
part-list `pg` is NOT confined to any finite universe. This theorem
protects exactly the declared universe: `pg ∈ U` is load-bearing. An
attacker-supplied out-of-universe `pg'` with `stableHashParts pg' =
stableHashParts pa` would be authorized by `pa`'s approval — FNV-1a-64 is
neither collision- nor preimage-resistant, and NO collision-resistance
claim is made here. That event is a POLICY-COVERAGE failure (the
deployment's labeled universe missed a resolvable part-list), not a bypass
of this theorem. The operational counterpart is
`seal adequacy check` / `seal adequacy find-collision` in the assurance
kit: same property, deployment-side probe.

## What is proved (this module)

* `Adequate U` — decidable hash-injectivity on a finite universe.
* `approval_authorizes_only_its_target` — the frozen statement, conclusion
  `pa = pg` (contrapositive of the landed
  `SealCore.approval_binds_to_target` + the adequacy lift).
* `minted_approval_authorizes_only_its_target` — the same through the
  visible `MintFaithful` seam hypothesis.
* `demoU_mirror_adequate` (kernel `decide`, unconditional) +
  `demoU_adequate` (transfer through A-HASH-MIRROR) — the discharge for
  `demoU`, the shipped demo policy's real part-lists (`db.execute` target
  spec `[db, arg:database, write, arg:sql]` instantiated at the demo's
  actual calls: `scripts/receipt_demo.sh`, `rust/tests/host_path.rs`).
* Non-vacuity: `demo_held_capability_authorizes` (a held fresh approval
  yields a step-allow on its own target — via the landed
  `fresh_approval_live` + `guarded_allow_iff_live`, no `Std.HashMap`
  kernel evaluation) and `demo_cross_capability_refused` (two distinct
  in-universe part-lists: the approval for one leaves the other dead —
  hash inequality by kernel `decide`).

Kernel `decide` only — no `native_decide` anywhere. No edit to the frozen
`mcp-seal` package or any landed theorem; the landed SealCore results are
cited, not re-proved.
-/

namespace Host.CapabilityAdequacy

/-- The deployment's part-list universe is hash-adequate: the deployed
FNV-1a-64 target hash (`Seal.stableHashParts`) is injective ON THIS
UNIVERSE. Decidable for any finite `U` — discharged per deployment by
kernel `decide` (see `demoU_adequate`). -/
def Adequate (U : List (List String)) : Prop :=
  ∀ pa ∈ U, ∀ pg ∈ U,
    Seal.stableHashParts pa = Seal.stableHashParts pg → pa = pg

instance (U : List (List String)) : Decidable (Adequate U) := by
  unfold Adequate; infer_instance

/-- **A-MINT (TCB assumption, made visible).** The minted approval target
(`ApprovalRecord.target : u64` on the Rust side) is exactly the deployed
hash of the labeled part-list — same bytes across the FFI seam. Consumed
as an explicit hypothesis; see the module docstring. -/
def MintFaithful (minted : SealCore.Hash) (toolName : String)
    (parts : List String) : Prop :=
  minted = Seal.stableHashParts (toolName :: parts)

/-- **The capability theorem (frozen statement, conclusion locked).** On a
hash-adequate universe, a held live approval for part-list `pa` authorizes
an action resolving to part-list `pg` only if `pa = pg`: a capability
authorizes exactly the action it was minted for, never a neighbor. -/
theorem approval_authorizes_only_its_target
    (U : List (List String)) (hadq : Adequate U)
    (pa pg : List String) (hpa : pa ∈ U) (hpg : pg ∈ U)
    (now deadline : Nat)
    (hlive : SealCore.live
      { approved := (∅ : Std.HashMap SealCore.Hash Nat).insert
          (Seal.stableHashParts pa) deadline }
      (Seal.stableHashParts pg) now = true) : pa = pg := by
  have hhash : Seal.stableHashParts pa = Seal.stableHashParts pg := by
    cases h : decide (Seal.stableHashParts pa = Seal.stableHashParts pg) with
    | true => exact of_decide_eq_true h
    | false =>
        have hne := of_decide_eq_false h
        have hdead := SealCore.approval_binds_to_target now deadline
          (Seal.stableHashParts pa) (Seal.stableHashParts pg) hne
        rw [hdead] at hlive
        exact Bool.noConfusion hlive
  exact hadq pa hpa pg hpg hhash

/-- **The capability theorem through the mint seam.** Same conclusion, with
the A-MINT trust-boundary assumption as an explicit, visible hypothesis:
IF the Rust-minted target is faithfully the hash of its labeled part-list,
THEN the minted approval authorizes only that part-list. -/
theorem minted_approval_authorizes_only_its_target
    (U : List (List String)) (hadq : Adequate U)
    (toolName : String) (parts pg : List String)
    (minted : SealCore.Hash) (hmint : MintFaithful minted toolName parts)
    (hpa : (toolName :: parts) ∈ U) (hpg : pg ∈ U)
    (now deadline : Nat)
    (hlive : SealCore.live
      { approved := (∅ : Std.HashMap SealCore.Hash Nat).insert minted deadline }
      (Seal.stableHashParts pg) now = true) : toolName :: parts = pg := by
  rw [MintFaithful] at hmint
  rw [hmint] at hlive
  exact approval_authorizes_only_its_target U hadq (toolName :: parts) pg
    hpa hpg now deadline hlive

/-- Kernel-computable mirror of the deployed hash: the same FNV-1a-64 fold,
expressed over `toList` (structural `List.foldl` — kernel-reducible; probes
P4/P6). `String.foldl` itself is iterator/WF-compiled in Lean v4.28 and does
NOT kernel-reduce, so no in-logic evaluation of `Seal.stableHashParts` is
possible without `native_decide` — see the A-HASH-MIRROR section of the
module docstring. -/
def natHash (l : List String) : Nat :=
  ("|".intercalate l).toList.foldl
    (fun acc ch => ((acc * 1099511628211) + ch.val.toNat) % 18446744073709551616)
    14695981039346656037

/-- The mirror as a `SealCore.Hash`. Fully kernel-computable. -/
def targetHash (l : List String) : SealCore.Hash :=
  UInt64.ofNat (natHash l)

/-- **A-HASH-MIRROR transfer.** If the deployed hash agrees with the
computable mirror on `U` (the named seam — carried by build-gated `#guard`
evidence below, or by a future hand-proved `String.foldl` bridge), then
mirror-level adequacy transfers to `Adequate U`. -/
theorem adequate_of_mirror (U : List (List String))
    (hm : ∀ l ∈ U, Seal.stableHashParts l = targetHash l)
    (h : ∀ pa ∈ U, ∀ pg ∈ U, targetHash pa = targetHash pg → pa = pg) :
    Adequate U := by
  intro pa hpa pg hpg hh
  rw [hm pa hpa, hm pg hpg] at hh
  exact h pa hpa pg hpg hh

/-- The shipped demo policy's REAL part-lists: the `db.execute` target spec
`[literal db, arg database, literal write, arg sql]`
(`config/trusted.example.json`) instantiated at the demo's actual calls
(`scripts/receipt_demo.sh` lines 56-58, `rust/tests/host_path.rs`
"drop table accounts"). -/
def demoU : List (List String) :=
  [["db.execute", "db", "prod", "write", "drop table customers"],
   ["db.execute", "db", "prod", "write", "delete from ledger"],
   ["db.execute", "db", "prod", "write", "truncate audit"],
   ["db.execute", "db", "prod", "write", "drop table accounts"]]

/-- **The kernel discharge (unconditional).** Mirror-level adequacy for the
shipped demo universe — kernel `decide`, no `native_decide`: the hash
separates every pair of really-deployed targets. -/
theorem demoU_mirror_adequate :
    ∀ pa ∈ demoU, ∀ pg ∈ demoU, targetHash pa = targetHash pg → pa = pg := by
  decide

-- Build-gated A-HASH-MIRROR evidence on exactly the discharge universe:
-- compiled evaluation (the same semantics the deployed binary runs) of the
-- deployed hash agrees with the mirror entry-by-entry. Evidence, not
-- theorem — the canonical-l0 `#guard` precedent; NO axiom enters any proof.
#guard Seal.stableHashParts ["db.execute", "db", "prod", "write", "drop table customers"]
  == targetHash ["db.execute", "db", "prod", "write", "drop table customers"]
#guard Seal.stableHashParts ["db.execute", "db", "prod", "write", "delete from ledger"]
  == targetHash ["db.execute", "db", "prod", "write", "delete from ledger"]
#guard Seal.stableHashParts ["db.execute", "db", "prod", "write", "truncate audit"]
  == targetHash ["db.execute", "db", "prod", "write", "truncate audit"]
#guard Seal.stableHashParts ["db.execute", "db", "prod", "write", "drop table accounts"]
  == targetHash ["db.execute", "db", "prod", "write", "drop table accounts"]

/-- **The discharged pair, honestly conditioned.** `Adequate demoU` holds
given the A-HASH-MIRROR instance on the four demo entries — the single
named seam, whose compiled-semantics truth is `#guard`-gated above. All
other content (mirror adequacy, the capability theorem itself) is
unconditional. -/
theorem demoU_adequate
    (hm : ∀ l ∈ demoU, Seal.stableHashParts l = targetHash l) :
    Adequate demoU :=
  adequate_of_mirror demoU hm demoU_mirror_adequate

/-- **Non-vacuity (authorize half).** A held fresh approval for a real demo
target yields a step-allow on exactly that target — via the landed
`fresh_approval_live` + `guarded_allow_iff_live`; no `Std.HashMap` kernel
evaluation. -/
theorem demo_held_capability_authorizes :
    (SealCore.step 1000
      (SealCore.step 1000 { approved := ∅ }
        (.approval (targetHash
          ["db.execute", "db", "prod", "write", "drop table customers"]) 2000)).2
      (.guarded (targetHash
        ["db.execute", "db", "prod", "write", "drop table customers"]))).1
      = SealCore.Decision.allow := by
  rw [SealCore.guarded_allow_iff_live]
  exact SealCore.fresh_approval_live 1000 2000 _ _ (by decide)

/-- **Non-vacuity (refusal half).** Two distinct really-deployed part-lists:
the approval minted for one leaves the other dead — the landed separation
theorem at a real pair, hash inequality by kernel `decide`. -/
theorem demo_cross_capability_refused :
    SealCore.live
      { approved := (∅ : Std.HashMap SealCore.Hash Nat).insert
          (targetHash ["db.execute", "db", "prod", "write", "drop table customers"]) 2000 }
      (targetHash ["db.execute", "db", "prod", "write", "delete from ledger"]) 1000
      = false :=
  SealCore.approval_binds_to_target 1000 2000 _ _ (by decide)

end Host.CapabilityAdequacy
