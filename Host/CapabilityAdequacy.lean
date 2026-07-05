/- SPDX-License-Identifier: Apache-2.0 -/

import SealCore.Safety
import Seal.Hash
import Host.Encoding

/-!
# Capability adequacy — a held capability authorizes ONLY its own target
# (UNCONDITIONAL over all part-lists, modulo A-CR on the commitment)

The ARIA S6 ocap theorem, strengthened. The deployed broker authorizes by
target commitments (`Seal.stableHashParts` → `SealCore.live`), where
`stableHashParts parts = stableHashString (encodeParts parts)`. Since
mcp-seal e36fc98 the encoding is a self-delimiting netstring framing, and
`Host.Encoding.encodeParts_injective` PROVES it injective over ALL of
`List String`. That kills the encoding half of the collision surface
outright, which lets the capability result drop its former finite-universe
premise entirely:

* the OLD result was conditional on a finite policy universe `U` with a
  decidable `Adequate U` side condition and `pa ∈ U`, `pg ∈ U` — runtime
  part-lists are not confined to any finite `U`, so that premise was the
  documented residual;
* the NEW result `capability_sound_or_commitment_clash` has NO universe, NO
  membership premises, and NO assumption hypothesis: for ANY two part-lists,
  a held live approval for `pa` authorizing an action resolving to `pg`
  forces `pa = pg` — OR exhibits two provably DISTINCT encoded strings on
  which `stableHashString` agrees. Unconditionally true, kernel-checked.

## A-CR — the named commitment assumption (TCB, loud, NEVER an axiom)

The residual disjunct is exactly a `stableHashString` collision on distinct
pre-images. A-CR ("the commitment is collision-resistant: that clash is not
reachable") is the NAMED assurance-case assumption that discharges it —
consumed as an explicit hypothesis of `approval_authorizes_only_its_target'`,
never as a Lean `axiom`. It CANNOT be an axiom: `stableHashString` is a
fixed-width compression, so by counting it HAS agreeing distinct
inputs — a total-injectivity axiom would be FALSE and everything downstream
vacuous. The hypothesis form states the reduction honestly: authorization-
uniqueness holds MODULO A-CR on the commitment.

Quantitative honesty (model ↔ deployment gap): the DEPLOYED commitment is
SHA-256 over the injective `encodeParts` bytes. This module still names the
crypto residual as an explicit A-CR hypothesis; the deployment now makes
that assumption credible instead of relying on the old audit-only FNV path.

The proofs keep `Seal.stableHashParts` fully OPAQUE: no unfolding to
concrete values, no `decide` on hash values, no evaluation seam. The former
A-HASH-MIRROR scaffold (`natHash`/`targetHash`, the four `#guard` compiled-
eval bridges, `Adequate`/`demoU`) is deleted — the unconditional result
needs no finite-universe enumeration and no mirror.

## A-MINT — the explicit mint-faithfulness assumption (TCB, loud)

Unchanged from the landed module: the Rust minting side produces
`ApprovalRecord { target: "<64 lowercase hex>", … }`; the assumption that
the MINTED target equals `Seal.stableHashParts (toolName :: approvedParts)`
— same bytes, same part-list, across the FFI seam — is the named, visible
`MintFaithful` proposition, consumed as an explicit hypothesis.
(Deliberately NOT a Lean `axiom`: Rust structs are not objects of this
logic. Operationally exercised by the four-bodies conformance chain and
`host_path.rs`.)

## What is proved (this module)

* `capability_sound_or_commitment_clash` — UNCONDITIONAL: authorization
  forces `pa = pg`, or names the only escape (a `stableHashString` clash on
  provably distinct encodings). No universe, no assumption hypotheses.
* `approval_authorizes_only_its_target'` — the uniqueness conclusion under
  the scoped, visible A-CR hypothesis.
* `minted_approval_authorizes_only_its_target'` — the same through the
  visible `MintFaithful` seam hypothesis.
* (imported) `Host.Encoding.encodeParts_injective` — the structural crux:
  the netstring encoding is injective over all part-lists.

Kernel proofs only — no `native_decide`, no new axioms, no edit to the
frozen `mcp-seal` package; the landed `SealCore.approval_binds_to_target`
is cited, not re-proved.
-/

namespace Host.CapabilityAdequacy

/-- **A-MINT (TCB assumption, made visible).** The minted approval target
(`ApprovalRecord.target : 64 lowercase hex` on the Rust side) is exactly the deployed
commitment of the labeled part-list — same bytes across the FFI seam.
Consumed as an explicit hypothesis; see the module docstring. -/
def MintFaithful (minted : SealCore.TargetHash) (toolName : String)
    (parts : List String) : Prop :=
  minted = Seal.stableHashParts (toolName :: parts)

/-- From the live-gate guard, the two target commitments agree. The
commitment stays OPAQUE: this is the contrapositive of the landed
`SealCore.approval_binds_to_target`, no hash value is ever computed. -/
private theorem hash_eq_of_live
    (pa pg : List String) (now deadline : Nat)
    (hguard : SealCore.live
      { approved := (∅ : Std.HashMap SealCore.TargetHash Nat).insert
          (Seal.stableHashParts pa) deadline }
      (Seal.stableHashParts pg) now = true) :
    Seal.stableHashParts pa = Seal.stableHashParts pg := by
  cases h : decide (Seal.stableHashParts pa = Seal.stableHashParts pg) with
  | true => exact of_decide_eq_true h
  | false =>
      have hne := of_decide_eq_false h
      have hdead := SealCore.approval_binds_to_target now deadline
        (Seal.stableHashParts pa) (Seal.stableHashParts pg) hne
      rw [hdead] at hguard
      exact Bool.noConfusion hguard

/-- **The unconditional reduction (no universe, no assumption premises).**
A held live approval for part-list `pa` authorizing an action resolving to
part-list `pg` forces `pa = pg` — or exhibits the ONLY residual path: two
provably DISTINCT encoded strings on which the fixed-width commitment
`Seal.stableHashString` agrees (a genuine commitment collision). The
disjunction is unconditionally TRUE for ALL part-lists; nothing confines
`pg` to a policy universe.

Honesty: the second disjunct is exactly what A-CR (see module docstring)
asserts to be unreachable. It is kept as a visible disjunct rather than
discharged by an axiom, because for a fixed-width commitment a total-
injectivity axiom is FALSE by counting. The deployed commitment is SHA-256;
the named residual remains an explicit crypto assumption, not a Lean axiom. -/
theorem capability_sound_or_commitment_clash
    (pa pg : List String) (now deadline : Nat)
    (hguard : SealCore.live
      { approved := (∅ : Std.HashMap SealCore.TargetHash Nat).insert
          (Seal.stableHashParts pa) deadline }
      (Seal.stableHashParts pg) now = true) :
    pa = pg ∨
    (Seal.encodeParts pa ≠ Seal.encodeParts pg ∧
     Seal.stableHashString (Seal.encodeParts pa)
       = Seal.stableHashString (Seal.encodeParts pg)) := by
  have hhash := hash_eq_of_live pa pg now deadline hguard
  cases h : decide (pa = pg) with
  | true => exact Or.inl (of_decide_eq_true h)
  | false =>
      refine Or.inr ⟨?_, hhash⟩
      intro henc
      exact of_decide_eq_false h (Host.Encoding.encodeParts_injective henc)

/-- **Authorization uniqueness, modulo A-CR on the commitment.** Under the
scoped, VISIBLE collision-resistance hypothesis `hACR` for
`Seal.stableHashString` (the named assurance-case assumption A-CR — an
explicit argument, deliberately never an in-Lean axiom; see the module
docstring for why an axiom here would be false), a held capability
authorizes exactly the part-list it was minted for, for ALL part-lists —
no finite universe, no membership side conditions. -/
theorem approval_authorizes_only_its_target'
    (hACR : ∀ x y, Seal.stableHashString x = Seal.stableHashString y → x = y)
    (pa pg : List String) (now deadline : Nat)
    (hguard : SealCore.live
      { approved := (∅ : Std.HashMap SealCore.TargetHash Nat).insert
          (Seal.stableHashParts pa) deadline }
      (Seal.stableHashParts pg) now = true) : pa = pg := by
  rcases capability_sound_or_commitment_clash pa pg now deadline hguard with
    heq | ⟨hne, hclash⟩
  · exact heq
  · exact absurd (hACR _ _ hclash) hne

/-- **The uniqueness conclusion through the mint seam.** Same as
`approval_authorizes_only_its_target'`, with the A-MINT trust-boundary
assumption as an explicit, visible hypothesis: IF the Rust-minted target is
faithfully the commitment of its labeled part-list, THEN the minted
approval authorizes only that part-list — for ALL resolving part-lists,
modulo A-CR. -/
theorem minted_approval_authorizes_only_its_target'
    (hACR : ∀ x y, Seal.stableHashString x = Seal.stableHashString y → x = y)
    (toolName : String) (parts pg : List String)
    (minted : SealCore.TargetHash) (hmint : MintFaithful minted toolName parts)
    (now deadline : Nat)
    (hguard : SealCore.live
      { approved := (∅ : Std.HashMap SealCore.TargetHash Nat).insert minted deadline }
      (Seal.stableHashParts pg) now = true) : toolName :: parts = pg := by
  rw [MintFaithful] at hmint
  rw [hmint] at hguard
  exact approval_authorizes_only_its_target' hACR (toolName :: parts) pg
    now deadline hguard

end Host.CapabilityAdequacy
