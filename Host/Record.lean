/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Hash
import Host.Audit

/-!
# The verifiable record — append-only, tamper-evident decision log (L1 CORE)

L0 proves the four-gate non-bypass over the deployed step core
(`Host.step_forward_non_bypass`). This module climbs one level: it proves the
LOG of those decisions is a hash-chain that is append-only and tamper-evident.

The chain head is an injective function of the entire log **relative to** the
collision-resistance of the commitment `H` (assumption `A-CR`) and a fresh
genesis (`A-GEN`). This is the standard crypto-proof discipline: the STRUCTURE
is machine-checked; the PRIMITIVE's collision-resistance is a named TCB
assumption — exactly as Ed25519-correctness is TCB(A3) in the L0 proofs.

TCB / honesty note: the deploy instance `chainHash` uses `Seal.stableHashParts`
(FNV-1a into `UInt64`). A 64-bit hash is NOT collision-resistant — `A-CR` is
literally false for it — so the deployed instance is **demonstration-grade**;
production must discharge `A-CR` by swapping in a real CR hash (e.g. SHA-256).
The abstract theorems below hold for any `H` that does satisfy `A-CR`.
-/

namespace Host.Record

open SealCore  -- `Hash := UInt64`

/-- The decision log: a list of audit payloads, MOST-RECENT-FIRST. Each payload
    is exactly what `Host.auditLine` emits for one mediated decision. -/
abbrev Log := List String

/-- Rolling chain head. The newest entry (list head) is the OUTERMOST
    commitment, so appending a decision is a `cons` and the new head commits
    the new payload over the UNCHANGED prior head. -/
def rollingHead (H : Hash → String → Hash) (genesis : Hash) : Log → Hash
  | []              => genesis
  | newest :: older => H (rollingHead H genesis older) newest

/-- **APPEND-ONLY.** Committing a new decision extends the chain: the new head
    is the commitment of the new payload over the prior head, which appears
    unchanged as a subterm. Appending cannot alter any existing entry or its
    head. (No assumption; definitional.) -/
theorem head_after_append
    (H : Hash → String → Hash) (genesis : Hash) (older : Log) (newest : String) :
    rollingHead H genesis (newest :: older)
      = H (rollingHead H genesis older) newest := rfl

/-- **TAMPER-EVIDENCE (CORE).** Under a collision-free commitment (`A-CR`) and a
    fresh genesis (`A-GEN`), the chain head is an INJECTIVE function of the
    entire log: two logs with equal heads are identical. Contrapositive — the
    ship claim — any insert, reorder, or mutation changes the log, hence
    changes the head, hence is detected. -/
theorem tamper_evident
    (H : Hash → String → Hash) (genesis : Hash)
    (hinj : ∀ a b p q, H a p = H b q → a = b ∧ p = q)   -- A-CR : collision-resistance
    (hgen : ∀ a p, H a p ≠ genesis)                      -- A-GEN: fresh genesis
    (l₁ l₂ : Log)
    (hhead : rollingHead H genesis l₁ = rollingHead H genesis l₂) :
    l₁ = l₂ := by
  induction l₁ generalizing l₂ with
  | nil =>
      cases l₂ with
      | nil => rfl
      | cons q qs =>
          -- genesis = H (rollingHead … qs) q contradicts A-GEN
          simp only [rollingHead] at hhead
          exact absurd hhead.symm (hgen _ _)
  | cons p ps ih =>
      cases l₂ with
      | nil =>
          simp only [rollingHead] at hhead
          exact absurd hhead (hgen _ _)
      | cons q qs =>
          simp only [rollingHead] at hhead
          obtain ⟨hheads, hpq⟩ := hinj _ _ _ _ hhead
          rw [hpq, ih qs hheads]

/-- The deployed commitment: chain the prior head (as its canonical decimal
    string) with the payload, via the V1 stable hash. **Demonstration-grade**:
    `Seal.stableHashParts` is FNV-1a/`UInt64`, so it does NOT satisfy `A-CR`
    (64-bit ⇒ collisions exist). Production discharges `A-CR` with a CR hash. -/
def chainHash (prevHead : Hash) (payload : String) : Hash :=
  Seal.stableHashParts [toString prevHead.toNat, payload]

end Host.Record
