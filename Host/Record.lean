/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Hash
import Host.Audit
import Host.Sha256

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

The structure is stated over an arbitrary commitment type `α`, so it
instantiates both at the legacy `UInt64` demo commitment (`chainHash`) and at
the PRODUCTION commitment (`prodChainHash`): the same
`sha256(prevHead || 0x1f || payload)` chain over hex-string heads that the
deployed Rust host emits (`rust/src/receipt.rs`, `scripts/seal_log.mjs`).
Byte-agreement of the Lean `prodChainHash` with the deployed Rust chain is
build-gated below on the reference golden vectors.

TCB / honesty note: SHA-256 collision-resistance is NOT proven in Lean —
`A-CR` remains the named crypto TCB assumption, exactly as before. What is
newly machine-checked is that the Lean MODEL emits the SAME BYTES as the
deployed Rust/reference chain, so `tamper_evident` is now instantiated at the
real production commitment rather than only the demo FNV one.
-/

namespace Host.Record

open SealCore  -- `Hash := UInt64`
open Host.Sha256 (sha256Hex)

/-- The decision log: a list of audit payloads, MOST-RECENT-FIRST. Each payload
    is exactly what `Host.auditLine` emits for one mediated decision —
    including its `request_sha256` commitment to the judged line. -/
abbrev Log := List String

/-- Rolling chain head, over an arbitrary commitment type `α`. The newest
    entry (list head) is the OUTERMOST commitment, so appending a decision is
    a `cons` and the new head commits the new payload over the UNCHANGED prior
    head. -/
def rollingHead {α : Type} (H : α → String → α) (genesis : α) : Log → α
  | []              => genesis
  | newest :: older => H (rollingHead H genesis older) newest

/-- **APPEND-ONLY.** Committing a new decision extends the chain: the new head
    is the commitment of the new payload over the prior head, which appears
    unchanged as a subterm. Appending cannot alter any existing entry or its
    head. (No assumption; definitional.) -/
theorem head_after_append {α : Type}
    (H : α → String → α) (genesis : α) (older : Log) (newest : String) :
    rollingHead H genesis (newest :: older)
      = H (rollingHead H genesis older) newest := rfl

/-- **TAMPER-EVIDENCE (CORE).** Under a collision-free commitment (`A-CR`) and a
    fresh genesis (`A-GEN`), the chain head is an INJECTIVE function of the
    entire log: two logs with equal heads are identical. Contrapositive — the
    ship claim — any insert, reorder, or mutation changes the log, hence
    changes the head, hence is detected. -/
theorem tamper_evident {α : Type}
    (H : α → String → α) (genesis : α)
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

/-- Cheap legacy/demo commitment — the `α := UInt64` instantiation of the
    chain structure: commit the prior `UInt64` head (as its canonical decimal
    string) with the payload via the explicit legacy audit hash.
    `Seal.auditHashParts` is FNV-1a/`UInt64`, so it does NOT satisfy `A-CR`.
    The deployed receipt commitment is the SHA-256 chain (`prodChainHash`). -/
def chainHash (prevHead : Hash) (payload : String) : Hash :=
  Seal.auditHashParts [toString prevHead.toNat, payload]

/-- **PRODUCTION commitment** — the `α := String` instantiation, mirroring
    `rust/src/receipt.rs` byte-for-byte: the prior head as its 64-character
    lowercase hex STRING (not raw digest bytes), a single 0x1f unit-separator
    byte, then the payload; hashed with SHA-256
    (`COMMITMENT = "sha256(prevHead || 0x1f || payload)"`).

    Honesty: `A-CR` for SHA-256 is assumed, not proven (named crypto TCB).
    What IS machine-checked (golden vectors below) is that this Lean function
    emits the same bytes as the deployed Rust `sha2` v0.10 chain. -/
def prodChainHash (prevHead : String) (payload : String) : String :=
  sha256Hex (prevHead.toUTF8 ++ ByteArray.mk #[0x1f] ++ payload.toUTF8)

/-- Production genesis head: `sha256("seal-verifiable-record/genesis/v1")`,
    mirroring `rust/src/receipt.rs::genesis()`. -/
def prodGenesis : String :=
  sha256Hex "seal-verifiable-record/genesis/v1".toUTF8

/-! ## Reference conformance (build-gated compiled evaluation)

Golden vectors from the deployed Rust chain (`rust/src/receipt.rs` tests,
`sha2` v0.10). A bare `lake build` fails on any byte mismatch. -/

/-- info: true -/
#guard_msgs in #eval
  prodGenesis == "0633b0b4c5ca8207b3174d64fe438b99eaa1f5d95d0d4bbaa5d3fe6bd5f700a9"

/-- info: true -/
#guard_msgs in #eval
  prodChainHash prodGenesis "audit-0"
    == "8dd24f08c8674e9b7b950837337c93d09d5240e1aedbb7d54269ee9381b84a4c"

end Host.Record
