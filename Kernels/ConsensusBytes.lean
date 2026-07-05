/- SPDX-License-Identifier: Apache-2.0 -/

import Kernels.Consensus
import SealV2.Serialization

/-!
# W2-T2 — Consensus over canonical bytes (model-level kernel)

The DEPLOYED consensus kernel votes on the TOOL NAME
(`Kernels.consensusKernel`, `quorumAccepts cfg.roster votes act.tool` — G3
binding granularity). This module is the model-level upgrade the wave brief
asks for: a quorum that ratifies the CANONICAL OUTPUT BYTES of the action, so
that "the forwarded bytes are exactly what the quorum agreed on" is a theorem,
not a convention.

Same discipline as the compatible-vs-canonicalL0 profile split: ADDITIVE — the
deployed kernel is untouched; do not describe the deployed host as
byte-quorum-gated.

Frozen operational semantics (WAVE2-STATEMENTS.md, W2-T2):
* a vote is `(acceptor : Nat, value : String)` — `Consensus.Checker.Votes`,
  unchanged; the value string IS the canonical byte string
  (`SealV2.CanonicalBytes := String`, so the proved checker applies
  byte-valued with zero new checker code);
* the agreed value is `(certFor votes bytes).value` (definitionally `bytes`);
* the threshold is the deployed strict majority of `Consensus.Checker.validB`
  (Nodup voters, roster membership, matching recorded votes,
  `members.length < 2 * voters.length`).

TRUST BOUNDARY: vote authenticity/transport is TCB, as for the deployed
kernel (roster = trusted config, votes = gathered evidence). The byte binding
is meaningful under the `canonicalL0` profile (see `Host/CompositionBytes.lean`);
the deployed `compatible` profile does not gate on canonical bytes.
-/

namespace Kernels

open Consensus.Checker

/-- The canonical bytes a mediated call commits to, when it carries a
    canonical parse witness. `SealV2.serializeAstValue` is total on `AST`;
    for `ast?` populated by `classifyLine` the witness is a genuine canonical
    parse (`SealV2.parse_returns_canonical`). -/
def canonicalBytesOf (a : Host.CanonicalAction) : Option SealV2.CanonicalBytes :=
  a.ast?.map SealV2.serializeAstValue

/-- Byte-quorum acceptance: the proved checker accepts a strict-majority
    certificate whose claimed value is the canonical bytes. `validB` re-checks
    every conjunct, so the untrusted `certFor` construction can only fail,
    never smuggle an allow (same argument as the deployed kernel). -/
def byteQuorumAccepts (roster : List Nat) (votes : Votes)
    (bytes : SealV2.CanonicalBytes) : Bool :=
  validB roster votes (certFor votes bytes)

/-- Kernel C-bytes — the byte-quorum Consensus Seal (MODEL-LEVEL). Gates the
    configured high-stakes tools; allows iff the act carries a canonical
    witness AND a strict-majority quorum ratified exactly its canonical
    bytes. Fail-closed on a missing witness. NOT the deployed kernel. -/
def byteConsensusKernel : Host.Kernel where
  name := "consensus-bytes"
  Config := ConsensusConfig
  Evidence := Votes
  State := Unit
  init := ()
  gates := fun cfg act => cfg.highStakes.contains act.tool
  ingest := fun _ st => st
  decide := fun act cfg votes st =>
    match canonicalBytesOf act with
    | none =>
        let reason := s!"no canonical witness: {act.tool}"
        ({ kernel := "consensus-bytes", kind := .deny, reason,
           certHash := Seal.auditHashParts ["consensus-bytes", "deny", reason] }, st)
    | some bytes =>
        if byteQuorumAccepts cfg.roster votes bytes then
          let reason := s!"byte quorum ok: {act.tool}"
          ({ kernel := "consensus-bytes", kind := .allow, reason,
             certHash := Seal.auditHashParts ["consensus-bytes", "allow", reason] }, st)
        else
          let reason := s!"byte quorum missing: {act.tool}"
          ({ kernel := "consensus-bytes", kind := .deny, reason,
             certHash := Seal.auditHashParts ["consensus-bytes", "deny", reason] }, st)

/-- Bridge for the composition theorems, mirroring
    `consensus_verdict_allow_iff`: kernel C-bytes allows exactly when the act
    carries a canonical witness whose bytes a strict-majority quorum
    ratified. -/
theorem byteConsensus_verdict_allow_iff
    (act : Host.CanonicalAction) (cfg : ConsensusConfig)
    (votes : Votes) (st : Unit) :
    (byteConsensusKernel.decide act cfg votes st).1.kind = .allow ↔
      ∃ bytes, canonicalBytesOf act = some bytes ∧
        byteQuorumAccepts cfg.roster votes bytes = true := by
  cases hb : canonicalBytesOf act with
  | none =>
      simp only [byteConsensusKernel, hb]
      constructor
      · intro h; cases h
      · rintro ⟨bytes, hbytes, -⟩
        simp at hbytes
  | some bytes =>
      simp only [byteConsensusKernel, hb]
      by_cases hq : byteQuorumAccepts cfg.roster votes bytes <;> simp [hq]

/-- Fail-closed branch is live: no canonical witness ⇒ deny, whatever the
    votes say. -/
theorem byteConsensus_denies_without_witness
    (act : Host.CanonicalAction) (hast : act.ast? = none)
    (cfg : ConsensusConfig) (votes : Votes) :
    (byteConsensusKernel.decide act cfg votes ()).1.kind = .deny := by
  simp [byteConsensusKernel, canonicalBytesOf, hast]

/-- **Byte-uniqueness of agreement (W2-T2 conjunct iii).** Two accepted
    byte-quorums against the same roster and votes ratify byte-identical
    values — `Consensus.Checker.agreement` at byte-valued certs, noting
    `(certFor votes b).value = b` definitionally. -/
theorem byte_quorum_agreement (roster : List Nat) (votes : Votes)
    (b b' : SealV2.CanonicalBytes)
    (h : byteQuorumAccepts roster votes b = true)
    (h' : byteQuorumAccepts roster votes b' = true) : b = b' :=
  Consensus.Checker.agreement roster votes (certFor votes b) (certFor votes b') h h'

/-! ## Non-vacuity: the byte-quorum is live on both sides

Checker-level exemplars over tiny concrete rosters/votes — kernel-cheap
(short `Nat`/`String` lists, no `SealV2.parse` anywhere). -/

/-- A concrete canonical byte string (content immaterial to the checker). -/
def exBytes : SealV2.CanonicalBytes := "{\"a\":1}"

/-- 2-of-3 strict majority on byte-identical values: accepted. -/
theorem byteQuorum_accepts_majority :
    byteQuorumAccepts [1, 2, 3] [(1, exBytes), (2, exBytes), (3, "other")] exBytes
      = true := by decide

/-- 1-of-3 is no majority: rejected. -/
theorem byteQuorum_rejects_minority :
    byteQuorumAccepts [1, 2, 3] [(1, exBytes)] exBytes = false := by decide

end Kernels
