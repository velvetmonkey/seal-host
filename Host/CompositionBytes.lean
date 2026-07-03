/- SPDX-License-Identifier: Apache-2.0 -/

import Host.CanonicalL0
import Host.Composition
import Kernels.ConsensusBytes

/-!
# W2-T2 — Byte-quorum on forward: the seam theorems (canonicalL0 model)

`Kernels/ConsensusBytes.lean` defines the model-level byte-quorum kernel.
This module composes it with the strict `canonicalL0` routing profile and
proves the frozen W2-T2 conclusions (WAVE2-STATEMENTS.md):

* **(i) quorum on byte-identical canonical output** — a `canonicalL0` forward
  with the byte-consensus verdict among the combined verdicts implies a
  strict-majority `validB` quorum ratified exactly the forwarded action's
  canonical bytes (`forward_high_stakes_byte_quorum`);
* **(ii) forwarded bytes = agreed bytes** — the ratified certificate's value
  IS the canonical serialization of the forwarded action's parse witness
  (same theorem, last conjunct — definitional from `certFor`);
* **(iii) uniqueness** — two such forwards under the same roster and votes
  carry byte-identical canonical payloads (`composed_byte_agreement`, via
  `Consensus.Checker.agreement`).

SCOPE (stated loud): `canonicalL0` profile at the proof layer. The DEPLOYED
profile is `compatible` and its consensus kernel votes on tool names — see
the caveats in `Kernels/ConsensusBytes.lean` and CLAIMS.md.
-/

namespace Host

/-- **W2-T2 (i)+(ii): byte-quorum on forward.** If the strict profile forwards
    a mediated line and the byte-consensus verdict is among the combined
    verdicts, then the line's canonical parse witness exists, a
    strict-majority quorum ratified exactly its canonical serialization, and
    the ratified certificate's value IS those bytes. -/
theorem forward_high_stakes_byte_quorum
    (line : String) (act : CanonicalAction) (verdicts : List Verdict)
    (cfg : Kernels.ConsensusConfig) (votes : Consensus.Checker.Votes)
    (hclass : classifyLine line = .act act)
    (hmem : (Kernels.byteConsensusKernel.decide act cfg votes ()).1 ∈ verdicts)
    (hfwd : stepRouteP .canonicalL0 (classifyLine line) verdicts = .forward) :
    ∃ ast : SealV2.AST,
      act.ast? = some ast ∧
      SealV2.parse line.trimAscii.toString = some ast ∧
      Kernels.byteQuorumAccepts cfg.roster votes (SealV2.serializeAstValue ast) = true ∧
      (Kernels.certFor votes (SealV2.serializeAstValue ast)).value
        = SealV2.serializeAstValue ast := by
  rw [hclass] at hfwd
  cases hast : act.ast? with
  | none =>
      exfalso
      have hblock : stepRouteP .canonicalL0 (.act act) verdicts = .block := by
        simp only [stepRouteP, hast]
      rw [hblock] at hfwd
      cases hfwd
  | some ast =>
      have hallow : combineVerdicts verdicts = .allow := by
        simp only [stepRouteP, hast] at hfwd
        exact (stepRoute_act_forward_iff act verdicts).mp hfwd
      have hkind : (Kernels.byteConsensusKernel.decide act cfg votes ()).1.kind = .allow :=
        combine_allow_implies_member verdicts _ hmem hallow
      obtain ⟨bytes, hbytes, hq⟩ :=
        (Kernels.byteConsensus_verdict_allow_iff act cfg votes ()).mp hkind
      have hb : bytes = SealV2.serializeAstValue ast := by
        simp only [Kernels.canonicalBytesOf, hast, Option.map_some] at hbytes
        exact (Option.some.inj hbytes).symm
      subst hb
      have hparse : SealV2.parse line.trimAscii.toString = some ast :=
        (classifyLine_act_ast line act hclass).symm.trans hast
      exact ⟨ast, rfl, hparse, hq, rfl⟩

/-- **W2-T2 (iii) at the seam.** Two `canonicalL0` forwards under the same
    roster and votes, each carrying the byte-consensus verdict, commit to
    byte-identical canonical payloads. -/
theorem composed_byte_agreement
    (line line' : String) (act act' : CanonicalAction)
    (verdicts verdicts' : List Verdict)
    (cfg : Kernels.ConsensusConfig) (votes : Consensus.Checker.Votes)
    (hclass : classifyLine line = .act act)
    (hclass' : classifyLine line' = .act act')
    (hmem : (Kernels.byteConsensusKernel.decide act cfg votes ()).1 ∈ verdicts)
    (hmem' : (Kernels.byteConsensusKernel.decide act' cfg votes ()).1 ∈ verdicts')
    (hfwd : stepRouteP .canonicalL0 (classifyLine line) verdicts = .forward)
    (hfwd' : stepRouteP .canonicalL0 (classifyLine line') verdicts' = .forward) :
    ∃ (ast ast' : SealV2.AST),
      act.ast? = some ast ∧ act'.ast? = some ast' ∧
      SealV2.serializeAstValue ast = SealV2.serializeAstValue ast' := by
  obtain ⟨ast, hast, -, hq, -⟩ :=
    forward_high_stakes_byte_quorum line act verdicts cfg votes hclass hmem hfwd
  obtain ⟨ast', hast', -, hq', -⟩ :=
    forward_high_stakes_byte_quorum line' act' verdicts' cfg votes hclass' hmem' hfwd'
  exact ⟨ast, ast', hast, hast',
    Kernels.byte_quorum_agreement cfg.roster votes _ _ hq hq'⟩

/-- Non-vacuity: the forward route is live through the byte-quorum gate — a
    mediated call with a canonical witness whose bytes a quorum ratified is
    forwarded by the strict profile on the byte-consensus verdict alone. -/
theorem forward_byte_quorum_route_live
    (a : CanonicalAction) (ast : SealV2.AST) (hast : a.ast? = some ast)
    (cfg : Kernels.ConsensusConfig) (votes : Consensus.Checker.Votes)
    (hq : Kernels.byteQuorumAccepts cfg.roster votes
            (SealV2.serializeAstValue ast) = true) :
    stepRouteP .canonicalL0 (.act a)
      [(Kernels.byteConsensusKernel.decide a cfg votes ()).1] = .forward := by
  have hkind : (Kernels.byteConsensusKernel.decide a cfg votes ()).1.kind = .allow :=
    (Kernels.byteConsensus_verdict_allow_iff a cfg votes ()).mpr
      ⟨SealV2.serializeAstValue ast,
        by simp [Kernels.canonicalBytesOf, hast], hq⟩
  have hallow :
      combineVerdicts [(Kernels.byteConsensusKernel.decide a cfg votes ()).1]
        = .allow := by
    simp [combineVerdicts, hkind]
    rfl
  simp only [stepRouteP, hast, stepRoute, hallow]

end Host
