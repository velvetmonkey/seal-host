/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Record
import Host.Composition

/-!
# Faithful reflection — the record reflects real L0-passing decisions (L1 STRETCH)

CORE (`Host.Record.tamper_evident`) proves the log CANNOT be altered undetectably.
This module proves the log MEANS what it says: every entry in the record of
admitted effects corresponds to a mediated decision that was forwarded through
the deployed step core, and therefore passed the L0 four-gate contract.

The chain is: a logged entry ⇒ its decision forwarded (`stepRoute (.act …) =
.forward`, the deployed routing core L0 is proven over) ⇒ the combined verdict
allowed ⇒ (via `combine_allow_iff`) at least one gate applied and EVERY gating
kernel returned allow. Composed with tamper-evidence, the record is both
unforgeable AND a faithful, order-preserving witness of what passed the gate.

Scope (honest): the theorem is about the record of ADMITTED (forwarded)
decisions — the security-relevant log of effects that actually executed. A
denied call never executed and is not what this witness is about.
-/

namespace Host.Record

open Host

/-- **FAITHFUL REFLECTION (STRETCH).** For a log built from a sequence of
    forwarded decisions (`hforward`), most-recent-first (`hbuilt` — the log is
    exactly the per-decision audits in reverse order, so order is preserved by
    construction), every entry corresponds to a decision whose verdict list
    passed L0: non-empty and every gate allowed. -/
theorem log_reflects_l0_decisions
    (decisions : List (CanonicalAction × List Verdict)) (epoch : Nat)
    (hforward : ∀ p ∈ decisions, stepRoute (.act p.1) p.2 = .forward)
    (log : Log)
    (hbuilt : log =
      (decisions.map fun p => auditLine epoch p.1.tool (combineVerdicts p.2) p.2).reverse) :
    ∀ entry ∈ log, ∃ (act : CanonicalAction) (verdicts : List Verdict),
      entry = auditLine epoch act.tool (combineVerdicts verdicts) verdicts ∧
      verdicts ≠ [] ∧ (∀ v ∈ verdicts, v.kind = .allow) := by
  intro entry hentry
  rw [hbuilt, List.mem_reverse, List.mem_map] at hentry
  obtain ⟨p, hp_mem, hp_eq⟩ := hentry
  refine ⟨p.1, p.2, hp_eq.symm, ?_⟩
  -- forwarded ⇒ combined allow ⇒ (combine_allow_iff) non-empty ∧ every gate allows
  exact (combine_allow_iff p.2).mp
    ((stepRoute_act_forward_iff p.1 p.2).mp (hforward p hp_mem))

end Host.Record
