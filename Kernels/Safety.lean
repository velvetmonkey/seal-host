/- SPDX-License-Identifier: Apache-2.0 -/

import SealCore
import Seal.Classify
import Seal.Hash
import Host.Kernel

namespace Kernels

open SealCore

/-- Evidence the host gathers for the Safety Seal kernel before each decision:
    one wall-clock reading and the approval records freshly ingested from the
    control file (each record exactly once — the host keeps the seen counter). -/
structure SafetyEvidence where
  now : Nat
  approvalEvents : List Event

private def kindOf : Decision → Host.VerdictKind
  | .allow => .allow
  | .block => .deny

/-- Kernel S — the Safety Seal. A pure lift of the mcp-seal V1 decision path
    (`Seal/Main.lean` processHostLine): fold freshly ingested approvals through
    `SealCore.step`, classify the call against the policy with the unchanged
    `Seal.classifyToolCall`, take one `SealCore.step`, prune. Behaviour is
    identical to V1 by construction; the proven automaton and classifier are
    imported, not reimplemented. -/
def safetyKernel : Host.Kernel where
  name := "safety"
  Config := Seal.Policy
  Evidence := SafetyEvidence
  State := SealCore.State
  init := SealCore.State.empty
  gates := fun _ _ => true
  -- Approval ingestion is committed unconditionally by the host (the seen
  -- counter has already advanced; losing these events would drop approvals).
  ingest := fun ev st =>
    ev.approvalEvents.foldl (fun s e => (step ev.now s e).2) st
  -- Decision + execution transition on the already-ingested state. On the
  -- host's combined deny this state is discarded: the approval is not
  -- consumed by a call that never executed, and skipping `prune` is
  -- decision-neutral (SealCore.prune changes no `live` answer).
  decide := fun act policy ev st1 =>
    let hostEvent := Seal.classifyToolCall policy act.tool act.argsJson
    let (decision, st2) := step ev.now st1 hostEvent.toEvent
    let st3 : State := { approved := prune ev.now st2.approved }
    let kind := kindOf decision
    let reason := hostEvent.targetText
    let verdict : Host.Verdict := {
      kernel := "safety"
      kind := kind
      reason := reason
      certHash := Seal.stableHashParts ["safety", kind.text, reason]
    }
    (verdict, st3)

end Kernels
