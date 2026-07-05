/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Hash
import Seal.JsonUtil
import Host.Kernel

namespace Kernels

/-- One replicated store mediated by kernel V: the tool that mutates it and
    the argument path carrying the operation name. -/
structure ReplicatedTool where
  tool : String
  opArg : List String
  deriving Repr

abbrev ConvergenceConfig := List ReplicatedTool

/-- The proven-convergent operation set. Every entry names an operation of a
    crdt-lean instance whose convergence is a kernel-checked theorem
    (join-semilattice CvRDTs — merge commutative/associative/idempotent and
    inflationary, so `Crdt.strong_eventual_consistency` and
    `Crdt.converged_states_agree` apply):

    * `gset.add` — grow-only set, merge = union (`Crdt.gset_merge_eq_union`)
    * `gcounter.inc` — grow-only counter, merge = pointwise max
    * `pncounter.inc` / `pncounter.dec` — PN-counter, componentwise max
    * `orset.add` / `orset.remove` — observed-remove set (`Crdt.ORSet.add_wins`)
    * `rga.insert` / `rga.remove` — replicated growable array
      (`Crdt.RGA.read_strong_eventual_consistency`)

    The set is FIXED IN CODE, not config: an operator can choose which tools
    kernel V governs, but cannot extend the convergent set without a proof. -/
def provenConvergentOps : List String :=
  ["gset.add", "gcounter.inc", "pncounter.inc", "pncounter.dec",
   "orset.add", "orset.remove", "rga.insert", "rga.remove"]

/-- Kernel V — the Convergence kernel. Gates the configured replicated-store
    mutation tools: a write is admitted only if its operation is in the
    proven-convergent set. Last-writer-wins assignment, blind overwrites and
    anything else unproven is denied — split-brain and divergent replicas are
    refused at the gate. Missing or non-scalar op field: deny (fail-closed). -/
def convergenceKernel : Host.Kernel where
  name := "convergence"
  Config := ConvergenceConfig
  Evidence := Unit
  State := Unit
  init := ()
  gates := fun cfg act => cfg.any (fun r => r.tool == act.tool)
  ingest := fun _ st => st
  decide := fun act cfg _ st =>
    let mk := fun (kind : Host.VerdictKind) (reason : String) =>
      ({ kernel := "convergence", kind, reason,
         certHash := Seal.auditHashParts ["convergence", kind.text, reason] }, st)
    match cfg.find? (fun r => r.tool == act.tool) with
    | none => mk .deny s!"not a configured replicated tool: {act.tool}"
    | some r =>
        match Seal.JsonUtil.atPath act.argsJson r.opArg >>=
            Seal.JsonUtil.jsonScalarToString with
        | none => mk .deny s!"missing op field for replicated tool: {act.tool}"
        | some op =>
            if provenConvergentOps.contains op then
              mk .allow s!"convergent op admitted: {op}"
            else
              mk .deny s!"op not in the proven-convergent set: {op}"

/-- The pure accept condition of kernel V, mirroring `Kernels.quorumAccepts`:
    the call names a configured replicated tool, its op field resolves to a
    scalar, and that op is in the fixed proven-convergent set. This is the
    internal condition the kernel's `decide` allows on. -/
def convergentAccepts (cfg : ConvergenceConfig) (act : Host.CanonicalAction) : Bool :=
  match cfg.find? (fun r => r.tool == act.tool) with
  | none => false
  | some r =>
      match Seal.JsonUtil.atPath act.argsJson r.opArg >>=
          Seal.JsonUtil.jsonScalarToString with
      | none => false
      | some op => provenConvergentOps.contains op

/-- Bridge for the composition theorem: kernel V's verdict is allow exactly
    when its accept condition holds — the admitted operation is in the
    fixed, kernel-checked convergent set. -/
theorem convergence_verdict_allow_iff
    (act : Host.CanonicalAction) (cfg : ConvergenceConfig) (ev : Unit) (st : Unit) :
    (convergenceKernel.decide act cfg ev st).1.kind = .allow ↔
      convergentAccepts cfg act = true := by
  simp only [convergenceKernel, convergentAccepts]
  repeat' split
  all_goals simp_all

end Kernels
