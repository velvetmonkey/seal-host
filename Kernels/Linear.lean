/- SPDX-License-Identifier: Apache-2.0 -/

import Seal.Hash
import Seal.JsonUtil
import Host.Kernel
import Kernels.LinearCore

namespace Kernels

/-- One linearly-gated tool: the tool name and the argument path naming the
    capability being spent. -/
structure LinearTool where
  tool : String
  capArg : List String
  deriving Repr

/-- Config section for kernel L: where grants are minted and which tools
    spend capabilities. -/
structure LinearConfig where
  grantsFile : System.FilePath
  tools : List LinearTool
  deriving Repr

/-- Kernel L — the Linear-resource kernel. Capabilities spend linearly: each
    grant carries a finite multiplicity, each gated call consumes exactly one
    use, and an exhausted capability denies — `LinearCore.no_double_spend` and
    the trace conservation theorem `LinearCore.spends_le_grants` are the
    invariants. Grants are ingested unconditionally (the host's seen counter
    has advanced); the spend is the execution transition, committed only when
    the combined verdict allows — a denied call spends nothing. -/
def linearKernel : Host.Kernel where
  name := "linear"
  Config := LinearConfig
  Evidence := List LinearCore.LEvent
  State := LinearCore.LState
  init := LinearCore.LState.empty
  gates := fun cfg act => cfg.tools.any (fun t => t.tool == act.tool)
  ingest := fun grants st =>
    grants.foldl (fun s e => (LinearCore.step s e).2) st
  decide := fun act cfg _ st =>
    let mk := fun (kind : Host.VerdictKind) (reason : String) (st' : LinearCore.LState) =>
      ({ kernel := "linear", kind, reason,
         certHash := Seal.auditHashParts ["linear", kind.text, reason] }, st')
    match cfg.tools.find? (fun t => t.tool == act.tool) with
    | none => mk .deny s!"not a linearly-gated tool: {act.tool}" st
    | some t =>
        match Seal.JsonUtil.atPath act.argsJson t.capArg >>=
            Seal.JsonUtil.jsonScalarToString with
        | none => mk .deny s!"missing capability field: {act.tool}" st
        | some cap =>
            match LinearCore.step st (.spend cap) with
            | (.allow, st') =>
                mk .allow s!"capability spent ({LinearCore.holds st' cap} uses left): {cap}" st'
            | (.block, _) =>
                mk .deny s!"capability exhausted, double-spend denied: {cap}" st

end Kernels
