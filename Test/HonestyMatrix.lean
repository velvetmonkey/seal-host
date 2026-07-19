/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import FfiSpec
import Host.ReceiptIdentity

/-!
# A2 — the honesty matrix, derived

Emits the machine-derivable cells of the per-kernel honesty matrix
(proven? / wired in `registryFor`? / tested?) as JSON on stdout, for
`scripts/honesty-matrix.mjs` to render into `docs/HONESTY-MATRIX.md`.

Two derivation mechanisms, one per bug class:

- **Compile-time theorem binding.** `boundTheorems` term-references all
  eleven FfiSpec theorems by name. Rename or delete one and this executable stops
  building, the matrix cannot regenerate, and the CI drift gate goes red.
  Scope stated honestly: this catches RENAME and DELETE, not RESTATEMENT — a
  weakened theorem that keeps its name still builds. That is exactly the bug
  class A0 was written to kill (edit `registryFor`, no proof notices), no
  more.
- **Evaluation.** `Ffi.activeKernels` is evaluated over all 64 deployable
  configs (6-bit mask over {C,V,K,L,B,PB}; S+T unconditional — V2.1 adds PB
  as a NEW high bit, so masks 0–31 are byte-identical to
  `rust/tests/topology_matrix.rs`'s 5-bit enumeration) plus calibration's
  configured-but-disabled variants. Every "wired" verdict below is computed
  from those evaluations, never transcribed. `Ffi.registryFor_kernels` is
  the theorem that licenses this: the deployed registry maps to exactly
  `activeKernels s.config` for every session, clock and evidence bundle, so
  evaluating `activeKernels` IS evaluating the shipped selection.

`Host.Kernel` carries `Type` fields and function fields, so `List Kernel`
has no decidable equality — every membership test, set comparison and dedup
below projects to `Kernel.name` first (the nine names are distinct string
literals; `FfiSpec.not_mem_of_name` is the proof-side twin of this move).

Any failed self-check prints to stderr and exits non-zero: no partial JSON,
no silent skip.
-/

namespace Test.HonestyMatrix

open Host
open Lean (Json toJson)

/-- Compile-time binding to the eleven FfiSpec theorems. Each string is
    inseparable from a term reference to the theorem it names: if the
    theorem goes, the string goes with it or the build breaks. -/
private def boundTheorems : List String :=
  [(let _ := @Ffi.registryFor_kernels; "Ffi.registryFor_kernels"),
   (let _ := @Ffi.safety_always_registered; "Ffi.safety_always_registered"),
   (let _ := @Ffi.temporal_always_registered; "Ffi.temporal_always_registered"),
   (let _ := @Ffi.consensus_registered_iff; "Ffi.consensus_registered_iff"),
   (let _ := @Ffi.convergence_registered_iff; "Ffi.convergence_registered_iff"),
   (let _ := @Ffi.calibration_registered_iff; "Ffi.calibration_registered_iff"),
   (let _ := @Ffi.linear_registered_iff; "Ffi.linear_registered_iff"),
   (let _ := @Ffi.budget_registered_iff; "Ffi.budget_registered_iff"),
   (let _ := @Ffi.principal_budget_registered_iff; "Ffi.principal_budget_registered_iff"),
   (let _ := @Ffi.registryFor_kernels_principal_irrelevant;
    "Ffi.registryFor_kernels_principal_irrelevant"),
   (let _ := @Ffi.byteConsensus_never_registered; "Ffi.byteConsensus_never_registered")]

/-- Compile-time binding to the D3 receipt-identity theorems
    (`Host/ReceiptIdentity.lean`): what the receipt's `approval_identity`
    binds (the approval trust root, boot-scoped, request-independent) and
    the caller no-go (no function of the mediated bytes authenticates the
    caller at the stdio topology). Same discipline as `boundTheorems`:
    rename or delete one and the matrix cannot regenerate. -/
private def identityTheorems : List String :=
  [(let _ := @Host.ReceiptIdentity.receipt_identity_names_trust_root;
    "Host.ReceiptIdentity.receipt_identity_names_trust_root"),
   (let _ := @Host.ReceiptIdentity.token_gates_presence_not_value;
    "Host.ReceiptIdentity.token_gates_presence_not_value"),
   (let _ := @Host.ReceiptIdentity.receipt_identity_separated;
    "Host.ReceiptIdentity.receipt_identity_separated"),
   (let _ := @Host.ReceiptIdentity.keyId_only_on_signed_channel;
    "Host.ReceiptIdentity.keyId_only_on_signed_channel")]

private def callerNogoTheorems : List String :=
  [(let _ := @Host.ReceiptIdentity.stdio_no_caller_authentication;
    "Host.ReceiptIdentity.stdio_no_caller_authentication"),
   (let _ := @Host.ReceiptIdentity.forgeable_echo;
    "Host.ReceiptIdentity.forgeable_echo"),
   (let _ := @Host.ReceiptIdentity.credentialed_topology_authenticates;
    "Host.ReceiptIdentity.credentialed_topology_authenticates")]

/-! ## Sample config sections

Minimal well-formed values for each kernel section. Only PRESENCE (and
calibration's `enabled`) drives `activeKernels`; the field contents are
irrelevant to selection and never touch a file. -/

private def samplePolicy : Seal.Policy :=
  { approvalTtlMs := 0
    approvalFile := System.FilePath.mk "unused.approvals"
    tools := [] }

private def sampleConsensus : Kernels.ConsensusConfig :=
  { roster := [1]
    votesFile := System.FilePath.mk "unused.votes"
    highStakes := ["payments.send"] }

private def sampleConvergence : Kernels.ConvergenceConfig :=
  [{ tool := "store.update", opArg := ["op"] }]

private def sampleCalibration (enabled : Bool) : Kernels.CalibrationConfig :=
  { enabled
    deltaNum := 1
    deltaDen := 10
    minSamples := 3
    recordsFile := System.FilePath.mk "unused.forecasts"
    gatedTools := ["model.act"] }

private def sampleLinear : Kernels.LinearConfig :=
  { grantsFile := System.FilePath.mk "unused.grants"
    tools := [] }

private def sampleBudget : Kernels.BudgetConfig :=
  [{ name := "notes", cap := 1, tools := ["notes.add"], costArg := none }]

private def samplePrincipals : Kernels.PrincipalsConfig :=
  { registry := [{ id := "alice", pubkey :=
      "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" }]
    budgets := [{ name := "alice-notes", cap := 1, tools := ["notes.add"],
                  costArg := none }] }

/-! ## The 64-topology enumeration (bits 0–4 match
`rust/tests/topology_matrix.rs`; bit 5 is the V2.1 principals section) -/

private def bitConsensus : Nat := 1
private def bitConvergence : Nat := 2
private def bitCalibration : Nat := 4
private def bitLinear : Nat := 8
private def bitBudget : Nat := 16
private def bitPrincipals : Nat := 32

/-- Calibration's three config states. `disabled` (section present,
    `enabled := false`) is the double gate's distinct middle state. -/
private inductive CalVariant where
  | active
  | absent
  | disabled

private def configFor (mask : Nat) (cal : CalVariant) : TrustedConfig :=
  { epoch := 1
    safety := samplePolicy
    temporal := []
    consensus := if mask &&& bitConsensus != 0 then some sampleConsensus else none
    convergence := if mask &&& bitConvergence != 0 then sampleConvergence else []
    calibration :=
      match cal with
      | .active => some (sampleCalibration true)
      | .absent => none
      | .disabled => some (sampleCalibration false)
    linear := if mask &&& bitLinear != 0 then some sampleLinear else none
    budget := if mask &&& bitBudget != 0 then sampleBudget else []
    principals := if mask &&& bitPrincipals != 0 then some samplePrincipals
                  else none }

/-- The selected kernel NAMES at a config — the only representation the exe
    compares (no `DecidableEq` on `Kernel`). -/
private def activeNames (mask : Nat) (cal : CalVariant) : List String :=
  (Ffi.activeKernels (configFor mask cal)).map Kernel.name

/-- Expected names for a mask, in registry order — derived from the mask
    literal alone, mirroring the A1 suite's discipline. This checks the exe's
    own enumeration round-trips through `activeKernels`; the registry itself
    is specified by `Ffi.registryFor_kernels`. -/
private def expectedNames (mask : Nat) (cal : CalVariant) : List String :=
  [Kernels.safetyKernel.name, Kernels.temporalKernel.name]
  ++ (if mask &&& bitConsensus != 0 then [Kernels.consensusKernel.name] else [])
  ++ (if mask &&& bitConvergence != 0 then [Kernels.convergenceKernel.name] else [])
  ++ (match cal with
      | .active => [Kernels.calibrationKernel.name]
      | _ => [])
  ++ (if mask &&& bitLinear != 0 then [Kernels.linearKernel.name] else [])
  ++ (if mask &&& bitBudget != 0 then [Kernels.budgetKernel.name] else [])
  ++ (if mask &&& bitPrincipals != 0 then [Kernels.principalBudgetKernel.name]
      else [])

/-- All nine proven kernels, bound to their definitions: the name strings
    are read off the defs, never retyped. -/
private def provenKernelNames : List String :=
  [Kernels.safetyKernel.name,
   Kernels.temporalKernel.name,
   Kernels.consensusKernel.name,
   Kernels.convergenceKernel.name,
   Kernels.calibrationKernel.name,
   Kernels.linearKernel.name,
   Kernels.budgetKernel.name,
   Kernels.principalBudgetKernel.name,
   Kernels.byteConsensusKernel.name]

/-- Which FfiSpec theorems speak for which kernel. Every string here must be
    a member of `boundTheorems` (checked at runtime), so a stale entry
    cannot survive a rename that the compile-time binding catches. -/
private def kernelTheorems : List (String × List String) :=
  [(Kernels.safetyKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.safety_always_registered"]),
   (Kernels.temporalKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.temporal_always_registered"]),
   (Kernels.consensusKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.consensus_registered_iff"]),
   (Kernels.convergenceKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.convergence_registered_iff"]),
   (Kernels.calibrationKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.calibration_registered_iff"]),
   (Kernels.linearKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.linear_registered_iff"]),
   (Kernels.budgetKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.budget_registered_iff"]),
   (Kernels.principalBudgetKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.principal_budget_registered_iff",
     "Ffi.registryFor_kernels_principal_irrelevant"]),
   (Kernels.byteConsensusKernel.name,
    ["Ffi.registryFor_kernels", "Ffi.byteConsensus_never_registered"])]

/-- Cal variant a deployable mask uses: active iff its calibration bit is
    set. -/
private def calFor (mask : Nat) : CalVariant :=
  if mask &&& bitCalibration != 0 then .active else .absent

private def allMasks : List Nat := List.range 64

/-- Self-checks over the evaluated space. Returns human-readable failures;
    empty means every derivation below is backed by an evaluation that held. -/
private def selfCheckErrors : List String := Id.run do
  let mut errs : List String := []
  -- Exact selection at every deployable mask, plus S+T membership and the
  -- eighth kernel's absence, at the name level throughout.
  for mask in allMasks do
    let names := activeNames mask (calFor mask)
    let expected := expectedNames mask (calFor mask)
    if names != expected then
      errs := errs ++ [s!"mask {mask}: activeKernels {names} ≠ expected {expected}"]
    if !names.contains Kernels.safetyKernel.name then
      errs := errs ++ [s!"mask {mask}: safety missing"]
    if !names.contains Kernels.temporalKernel.name then
      errs := errs ++ [s!"mask {mask}: temporal missing"]
    if names.contains Kernels.byteConsensusKernel.name then
      errs := errs ++ [s!"mask {mask}: byteConsensus present — never wired must hold"]
  -- Calibration's double gate: configured-but-disabled ≡ absent, at every
  -- calibration-clear mask, and the disabled variant never selects K.
  for mask in allMasks do
    if mask &&& bitCalibration == 0 then
      let absent := activeNames mask .absent
      let disabled := activeNames mask .disabled
      if absent != disabled then
        errs := errs ++
          [s!"mask {mask}: disabled {disabled} ≠ absent {absent} — double gate broken"]
      if disabled.contains Kernels.calibrationKernel.name then
        errs := errs ++ [s!"mask {mask}: disabled calibration selected"]
  -- The 64 masks yield 64 DISTINCT selections (the topology count is real).
  let sets := allMasks.map (fun m => activeNames m (calFor m))
  if sets.eraseDups.length != 64 then
    errs := errs ++ [s!"expected 64 distinct active sets, got {sets.eraseDups.length}"]
  -- Every per-kernel theorem citation is a bound theorem.
  for (k, thms) in kernelTheorems do
    for t in thms do
      if !boundTheorems.contains t then
        errs := errs ++ [s!"kernel {k} cites unbound theorem {t}"]
  -- The theorem→kernel map covers exactly the proven kernels.
  if kernelTheorems.map (·.1) != provenKernelNames then
    errs := errs ++ ["kernelTheorems keys ≠ provenKernelNames"]
  return errs

/-- In how many of the 64 deployable configs a kernel is selected. -/
private def activeCount (kernel : String) : Nat :=
  (allMasks.filter (fun m => (activeNames m (calFor m)).contains kernel)).length

/-- Wired verdict, computed from the evaluation — never transcribed. -/
private def wiredVerdict (kernel : String) : String :=
  match activeCount kernel with
  | 64 => "always"
  | 0 => "never"
  | _ => "config-gated"

/-- Double gate, computed: gated kernel whose section-present-but-disabled
    state is also inactive (only calibration has such a state). -/
private def hasDoubleGate (kernel : String) : Bool :=
  kernel == Kernels.calibrationKernel.name
  && allMasks.all (fun m =>
       m &&& bitCalibration != 0 || !(activeNames m .disabled).contains kernel)

/-- Kernels selected at EVERY deployable config (the mandatory set). -/
private def mandatoryKernels : List String :=
  provenKernelNames.filter (fun k => activeCount k == 64)

/-- Kernels selected at SOME deployable config (the selectable set). -/
private def selectableKernels : List String :=
  provenKernelNames.filter (fun k => activeCount k > 0)

private def kernelRow (kernel : String) : Json :=
  Json.mkObj
    [("name", toJson kernel),
     ("wired", toJson (wiredVerdict kernel)),
     ("activeCount", toJson (activeCount kernel)),
     ("doubleGate", toJson (hasDoubleGate kernel)),
     ("theorems",
      Json.arr (((kernelTheorems.lookup kernel).getD []).map toJson).toArray)]

/-- The D3 identity block: who a receipt authenticates. The channel names
    are read off `Host.ReceiptIdentity.Channel.name`, never retyped; the
    theorem names are the compile-time-bound lists above. -/
private def identityJson : Json :=
  Json.mkObj
    [("signedChannel", toJson Host.ReceiptIdentity.Channel.ed25519.name),
     ("unauthenticatedChannels",
      Json.arr #[toJson Host.ReceiptIdentity.Channel.file.name,
                 toJson Host.ReceiptIdentity.Channel.interactive.name]),
     ("approverTheorems", Json.arr (identityTheorems.map toJson).toArray),
     ("callerNogoTheorems", Json.arr (callerNogoTheorems.map toJson).toArray)]

private def matrixJson : Json :=
  Json.mkObj
    [("schema", toJson "seal-honesty-matrix/v2"),
     ("boundTheorems", Json.arr (boundTheorems.map toJson).toArray),
     ("identity", identityJson),
     ("kernels", Json.arr (provenKernelNames.map kernelRow).toArray),
     ("arithmetic",
      Json.mkObj
        [("provenKernels", toJson provenKernelNames.length),
         ("selectableKernels", toJson selectableKernels.length),
         ("mandatoryKernels", toJson mandatoryKernels.length),
         ("deployableTopologies",
          toJson ((allMasks.map (fun m => activeNames m (calFor m))).eraseDups.length))]),
     ("mandatory", Json.arr (mandatoryKernels.map toJson).toArray),
     ("calibrationDisabledEqualsAbsent", toJson true)]

def main : IO UInt32 := do
  let errs := selfCheckErrors
  if errs.isEmpty then
    IO.println matrixJson.compress
    return 0
  else
    for e in errs do
      IO.eprintln s!"honesty_matrix self-check FAILED: {e}"
    return 1

end Test.HonestyMatrix

/-- Lake exe entry point (module-level, as `lake exe` requires). -/
def main : IO UInt32 := Test.HonestyMatrix.main
