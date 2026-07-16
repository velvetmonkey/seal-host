/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser
import SealV2.Crypto
import Seal.Policy
import Seal.PolicyBundle
import Seal.JsonUtil
import Kernels.Temporal
import Kernels.Consensus
import Kernels.Convergence
import Kernels.Calibration
import Kernels.Linear
import Kernels.Budget

namespace Host

open Lean
open Seal.JsonUtil

/-- The host's one trusted config: signed, epoch-stamped, one section per
    kernel. `safety` is the V1 policy shape (kernel S); `temporal` is the LTL
    safety-policy list (kernel T), absent section = no temporal constraints. -/
structure TrustedConfig where
  epoch : Nat
  safety : Seal.Policy
  temporal : List Kernels.TemporalPolicy
  consensus : Option Kernels.ConsensusConfig
  convergence : Kernels.ConvergenceConfig
  calibration : Option Kernels.CalibrationConfig
  linear : Option Kernels.LinearConfig
  budget : Kernels.BudgetConfig

/-- Map the parsed policy-v2 bundle (`Seal.parsePolicyBundle` — the verified
    7-kernel config vocabulary) onto the kernel config types. Field-by-field
    and total up to the budget lint: the `Kernels.*` types and `TrustedConfig`
    are unchanged, so `registryFor` / `activeKernels` / the A0 tripwires
    attach exactly as before; the `ofBundle_*` lemmas below pin that this
    mapping preserves each section's activation.

    `enabled := false` sections were already collapsed by the bundle's
    `effective*` views — except calibration, which deliberately maps
    present-but-disabled to `some { enabled := false, .. }` (the distinct
    double-gate state pinned by `calibration_registered_iff`). -/
def ofBundle (b : Seal.PolicyBundle) : Except String TrustedConfig :=
  -- Fail closed: same-name budgets share one counter, so conflicting caps
  -- would leave the smaller cap silently unenforceable (see
  -- `Kernels.budgetCapsConsistent`). Equal-cap duplicates stay legal.
  if Kernels.budgetCapsConsistent (b.effectiveBudget.map fun r =>
      { name := r.name, cap := r.cap, tools := r.tools, costArg := r.costArg }) then
    .ok { epoch := b.epoch
          safety := b.safety
          temporal := b.effectiveTemporal.map fun r =>
            { name := r.name, trigger := r.trigger, forbidden := r.forbidden }
          consensus := b.effectiveConsensus.map fun s =>
            { roster := s.roster, votesFile := System.FilePath.mk s.votesFile
              highStakes := s.highStakes }
          convergence := b.effectiveConvergence.map fun t =>
            { tool := t.tool, opArg := t.opArg }
          calibration := b.calibration.map fun s =>
            { enabled := s.enabled, deltaNum := s.deltaNum, deltaDen := s.deltaDen
              minSamples := s.minSamples, gatedTools := s.gatedTools
              recordsFile := System.FilePath.mk s.recordsFile }
          linear := b.effectiveLinear.map fun s =>
            { grantsFile := System.FilePath.mk s.grantsFile
              tools := s.tools.map fun t => { tool := t.tool, capArg := t.capArg } }
          budget := b.effectiveBudget.map fun r =>
            { name := r.name, cap := r.cap, tools := r.tools, costArg := r.costArg } }
  else
    .error "duplicate budget name with conflicting caps"

/-! ### Mapping-preservation lemmas

The activation-relevant shape of every section survives `ofBundle`: these are
the seams the `bundle_*_registered_iff` tripwires (`FfiSpec.lean`) compose
with `registryFor_kernels` through. -/

theorem ofBundle_epoch {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) : cfg.epoch = b.epoch := by
  unfold ofBundle at h
  split at h
  · injection h with h
    subst h
    rfl
  · simp at h

theorem ofBundle_safety {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) : cfg.safety = b.safety := by
  unfold ofBundle at h
  split at h
  · injection h with h
    subst h
    rfl
  · simp at h

theorem ofBundle_consensus {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.consensus.isSome = b.effectiveConsensus.isSome := by
  unfold ofBundle at h
  split at h
  · injection h with h
    subst h
    cases b.effectiveConsensus <;> rfl
  · simp at h

theorem ofBundle_convergence {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.convergence.isEmpty = b.effectiveConvergence.isEmpty := by
  unfold ofBundle at h
  split at h
  · injection h with h
    subst h
    cases b.effectiveConvergence <;> rfl
  · simp at h

theorem ofBundle_calibration {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    (∃ c, cfg.calibration = some c ∧ c.enabled = true)
      ↔ (∃ s, b.calibration = some s ∧ s.enabled = true) := by
  unfold ofBundle at h
  split at h
  · injection h with h
    subst h
    cases b.calibration <;> simp
  · simp at h

theorem ofBundle_linear {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.linear.isSome = b.effectiveLinear.isSome := by
  unfold ofBundle at h
  split at h
  · injection h with h
    subst h
    cases b.effectiveLinear <;> rfl
  · simp at h

theorem ofBundle_budget {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.budget.isEmpty = b.effectiveBudget.isEmpty := by
  unfold ofBundle at h
  split at h
  · injection h with h
    subst h
    cases b.effectiveBudget <;> rfl
  · simp at h

theorem ofBundle_temporal {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.temporal = b.effectiveTemporal.map fun r =>
      { name := r.name, trigger := r.trigger, forbidden := r.forbidden } := by
  unfold ofBundle at h
  split at h
  · injection h with h
    subst h
    rfl
  · simp at h

/-- Real Ed25519 verification for the trusted config envelope. The config
    signing key is a startup trust root, separate from approval-token keys.
    The signature covers the exact `payload` string bytes carried by the
    envelope; no normalized or reserialized substitute is verified. -/
def verifyConfigSignature (publicKey payload signature : String) : Bool :=
  match SealV2.hexDecode? publicKey, SealV2.hexDecode? signature with
  | some pk, some sig => SealV2.ed25519Verify pk payload.toUTF8 sig
  | _, _ => false

/-- Parse the already-authenticated config payload. This does NOT verify
    signatures and is therefore not a trust boundary by itself; real loaders
    must call `checkTrustedConfig` / `checkEnvelope` first. It is factored out
    so the conformance model oracle can initialise from a harness-trusted
    payload without executing the `@[extern]` Ed25519 leaf in the interpreter.

    The vocabulary is `Seal.parsePolicyBundle` — the policy-v2 7-kernel
    bundle, one parser across the native, wasm, and model lanes, with hard
    errors on unknown keys at the payload, section, and entry levels. -/
def parseCanonicalConfigPayload (payload : String) :
    Except String TrustedConfig := do
  if (SealV2.parse payload).isNone then
    throw "config payload is not canonical (SealV2 parse rejected it)"
  let json ← Json.parse payload
  ofBundle (← Seal.parsePolicyBundle json)

/-- Pure, fail-closed config check. The payload must
    1. carry a real Ed25519 signature binding it to the trusted public key,
    2. be accepted by the SealV2 verified canonical parser (one canonical
       byte-form, no parser differential on the trusted input), and
    3. parse to an epoch ≥ 1 plus a well-formed `safety` policy section.
    The epoch lives INSIDE the signed payload, so it cannot be tampered with
    independently of the signature. Any failure is an error — never a default. -/
def checkTrustedConfig (publicKey payload signature : String) :
    Except String TrustedConfig := do
  let config ← parseCanonicalConfigPayload payload
  if !verifyConfigSignature publicKey payload signature then
    throw "config signature verification failed"
  pure config

/-- Pure envelope check:
    `{"payload": "<canonical JSON>", "signature": "<ed25519 signature hex>"}`.
    The config public key is a startup trust root and is not read from the
    envelope it authenticates. -/
def checkEnvelope (text publicKey : String) : Except String TrustedConfig := do
  let envelope ← Json.parse text
  let payload ← getObjString envelope "payload"
  let signature ← getObjString envelope "signature"
  checkTrustedConfig publicKey payload signature

/-- Load and verify the signed config envelope. Fail-closed: any failure
    aborts the host before it touches stdio. -/
def loadTrustedConfig (path : System.FilePath) (publicKey : String) :
    IO TrustedConfig := do
  let text ← IO.FS.readFile path
  match checkEnvelope text publicKey with
  | .ok config => pure config
  | .error err => throw <| IO.userError s!"trusted config rejected: {err}"

end Host
