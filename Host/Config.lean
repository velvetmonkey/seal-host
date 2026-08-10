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
import Kernels.PrincipalBudget

namespace Host

open Lean
open Seal.JsonUtil

/-- The host's one trusted config: signed, epoch-stamped, one section per
    kernel. `safety` is the V1 policy shape (kernel S); `temporal` is the LTL
    safety-policy list (kernel T), absent section = no temporal constraints. -/
structure TrustedConfig where
  /-- Config epoch, carried inside the signed payload (≥ 1 enforced at load)
      and stamped into every audit line. -/
  epoch : Nat
  /-- The V1 safety policy (kernel S). -/
  safety : Seal.Policy
  /-- LTL safety policies (kernel T); empty list = no temporal constraints. -/
  temporal : List Kernels.TemporalPolicy
  /-- Quorum-approval config (kernel C); `none` = kernel not deployed. -/
  consensus : Option Kernels.ConsensusConfig
  /-- CRDT convergence config (kernel V). -/
  convergence : Kernels.ConvergenceConfig
  /-- Forecast-calibration config (kernel K); `none` = kernel not deployed. -/
  calibration : Option Kernels.CalibrationConfig
  /-- Linear-grant config (kernel L); `none` = kernel not deployed. -/
  linear : Option Kernels.LinearConfig
  /-- Global budget-cap config (kernel B). -/
  budget : Kernels.BudgetConfig
  /-- V2.1: the signed principal key registry + per-principal budgets
      (kernel PB). Defaulted so existing config literals stay valid; the
      `ofBundle_principals` tripwire pins that the mapping is not forgotten. -/
  principals : Option Kernels.PrincipalsConfig := none

/-- Config lints for the `principals` section, fail-closed in `ofBundle`:
    1. duplicate principal ids with DIFFERENT pubkeys — an ambiguous registry
       (`verifyEnvelope` reads the FIRST match; a second key under the same id
       would be silently dead, or worse, order-dependent);
    2. same-name per-principal budgets with conflicting caps — each
       (principal, name) pair shares one counter, the `budgetCapsConsistent`
       lint verbatim;
    3. per-principal budgets with an EMPTY key registry — every covered call
       would deny unconditionally (the mixed-mode footgun, refused at load
       instead of surprising the operator at runtime). -/
def principalsConsistent (cfg : Kernels.PrincipalsConfig) : Bool :=
  (cfg.registry.all fun k => cfg.registry.all fun k' =>
      k'.id != k.id || k'.pubkey == k.pubkey)
  && Kernels.budgetCapsConsistent cfg.budgets
  && (cfg.budgets.isEmpty || !cfg.registry.isEmpty)

/-- The principals bundle section mapped onto the kernel config type. -/
def principalsOfBundle (b : Seal.PolicyBundle) : Option Kernels.PrincipalsConfig :=
  b.effectivePrincipals.map fun s =>
    { registry := s.keys.map fun k => { id := k.id, pubkey := k.pubkey }
      budgets := s.budgets.map fun r =>
        { name := r.name, cap := r.cap, tools := r.tools, costArg := r.costArg } }

/-- Map the parsed policy-v2 bundle (`Seal.parsePolicyBundle` — the verified
    8-section config vocabulary) onto the kernel config types. Field-by-field
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
    -- Fail closed on the principals lints (`principalsConsistent`): ambiguous
    -- registry, conflicting per-principal caps, or budgets with no keys.
    if (principalsOfBundle b).all principalsConsistent then
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
              { name := r.name, cap := r.cap, tools := r.tools, costArg := r.costArg }
            principals := principalsOfBundle b }
    else
      .error "inconsistent principals section (duplicate id, conflicting caps, or empty key registry)"
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
  · split at h
    · injection h with h
      subst h
      rfl
    · simp at h
  · simp at h

theorem ofBundle_safety {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) : cfg.safety = b.safety := by
  unfold ofBundle at h
  split at h
  · split at h
    · injection h with h
      subst h
      rfl
    · simp at h
  · simp at h

theorem ofBundle_consensus {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.consensus.isSome = b.effectiveConsensus.isSome := by
  unfold ofBundle at h
  split at h
  · split at h
    · injection h with h
      subst h
      cases b.effectiveConsensus <;> rfl
    · simp at h
  · simp at h

theorem ofBundle_convergence {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.convergence.isEmpty = b.effectiveConvergence.isEmpty := by
  unfold ofBundle at h
  split at h
  · split at h
    · injection h with h
      subst h
      cases b.effectiveConvergence <;> rfl
    · simp at h
  · simp at h

theorem ofBundle_calibration {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    (∃ c, cfg.calibration = some c ∧ c.enabled = true)
      ↔ (∃ s, b.calibration = some s ∧ s.enabled = true) := by
  unfold ofBundle at h
  split at h
  · split at h
    · injection h with h
      subst h
      cases b.calibration <;> simp
    · simp at h
  · simp at h

theorem ofBundle_linear {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.linear.isSome = b.effectiveLinear.isSome := by
  unfold ofBundle at h
  split at h
  · split at h
    · injection h with h
      subst h
      cases b.effectiveLinear <;> rfl
    · simp at h
  · simp at h

theorem ofBundle_budget {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.budget.isEmpty = b.effectiveBudget.isEmpty := by
  unfold ofBundle at h
  split at h
  · split at h
    · injection h with h
      subst h
      cases b.effectiveBudget <;> rfl
    · simp at h
  · simp at h

theorem ofBundle_temporal {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.temporal = b.effectiveTemporal.map fun r =>
      { name := r.name, trigger := r.trigger, forbidden := r.forbidden } := by
  unfold ofBundle at h
  split at h
  · split at h
    · injection h with h
      subst h
      rfl
    · simp at h
  · simp at h

/-- V2.1: the principals section's activation survives `ofBundle` — the
    tripwire against a forgotten mapping (the `principals` field is defaulted
    on `TrustedConfig`, so without this lemma a dropped `principals :=` line
    would compile silently). -/
theorem ofBundle_principals {b : Seal.PolicyBundle} {cfg : TrustedConfig}
    (h : ofBundle b = .ok cfg) :
    cfg.principals.isSome = b.effectivePrincipals.isSome := by
  unfold ofBundle at h
  split at h
  · split at h
    · injection h with h
      subst h
      cases hb : b.effectivePrincipals <;> simp [principalsOfBundle, hb]
    · simp at h
  · simp at h

/-- The lint holds of every loaded config — the `hconsist` discharge hook for
    `principal_budget_committed_trace_within_cap_of_consistent`
    (`Host/PrincipalCommit.lean`): any config `ofBundle` accepts carries
    consistent per-principal caps. -/
theorem ofBundle_principals_consistent {b : Seal.PolicyBundle}
    {cfg : TrustedConfig} (h : ofBundle b = .ok cfg)
    (pc : Kernels.PrincipalsConfig) (hp : cfg.principals = some pc) :
    Kernels.budgetCapsConsistent pc.budgets = true := by
  unfold ofBundle at h
  split at h
  · split at h
    · next hall =>
        injection h with h
        subst h
        simp only at hp
        rw [hp] at hall
        have hc : principalsConsistent pc = true := by simpa using hall
        simp only [principalsConsistent, Bool.and_eq_true] at hc
        exact hc.1.2
    · simp at h
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

    The vocabulary is `Seal.parsePolicyBundle` — the policy-v2 8-section
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
    `{"payload": "<exact compact JSON bytes>", "signature": "<ed25519 signature hex>"}`.
    The spelling is the signer-defined byte contract, not an RFC 8785/JCS
    conformance claim.
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
