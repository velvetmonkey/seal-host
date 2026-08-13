/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Sha256
import Host.JsonWire
import SealV2.EffectEnvelope
import Lean.Data.Json

/-!
Object B's kernel model. `CorePayload` carries the durable release status but
has no EXECUTED field. `ObjectB ctx` is constructible only when
the executable `Established` gate accepts the payload.

`EstablishmentContext` is the explicit verifier-supplied assumption boundary:
the decision-input kernel-production predicate, offline delegation trust, and
durable recording. The signed-effect fields are bound directly to the pinned
kernel's `SealV2.Effect.deriveEffect`; this module defines no competing
canonical-byte function. Request and approval references, the config digest,
and decoding of the deployed host's raw route result are fixed functions below
rather than caller-chosen fields. This module proves only that the deployment
predicates accepted their payload arguments; it does not prove those external
checks faithful, global sequence monotonicity, or signatures. The separate
`Host.ThreeArtifactByteLock` module owns the wire encoding and its Rust/Lean
agreement witness; this module does not duplicate either.

The gate imposes no independent meaning or validity check on `schema`,
`verificationProfile`, `recordedAt`, `sequenceNumber`, `postStateHash`,
`receiptNonce`, `operationId`, `releaseStatus`, or `kernelArtifactSha256`.
Operation and artifact identity can be observed by deployment-supplied
predicates, but this module does not constrain how those predicates use them.
-/

namespace Host.ObjectB

open Lean

abbrev Digest256 := Host.Sha256.Digest256

inductive Schema where
  | v1
  deriving Repr, BEq, DecidableEq

structure DeploymentId where
  bytes : ByteArray
  deriving BEq, DecidableEq

structure ReceiptKeyDelegationRef where
  digest : Digest256
  deriving Repr, BEq, DecidableEq

structure KernelProfile where
  name : String
  deriving Repr, BEq, DecidableEq

inductive VerificationProfile where
  | singleStepClosedV1
  deriving Repr, BEq, DecidableEq

inductive Verdict where
  | allow
  | block
  | error
  deriving Repr, BEq, DecidableEq

inductive DurabilityClass where
  | assertedLocalFsync
  | witnessedExternal
  | unknown
  deriving Repr, BEq, DecidableEq

inductive ReleaseStatus where
  | pending
  | unknown
  | released
  | notApplicable
  deriving Repr, BEq, DecidableEq

structure UntrustedWallTime where
  value : Nat
  deriving Repr, BEq, DecidableEq

structure OperationId where
  bytes : ByteArray
  deriving BEq, DecidableEq

inductive PostStateHash where
  | candidate (digest : Digest256)
  | stateless
  deriving Repr, BEq, DecidableEq

structure ReceiptNonce where
  bytes : ByteArray
  deriving BEq, DecidableEq

structure DecisionInputs where
  requestStatementBytes : ByteArray
  approvalStatementBytes : List ByteArray
  signedConfigBytes : ByteArray
  kernelArtifactSha256 : Digest256
  kernelProfile : KernelProfile
  stepInput : SealV2.RawBytes
  effectClaim : SealV2.Effect.EffectClaim
  logicalTime : Nat
  deriving BEq, DecidableEq

structure CorePayload where
  schema : Schema
  deploymentId : DeploymentId
  receiptKeyDelegationRef : ReceiptKeyDelegationRef
  requestStatementRef : Digest256
  requestStatementBytes : ByteArray
  approvalStatementRefs : List Digest256
  approvalStatementBytes : List ByteArray
  configDigest : Digest256
  signedConfigBytes : ByteArray
  kernelArtifactSha256 : Digest256
  kernelProfile : KernelProfile
  stepInput : SealV2.RawBytes
  effectClaim : SealV2.Effect.EffectClaim
  rawKernelOutputBytes : ByteArray
  verdict : Verdict
  verificationProfile : VerificationProfile
  logicalTime : Nat
  recordedAt : UntrustedWallTime
  releaseStatus : ReleaseStatus
  durabilityClass : DurabilityClass
  operationId : OperationId
  sequenceNumber : Nat
  postStateHash : PostStateHash
  receiptNonce : ReceiptNonce
  deriving BEq, DecidableEq

def CorePayload.decisionInputs (p : CorePayload) : DecisionInputs :=
  { requestStatementBytes := p.requestStatementBytes
    approvalStatementBytes := p.approvalStatementBytes
    signedConfigBytes := p.signedConfigBytes
    kernelArtifactSha256 := p.kernelArtifactSha256
    kernelProfile := p.kernelProfile
    stepInput := p.stepInput
    effectClaim := p.effectClaim
    logicalTime := p.logicalTime }

structure EstablishmentContext where
  kernelProduced : DecisionInputs → ByteArray → Verdict → Bool
  delegated : DeploymentId → ReceiptKeyDelegationRef → Bool
  durablyRecorded : DurabilityClass → CorePayload → Bool

def requestStatementRef (bytes : ByteArray) : Digest256 :=
  Host.Sha256.sha256Digest ("seal.request-ref/v1\x00".toUTF8 ++ bytes)

def approvalStatementRef (bytes : ByteArray) : Digest256 :=
  Host.Sha256.sha256Digest bytes

def configDigest (bytes : ByteArray) : Digest256 :=
  Host.Sha256.sha256Digest bytes

def verdictOfRaw (raw : ByteArray) : Option Verdict := do
  let text ← String.fromUTF8? raw
  guard (Host.JsonWire.safe text)
  let json ← (Json.parse text).toOption
  let route ← (json.getObjVal? "route").toOption.bind (·.getStr?.toOption)
  match route with
  | "forward" => some .allow
  | "block" => some .block
  | _ => none

def Established (ctx : EstablishmentContext) (p : CorePayload) : Bool :=
  decide (SealV2.Effect.deriveEffect p.stepInput.trimAscii.toString = some p.effectClaim) &&
  decide (verdictOfRaw p.rawKernelOutputBytes = some p.verdict) &&
  ctx.kernelProduced p.decisionInputs p.rawKernelOutputBytes p.verdict &&
  ctx.delegated p.deploymentId p.receiptKeyDelegationRef &&
  decide (p.requestStatementRef = requestStatementRef p.requestStatementBytes) &&
  decide (p.approvalStatementRefs =
    p.approvalStatementBytes.map approvalStatementRef) &&
  decide (p.configDigest = configDigest p.signedConfigBytes) &&
  ctx.durablyRecorded p.durabilityClass p

structure ObjectB (ctx : EstablishmentContext) where
  payload : CorePayload
  established : Established ctx payload = true

def check (ctx : EstablishmentContext) (p : CorePayload) : Option (ObjectB ctx) :=
  if h : Established ctx p = true then some { payload := p, established := h } else none

theorem kernel_effect_boundary_matches_payload
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    SealV2.Effect.deriveEffect r.payload.stepInput.trimAscii.toString =
      some r.payload.effectClaim :=
  by
    have h := r.established
    simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at h
    exact h.1.1.1.1.1.1.1

theorem verdict_decoder_matches_payload
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    verdictOfRaw r.payload.rawKernelOutputBytes = some r.payload.verdict :=
  by
    have h := r.established
    simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at h
    exact h.1.1.1.1.1.1.2

theorem check_refuses_kernel_effect_mismatch
    (ctx : EstablishmentContext) (p : CorePayload) (got : SealV2.Effect.EffectClaim)
    (hgot : SealV2.Effect.deriveEffect p.stepInput.trimAscii.toString = some got)
    (hne : got ≠ p.effectClaim) :
    check ctx p = none := by
  unfold check
  split
  next hvalid =>
    have heffect :
        SealV2.Effect.deriveEffect p.stepInput.trimAscii.toString =
          some p.effectClaim := by
      simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at hvalid
      exact hvalid.1.1.1.1.1.1.1
    have hsome : some got = some p.effectClaim := hgot.symm.trans heffect
    exact (hne (Option.some.inj hsome)).elim
  next => rfl

theorem check_refuses_verdict_mismatch
    (ctx : EstablishmentContext) (p : CorePayload) (got : Verdict)
    (hgot : verdictOfRaw p.rawKernelOutputBytes = some got)
    (hne : got ≠ p.verdict) :
    check ctx p = none := by
  unfold check
  split
  next hvalid =>
    have hraw :
        verdictOfRaw p.rawKernelOutputBytes = some p.verdict := by
      simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at hvalid
      exact hvalid.1.1.1.1.1.1.2
    have hsome : some got = some p.verdict :=
      hgot.symm.trans hraw
    exact (hne (Option.some.inj hsome)).elim
  next => rfl

theorem context_delegation_predicate_accepted
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    ctx.delegated r.payload.deploymentId r.payload.receiptKeyDelegationRef = true :=
  by
    have h := r.established
    simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at h
    exact h.1.1.1.1.2

theorem context_kernel_production_predicate_accepted
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    ctx.kernelProduced r.payload.decisionInputs r.payload.rawKernelOutputBytes
      r.payload.verdict = true := by
  have h := r.established
  simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1.1.2

theorem context_recording_predicate_accepted
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    ctx.durablyRecorded r.payload.durabilityClass r.payload = true := by
  have h := r.established
  simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.2

structure OperationObservation where
  decisionInputs : DecisionInputs
  rawKernelOutputBytes : ByteArray
  verdict : Verdict
  recordedPayload : CorePayload
  released : Bool
  executed : Bool
  deriving BEq, DecidableEq

def CoreClaimHolds {ctx : EstablishmentContext}
    (r : ObjectB ctx) (o : OperationObservation) : Prop :=
  o.decisionInputs = r.payload.decisionInputs ∧
  o.rawKernelOutputBytes = r.payload.rawKernelOutputBytes ∧
  o.verdict = r.payload.verdict ∧
  o.recordedPayload = r.payload

theorem core_claim_does_not_constrain_release_or_execution
    {ctx : EstablishmentContext} (r : ObjectB ctx) (released executed : Bool) :
    ∃ o, CoreClaimHolds r o ∧ o.released = released ∧ o.executed = executed := by
  let o : OperationObservation :=
    { decisionInputs := r.payload.decisionInputs
      rawKernelOutputBytes := r.payload.rawKernelOutputBytes
      verdict := r.payload.verdict
      recordedPayload := r.payload
      released := released
      executed := executed }
  exact ⟨o, ⟨rfl, rfl, rfl, rfl⟩, rfl, rfl⟩

structure AssertedProvenance where
  hostBinarySha256 : Option Digest256
  toolchain : Option String
  axioms : List String
  deriving Repr, BEq, DecidableEq

structure PresentedObjectB (ctx : EstablishmentContext) where
  core : ObjectB ctx
  assertedProvenance : Option AssertedProvenance

def PresentedObjectB.verdict {ctx : EstablishmentContext}
    (r : PresentedObjectB ctx) : Verdict :=
  r.core.payload.verdict

theorem asserted_provenance_cannot_affect_verdict
    {ctx : EstablishmentContext} (r : ObjectB ctx)
    (a b : Option AssertedProvenance) :
    (PresentedObjectB.verdict { core := r, assertedProvenance := a }) =
      PresentedObjectB.verdict { core := r, assertedProvenance := b } :=
  rfl

namespace Witness

def requestBytes : ByteArray := "signed-object-a".toUTF8
def approvalBytes : List ByteArray := ["signed-approval".toUTF8]
def configBytes : ByteArray := "signed-config".toUTF8
def stepInput : SealV2.RawBytes :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"action\":\"call\",\"arguments\":{\"q\":\"ok\"}}}"
def effectClaim : SealV2.Effect.EffectClaim :=
  { resource := "db.execute"
    action := "call"
    args := "{\"q\":\"ok\"}"
    metadata := .absent }
def rawAllow : ByteArray := "{\"route\":\"forward\"}".toUTF8
def rawBlock : ByteArray := "{\"route\":\"block\"}".toUTF8
def profile : KernelProfile := ⟨"kernel-profile-v1"⟩
def deployment : DeploymentId := ⟨"deployment-7".toUTF8⟩
def delegation : ReceiptKeyDelegationRef :=
  ⟨Host.Sha256.sha256Digest "offline-delegation".toUTF8⟩
def artifact : Digest256 := Host.Sha256.sha256Digest "kernel-artifact".toUTF8
def operation : OperationId := ⟨"operation-91".toUTF8⟩

def inputs : DecisionInputs :=
  { requestStatementBytes := requestBytes
    approvalStatementBytes := approvalBytes
    signedConfigBytes := configBytes
    kernelArtifactSha256 := artifact
    kernelProfile := profile
    stepInput := stepInput
    effectClaim := effectClaim
    logicalTime := 41 }

def context : EstablishmentContext :=
  { kernelProduced := fun seenInputs raw verdict =>
      decide (seenInputs = inputs) && decide (raw = rawAllow) && decide (verdict = .allow)
    delegated := fun dep ref => decide (dep = deployment) && decide (ref = delegation)
    durablyRecorded := fun durability p =>
      decide (durability = .assertedLocalFsync) && decide (p.operationId = operation) }

def payload : CorePayload :=
  { schema := .v1
    deploymentId := deployment
    receiptKeyDelegationRef := delegation
    requestStatementRef := requestStatementRef requestBytes
    requestStatementBytes := requestBytes
    approvalStatementRefs := approvalBytes.map approvalStatementRef
    approvalStatementBytes := approvalBytes
    configDigest := configDigest configBytes
    signedConfigBytes := configBytes
    kernelArtifactSha256 := artifact
    kernelProfile := profile
    stepInput := stepInput
    effectClaim := effectClaim
    rawKernelOutputBytes := rawAllow
    verdict := .allow
    verificationProfile := .singleStepClosedV1
    logicalTime := 41
    recordedAt := ⟨1722513600⟩
    releaseStatus := .pending
    durabilityClass := .assertedLocalFsync
    operationId := operation
    sequenceNumber := 17
    postStateHash := .stateless
    receiptNonce := ⟨"local-handle".toUTF8⟩ }

def receipt? : Option (ObjectB context) := check context payload

def wrongVerdict : CorePayload := { payload with verdict := .block }
def wrongRawBytes : CorePayload := { payload with rawKernelOutputBytes := rawBlock }
def wrongCanonicalInput : CorePayload :=
  { payload with
    stepInput :=
      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"action\":\"call\",\"arguments\":{\"q\":\"ox\"}}}" }
def wrongRequestStatementRef : CorePayload :=
  { payload with
    requestStatementRef := requestStatementRef "other-request".toUTF8 }
def wrongApprovalStatementRefs : CorePayload :=
  { payload with
    approvalStatementRefs := [approvalStatementRef "other-approval".toUTF8] }
def wrongConfigDigest : CorePayload :=
  { payload with configDigest := configDigest "other-config".toUTF8 }

def unrecordedContext : EstablishmentContext :=
  { context with durablyRecorded := fun _ _ => false }

def undelegatedContext : EstablishmentContext :=
  { context with delegated := fun _ _ => false }

def liarContext : EstablishmentContext :=
  { kernelProduced := fun _ _ _ => true
    delegated := fun _ _ => true
    durablyRecorded := fun _ _ => true }

def forged : CorePayload :=
  { payload with rawKernelOutputBytes := rawBlock, verdict := .allow }

#guard (check context payload).isSome
#guard SealV2.Effect.deriveEffect payload.stepInput.trimAscii.toString ==
  some payload.effectClaim
#guard verdictOfRaw payload.rawKernelOutputBytes == some payload.verdict
#guard verdictOfRaw "{\"route\":\"block\",\"route\":\"forward\"}".toUTF8 == none
#guard (check context wrongVerdict).isNone
#guard (check context wrongRawBytes).isNone
#guard (check context wrongCanonicalInput).isNone
#guard (check context wrongRequestStatementRef).isNone
#guard (check context wrongApprovalStatementRefs).isNone
#guard (check context wrongConfigDigest).isNone
#guard (check unrecordedContext payload).isNone
#guard (check undelegatedContext payload).isNone
#guard verdictOfRaw forged.rawKernelOutputBytes == some .block
#guard forged.verdict == .allow
#guard (check liarContext forged).isNone

end Witness

end Host.ObjectB
