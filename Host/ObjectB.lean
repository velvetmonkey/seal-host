/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Sha256

/-!
Object B's kernel model. `CorePayload` carries DECIDED + RECORDED data only;
it has no RELEASED or EXECUTED field. `ObjectB ctx` is constructible only when
the executable `Established` gate accepts the payload.

`EstablishmentContext` is the explicit assumption boundary: statement
framing/reference rules, interpretation of raw kernel output, the exact-input
kernel-production check, offline delegation, and durable recording. This
module does not prove those external checks faithful, global sequence
monotonicity, signatures, or a wire encoding.
-/

namespace Host.ObjectB

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
  | localFsync
  | replicatedQuorum
  | externallyWitnessed
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
  stepInputBytes : ByteArray
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
  stepInputBytes : ByteArray
  rawKernelOutputBytes : ByteArray
  verdict : Verdict
  verificationProfile : VerificationProfile
  logicalTime : Nat
  recordedAt : UntrustedWallTime
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
    stepInputBytes := p.stepInputBytes
    logicalTime := p.logicalTime }

structure EstablishmentContext where
  frameRequestStatement : ByteArray → ByteArray
  approvalStatementRef : ByteArray → Digest256
  verdictOfRaw : KernelProfile → ByteArray → Option Verdict
  kernelProduced : DecisionInputs → ByteArray → Verdict → Bool
  delegated : DeploymentId → ReceiptKeyDelegationRef → Bool
  durablyRecorded : DurabilityClass → CorePayload → Bool

def requestRefTag : ByteArray := "seal.request-ref/v1\x00".toUTF8

def requestStatementRef (ctx : EstablishmentContext) (bytes : ByteArray) : Digest256 :=
  Host.Sha256.sha256Digest (requestRefTag ++ ctx.frameRequestStatement bytes)

def Established (ctx : EstablishmentContext) (p : CorePayload) : Bool :=
  decide (ctx.verdictOfRaw p.kernelProfile p.rawKernelOutputBytes = some p.verdict) &&
  ctx.kernelProduced p.decisionInputs p.rawKernelOutputBytes p.verdict &&
  ctx.delegated p.deploymentId p.receiptKeyDelegationRef &&
  decide (p.requestStatementRef = requestStatementRef ctx p.requestStatementBytes) &&
  decide (p.approvalStatementRefs =
    p.approvalStatementBytes.map ctx.approvalStatementRef) &&
  decide (p.configDigest = Host.Sha256.sha256Digest p.signedConfigBytes) &&
  ctx.durablyRecorded p.durabilityClass p

structure ObjectB (ctx : EstablishmentContext) where
  payload : CorePayload
  established : Established ctx payload = true

def check (ctx : EstablishmentContext) (p : CorePayload) : Option (ObjectB ctx) :=
  if h : Established ctx p = true then some { payload := p, established := h } else none

theorem verdict_agrees_with_raw_kernel_output_bytes
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    ctx.verdictOfRaw r.payload.kernelProfile r.payload.rawKernelOutputBytes
      = some r.payload.verdict :=
  by
    have h := r.established
    simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at h
    exact h.1.1.1.1.1.1

theorem check_refuses_verdict_mismatch
    (ctx : EstablishmentContext) (p : CorePayload) (got : Verdict)
    (hgot : ctx.verdictOfRaw p.kernelProfile p.rawKernelOutputBytes = some got)
    (hne : got ≠ p.verdict) :
    check ctx p = none := by
  unfold check
  split
  next hvalid =>
    have hraw :
        ctx.verdictOfRaw p.kernelProfile p.rawKernelOutputBytes = some p.verdict := by
      simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at hvalid
      exact hvalid.1.1.1.1.1.1
    have hsome : some got = some p.verdict :=
      hgot.symm.trans hraw
    exact (hne (Option.some.inj hsome)).elim
  next => rfl

theorem external_delegation_required
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    ctx.delegated r.payload.deploymentId r.payload.receiptKeyDelegationRef = true :=
  by
    have h := r.established
    simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at h
    exact h.1.1.1.1.2

theorem kernel_produced_over_exact_decision_inputs
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    ctx.kernelProduced r.payload.decisionInputs r.payload.rawKernelOutputBytes
      r.payload.verdict = true := by
  have h := r.established
  simp only [Established, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1.1.2

theorem durably_recorded_under_stated_class
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

theorem decided_recorded_does_not_entail_released
    {ctx : EstablishmentContext} (r : ObjectB ctx) :
    ¬ (∀ o, CoreClaimHolds r o → o.released = true) := by
  intro h
  let o : OperationObservation :=
    { decisionInputs := r.payload.decisionInputs
      rawKernelOutputBytes := r.payload.rawKernelOutputBytes
      verdict := r.payload.verdict
      recordedPayload := r.payload
      released := false
      executed := false }
  have hcore : CoreClaimHolds r o := ⟨rfl, rfl, rfl, rfl⟩
  have := h o hcore
  contradiction

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
def stepBytes : ByteArray := "step-input".toUTF8
def rawAllow : ByteArray := "kernel-output:ALLOW".toUTF8
def rawBlock : ByteArray := "kernel-output:BLOCK".toUTF8
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
    stepInputBytes := stepBytes
    logicalTime := 41 }

def approvalRef (bytes : ByteArray) : Digest256 := Host.Sha256.sha256Digest bytes

def verdictOfRaw (_ : KernelProfile) (raw : ByteArray) : Option Verdict :=
  if raw = rawAllow then some .allow
  else if raw = rawBlock then some .block
  else none

def context : EstablishmentContext :=
  { frameRequestStatement := fun bytes => bytes
    approvalStatementRef := approvalRef
    verdictOfRaw := verdictOfRaw
    kernelProduced := fun seenInputs raw verdict =>
      decide (seenInputs = inputs) && decide (raw = rawAllow) && decide (verdict = .allow)
    delegated := fun dep ref => decide (dep = deployment) && decide (ref = delegation)
    durablyRecorded := fun durability p =>
      decide (durability = .localFsync) && decide (p.operationId = operation) }

def payload : CorePayload :=
  { schema := .v1
    deploymentId := deployment
    receiptKeyDelegationRef := delegation
    requestStatementRef := requestStatementRef context requestBytes
    requestStatementBytes := requestBytes
    approvalStatementRefs := approvalBytes.map approvalRef
    approvalStatementBytes := approvalBytes
    configDigest := Host.Sha256.sha256Digest configBytes
    signedConfigBytes := configBytes
    kernelArtifactSha256 := artifact
    kernelProfile := profile
    stepInputBytes := stepBytes
    rawKernelOutputBytes := rawAllow
    verdict := .allow
    verificationProfile := .singleStepClosedV1
    logicalTime := 41
    recordedAt := ⟨1722513600⟩
    durabilityClass := .localFsync
    operationId := operation
    sequenceNumber := 17
    postStateHash := .stateless
    receiptNonce := ⟨"local-handle".toUTF8⟩ }

def receipt : ObjectB context :=
  { payload := payload
    established := by
      simp [Established, payload, context, verdictOfRaw, inputs,
        CorePayload.decisionInputs] }

def wrongVerdict : CorePayload := { payload with verdict := .block }
def wrongRawBytes : CorePayload := { payload with rawKernelOutputBytes := rawBlock }
def wrongStepInputs : CorePayload := { payload with stepInputBytes := "other-step".toUTF8 }

def unrecordedContext : EstablishmentContext :=
  { context with durablyRecorded := fun _ _ => false }

def undelegatedContext : EstablishmentContext :=
  { context with delegated := fun _ _ => false }

def noRelease : OperationObservation :=
  { decisionInputs := receipt.payload.decisionInputs
    rawKernelOutputBytes := receipt.payload.rawKernelOutputBytes
    verdict := receipt.payload.verdict
    recordedPayload := receipt.payload
    released := false
    executed := false }

def provenanceA : AssertedProvenance :=
  { hostBinarySha256 := none, toolchain := some "asserted-toolchain-a", axioms := [] }

def provenanceB : AssertedProvenance :=
  { hostBinarySha256 := some artifact
    toolchain := some "asserted-toolchain-b"
    axioms := ["asserted-only"] }

#guard (check context payload).isSome
#guard verdictOfRaw profile payload.rawKernelOutputBytes == some payload.verdict
#guard (check context wrongVerdict).isNone
#guard (check context wrongRawBytes).isNone
#guard (check context wrongStepInputs).isNone
#guard (check unrecordedContext payload).isNone
#guard (check undelegatedContext payload).isNone
#guard noRelease.decisionInputs == receipt.payload.decisionInputs
#guard noRelease.recordedPayload == receipt.payload
#guard noRelease.released == false
#guard
  PresentedObjectB.verdict { core := receipt, assertedProvenance := some provenanceA } ==
  PresentedObjectB.verdict { core := receipt, assertedProvenance := some provenanceB }

end Witness

end Host.ObjectB
