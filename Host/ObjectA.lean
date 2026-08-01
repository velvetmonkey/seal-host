/- SPDX-License-Identifier: Apache-2.0 -/

import Host.ObjectB

/-!
# Object A and Approval Statement

This module gives the signed request (Object A) and each signed approval
statement an executable, independently checkable gate.  The canonical model
encodings and SHA-256 functions are top-level definitions; callers cannot
replace them.  Deployment-supplied context is limited to the current time and
predicates for signature verification, role delegation, and accepted adapter
profiles.  The theorem names say only that those predicates accepted.

This is not the three-artifact byte-lock.  In particular, this module does not
compare an approval's `requestStatementRef` with an Object A, nor either
statement with Object B.  It also does not implement DSSE JSON parsing or prove
the deployment predicates faithful.

There are no fields wholly unread by the gates: every payload field is bound
into canonical `statementBytes`.  The semantic limits are explicit.  For
Object A, `schema`, `requestNonce`, and `sessionId` receive no independent
meaning check; `deploymentId`, `configRef`, `keyEpoch`, and `signer` are only
arguments to the request-delegation predicate; `adapterProfile` is only an
argument to the adapter predicate; `signatureBytes` is only an argument to the
signature predicate; `issuedAt` and `expiresAt` are checked only against
context-supplied `now`; and `judgedRequestBytes` is digest-bound but not parsed.
For Approval, `schema`, `approvalNonce`, `requestStatementRef`,
`targetCommitment`, `constraints`, and `sessionId` receive no independent
meaning check; `authorityRef`, `deploymentId`, `configRef`, and
`approverIdentity` are only arguments to the approver-delegation predicate;
`adapterProfile` is only an argument to the adapter predicate;
`signatureBytes` is only an argument to the signature predicate; and
`approvedAt` / `approvalExpiresAt` are checked only against context-supplied
`now`.  Thus nonce uniqueness, key-epoch derivation, constraint meaning,
target/request correspondence, cross-artifact context equality, and human
intent are outside these gates.
-/

namespace Host

namespace StatementEncoding

/-- Eight-byte big-endian encoding.  Values at least `2^64` are encoded modulo
    `2^64`; the executable gates below therefore separately require all times
    to be below `2^64`. -/
def u64be (n : Nat) : ByteArray :=
  ByteArray.mk #[
    UInt8.ofNat (n >>> 56), UInt8.ofNat (n >>> 48), UInt8.ofNat (n >>> 40),
    UInt8.ofNat (n >>> 32), UInt8.ofNat (n >>> 24), UInt8.ofNat (n >>> 16),
    UInt8.ofNat (n >>> 8), UInt8.ofNat n]

/-- Length-frame arbitrary bytes so adjacent variable-width fields cannot be
    confused in the model encoding. -/
def frame (bytes : ByteArray) : ByteArray :=
  u64be bytes.size ++ bytes

def frameString (value : String) : ByteArray :=
  frame value.toUTF8

def digestBytes (digest : Host.Sha256.Digest256) : ByteArray :=
  SealCore.Sha256.Digest256.toHex digest |>.toUTF8

end StatementEncoding

namespace ObjectA

abbrev Digest256 := Host.Sha256.Digest256
abbrev DeploymentId := Host.ObjectB.DeploymentId

inductive Schema where
  | v1
  deriving Repr, BEq, DecidableEq

structure RequestNonce where
  bytes : ByteArray
  deriving BEq, DecidableEq

structure SessionId where
  bytes : ByteArray
  deriving BEq, DecidableEq

structure RequestSignerRef where
  bytes : ByteArray
  deriving BEq, DecidableEq

structure AdapterProfile where
  identifier : String
  version : String
  artifactSha256 : Digest256
  deriving Repr, BEq, DecidableEq

structure Payload where
  schema : Schema
  requestNonce : RequestNonce
  deploymentId : DeploymentId
  sessionId : SessionId
  configRef : Digest256
  keyEpoch : Digest256
  adapterProfile : AdapterProfile
  issuedAt : Nat
  expiresAt : Nat
  judgedRequestBytes : ByteArray
  judgedRequestSha256 : Digest256
  deriving BEq, DecidableEq

structure Candidate where
  payload : Payload
  signer : RequestSignerRef
  signatureBytes : ByteArray
  statementBytes : ByteArray
  deriving BEq, DecidableEq

structure VerificationContext where
  now : Nat
  requestSignerDelegated :
    DeploymentId -> Digest256 -> Digest256 -> RequestSignerRef -> Bool
  adapterProfileAccepted : DeploymentId -> Digest256 -> AdapterProfile -> Bool
  signatureVerified : RequestSignerRef -> ByteArray -> ByteArray -> Bool

def schemaBytes : Schema -> ByteArray
  | .v1 => ByteArray.mk #[0x01]

def adapterProfileBytes (profile : AdapterProfile) : ByteArray :=
  StatementEncoding.frameString profile.identifier ++
  StatementEncoding.frameString profile.version ++
  StatementEncoding.digestBytes profile.artifactSha256

/-- Canonical signed preimage for Object A in this model. -/
def signingBytes (payload : Payload) : ByteArray :=
  "seal.authenticated-request/v1\x00".toUTF8 ++
  schemaBytes payload.schema ++
  StatementEncoding.frame payload.requestNonce.bytes ++
  StatementEncoding.frame payload.deploymentId.bytes ++
  StatementEncoding.frame payload.sessionId.bytes ++
  StatementEncoding.digestBytes payload.configRef ++
  StatementEncoding.digestBytes payload.keyEpoch ++
  StatementEncoding.frame (adapterProfileBytes payload.adapterProfile) ++
  StatementEncoding.u64be payload.issuedAt ++
  StatementEncoding.u64be payload.expiresAt ++
  StatementEncoding.frame payload.judgedRequestBytes ++
  StatementEncoding.digestBytes payload.judgedRequestSha256

/-- Canonical complete statement bytes: signed preimage, signer reference, and
    signature, each length-framed.  This is a model encoding, not a DSSE JSON
    serializer. -/
def statementBytes (payload : Payload) (signer : RequestSignerRef)
    (signatureBytes : ByteArray) : ByteArray :=
  StatementEncoding.frame (signingBytes payload) ++
  StatementEncoding.frame signer.bytes ++
  StatementEncoding.frame signatureBytes

def judgedRequestDigest (bytes : ByteArray) : Digest256 :=
  Host.Sha256.sha256Digest bytes

def validAt (now issuedAt expiresAt : Nat) : Bool :=
  expiresAt < 2 ^ 64 && issuedAt <= now && now <= expiresAt

def Accepted (ctx : VerificationContext) (candidate : Candidate) : Bool :=
  decide (candidate.statementBytes =
    statementBytes candidate.payload candidate.signer candidate.signatureBytes) &&
  decide (candidate.payload.judgedRequestSha256 =
    judgedRequestDigest candidate.payload.judgedRequestBytes) &&
  validAt ctx.now candidate.payload.issuedAt candidate.payload.expiresAt &&
  ctx.requestSignerDelegated candidate.payload.deploymentId candidate.payload.configRef
    candidate.payload.keyEpoch candidate.signer &&
  ctx.adapterProfileAccepted candidate.payload.deploymentId candidate.payload.configRef
    candidate.payload.adapterProfile &&
  ctx.signatureVerified candidate.signer (signingBytes candidate.payload)
    candidate.signatureBytes

structure ObjectA (ctx : VerificationContext) where
  candidate : Candidate
  accepted : Accepted ctx candidate = true

def check (ctx : VerificationContext) (candidate : Candidate) : Option (ObjectA ctx) :=
  if h : Accepted ctx candidate = true then
    some { candidate := candidate, accepted := h }
  else none

theorem canonical_statement_bytes_match_fields
    {ctx : VerificationContext} (request : ObjectA ctx) :
    request.candidate.statementBytes = statementBytes request.candidate.payload
      request.candidate.signer request.candidate.signatureBytes := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1.1

theorem canonical_judged_request_digest_matches_bytes
    {ctx : VerificationContext} (request : ObjectA ctx) :
    request.candidate.payload.judgedRequestSha256 =
      judgedRequestDigest request.candidate.payload.judgedRequestBytes := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1.2

theorem context_time_is_inside_validity_window
    {ctx : VerificationContext} (request : ObjectA ctx) :
    validAt ctx.now request.candidate.payload.issuedAt
      request.candidate.payload.expiresAt = true := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.2

theorem context_request_signer_delegation_predicate_accepted
    {ctx : VerificationContext} (request : ObjectA ctx) :
    ctx.requestSignerDelegated request.candidate.payload.deploymentId
      request.candidate.payload.configRef request.candidate.payload.keyEpoch
      request.candidate.signer = true := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.2

theorem context_adapter_profile_predicate_accepted
    {ctx : VerificationContext} (request : ObjectA ctx) :
    ctx.adapterProfileAccepted request.candidate.payload.deploymentId
      request.candidate.payload.configRef request.candidate.payload.adapterProfile = true := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.2

theorem context_signature_predicate_accepted
    {ctx : VerificationContext} (request : ObjectA ctx) :
    ctx.signatureVerified request.candidate.signer
      (signingBytes request.candidate.payload) request.candidate.signatureBytes = true := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.2

theorem check_refuses_statement_field_mismatch
    (ctx : VerificationContext) (candidate : Candidate)
    (hne : candidate.statementBytes ≠
      statementBytes candidate.payload candidate.signer candidate.signatureBytes) :
    check ctx candidate = none := by
  unfold check
  split
  next haccepted =>
    simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at haccepted
    exact absurd haccepted.1.1.1.1.1 hne
  next => rfl

end ObjectA

namespace ApprovalStatement

abbrev Digest256 := Host.Sha256.Digest256
abbrev DeploymentId := Host.ObjectB.DeploymentId
abbrev SessionId := Host.ObjectA.SessionId
abbrev AdapterProfile := Host.ObjectA.AdapterProfile

inductive Schema where
  | v1
  deriving Repr, BEq, DecidableEq

structure ApproverIdentity where
  bytes : ByteArray
  deriving BEq, DecidableEq

structure ApprovalNonce where
  bytes : ByteArray
  deriving BEq, DecidableEq

structure AuthorityRef where
  digest : Digest256
  deriving Repr, BEq, DecidableEq

structure Payload where
  schema : Schema
  approverIdentity : ApproverIdentity
  approvalNonce : ApprovalNonce
  requestStatementRef : Digest256
  targetCommitment : Digest256
  constraints : ByteArray
  approvedAt : Nat
  approvalExpiresAt : Nat
  authorityRef : AuthorityRef
  deploymentId : DeploymentId
  sessionId : SessionId
  configRef : Digest256
  adapterProfile : AdapterProfile
  deriving BEq, DecidableEq

structure Candidate where
  payload : Payload
  signatureBytes : ByteArray
  statementBytes : ByteArray
  deriving BEq, DecidableEq

structure VerificationContext where
  now : Nat
  approverDelegated :
    AuthorityRef -> DeploymentId -> Digest256 -> ApproverIdentity -> Bool
  adapterProfileAccepted : DeploymentId -> Digest256 -> AdapterProfile -> Bool
  signatureVerified : ApproverIdentity -> ByteArray -> ByteArray -> Bool

def schemaBytes : Schema -> ByteArray
  | .v1 => ByteArray.mk #[0x01]

/-- Canonical signed preimage for an Approval Statement in this model. -/
def signingBytes (payload : Payload) : ByteArray :=
  "seal.approval-statement/v1\x00".toUTF8 ++
  schemaBytes payload.schema ++
  StatementEncoding.frame payload.approverIdentity.bytes ++
  StatementEncoding.frame payload.approvalNonce.bytes ++
  StatementEncoding.digestBytes payload.requestStatementRef ++
  StatementEncoding.digestBytes payload.targetCommitment ++
  StatementEncoding.frame payload.constraints ++
  StatementEncoding.u64be payload.approvedAt ++
  StatementEncoding.u64be payload.approvalExpiresAt ++
  StatementEncoding.digestBytes payload.authorityRef.digest ++
  StatementEncoding.frame payload.deploymentId.bytes ++
  StatementEncoding.frame payload.sessionId.bytes ++
  StatementEncoding.digestBytes payload.configRef ++
  StatementEncoding.frame (ObjectA.adapterProfileBytes payload.adapterProfile)

def statementBytes (payload : Payload) (signatureBytes : ByteArray) : ByteArray :=
  StatementEncoding.frame (signingBytes payload) ++
  StatementEncoding.frame signatureBytes

def validAt (now approvedAt expiresAt : Nat) : Bool :=
  expiresAt < 2 ^ 64 && approvedAt <= now && now <= expiresAt

def Accepted (ctx : VerificationContext) (candidate : Candidate) : Bool :=
  decide (candidate.statementBytes =
    statementBytes candidate.payload candidate.signatureBytes) &&
  validAt ctx.now candidate.payload.approvedAt candidate.payload.approvalExpiresAt &&
  ctx.approverDelegated candidate.payload.authorityRef candidate.payload.deploymentId
    candidate.payload.configRef candidate.payload.approverIdentity &&
  ctx.adapterProfileAccepted candidate.payload.deploymentId candidate.payload.configRef
    candidate.payload.adapterProfile &&
  ctx.signatureVerified candidate.payload.approverIdentity
    (signingBytes candidate.payload) candidate.signatureBytes

structure ApprovalStatement (ctx : VerificationContext) where
  candidate : Candidate
  accepted : Accepted ctx candidate = true

def check (ctx : VerificationContext)
    (candidate : Candidate) : Option (ApprovalStatement ctx) :=
  if h : Accepted ctx candidate = true then
    some { candidate := candidate, accepted := h }
  else none

theorem canonical_statement_bytes_match_fields
    {ctx : VerificationContext} (approval : ApprovalStatement ctx) :
    approval.candidate.statementBytes =
      statementBytes approval.candidate.payload approval.candidate.signatureBytes := by
  have h := approval.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1

theorem context_time_is_inside_validity_window
    {ctx : VerificationContext} (approval : ApprovalStatement ctx) :
    validAt ctx.now approval.candidate.payload.approvedAt
      approval.candidate.payload.approvalExpiresAt = true := by
  have h := approval.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.2

theorem context_approver_delegation_predicate_accepted
    {ctx : VerificationContext} (approval : ApprovalStatement ctx) :
    ctx.approverDelegated approval.candidate.payload.authorityRef
      approval.candidate.payload.deploymentId approval.candidate.payload.configRef
      approval.candidate.payload.approverIdentity = true := by
  have h := approval.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.2

theorem context_adapter_profile_predicate_accepted
    {ctx : VerificationContext} (approval : ApprovalStatement ctx) :
    ctx.adapterProfileAccepted approval.candidate.payload.deploymentId
      approval.candidate.payload.configRef approval.candidate.payload.adapterProfile = true := by
  have h := approval.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.2

theorem context_signature_predicate_accepted
    {ctx : VerificationContext} (approval : ApprovalStatement ctx) :
    ctx.signatureVerified approval.candidate.payload.approverIdentity
      (signingBytes approval.candidate.payload) approval.candidate.signatureBytes = true := by
  have h := approval.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.2

theorem check_refuses_statement_field_mismatch
    (ctx : VerificationContext) (candidate : Candidate)
    (hne : candidate.statementBytes ≠
      statementBytes candidate.payload candidate.signatureBytes) :
    check ctx candidate = none := by
  unfold check
  split
  next haccepted =>
    simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at haccepted
    exact absurd haccepted.1.1.1.1 hne
  next => rfl

end ApprovalStatement

namespace StatementWitness

def deployment : ObjectB.DeploymentId := { bytes := "deployment-7".toUTF8 }
def session : ObjectA.SessionId := { bytes := "session-4".toUTF8 }
def configRef : Host.Sha256.Digest256 :=
  Host.Sha256.sha256Digest "signed-config".toUTF8
def keyEpoch : Host.Sha256.Digest256 :=
  Host.Sha256.sha256Digest "request-key-epoch".toUTF8
def adapterDigest : Host.Sha256.Digest256 :=
  Host.Sha256.sha256Digest "adapter-artifact".toUTF8
def adapter : ObjectA.AdapterProfile :=
  { identifier := "stdio-gated-sink", version := "1.0.0", artifactSha256 := adapterDigest }
def requestSigner : ObjectA.RequestSignerRef := { bytes := "request-key-3".toUTF8 }
def requestSignature : ByteArray := "request-signature".toUTF8
def requestBytes : ByteArray := "tools.call:database.drop".toUTF8

def requestPayload : ObjectA.Payload :=
  { schema := .v1
    requestNonce := { bytes := "request-nonce-11".toUTF8 }
    deploymentId := deployment
    sessionId := session
    configRef := configRef
    keyEpoch := keyEpoch
    adapterProfile := adapter
    issuedAt := 100
    expiresAt := 200
    judgedRequestBytes := requestBytes
    judgedRequestSha256 := ObjectA.judgedRequestDigest requestBytes }

def requestCandidate : ObjectA.Candidate :=
  { payload := requestPayload
    signer := requestSigner
    signatureBytes := requestSignature
    statementBytes := ObjectA.statementBytes requestPayload requestSigner requestSignature }

def requestContext : ObjectA.VerificationContext :=
  { now := 150
    requestSignerDelegated := fun dep cfg epoch signer =>
      decide (dep = deployment) && decide (cfg = configRef) &&
      decide (epoch = keyEpoch) && decide (signer = requestSigner)
    adapterProfileAccepted := fun dep cfg profile =>
      decide (dep = deployment) && decide (cfg = configRef) && decide (profile = adapter)
    signatureVerified := fun signer message signature =>
      decide (signer = requestSigner) &&
      decide (message = ObjectA.signingBytes requestPayload) &&
      decide (signature = requestSignature) }

def request : ObjectA.ObjectA requestContext :=
  { candidate := requestCandidate
    accepted := by
      simp [ObjectA.Accepted, requestCandidate, requestPayload, requestContext,
        ObjectA.validAt, ObjectA.statementBytes, ObjectA.judgedRequestDigest] }

def requestWrongStatementBytes : ObjectA.Candidate :=
  { requestCandidate with statementBytes := "different-signed-request".toUTF8 }
def requestWrongDigest : ObjectA.Candidate :=
  let wrongDigest := Host.Sha256.sha256Digest ("different-request".toUTF8)
  let payload : ObjectA.Payload := { requestPayload with judgedRequestSha256 := wrongDigest }
  { payload := payload
    signer := requestSigner
    signatureBytes := requestSignature
    statementBytes := ObjectA.statementBytes payload requestSigner requestSignature }
def requestIssuedInFuture : ObjectA.Candidate :=
  let payload : ObjectA.Payload := { requestPayload with issuedAt := 151 }
  { payload := payload
    signer := requestSigner
    signatureBytes := requestSignature
    statementBytes := ObjectA.statementBytes payload requestSigner requestSignature }
def requestExpired : ObjectA.Candidate :=
  let payload : ObjectA.Payload := { requestPayload with expiresAt := 149 }
  { payload := payload
    signer := requestSigner
    signatureBytes := requestSignature
    statementBytes := ObjectA.statementBytes payload requestSigner requestSignature }
def requestExpiryOutOfRange : ObjectA.Candidate :=
  let payload : ObjectA.Payload := { requestPayload with expiresAt := 2 ^ 64 }
  { payload := payload
    signer := requestSigner
    signatureBytes := requestSignature
    statementBytes := ObjectA.statementBytes payload requestSigner requestSignature }
def requestBadSignature : ObjectA.Candidate :=
  let signature := "wrong-request-signature".toUTF8
  { payload := requestPayload
    signer := requestSigner
    signatureBytes := signature
    statementBytes := ObjectA.statementBytes requestPayload requestSigner signature }
def requestUndelegatedContext : ObjectA.VerificationContext :=
  { requestContext with requestSignerDelegated := fun _ _ _ _ => false }
def requestRejectedAdapterContext : ObjectA.VerificationContext :=
  { requestContext with adapterProfileAccepted := fun _ _ _ => false }
def requestPermissiveSignatureContext : ObjectA.VerificationContext :=
  { requestContext with signatureVerified := fun _ _ _ => true }

def permissiveRequestContext : ObjectA.VerificationContext :=
  { now := 150
    requestSignerDelegated := fun _ _ _ _ => true
    adapterProfileAccepted := fun _ _ _ => true
    signatureVerified := fun _ _ _ => true }

/-- Strongest admitted-context forgery attempt: the canonical statement bytes
    still encode `requestPayload`, while the visible fields claim a different
    judged request and matching digest.  Even predicates that always return
    true cannot make the canonical-byte conjunct accept it. -/
def forgedRequest : ObjectA.Candidate :=
  let payload :=
    { requestPayload with
      judgedRequestBytes := "tools.call:notes.read".toUTF8
      judgedRequestSha256 := ObjectA.judgedRequestDigest "tools.call:notes.read".toUTF8 }
  { requestCandidate with payload := payload }

def approver : ApprovalStatement.ApproverIdentity :=
  { bytes := "approver-key-8".toUTF8 }
def approvalSignature : ByteArray := "approval-signature".toUTF8
def authority : ApprovalStatement.AuthorityRef :=
  { digest := Host.Sha256.sha256Digest "approval-authority".toUTF8 }
def targetCommitment : Host.Sha256.Digest256 :=
  Host.Sha256.sha256Digest "database/drop/main".toUTF8
def requestRef : Host.Sha256.Digest256 :=
  Host.ObjectB.requestStatementRef requestCandidate.statementBytes

def approvalPayload : ApprovalStatement.Payload :=
  { schema := .v1
    approverIdentity := approver
    approvalNonce := { bytes := "approval-nonce-12".toUTF8 }
    requestStatementRef := requestRef
    targetCommitment := targetCommitment
    constraints := "one-use;before=200".toUTF8
    approvedAt := 120
    approvalExpiresAt := 180
    authorityRef := authority
    deploymentId := deployment
    sessionId := session
    configRef := configRef
    adapterProfile := adapter }

def approvalCandidate : ApprovalStatement.Candidate :=
  { payload := approvalPayload
    signatureBytes := approvalSignature
    statementBytes := ApprovalStatement.statementBytes approvalPayload approvalSignature }

def approvalContext : ApprovalStatement.VerificationContext :=
  { now := 150
    approverDelegated := fun auth dep cfg identity =>
      decide (auth = authority) && decide (dep = deployment) &&
      decide (cfg = configRef) && decide (identity = approver)
    adapterProfileAccepted := fun dep cfg profile =>
      decide (dep = deployment) && decide (cfg = configRef) && decide (profile = adapter)
    signatureVerified := fun identity message signature =>
      decide (identity = approver) &&
      decide (message = ApprovalStatement.signingBytes approvalPayload) &&
      decide (signature = approvalSignature) }

def approval : ApprovalStatement.ApprovalStatement approvalContext :=
  { candidate := approvalCandidate
    accepted := by
      simp [ApprovalStatement.Accepted, approvalCandidate, approvalPayload,
        approvalContext, ApprovalStatement.validAt, ApprovalStatement.statementBytes] }

def approvalWrongStatementBytes : ApprovalStatement.Candidate :=
  { approvalCandidate with statementBytes := "different-signed-approval".toUTF8 }
def approvalApprovedInFuture : ApprovalStatement.Candidate :=
  let payload : ApprovalStatement.Payload := { approvalPayload with approvedAt := 151 }
  { payload := payload
    signatureBytes := approvalSignature
    statementBytes := ApprovalStatement.statementBytes payload approvalSignature }
def approvalExpired : ApprovalStatement.Candidate :=
  let payload : ApprovalStatement.Payload := { approvalPayload with approvalExpiresAt := 149 }
  { payload := payload
    signatureBytes := approvalSignature
    statementBytes := ApprovalStatement.statementBytes payload approvalSignature }
def approvalExpiryOutOfRange : ApprovalStatement.Candidate :=
  let payload : ApprovalStatement.Payload :=
    { approvalPayload with approvalExpiresAt := 2 ^ 64 }
  { payload := payload
    signatureBytes := approvalSignature
    statementBytes := ApprovalStatement.statementBytes payload approvalSignature }
def approvalBadSignature : ApprovalStatement.Candidate :=
  let signature := "wrong-approval-signature".toUTF8
  { payload := approvalPayload
    signatureBytes := signature
    statementBytes := ApprovalStatement.statementBytes approvalPayload signature }
def approvalUndelegatedContext : ApprovalStatement.VerificationContext :=
  { approvalContext with approverDelegated := fun _ _ _ _ => false }
def approvalRejectedAdapterContext : ApprovalStatement.VerificationContext :=
  { approvalContext with adapterProfileAccepted := fun _ _ _ => false }
def approvalPermissiveSignatureContext : ApprovalStatement.VerificationContext :=
  { approvalContext with signatureVerified := fun _ _ _ => true }

/-- The approval analogue of the Object A byte/field forgery: the statement
    bytes still encode `approvalPayload`, while the visible target and
    constraints claim something else. -/
def forgedApproval : ApprovalStatement.Candidate :=
  let payload :=
    { approvalPayload with
      targetCommitment := Host.Sha256.sha256Digest "notes/read".toUTF8,
      constraints := "unlimited".toUTF8 }
  { approvalCandidate with payload := payload }

#guard (ObjectA.check requestContext requestCandidate).isSome
#guard (ObjectA.check requestContext requestWrongStatementBytes).isNone
#guard (ObjectA.check requestPermissiveSignatureContext requestWrongDigest).isNone
#guard (ObjectA.check requestPermissiveSignatureContext requestIssuedInFuture).isNone
#guard (ObjectA.check requestPermissiveSignatureContext requestExpired).isNone
#guard (ObjectA.check requestPermissiveSignatureContext requestExpiryOutOfRange).isNone
#guard (ObjectA.check requestUndelegatedContext requestCandidate).isNone
#guard (ObjectA.check requestRejectedAdapterContext requestCandidate).isNone
#guard (ObjectA.check requestContext requestBadSignature).isNone
#guard (ObjectA.check permissiveRequestContext forgedRequest).isNone

#guard (ApprovalStatement.check approvalContext approvalCandidate).isSome
#guard (ApprovalStatement.check approvalContext approvalWrongStatementBytes).isNone
#guard (ApprovalStatement.check approvalPermissiveSignatureContext
  approvalApprovedInFuture).isNone
#guard (ApprovalStatement.check approvalPermissiveSignatureContext approvalExpired).isNone
#guard (ApprovalStatement.check approvalPermissiveSignatureContext
  approvalExpiryOutOfRange).isNone
#guard (ApprovalStatement.check approvalUndelegatedContext approvalCandidate).isNone
#guard (ApprovalStatement.check approvalRejectedAdapterContext approvalCandidate).isNone
#guard (ApprovalStatement.check approvalContext approvalBadSignature).isNone
#guard (ApprovalStatement.check approvalPermissiveSignatureContext forgedApproval).isNone

end StatementWitness

end Host
