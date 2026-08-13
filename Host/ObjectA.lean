/- SPDX-License-Identifier: Apache-2.0 -/

import Host.ObjectB
import Host.JsonWire
import SealV2.EffectEnvelope
import Lean.Data.Json

/-!
# Object A and Approval Statement

This module gives the authenticated request (Object A) and each approval
statement an executable, independently checkable gate. Presented statement
bytes are the sole signed byte source: a fixed parser binds them to every typed
payload field, and the signature predicate receives those exact presented
bytes. This module deliberately defines no statement serializer and no
canonical-byte helper.

Both statement parsers cross the host's complete seven-guard raw-wire boundary
before `Lean.Json.parse`. Object A additionally sends the exact judged request
through the pinned kernel's `SealV2.Effect.deriveEffect`; it defines no
competing request canonicaliser.

The separate `Host.ThreeArtifactByteLock` module now supplies the
three-artifact byte-lock. This module itself does not
compare an approval's `requestStatementRef` with an Object A, nor either
statement with Object B, and it does not prove deployment predicates faithful.

Every payload field is bound by parsing the presented statement bytes. For
Object A, `schema`, `requestNonce`, and `sessionId` receive no independent
meaning check; `deploymentId` and `configRef` are arguments to both the
request-delegation and adapter predicates; `keyEpoch` is only an argument to
the request-delegation predicate; `signer` is an argument to both delegation
and signature verification; `adapterProfile` is only an argument to the
adapter predicate; `signatureBytes` is only an argument to the signature
predicate; `issuedAt` and `expiresAt` are checked only against context-supplied
`now`; and `judgedRequestBytes` is digest-bound and must be accepted by the C0
effect boundary. For Approval, `schema`, `approvalNonce`,
`requestStatementRef`, `targetCommitment`, `constraints`, and `sessionId`
receive no independent meaning check; `authorityRef` is only an argument to
the approver-delegation predicate; `deploymentId` and `configRef` are arguments
to both delegation and the adapter predicate; `approverIdentity` is an
argument to both delegation and signature verification; `adapterProfile` is
only an argument to the adapter predicate; `signatureBytes` is only an
argument to the signature predicate; and `approvedAt` / `approvalExpiresAt`
are checked only against context-supplied `now`. Thus nonce uniqueness,
key-epoch derivation, constraint meaning, target/request correspondence,
cross-artifact context equality, and human intent are outside these gates.
-/

namespace Host

open Lean

namespace StatementParsing

/-- The only `Lean.Json.parse` entry point for presented statement bytes. -/
def presentedJson? (raw : ByteArray) : Option Json := do
  let text ← String.fromUTF8? raw
  guard (Host.JsonWire.safe text)
  (Json.parse text).toOption

def exactKeys? (json : Json) (keys : List String) (context : String) : Option Unit :=
  (Seal.JsonUtil.expectObjKeys json keys context).toOption

def string? (json : Json) (key : String) : Option String :=
  (json.getObjVal? key).toOption.bind (·.getStr?.toOption)

def nat? (json : Json) (key : String) : Option Nat :=
  (json.getObjVal? key).toOption.bind (·.getNat?.toOption)

def bytes? (json : Json) (key : String) : Option ByteArray :=
  (string? json key).bind SealV2.hexDecode?

def digest? (json : Json) (key : String) : Option Host.Sha256.Digest256 :=
  (string? json key).bind SealCore.Sha256.Digest256.parseHex?

end StatementParsing

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
  /-- Exact presented payload bytes covered by `signatureVerified`. -/
  statementBytes : ByteArray
  deriving BEq, DecidableEq

structure VerificationContext where
  now : Nat
  requestSignerDelegated :
    DeploymentId → Digest256 → Digest256 → RequestSignerRef → Bool
  adapterProfileAccepted : DeploymentId → Digest256 → AdapterProfile → Bool
  signatureVerified : RequestSignerRef → ByteArray → ByteArray → Bool

private def schema? (json : Json) : Option Schema := do
  let value ← StatementParsing.string? json "schema"
  guard (value = "v1")
  pure .v1

private def adapterProfile? (json : Json) : Option AdapterProfile := do
  let _ ← StatementParsing.exactKeys? json
    ["identifier", "version", "artifact_sha256"] "Object A adapter_profile"
  pure {
    identifier := ← StatementParsing.string? json "identifier"
    version := ← StatementParsing.string? json "version"
    artifactSha256 := ← StatementParsing.digest? json "artifact_sha256"
  }

/-- Parse exact presented Object A payload bytes into the fields the gate uses.
    There is intentionally no inverse serializer in this module. -/
def parsePayload (raw : ByteArray) : Option Payload := do
  let json ← StatementParsing.presentedJson? raw
  let _ ← StatementParsing.exactKeys? json
    ["schema", "request_nonce", "deployment_id", "session_id", "config_ref",
      "key_epoch", "adapter_profile", "issued_at", "expires_at",
      "judged_request_bytes", "judged_request_sha256"] "Object A payload"
  let adapterJson ← (json.getObjVal? "adapter_profile").toOption
  pure {
    schema := ← schema? json
    requestNonce := ⟨← StatementParsing.bytes? json "request_nonce"⟩
    deploymentId := ⟨← StatementParsing.bytes? json "deployment_id"⟩
    sessionId := ⟨← StatementParsing.bytes? json "session_id"⟩
    configRef := ← StatementParsing.digest? json "config_ref"
    keyEpoch := ← StatementParsing.digest? json "key_epoch"
    adapterProfile := ← adapterProfile? adapterJson
    issuedAt := ← StatementParsing.nat? json "issued_at"
    expiresAt := ← StatementParsing.nat? json "expires_at"
    judgedRequestBytes := ← StatementParsing.bytes? json "judged_request_bytes"
    judgedRequestSha256 := ← StatementParsing.digest? json "judged_request_sha256"
  }

def judgedRequestDigest (bytes : ByteArray) : Digest256 :=
  Host.Sha256.sha256Digest bytes

/-- The imported C0 parser is the only request-effect interpretation used by
    Object A. -/
def judgedEffect (bytes : ByteArray) : Option SealV2.Effect.EffectClaim := do
  let text ← String.fromUTF8? bytes
  SealV2.Effect.deriveEffect text.trimAscii.toString

def validAt (now issuedAt expiresAt : Nat) : Bool :=
  expiresAt < 2 ^ 64 && issuedAt ≤ now && now ≤ expiresAt

def Accepted (ctx : VerificationContext) (candidate : Candidate) : Bool :=
  decide (parsePayload candidate.statementBytes = some candidate.payload) &&
  decide (candidate.payload.judgedRequestSha256 =
    judgedRequestDigest candidate.payload.judgedRequestBytes) &&
  (judgedEffect candidate.payload.judgedRequestBytes).isSome &&
  validAt ctx.now candidate.payload.issuedAt candidate.payload.expiresAt &&
  ctx.requestSignerDelegated candidate.payload.deploymentId candidate.payload.configRef
    candidate.payload.keyEpoch candidate.signer &&
  ctx.adapterProfileAccepted candidate.payload.deploymentId candidate.payload.configRef
    candidate.payload.adapterProfile &&
  ctx.signatureVerified candidate.signer candidate.statementBytes candidate.signatureBytes

structure ObjectA (ctx : VerificationContext) where
  candidate : Candidate
  accepted : Accepted ctx candidate = true

def check (ctx : VerificationContext) (candidate : Candidate) : Option (ObjectA ctx) :=
  if h : Accepted ctx candidate = true then
    some { candidate := candidate, accepted := h }
  else none

theorem presented_statement_bytes_match_fields
    {ctx : VerificationContext} (request : ObjectA ctx) :
    parsePayload request.candidate.statementBytes = some request.candidate.payload := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1.1.1

theorem judged_request_digest_matches_bytes
    {ctx : VerificationContext} (request : ObjectA ctx) :
    request.candidate.payload.judgedRequestSha256 =
      judgedRequestDigest request.candidate.payload.judgedRequestBytes := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.1.1.1.1.1.2

theorem kernel_effect_boundary_accepts_judged_request
    {ctx : VerificationContext} (request : ObjectA ctx) :
    (judgedEffect request.candidate.payload.judgedRequestBytes).isSome = true := by
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
    ctx.signatureVerified request.candidate.signer request.candidate.statementBytes
      request.candidate.signatureBytes = true := by
  have h := request.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.2

theorem check_refuses_statement_field_mismatch
    (ctx : VerificationContext) (candidate : Candidate)
    (hne : parsePayload candidate.statementBytes ≠ some candidate.payload) :
    check ctx candidate = none := by
  unfold check
  split
  next haccepted =>
    simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at haccepted
    exact absurd haccepted.1.1.1.1.1.1 hne
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
  /-- Exact presented payload bytes covered by `signatureVerified`. -/
  statementBytes : ByteArray
  deriving BEq, DecidableEq

structure VerificationContext where
  now : Nat
  approverDelegated :
    AuthorityRef → DeploymentId → Digest256 → ApproverIdentity → Bool
  adapterProfileAccepted : DeploymentId → Digest256 → AdapterProfile → Bool
  signatureVerified : ApproverIdentity → ByteArray → ByteArray → Bool

private def schema? (json : Json) : Option Schema := do
  let value ← StatementParsing.string? json "schema"
  guard (value = "v1")
  pure .v1

private def adapterProfile? (json : Json) : Option AdapterProfile := do
  let _ ← StatementParsing.exactKeys? json
    ["identifier", "version", "artifact_sha256"] "approval adapter_profile"
  pure {
    identifier := ← StatementParsing.string? json "identifier"
    version := ← StatementParsing.string? json "version"
    artifactSha256 := ← StatementParsing.digest? json "artifact_sha256"
  }

/-- Parse exact presented approval payload bytes into the fields the gate uses.
    There is intentionally no inverse serializer in this module. -/
def parsePayload (raw : ByteArray) : Option Payload := do
  let json ← StatementParsing.presentedJson? raw
  let _ ← StatementParsing.exactKeys? json
    ["schema", "approver_identity", "approval_nonce", "request_statement_ref",
      "target_commitment", "constraints", "approved_at", "approval_expires_at",
      "authority_ref", "deployment_id", "session_id", "config_ref",
      "adapter_profile"] "approval payload"
  let adapterJson ← (json.getObjVal? "adapter_profile").toOption
  pure {
    schema := ← schema? json
    approverIdentity := ⟨← StatementParsing.bytes? json "approver_identity"⟩
    approvalNonce := ⟨← StatementParsing.bytes? json "approval_nonce"⟩
    requestStatementRef := ← StatementParsing.digest? json "request_statement_ref"
    targetCommitment := ← StatementParsing.digest? json "target_commitment"
    constraints := ← StatementParsing.bytes? json "constraints"
    approvedAt := ← StatementParsing.nat? json "approved_at"
    approvalExpiresAt := ← StatementParsing.nat? json "approval_expires_at"
    authorityRef := ⟨← StatementParsing.digest? json "authority_ref"⟩
    deploymentId := ⟨← StatementParsing.bytes? json "deployment_id"⟩
    sessionId := ⟨← StatementParsing.bytes? json "session_id"⟩
    configRef := ← StatementParsing.digest? json "config_ref"
    adapterProfile := ← adapterProfile? adapterJson
  }

def validAt (now approvedAt expiresAt : Nat) : Bool :=
  expiresAt < 2 ^ 64 && approvedAt ≤ now && now ≤ expiresAt

def Accepted (ctx : VerificationContext) (candidate : Candidate) : Bool :=
  decide (parsePayload candidate.statementBytes = some candidate.payload) &&
  validAt ctx.now candidate.payload.approvedAt candidate.payload.approvalExpiresAt &&
  ctx.approverDelegated candidate.payload.authorityRef candidate.payload.deploymentId
    candidate.payload.configRef candidate.payload.approverIdentity &&
  ctx.adapterProfileAccepted candidate.payload.deploymentId candidate.payload.configRef
    candidate.payload.adapterProfile &&
  ctx.signatureVerified candidate.payload.approverIdentity candidate.statementBytes
    candidate.signatureBytes

structure ApprovalStatement (ctx : VerificationContext) where
  candidate : Candidate
  accepted : Accepted ctx candidate = true

def check (ctx : VerificationContext)
    (candidate : Candidate) : Option (ApprovalStatement ctx) :=
  if h : Accepted ctx candidate = true then
    some { candidate := candidate, accepted := h }
  else none

theorem presented_statement_bytes_match_fields
    {ctx : VerificationContext} (approval : ApprovalStatement ctx) :
    parsePayload approval.candidate.statementBytes = some approval.candidate.payload := by
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
      approval.candidate.statementBytes approval.candidate.signatureBytes = true := by
  have h := approval.accepted
  simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at h
  exact h.2

theorem check_refuses_statement_field_mismatch
    (ctx : VerificationContext) (candidate : Candidate)
    (hne : parsePayload candidate.statementBytes ≠ some candidate.payload) :
    check ctx candidate = none := by
  unfold check
  split
  next haccepted =>
    simp only [Accepted, Bool.and_eq_true, decide_eq_true_eq] at haccepted
    exact absurd haccepted.1.1.1.1 hne
  next => rfl

end ApprovalStatement

namespace StatementWitness

def deployment : ObjectB.DeploymentId := ⟨"deployment-7".toUTF8⟩
def session : ObjectA.SessionId := ⟨"session-4".toUTF8⟩
def configRef : Host.Sha256.Digest256 :=
  Host.Sha256.sha256Digest "signed-config".toUTF8
def keyEpoch : Host.Sha256.Digest256 :=
  Host.Sha256.sha256Digest "request-key-epoch".toUTF8
def adapterDigest : Host.Sha256.Digest256 :=
  Host.Sha256.sha256Digest "adapter-artifact".toUTF8
def adapter : ObjectA.AdapterProfile :=
  { identifier := "stdio-gated-sink", version := "1.0.0", artifactSha256 := adapterDigest }
def requestSigner : ObjectA.RequestSignerRef := ⟨"request-key-3".toUTF8⟩
def requestSignature : ByteArray := "request-signature".toUTF8
def requestBytes : ByteArray :=
  "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"database.drop\",\"action\":\"call\",\"arguments\":{\"table\":\"main\"}}}".toUTF8

def requestStatementText : String :=
  "{\"schema\":\"v1\",\"request_nonce\":\"726571756573742d6e6f6e63652d3131\",\"deployment_id\":\"6465706c6f796d656e742d37\",\"session_id\":\"73657373696f6e2d34\",\"config_ref\":\"8db65cb58c559fce3abf6b1f376008eaab0408ea1e2ed48a5e840e87e1a1d635\",\"key_epoch\":\"926215a4a5de0bdecd59c7e0e76a336861d648d3ede6eec36563a3c369c51c64\",\"adapter_profile\":{\"identifier\":\"stdio-gated-sink\",\"version\":\"1.0.0\",\"artifact_sha256\":\"2de1f3a1752dc35308e48cde8ee2e146620d022fa0974ffbd4acf078bcb665f0\"},\"issued_at\":100,\"expires_at\":200,\"judged_request_bytes\":\"7b226a736f6e727063223a22322e30222c226964223a312c226d6574686f64223a22746f6f6c732f63616c6c222c22706172616d73223a7b226e616d65223a2264617461626173652e64726f70222c22616374696f6e223a2263616c6c222c22617267756d656e7473223a7b227461626c65223a226d61696e227d7d7d\",\"judged_request_sha256\":\"12ff30aa21c01589b337813c8fd9c39b0e38cb5b6b067920437c9d39b008ca30\"}"

def requestStatementBytes : ByteArray := requestStatementText.toUTF8

def requestPayload : ObjectA.Payload :=
  { schema := .v1
    requestNonce := ⟨"request-nonce-11".toUTF8⟩
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
    statementBytes := requestStatementBytes }

def requestContext : ObjectA.VerificationContext :=
  { now := 150
    requestSignerDelegated := fun dep cfg epoch signer =>
      decide (dep = deployment) && decide (cfg = configRef) &&
      decide (epoch = keyEpoch) && decide (signer = requestSigner)
    adapterProfileAccepted := fun dep cfg profile =>
      decide (dep = deployment) && decide (cfg = configRef) && decide (profile = adapter)
    signatureVerified := fun signer message signature =>
      decide (signer = requestSigner) && decide (message = requestStatementBytes) &&
      decide (signature = requestSignature) }

def requestWrongStatementBytes : ObjectA.Candidate :=
  { requestCandidate with statementBytes := "different-signed-request".toUTF8 }

def requestWrongDigest : ObjectA.Candidate :=
  let wrongDigest := Host.Sha256.sha256Digest "different-request".toUTF8
  let payload : ObjectA.Payload := { requestPayload with judgedRequestSha256 := wrongDigest }
  { requestCandidate with
    payload := payload
    statementBytes := (requestStatementText.replace
      "12ff30aa21c01589b337813c8fd9c39b0e38cb5b6b067920437c9d39b008ca30"
      "a01a668e54ecdd7fe83fe7e807084e029a08c58a8dfc8ff2da6b0e9cb4d33fd1").toUTF8 }

def requestIssuedInFuture : ObjectA.Candidate :=
  { requestCandidate with
    payload := { requestPayload with issuedAt := 151 }
    statementBytes := (requestStatementText.replace "\"issued_at\":100" "\"issued_at\":151").toUTF8 }

def requestExpired : ObjectA.Candidate :=
  { requestCandidate with
    payload := { requestPayload with expiresAt := 149 }
    statementBytes := (requestStatementText.replace "\"expires_at\":200" "\"expires_at\":149").toUTF8 }

def requestExpiryOutOfRange : ObjectA.Candidate :=
  { requestCandidate with
    payload := { requestPayload with expiresAt := 2 ^ 64 }
    statementBytes := (requestStatementText.replace "\"expires_at\":200"
      "\"expires_at\":18446744073709551616").toUTF8 }

def requestBadSignature : ObjectA.Candidate :=
  { requestCandidate with signatureBytes := "wrong-request-signature".toUTF8 }

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

/-- A field/byte forgery attempt: visible fields claim a different request and
    matching digest while the exact signed bytes still parse to `requestPayload`. -/
def forgedRequest : ObjectA.Candidate :=
  let forgedBytes :=
    "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"notes.read\",\"action\":\"call\",\"arguments\":{\"id\":\"1\"}}}".toUTF8
  { requestCandidate with
    payload := { requestPayload with
      judgedRequestBytes := forgedBytes
      judgedRequestSha256 := ObjectA.judgedRequestDigest forgedBytes } }

def approver : ApprovalStatement.ApproverIdentity := ⟨"approver-key-8".toUTF8⟩
def approvalSignature : ByteArray := "approval-signature".toUTF8
def authority : ApprovalStatement.AuthorityRef :=
  ⟨Host.Sha256.sha256Digest "approval-authority".toUTF8⟩
def targetCommitment : Host.Sha256.Digest256 :=
  Host.Sha256.sha256Digest "database/drop/main".toUTF8
def requestRef : Host.Sha256.Digest256 :=
  { w0 := 0xc85e6bb2, w1 := 0xa85a9432, w2 := 0xb20250d8, w3 := 0xf95b0aa9
    w4 := 0xef38761c, w5 := 0x17e078c4, w6 := 0xcbc86ca9, w7 := 0x55f9d1cd }

def approvalStatementText : String :=
  "{\"schema\":\"v1\",\"approver_identity\":\"617070726f7665722d6b65792d38\",\"approval_nonce\":\"617070726f76616c2d6e6f6e63652d3132\",\"request_statement_ref\":\"c85e6bb2a85a9432b20250d8f95b0aa9ef38761c17e078c4cbc86ca955f9d1cd\",\"target_commitment\":\"48a52f63a1ed1f9fec082f0965e26b4e500f9f0f1018550e2184cf9249689dcb\",\"constraints\":\"6f6e652d7573653b6265666f72653d323030\",\"approved_at\":120,\"approval_expires_at\":180,\"authority_ref\":\"e4fcc152a6e69875645683e8287273211e7415875e558c3ea9f18a5410c79daa\",\"deployment_id\":\"6465706c6f796d656e742d37\",\"session_id\":\"73657373696f6e2d34\",\"config_ref\":\"8db65cb58c559fce3abf6b1f376008eaab0408ea1e2ed48a5e840e87e1a1d635\",\"adapter_profile\":{\"identifier\":\"stdio-gated-sink\",\"version\":\"1.0.0\",\"artifact_sha256\":\"2de1f3a1752dc35308e48cde8ee2e146620d022fa0974ffbd4acf078bcb665f0\"}}"

def approvalStatementBytes : ByteArray := approvalStatementText.toUTF8

def approvalPayload : ApprovalStatement.Payload :=
  { schema := .v1
    approverIdentity := approver
    approvalNonce := ⟨"approval-nonce-12".toUTF8⟩
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
    statementBytes := approvalStatementBytes }

def approvalContext : ApprovalStatement.VerificationContext :=
  { now := 150
    approverDelegated := fun auth dep cfg identity =>
      decide (auth = authority) && decide (dep = deployment) &&
      decide (cfg = configRef) && decide (identity = approver)
    adapterProfileAccepted := fun dep cfg profile =>
      decide (dep = deployment) && decide (cfg = configRef) && decide (profile = adapter)
    signatureVerified := fun identity message signature =>
      decide (identity = approver) && decide (message = approvalStatementBytes) &&
      decide (signature = approvalSignature) }

def approvalWrongStatementBytes : ApprovalStatement.Candidate :=
  { approvalCandidate with statementBytes := "different-signed-approval".toUTF8 }

def approvalApprovedInFuture : ApprovalStatement.Candidate :=
  { approvalCandidate with
    payload := { approvalPayload with approvedAt := 151 }
    statementBytes := (approvalStatementText.replace
      "\"approved_at\":120" "\"approved_at\":151").toUTF8 }

def approvalExpired : ApprovalStatement.Candidate :=
  { approvalCandidate with
    payload := { approvalPayload with approvalExpiresAt := 149 }
    statementBytes := (approvalStatementText.replace
      "\"approval_expires_at\":180" "\"approval_expires_at\":149").toUTF8 }

def approvalExpiryOutOfRange : ApprovalStatement.Candidate :=
  { approvalCandidate with
    payload := { approvalPayload with approvalExpiresAt := 2 ^ 64 }
    statementBytes := (approvalStatementText.replace
      "\"approval_expires_at\":180" "\"approval_expires_at\":18446744073709551616").toUTF8 }

def approvalBadSignature : ApprovalStatement.Candidate :=
  { approvalCandidate with signatureBytes := "wrong-approval-signature".toUTF8 }

def approvalUndelegatedContext : ApprovalStatement.VerificationContext :=
  { approvalContext with approverDelegated := fun _ _ _ _ => false }
def approvalRejectedAdapterContext : ApprovalStatement.VerificationContext :=
  { approvalContext with adapterProfileAccepted := fun _ _ _ => false }
def approvalPermissiveSignatureContext : ApprovalStatement.VerificationContext :=
  { approvalContext with signatureVerified := fun _ _ _ => true }

/-- The approval analogue of the field/byte forgery: visible fields claim a
    different target and constraints while signed bytes still parse to the
    original payload. -/
def forgedApproval : ApprovalStatement.Candidate :=
  { approvalCandidate with
    payload := { approvalPayload with
      targetCommitment := Host.Sha256.sha256Digest "notes/read".toUTF8
      constraints := "unlimited".toUTF8 } }

def fipsAbcDigest : Host.Sha256.Digest256 :=
  { w0 := 0xba7816bf, w1 := 0x8f01cfea, w2 := 0x414140de, w3 := 0x5dae2223
    w4 := 0xb00361a3, w5 := 0x96177a9c, w6 := 0xb410ff61, w7 := 0xf20015ad }

def expectedRequestEffect : SealV2.Effect.EffectClaim :=
  { resource := "database.drop"
    action := "call"
    args := "{\"table\":\"main\"}"
    metadata := .absent }

/-! Seven direct boundary/helper controls replace the removed seven private
canonical-encoder controls. Together with the nineteen gate controls below,
the Object A layer retains its original 26-control census. -/

#guard ObjectA.parsePayload requestStatementBytes = some requestPayload
#guard ApprovalStatement.parsePayload approvalStatementBytes = some approvalPayload
#guard ObjectA.judgedRequestDigest "abc".toUTF8 = fipsAbcDigest
#guard ObjectA.judgedEffect requestBytes = some expectedRequestEffect
#guard StatementParsing.presentedJson? "{\"issued_at\":1e9999999}".toUTF8 = none
#guard StatementParsing.presentedJson? "{\"schema\":\"v1\",\"schema\":\"v2\"}".toUTF8 = none
#guard ObjectA.parsePayload
  (requestStatementText.replace "726571756573742d6e6f6e63652d3131" "not-hex").toUTF8 = none

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
