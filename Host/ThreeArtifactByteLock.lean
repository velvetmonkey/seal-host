/- SPDX-License-Identifier: Apache-2.0 -/

/-!
# Three-artifact byte lock

This is the kernel-owned byte shape for the exact Object A bytes, an optional
Approval Statement, and the unsigned Object B bytes.  The v1 Object B signing
domain was `seal.object-b/v1`; this one migration changes it to
`seal.object-b/v2` and adds the signed `release_status`, `operation_id`, and
`durability_class` fields in that same shape.

Each arbitrary byte string is escaped as `(0, byte)*, 1`.  The approval seat is
tagged `2` when absent and `3` when present.  Release and durability values use
closed one-byte tags.  This makes every boundary structural, including empty
and arbitrary binary artifacts, without relying on JSON rendering.

`decode_encode_exact_content` says in plain words: encoding any logical
three-artifact content and then decoding those bytes recovers exactly that
content.  `one_logical_content_one_encoding` is the corresponding uniqueness
statement: equal emitted bytes imply equal logical content.

These theorems do NOT prove JSON semantics, that Object A or the Approval
Statement signatures are valid, that the Object B receipt signature is valid,
that a host fsync occurred, or that deployment trust predicates are faithful.
They lock only the byte representation and the closed enumerations named here.
-/

namespace Host.ThreeArtifactByteLock

abbrev Bytes := List UInt8

def domainTag : Bytes := "seal.object-b/v2\x00".toUTF8.data.toList

inductive ReleaseStatus where
  | pending
  | unknown
  | released
  | notApplicable
  deriving Repr, BEq, DecidableEq

/-- The ruled closed list.  No fourth constructor exists. -/
inductive DurabilityClass where
  | assertedLocalFsync
  | witnessedExternal
  | unknown
  deriving Repr, BEq, DecidableEq

structure Content where
  objectA : Bytes
  approvalStatement : Option Bytes
  objectB : Bytes
  releaseStatus : ReleaseStatus
  operationId : Bytes
  durabilityClass : DurabilityClass
  deriving Repr, BEq, DecidableEq

/-- Arbitrary bytes, framed without a size limit: `(0, byte)*, 1`. -/
def encodeBlob : Bytes → Bytes
  | [] => [1]
  | byte :: rest => 0 :: byte :: encodeBlob rest

def decodeBlob : Bytes → Option (Bytes × Bytes)
  | [] => none
  | 1 :: rest => some ([], rest)
  | 0 :: tail =>
      match tail with
      | byte :: rest => do
          let (decoded, suffix) ← decodeBlob rest
          pure (byte :: decoded, suffix)
      | [] => none
  | _ => none

theorem decodeBlob_encodeBlob_append (bytes suffix : Bytes) :
    decodeBlob (encodeBlob bytes ++ suffix) = some (bytes, suffix) := by
  induction bytes with
  | nil => simp [encodeBlob, decodeBlob]
  | cons byte rest ih => simp [encodeBlob, decodeBlob, ih]

def releaseTag : ReleaseStatus → UInt8
  | .pending => 4
  | .unknown => 5
  | .released => 6
  | .notApplicable => 7

def decodeRelease : Bytes → Option (ReleaseStatus × Bytes)
  | 4 :: rest => some (.pending, rest)
  | 5 :: rest => some (.unknown, rest)
  | 6 :: rest => some (.released, rest)
  | 7 :: rest => some (.notApplicable, rest)
  | _ => none

theorem decodeRelease_releaseTag (status : ReleaseStatus) (suffix : Bytes) :
    decodeRelease (releaseTag status :: suffix) = some (status, suffix) := by
  cases status <;> rfl

def durabilityTag : DurabilityClass → UInt8
  | .assertedLocalFsync => 8
  | .witnessedExternal => 9
  | .unknown => 10

def decodeDurability : Bytes → Option (DurabilityClass × Bytes)
  | 8 :: rest => some (.assertedLocalFsync, rest)
  | 9 :: rest => some (.witnessedExternal, rest)
  | 10 :: rest => some (.unknown, rest)
  | _ => none

theorem decodeDurability_durabilityTag
    (durability : DurabilityClass) (suffix : Bytes) :
    decodeDurability (durabilityTag durability :: suffix) =
      some (durability, suffix) := by
  cases durability <;> rfl

def encodeApproval : Option Bytes → Bytes
  | none => [2]
  | some bytes => 3 :: encodeBlob bytes

def decodeApproval : Bytes → Option (Option Bytes × Bytes)
  | 2 :: rest => some (none, rest)
  | 3 :: rest => do
      let (bytes, suffix) ← decodeBlob rest
      pure (some bytes, suffix)
  | _ => none

theorem decodeApproval_encodeApproval_append
    (approval : Option Bytes) (suffix : Bytes) :
    decodeApproval (encodeApproval approval ++ suffix) = some (approval, suffix) := by
  cases approval with
  | none => simp [encodeApproval, decodeApproval]
  | some bytes => simp [encodeApproval, decodeApproval, decodeBlob_encodeBlob_append]

def consumePrefix : Bytes → Bytes → Option Bytes
  | [], input => some input
  | expected :: expectedRest, actual :: actualRest =>
      if expected = actual then consumePrefix expectedRest actualRest else none
  | _ :: _, [] => none

theorem consumePrefix_self_append (expectedPrefix suffix : Bytes) :
    consumePrefix expectedPrefix (expectedPrefix ++ suffix) = some suffix := by
  induction expectedPrefix with
  | nil => rfl
  | cons byte rest ih => simp [consumePrefix, ih]

def encode (content : Content) : Bytes :=
  domainTag ++
  encodeBlob content.objectA ++
  encodeApproval content.approvalStatement ++
  encodeBlob content.objectB ++
  releaseTag content.releaseStatus ::
  (encodeBlob content.operationId ++ [durabilityTag content.durabilityClass])

def decode (input : Bytes) : Option Content := do
  let afterDomain ← consumePrefix domainTag input
  let (objectA, afterObjectA) ← decodeBlob afterDomain
  let (approvalStatement, afterApproval) ← decodeApproval afterObjectA
  let (objectB, afterObjectB) ← decodeBlob afterApproval
  let (releaseStatus, afterStatus) ← decodeRelease afterObjectB
  let (operationId, afterOperation) ← decodeBlob afterStatus
  let (durabilityClass, suffix) ← decodeDurability afterOperation
  if suffix.isEmpty then
    pure {
      objectA
      approvalStatement
      objectB
      releaseStatus
      operationId
      durabilityClass
    }
  else none

/-- Encoding followed by verification recovers exactly the logical content. -/
theorem decode_encode_exact_content (content : Content) :
    decode (encode content) = some content := by
  cases content
  simp [decode, encode, consumePrefix_self_append,
    decodeBlob_encodeBlob_append, decodeApproval_encodeApproval_append,
    decodeRelease_releaseTag, decodeDurability_durabilityTag]

/-- A byte string emitted by this encoder cannot name two logical contents. -/
theorem one_logical_content_one_encoding {left right : Content}
    (sameBytes : encode left = encode right) : left = right := by
  have decoded : decode (encode left) = decode (encode right) := congrArg decode sameBytes
  simpa [decode_encode_exact_content] using decoded

end Host.ThreeArtifactByteLock
