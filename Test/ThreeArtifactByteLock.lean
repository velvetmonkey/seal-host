/- SPDX-License-Identifier: Apache-2.0 -/

import Host.ThreeArtifactByteLock

namespace Test.ThreeArtifactByteLock

open Host.ThreeArtifactByteLock

def witness : Content := {
  objectA := "object-a".toUTF8.data.toList
  approvalStatement := some "approval-statement".toUTF8.data.toList
  objectB := "object-b".toUTF8.data.toList
  releaseStatus := .pending
  operationId := "operation-17".toUTF8.data.toList
  durabilityClass := .assertedLocalFsync
}

#guard decode (encode witness) == some witness
#guard (encode { witness with releaseStatus := .released }) != encode witness
#guard (encode { witness with operationId := "operation-18".toUTF8.data.toList }) != encode witness
#guard (encode { witness with durabilityClass := .unknown }) != encode witness

def main : IO UInt32 := do
  let stdout ← IO.getStdout
  stdout.write (ByteArray.mk (encode witness).toArray)
  stdout.flush
  pure 0

end Test.ThreeArtifactByteLock

def main : IO UInt32 := Test.ThreeArtifactByteLock.main
