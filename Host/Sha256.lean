/- SPDX-License-Identifier: Apache-2.0 -/

import SealCore.Sha256

/-!
# SHA-256 host API

The byte-exact implementation lives in `SealCore.Sha256` so the deployed
target commitment and the host record-chain checks cannot drift. This module
keeps the historical `Host.Sha256` API used by record-chain code and tests.
-/

namespace Host.Sha256

/-- A SHA-256 digest as eight 32-bit words (re-export of
    `SealCore.Sha256.Digest256`). -/
abbrev Digest256 := SealCore.Sha256.Digest256

/-- A 32-byte target hash value (re-export of `SealCore.Sha256.TargetHash`). -/
abbrev TargetHash := SealCore.Sha256.TargetHash

/-- SHA-256 of a byte array as a `Digest256`. -/
def sha256Digest (input : ByteArray) : Digest256 :=
  SealCore.Sha256.sha256Digest input

/-- SHA-256 of a byte array as the raw 32-byte digest. -/
def sha256 (input : ByteArray) : ByteArray :=
  SealCore.Sha256.sha256 input

/-- SHA-256 of a byte array as a lowercase hex string. -/
def sha256Hex (input : ByteArray) : String :=
  SealCore.Sha256.sha256Hex input

/-- SHA-256 of a string's UTF-8 bytes as a lowercase hex string. -/
def sha256HexStr (s : String) : String :=
  SealCore.Sha256.sha256HexStr s

/-! ## Conformance evidence (build-gated compiled evaluation) -/

/-- info: true -/
#guard_msgs in #eval
  sha256HexStr "" == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

/-- info: true -/
#guard_msgs in #eval
  sha256HexStr "abc" == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

/-- info: true -/
#guard_msgs in #eval
  sha256HexStr "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

end Host.Sha256
