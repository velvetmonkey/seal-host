/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Record

/-! # SHA-256 reference-conformance selfcheck

Runs the compiled Lean SHA-256 against the three FIPS 180-4 anchor vectors and
the two golden vectors from the deployed Rust chain (`rust/src/receipt.rs`,
`sha2` v0.10). Exits non-zero on any byte mismatch. The same five vectors are
also build-gated with `#guard_msgs in #eval` in `Host/Sha256.lean` and
`Host/Record.lean`; this executable is the standalone, exit-status form. -/

open Host.Sha256 Host.Record

def vectors : List (String × String × String) := [
  ("FIPS empty", sha256HexStr "",
   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
  ("FIPS abc", sha256HexStr "abc",
   "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
  ("FIPS 448-bit", sha256HexStr "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
   "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
  ("golden genesis", prodGenesis,
   "0633b0b4c5ca8207b3174d64fe438b99eaa1f5d95d0d4bbaa5d3fe6bd5f700a9"),
  ("golden commit audit-0", prodChainHash prodGenesis "audit-0",
   "8dd24f08c8674e9b7b950837337c93d09d5240e1aedbb7d54269ee9381b84a4c")]

def main : IO UInt32 := do
  let mut failures := 0
  for (name, got, want) in vectors do
    if got == want then
      IO.println s!"PASS {name}"
    else
      IO.println s!"FAIL {name}\n  got  {got}\n  want {want}"
      failures := failures + 1
  if failures == 0 then
    IO.println "sha256 selfcheck: all 5 vectors match the reference"
    return 0
  else
    IO.println s!"sha256 selfcheck: {failures} MISMATCH(ES)"
    return 1
