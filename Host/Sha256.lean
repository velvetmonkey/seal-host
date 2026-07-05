/- SPDX-License-Identifier: Apache-2.0 -/

/-!
# SHA-256 (FIPS 180-4) — pure Lean reference implementation

Byte-exact SHA-256 over `ByteArray`: message padding (0x80 + 64-bit big-endian
bit length), 16-word big-endian message schedule extended to 64 words, and the
standard 64-round compression over the eight working variables, all in `UInt32`
modular arithmetic. No FFI, no external dependencies.

CONFORMANCE DISCIPLINE. Correctness is established by COMPILED evaluation
against the published FIPS 180-4 vectors (and, downstream, the deployed Rust
`sha2` v0.10 chain vectors in `Host/Record.lean`), gated at build time with
`#guard_msgs in #eval`. A kernel-level proof of concrete digest values is NOT
attempted: the block loops compile through well-founded/imperative constructs
that do not kernel-reduce in this toolchain, and no `native_decide` is
admitted in this repo. Nothing in this module is a theorem; it is the
executable model of the production commitment primitive.
-/

namespace Host.Sha256

/-- The 64 FIPS 180-4 round constants (fractional parts of the cube roots of
    the first 64 primes). -/
private def k : Array UInt32 := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

/-- The eight initial hash values (fractional parts of the square roots of the
    first 8 primes). -/
private def h0 : Array UInt32 := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]

/-- Right rotation on `UInt32`. All SHA-256 rotation amounts are in
    `{2,…,25}`, so the `32 - n` shift never hits the 0/32 edge. -/
@[inline] private def rotr (x : UInt32) (n : UInt32) : UInt32 :=
  (x >>> n) ||| (x <<< (32 - n))

/-- FIPS 180-4 padding: append `0x80`, zero-fill to 56 (mod 64), then the
    64-bit big-endian BIT length of the original message. -/
private def pad (msg : ByteArray) : ByteArray := Id.run do
  let len := msg.size
  let bitLen : UInt64 := (UInt64.ofNat len) * 8
  -- zero-fill count: len + 1 + zeros ≡ 56 (mod 64)
  let zeros := (119 - (len % 64)) % 64
  let mut out := msg
  out := out.push 0x80
  out := out ++ ByteArray.mk (Array.replicate zeros 0x00)
  for i in [0:8] do
    out := out.push (UInt8.ofNat (((bitLen >>> (UInt64.ofNat ((7 - i) * 8))).toNat) % 256))
  return out

/-- One 64-byte block: build the 64-word schedule and run the 64-round
    compression, adding the result into the running state. -/
private def compress (state : Array UInt32) (block : ByteArray) (off : Nat) :
    Array UInt32 := Id.run do
  -- message schedule
  let mut w : Array UInt32 := Array.replicate 64 0
  for t in [0:16] do
    let b0 := (block[off + 4*t]!).toUInt32
    let b1 := (block[off + 4*t + 1]!).toUInt32
    let b2 := (block[off + 4*t + 2]!).toUInt32
    let b3 := (block[off + 4*t + 3]!).toUInt32
    w := w.set! t ((b0 <<< 24) ||| (b1 <<< 16) ||| (b2 <<< 8) ||| b3)
  for t in [16:64] do
    let s0 := rotr (w[t-15]!) 7 ^^^ rotr (w[t-15]!) 18 ^^^ (w[t-15]! >>> 3)
    let s1 := rotr (w[t-2]!) 17 ^^^ rotr (w[t-2]!) 19 ^^^ (w[t-2]! >>> 10)
    w := w.set! t (w[t-16]! + s0 + w[t-7]! + s1)
  -- working variables
  let mut a := state[0]!
  let mut b := state[1]!
  let mut c := state[2]!
  let mut d := state[3]!
  let mut e := state[4]!
  let mut f := state[5]!
  let mut g := state[6]!
  let mut h := state[7]!
  for t in [0:64] do
    let bigS1 := rotr e 6 ^^^ rotr e 11 ^^^ rotr e 25
    let ch := (e &&& f) ^^^ ((~~~e) &&& g)
    let t1 := h + bigS1 + ch + k[t]! + w[t]!
    let bigS0 := rotr a 2 ^^^ rotr a 13 ^^^ rotr a 22
    let maj := (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)
    let t2 := bigS0 + maj
    h := g
    g := f
    f := e
    e := d + t1
    d := c
    c := b
    b := a
    a := t1 + t2
  return #[state[0]! + a, state[1]! + b, state[2]! + c,
           state[3]! + d, state[4]! + e, state[5]! + f,
           state[6]! + g, state[7]! + h]

/-- SHA-256 digest: 32 bytes. -/
def sha256 (input : ByteArray) : ByteArray := Id.run do
  let padded := pad input
  let mut state := h0
  for b in [0:padded.size / 64] do
    state := compress state padded (b * 64)
  let mut out := ByteArray.empty
  for i in [0:8] do
    let word := state[i]!
    out := out.push (UInt8.ofNat ((word >>> 24).toNat % 256))
    out := out.push (UInt8.ofNat ((word >>> 16).toNat % 256))
    out := out.push (UInt8.ofNat ((word >>> 8).toNat % 256))
    out := out.push (UInt8.ofNat (word.toNat % 256))
  return out

private def hexDigit (n : Nat) : Char :=
  if n < 10 then Char.ofNat (48 + n) else Char.ofNat (87 + n)  -- '0'-'9', 'a'-'f'

/-- 64-character lowercase hex encoding of the digest. -/
def sha256Hex (input : ByteArray) : String := Id.run do
  let digest := sha256 input
  let mut s := ""
  for i in [0:digest.size] do
    let b := (digest[i]!).toNat
    s := s.push (hexDigit (b / 16))
    s := s.push (hexDigit (b % 16))
  return s

/-- Hex digest of a string's UTF-8 bytes. -/
def sha256HexStr (s : String) : String := sha256Hex s.toUTF8

/-! ## Conformance evidence (build-gated compiled evaluation)

FIPS 180-4 anchor vectors. These `#guard_msgs in #eval` gates run the COMPILED
implementation at elaboration time, so a bare `lake build` fails on any
mismatch. This is reference conformance (same vectors the Rust `sha2` v0.10
crate publishes), not a kernel proof. -/

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
