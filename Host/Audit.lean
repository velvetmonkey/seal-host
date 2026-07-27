/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import Host.Kernel
import Host.Sha256

namespace Host

open Lean

/-- One audit line per mediated call: the config epoch, the tool, the combined
    verdict, every gating kernel's certificate, and `request_sha256` — the
    kernel's own commitment to the EXACT bytes it judged (lowercase-hex
    SHA-256 of `reqLine`, mirroring `rust/src/authorization_decision.rs`
    `sha256_hex(input.line.as_bytes())` byte-for-byte).

    `reqLine` is the terminator-stripped `lean_view` of the wire line: the
    strip (`\n`, then `\r`) happens in the Rust host (`rust/src/main.rs`
    `lean_view`) BEFORE the line reaches Lean, so both sides hash the
    post-strip bytes. The hash is computed HERE, behind the proven boundary,
    from the line this function receives — a pre-computed hash parameter
    would let a confused host commit to different bytes than it judged,
    which is exactly the defect this field exists to kill.

    Compact JSON, one line; `Json.compress` emits object keys in
    lexicographic order regardless of insertion order. -/
def auditLine (epoch : Nat) (tool : String) (combined : VerdictKind)
    (verdicts : List Verdict) (reqLine : String) : String :=
  let certs := verdicts.map fun v =>
    Json.mkObj [
      ("kernel", Json.str v.kernel),
      ("verdict", Json.str v.kind.text),
      ("reason", Json.str v.reason),
      ("certHash", Json.str (toString v.certHash.toNat))
    ]
  let line := Json.mkObj [
    ("epoch", toJson epoch),
    ("tool", Json.str tool),
    ("verdict", Json.str combined.text),
    ("request_sha256", Json.str (Host.Sha256.sha256HexStr reqLine)),
    ("certs", Json.arr certs.toArray)
  ]
  line.compress

/-! ## Reference conformance (build-gated compiled evaluation)

Golden vectors mirroring `rust/src/authorization_decision.rs`
(`request_sha256 = sha256_hex(input.line.as_bytes())`). A bare `lake build`
fails on any byte mismatch. Rust twins: `authorization_decision.rs`
`request_hash_golden_vectors_match_lean` and `main.rs`
`request_commitment_is_over_the_terminator_stripped_lean_view`.

As with `Host.Record.prodChainHash`: A-CR (collision resistance) for
SHA-256 is ASSUMED, a named crypto TCB item — these vectors pin
byte-agreement of the two implementations, they do not prove the hash
strong. -/

-- (v1) Full audit line on a tiny request: pins the field NAME, the
-- lexicographic key order, and sha256("x").
/-- info: true -/
#guard_msgs in #eval
  auditLine 1 "db.execute" .deny [⟨"safety", .deny, "approval required", 42⟩] "x"
    == "{\"certs\":[{\"certHash\":\"42\",\"kernel\":\"safety\",\"reason\":\"approval required\",\"verdict\":\"deny\"}],\"epoch\":1,\"request_sha256\":\"2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881\",\"tool\":\"db.execute\",\"verdict\":\"deny\"}"

-- (v2) The pinned differential-corpus line serde cannot parse (1e309
-- overflows f64): the exact line of rust/tests/host_path.rs
-- `receipt_layer_never_vetoes_kernel_verdicts` and of the fleet's
-- unparseable-receipt fixtures. The kernel-attested hash must equal the
-- receipt's `request_sha256` for precisely this class of line — that is
-- the binding this commitment exists to provide.
/-- info: true -/
#guard_msgs in #eval
  Host.Sha256.sha256HexStr "{\"jsonrpc\":\"2.0\",\"id\":90,\"method\":\"tools/call\",\"params\":{\"name\":\"db.execute\",\"arguments\":{\"database\":\"prod\",\"sql\":\"drop table accounts\",\"x\":1e309}}}"
    == "c88367514666fdf3ec74b6157deeae7ea2018bea9ce87d6e64120502df81fd30"

-- (v3) Multibyte UTF-8: `String.toUTF8` (Lean) and `str::as_bytes` (Rust)
-- must agree on the encoding of non-ASCII request bytes.
/-- info: true -/
#guard_msgs in #eval
  Host.Sha256.sha256HexStr "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"tools/call\",\"params\":{\"name\":\"héllo\",\"arguments\":{\"memo\":\"naïve 日本語 ✓\"}}}"
    == "e7c75841cb1440437b83851d8ccfbbee7fe47a510cf48ef7de6fab6aaedc8d96"

end Host
