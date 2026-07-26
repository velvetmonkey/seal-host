# V3.1 downstream parser-agreement experiment

Date: 2026-07-26

Branch: `v31run/downstream-parser-agreement`, based on
`exp/parser-interop` at `bc69205`. The alternative
`exp/downstream-parser-agreement` pointed to the same commit.

## Result

**DISAGREEMENT. The experiment stopped at the first differing downstream
extraction, as required.**

| Vector | Lean `CanonicalAction` | Downstream extraction | Verdict |
|---|---|---|---|
| `i_number_neg_int_huge_exp.json` (`[-1e+9999]`) | tool `external.json_corpus`; arguments: one exact negative integer with 10,000 digits | tool `external.json_corpus`; arguments: `[{"$nonFiniteNumber":"-Infinity"}]` | **DISAGREE** |

The downstream parser was Node.js 22.22.3 `JSON.parse`, reached through
`@modelcontextprotocol/server-github` 2025.4.8 and
`@modelcontextprotocol/sdk` 1.0.1. It was invoked behind the real
`rust/target/debug/seal-host-rs` process with the observer preloaded by Node's
`--import` option.

## Exact-byte and approval evidence

- Untouched corpus vector SHA-256:
  `92123944cf252563cc9d402ad83df085a20f9899144b3b59661f898fcffd1e2b`.
- Terminator-stripped JSON-RPC payload SHA-256:
  `2206dfa48d2d74bbe8edb0a154b2f6691d0171f407b223b27c70f479d1191006`.
- LF-framed wire request SHA-256:
  `a508b78a0cdf5641918dbbb49d04b6d668b1c60e8ba64fb30dd4614226b1b50f`.
- The Node parser observation reported the same payload and wire-frame
  commitments.
- Lean-issued approval target:
  `cdaa67294085f0e0751a18867b4963b94e04a34e6ec57e1feb2f622bf2b2a179`.
- The first host decision denied with that target. After the isolated approval
  file received the target, the second byte-identical request was allowed and
  the host emitted:

  ```text
  {"event":"reduced_scope_forward","request_sha256":"2206dfa48d2d74bbe8edb0a154b2f6691d0171f407b223b27c70f479d1191006","parse_error":"cannot parse mediated request for receipt: number out of range at line 1 column 107","tool_hint":null,"count":1}
  ```

- The downstream application subsequently rejected `params.arguments` because
  it was an array rather than an object. That later schema verdict does not erase
  the parser disagreement: `JSON.parse` had already accepted the exact frame and
  extracted `-Infinity`.

## Scope

One of the 18 triaged divergent vectors was tested. Four `Rust Act / Lean
Refuse` vectors were outside this forwarding experiment because Lean produces no
approvable `CanonicalAction` for them. The remaining 13 `Rust NotAct / Lean Act`
vectors and the remaining four configured observers were not run after the
first disagreement, following the experiment's stop rule.

This demonstrates the V3.1 defect: bytes approved according to Lean's exact
integer semantics can be forwarded to a real downstream parser that assigns
different numeric semantics. It does not characterize every divergent vector,
every downstream parser, or establish a replacement parser/serialization
invariant.

## Scaffold repairs required before the valid run

1. `Test.DownstreamParserOracle` existed, and a stale built executable was
   present, but the checked-out `lakefile.toml` had no executable target for it.
2. Observer records hashed the parser input, while the harness required the
   LF-framed wire hash. Node's MCP transport strips the LF before `JSON.parse`,
   so no observation could match until the observer recorded the reconstructed
   wire-frame commitment.
3. The harness treated a later application error as the experiment's verdict
   and skipped parser extraction comparison whenever such an error existed.
4. The harness did not stop or return a failing status on disagreement.
