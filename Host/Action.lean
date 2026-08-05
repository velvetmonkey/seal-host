/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser

namespace Host

/-- One mediated MCP `tools/call`, carrying both views of the request:

    * `argsJson` — the V1 `Lean.Json` view. In G1 this is the decision-bearing
      input (kernel S classifies on it via the unchanged `Seal.classifyToolCall`),
      so behaviour matches the mcp-seal V1 host exactly.
    * `ast?` — the SealV2 canonical view of the full wire line, when the line
      IS canonical. The shared canonical parser closes the parser-differential
      on the seal side (a canonical line has exactly one byte form, the form an
      approval signature commits to); the residual wire-vs-canonical gap is the
      G6 differential-harness matter. The canonical view is an audit artifact /
      input for later kernels — NOT a mediation gate: a `tools/call` is decided
      on `argsJson` (the V1 view) whether or not it is canonical, so legitimate
      multiline/Unicode tool arguments are mediated, not refused. -/
structure CanonicalAction where
  /-- The MCP tool name being called (`params.name` on the wire). -/
  tool : String
  /-- The V1 `Lean.Json` view of the call arguments — the decision-bearing
      input every kernel classifies on. -/
  argsJson : Lean.Json
  /-- The SealV2 canonical AST of the full wire line when the line is
      canonical; `none` otherwise. Audit artifact, not a mediation gate. -/
  ast? : Option SealV2.AST
  /-- The raw wire line exactly as received, byte-for-byte. -/
  raw : String
  /-- The JSON-RPC `id` of the request, echoed into verdict responses. -/
  requestId : Lean.Json

end Host
