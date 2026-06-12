/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import SealV2.Parser

namespace Host

/-- One mediated MCP `tools/call`, carrying both views of the request:

    * `argsJson` — the V1 `Lean.Json` view. In G1 this is the decision-bearing
      input (kernel S classifies on it via the unchanged `Seal.classifyToolCall`),
      so behaviour matches the mcp-seal V1 host exactly.
    * `ast` — the SealV2 canonical view of the full wire line. The host refuses
      to mediate a `tools/call` the verified canonical parser rejects
      (fail-closed), and the AST is the audit artifact / input for later
      kernels. -/
structure CanonicalAction where
  tool : String
  argsJson : Lean.Json
  ast : SealV2.AST
  raw : String
  requestId : Lean.Json

end Host
