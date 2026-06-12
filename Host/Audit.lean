/- SPDX-License-Identifier: Apache-2.0 -/

import Lean.Data.Json
import Host.Kernel

namespace Host

open Lean

/-- One audit line per mediated call: the config epoch, the tool, the combined
    verdict, and every gating kernel's certificate. Compact JSON, one line. -/
def auditLine (epoch : Nat) (tool : String) (combined : VerdictKind)
    (verdicts : List Verdict) : String :=
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
    ("certs", Json.arr certs.toArray)
  ]
  line.compress

end Host
