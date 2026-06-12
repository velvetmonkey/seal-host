/- SPDX-License-Identifier: Apache-2.0 -/

import SealCore.Event
import Host.Action

namespace Host

inductive VerdictKind where
  | allow
  | deny
  deriving Repr, BEq, DecidableEq

def VerdictKind.text : VerdictKind → String
  | .allow => "allow"
  | .deny => "deny"

/-- One kernel's answer for one mediated call. `certHash` is a stable hash over
    the kernel name, verdict and reason — the audit-log certificate for this
    decision. -/
structure Verdict where
  kernel : String
  kind : VerdictKind
  reason : String
  certHash : SealCore.Hash
  deriving Repr

/-- A verified kernel hosted by the Seal Host.

    `decide` is pure: all IO (clock, approval file, network) lives in the
    host-side evidence gatherer, so composition over kernels is a pure fold —
    the shape G3's composition theorem quantifies over. -/
structure Kernel where
  name : String
  Config : Type
  Evidence : Type
  State : Type
  init : State
  gates : Config → CanonicalAction → Bool
  decide : CanonicalAction → Config → Evidence → State → Verdict × State

end Host
