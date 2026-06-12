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

    `ingest` and `decide` are pure: all IO (clock, approval file, network)
    lives in the host-side evidence gatherer, so composition over kernels is a
    pure fold — the shape G3's composition theorem quantifies over.

    Two-phase state discipline: `ingest` folds gathered evidence into the
    state and is committed unconditionally (approvals read from the control
    file must not be lost when another kernel denies the call). `decide`'s
    returned state is the EXECUTION transition — the host commits it only when
    the COMBINED verdict is allow, i.e. only when the call actually executes
    (`Temporal.gateEvent` semantics: a denied call never executed, so no
    kernel's trace/automaton may advance on it). -/
structure Kernel where
  name : String
  Config : Type
  Evidence : Type
  State : Type
  init : State
  gates : Config → CanonicalAction → Bool
  ingest : Evidence → State → State
  decide : CanonicalAction → Config → Evidence → State → Verdict × State

end Host
