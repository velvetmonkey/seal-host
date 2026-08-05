/- SPDX-License-Identifier: Apache-2.0 -/

import SealCore.Event
import Host.Action

namespace Host

/-- The two possible outcomes of a kernel's decision on one mediated call. -/
inductive VerdictKind where
  | allow
  | deny
  deriving Repr, BEq, DecidableEq

/-- The wire/audit-log spelling of a `VerdictKind`. -/
def VerdictKind.text : VerdictKind → String
  | .allow => "allow"
  | .deny => "deny"

/-- One kernel's answer for one mediated call. `certHash` is a stable hash over
    the kernel name, verdict and reason — the audit-log certificate for this
    decision. -/
structure Verdict where
  /-- Name of the kernel that produced this verdict. -/
  kernel : String
  /-- Whether the kernel allows or denies the call. -/
  kind : VerdictKind
  /-- Human-readable justification recorded in the audit log. -/
  reason : String
  /-- Stable hash over kernel name, verdict and reason — the audit-log
      certificate for this decision. -/
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
  /-- Stable kernel name used in verdicts, audit records and config lookup. -/
  name : String
  /-- The kernel's section of the signed `TrustedConfig`. -/
  Config : Type
  /-- Host-gathered per-call evidence (clock, approvals, …) fed to `ingest`. -/
  Evidence : Type
  /-- The kernel's persistent state across mediated calls. -/
  State : Type
  /-- The state before any call has been mediated. -/
  init : State
  /-- Whether this kernel claims jurisdiction over the given call under the
      given config; non-gating kernels are skipped for that call. -/
  gates : Config → CanonicalAction → Bool
  /-- Fold gathered evidence into the state. Committed unconditionally —
      evidence (e.g. approvals) must survive another kernel's deny. -/
  ingest : Evidence → State → State
  /-- Decide the call and return the EXECUTION state transition, committed
      only when the combined verdict is allow. -/
  decide : CanonicalAction → Config → Evidence → State → Verdict × State

end Host
