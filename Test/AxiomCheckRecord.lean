/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Record

/-! Axiom-footprint gate for the L1 verifiable-record CORE. Both theorems must
    report only `[propext, Classical.choice, Quot.sound]` (the L0 baseline) or
    a subset. Any `sorryAx`, `Lean.ofReduceBool` (native_decide), or new axiom
    is a failure. -/

#print axioms Host.Record.head_after_append
#print axioms Host.Record.tamper_evident
