/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Record
import Host.RecordReflection

/-! Axiom-footprint gate for the L1 verifiable-record CORE + STRETCH. Every
    theorem must report only `[propext, Classical.choice, Quot.sound]` (the L0
    baseline) or a subset. Any `sorryAx`, `Lean.ofReduceBool` (native_decide),
    or new axiom is a failure. -/

#print axioms Host.Record.head_after_append
#print axioms Host.Record.tamper_evident
#print axioms Host.Record.log_reflects_l0_decisions
