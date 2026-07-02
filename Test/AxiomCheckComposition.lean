/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Composition
import Host.Step

/-! Axiom-footprint probe for the L0 multi-gate composition proofs. Every
    theorem below must report only `[propext, Classical.choice, Quot.sound]`
    (or a subset). Any `sorryAx`, `Lean.ofReduceBool` (native_decide), or new
    axiom is a failure. -/

-- The two new per-gate allow-iff bridges.
#print axioms Kernels.convergence_verdict_allow_iff
#print axioms Kernels.temporal_verdict_allow_iff

-- The two new composed invariant-survival theorems.
#print axioms Host.composed_convergent
#print axioms Host.composed_temporal_safety

-- The flagship multi-gate non-bypass over the deployed step core, plus the
-- pure routing lemmas it rests on.
#print axioms Host.stepRoute_act_forward_iff
#print axioms Host.classify_act_witness
#print axioms Host.step_forward_non_bypass
