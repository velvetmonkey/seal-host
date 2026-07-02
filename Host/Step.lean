/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Canonical
import Host.Registry

/-!
# The pure routing core of the mediation step

`Ffi.stepImpl` is an `unsafe`/IO wrapper: it reads session state and gathers
evidence through `IO.Ref`s, folds it through the kernel registry with
`Host.dispatch`, and marshals the result to/from JSON across the C ABI. All of
that IO — the evidence provenance, the ref state, the `unsafeBaseIO` FFI
boundary in `Ffi.sealHostStep` — is TRUSTED (named in `RUST_BRIDGE.md` /
`TCB.md`); it is not proven here.

What IS proven is the pure decision the wrapper delegates to. `stepImpl`'s
`.act` branch routes a line by exactly `stepRoute (classifyLine line)
verdicts`, where `verdicts` is the per-kernel verdict list `dispatch`
returned. `stepRoute` is total and depends only on the routing class and those
verdicts, so `step_forward_non_bypass` (in `Host.Composition`) pins the
multi-gate non-bypass over the function the deployed entrypoint actually runs.
-/

namespace Host

/-- The route a mediation step takes for one wire line. -/
inductive StepRoute where
  | passthrough
  | forward
  | block
  deriving DecidableEq, Repr

/-- The PURE routing decision of `stepImpl`, with the IO stripped:

    * a line that does not classify as a mediated `tools/call` passes through;
    * a mediated call is forwarded iff the fail-closed AND-combinator over the
      per-kernel verdicts allows (`combineVerdicts`, Registry.lean) — exactly
      `stepImpl`'s `match combined with | .allow => forward | .deny => block`,
      since `dispatch` returns `combined = combineVerdicts verdicts`. -/
def stepRoute (lc : LineClass) (verdicts : List Verdict) : StepRoute :=
  match lc with
  | .passthrough => .passthrough
  | .act _ =>
      match combineVerdicts verdicts with
      | .allow => .forward
      | .deny => .block

@[simp] theorem stepRoute_passthrough (verdicts : List Verdict) :
    stepRoute .passthrough verdicts = .passthrough := rfl

/-- On a mediated call, `stepRoute` forwards iff the combined verdict allows. -/
theorem stepRoute_act_forward_iff (a : CanonicalAction) (verdicts : List Verdict) :
    stepRoute (.act a) verdicts = .forward ↔ combineVerdicts verdicts = .allow := by
  unfold stepRoute
  cases h : combineVerdicts verdicts <;> simp [h]

end Host
