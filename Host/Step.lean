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
  -- A refused line (pathological number) is blocked unconditionally — no
  -- verdicts, no policy dependence: fail-closed, and it never forwards.
  | .refuse => .block

@[simp] theorem stepRoute_refuse (verdicts : List Verdict) :
    stepRoute .refuse verdicts = .block := rfl

/-- A refused line NEVER forwards, whatever the verdicts — the fail-closed
    guarantee for a pathological numeric literal, independent of any policy. -/
theorem stepRoute_refuse_ne_forward (verdicts : List Verdict) :
    stepRoute .refuse verdicts ≠ .forward := by
  simp [stepRoute_refuse]

/-- **Pathological numeric literal never forwards.** A wire line the pre-parse
    number guard rejects routes to `.block` and NEVER `.forward`, whatever the
    kernel verdicts and whatever the policy — the fail-closed guarantee over the
    exact routing core `Ffi.stepImpl` runs. Combined with
    `stepRoute_passthrough`, the refused line is also never passed through: no
    input in this class yields a forward or a passthrough. -/
theorem pathological_never_forwards (line : String) (verdicts : List Verdict)
    (h : Seal.JsonUtil.wireNumbersSafe line.trimAscii.toString = false) :
    stepRoute (classifyLine line) verdicts = .block := by
  rw [classifyLine_refuse_of_unsafe line h, stepRoute_refuse]

@[simp] theorem stepRoute_passthrough (verdicts : List Verdict) :
    stepRoute .passthrough verdicts = .passthrough := rfl

/-- On a mediated call, `stepRoute` forwards iff the combined verdict allows. -/
theorem stepRoute_act_forward_iff (a : CanonicalAction) (verdicts : List Verdict) :
    stepRoute (.act a) verdicts = .forward ↔ combineVerdicts verdicts = .allow := by
  unfold stepRoute
  cases h : combineVerdicts verdicts <;> simp

end Host
