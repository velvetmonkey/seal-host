/- SPDX-License-Identifier: Apache-2.0 -/

import Host.Canonical
import Host.Step
import Host.Registry

/-!
# The `canonical-l0` strict validation profile, resolved at the proof layer

`Host.classifyLine` runs the COMPATIBLE profile: the SealV2 canonical parse is
attached to a mediated call as `CanonicalAction.ast?` for audit only and never
gates routing (`Host/Canonical.lean`, `CLAIMS.md`). The strict `canonical-l0`
profile — reject on canonical-parse failure, every forward carries a parse
witness — was previously documented but not implemented.

This file implements it as a pure, ADDITIVE profile switch over the same
routing core and proves the two properties that define it:

* `canonicalL0_reject_on_parse_failure` (soundness) — a wire line the V1 view
  recognises as a `tools/call` whose canonical parse fails
  (`SealV2.parse = none` on the trimmed line, the byte form `classifyLine`
  actually canonicalizes) routes to `.block` under `canonicalL0`, for EVERY
  verdict list: no kernel outcome can forward a canonical-reject.
* `canonicalL0_witness_on_forward` (audit completeness) — any wire line
  `canonicalL0` forwards is a recognised `tools/call` carrying a canonical
  parse witness (`ast? = some ast` with `SealV2.parse (trimmed line) = some
  ast`), and the fail-closed combined verdict allowed it. ALLOW ⇒ witness.

The COMPATIBLE profile is untouched: `stepRouteP .compatible` is definitionally
`stepRoute` (`stepRouteP_compatible` is `rfl`), `classifyLine` is not modified,
and the deployed `Ffi.stepImpl` path still routes by `stepRoute`.
-/

namespace Host

/-- Which mediation profile the routing layer runs.

    * `compatible` — the deployed behaviour: V1 routing, canonical parse
      attached for audit only (`Host/Canonical.lean`).
    * `canonicalL0` — strict: a mediated call whose canonical parse failed is
      rejected; only canonical calls reach the kernels' verdict. -/
inductive MediationProfile where
  | compatible
  | canonicalL0
  deriving DecidableEq, Repr

/-- Profile-indexed pure routing. `compatible` is exactly `stepRoute` — the
    pure core the deployed `Ffi.stepImpl` runs. `canonicalL0` first gates on
    the canonical parse witness: `ast? = none` rejects, `ast? = some _` routes
    through the unchanged verdict fold. -/
def stepRouteP : MediationProfile → LineClass → List Verdict → StepRoute
  | .compatible, lc, verdicts => stepRoute lc verdicts
  | .canonicalL0, .passthrough, _ => .passthrough
  | .canonicalL0, .refuse, _ => .block
  | .canonicalL0, .act a, verdicts =>
      match a.ast? with
      | none => .block
      | some _ => stepRoute (.act a) verdicts

/-- COMPATIBLE is byte-for-byte the deployed routing core (no regression). -/
@[simp] theorem stepRouteP_compatible (lc : LineClass) (verdicts : List Verdict) :
    stepRouteP .compatible lc verdicts = stepRoute lc verdicts := rfl

/-- What `classifyLine` attaches as `ast?` IS the SealV2 canonical parse of the
    trimmed wire line. The bridge between the wire-level theorems and the
    `ast?` field the profile gates on. -/
theorem classifyLine_act_ast (line : String) (a : CanonicalAction)
    (hclass : classifyLine line = .act a) :
    a.ast? = SealV2.parse line.trimAscii.toString := by
  simp only [classifyLine] at hclass
  split at hclass
  · exact absurd hclass (by simp)      -- unsafe wire ⇒ .refuse ≠ .act a
  · split at hclass
    · exact absurd hclass (by simp)    -- parse error ⇒ .passthrough
    · split at hclass
      · exact absurd hclass (by simp)  -- not a tools/call ⇒ .passthrough
      · cases hclass
        rfl

/-- **Reject-on-parse-failure (soundness).** A wire line the V1 view
    recognises as a `tools/call` whose canonical parse fails routes to
    `.block` under `canonicalL0`, whatever the kernels would have said. -/
theorem canonicalL0_reject_on_parse_failure (line : String) (a : CanonicalAction)
    (hclass : classifyLine line = .act a)
    (hreject : SealV2.parse line.trimAscii.toString = none)
    (verdicts : List Verdict) :
    stepRouteP .canonicalL0 (classifyLine line) verdicts = .block := by
  rw [hclass]
  have hast : a.ast? = none := (classifyLine_act_ast line a hclass).trans hreject
  simp only [stepRouteP, hast]

/-- **Witness-on-forward (audit completeness).** Any wire line `canonicalL0`
    FORWARDS is a recognised `tools/call` carrying a canonical parse witness,
    and the fail-closed combined verdict allowed it. ALLOW ⇒ witness. -/
theorem canonicalL0_witness_on_forward (line : String) (verdicts : List Verdict)
    (hfwd : stepRouteP .canonicalL0 (classifyLine line) verdicts = .forward) :
    ∃ (a : CanonicalAction) (ast : SealV2.AST),
      classifyLine line = .act a ∧ a.ast? = some ast ∧
      SealV2.parse line.trimAscii.toString = some ast ∧
      combineVerdicts verdicts = .allow := by
  cases hclass : classifyLine line with
  | passthrough =>
      rw [hclass] at hfwd
      exact absurd hfwd (by simp [stepRouteP])
  | refuse =>
      rw [hclass] at hfwd
      exact absurd hfwd (by simp [stepRouteP])
  | act a =>
      rw [hclass] at hfwd
      cases hast : a.ast? with
      | none =>
          simp only [stepRouteP, hast] at hfwd
          exact absurd hfwd (by simp)
      | some ast =>
          simp only [stepRouteP, hast] at hfwd
          have hallow : combineVerdicts verdicts = .allow :=
            (stepRoute_act_forward_iff a verdicts).mp hfwd
          have hparse : SealV2.parse line.trimAscii.toString = some ast :=
            (classifyLine_act_ast line a hclass).symm.trans hast
          exact ⟨a, ast, rfl, hast, hparse, hallow⟩

/-! ## Non-vacuity: `canonicalL0` is a live route

The split below is deliberate and load-bearing — read it before trusting a
green build:

* **THEOREM = kernel-checked semantic property on a minimal exemplar**, zero
  axioms beyond `[propext, Classical.choice, Quot.sound]`: the canonical
  parser rejects a genuine duplicate-key object and accepts genuinely
  canonical bytes (`sealV2_rejects_duplicate_key`, `sealV2_accepts_canonical`);
  the profile's reject and forward routes are both live at the routing layer
  (`canonicalL0_reject_route_live`, `canonicalL0_forward_route_live`).
* **`#guard` = full-wire evaluation, a build-gated TEST, not a kernel
  theorem**: the two real wire lines below are checked end-to-end (V1
  recognition + attached witness state + profile route) by the compiler
  evaluator at elaboration time. A failing guard fails the build; no axiom is
  introduced.

Why the residue cannot be theorems, measured on this development:

* `Lean.Json.parse` is implemented with `partial` functions — opaque to the
  kernel; nothing routed through `classifyLine` on a concrete string can be a
  kernel theorem at all.
* `SealV2.parse` IS kernel-evaluable, but object parsing blows up in kernel
  whnf (the classic literal-reduction blowup): the minimal 13-char
  duplicate-key object OOMs a 6 GiB kernel and completes only under a 12 GiB
  cap (≈40 s); the 69-char nested wire lines below are far beyond this
  machine. `native_decide` WOULD evaluate the full lines, and is refused: it
  buys the theorem at the price of `Lean.ofReduceBool`, torching the
  zero-extra-axiom property this development holds. -/

-- The `SealV2.parse` exemplar theorems (`sealV2_rejects_noncanonical_escape`,
-- `sealV2_rejects_noncanonical_decimal`, `sealV2_accepts_canonical`) and the
-- full-wire `#guard`s live in `Host/CanonicalL0Liveness.lean`: the kernel
-- evaluations are expensive, so they get a leaf module (own `lean` process)
-- rather than sharing this file's elaboration budget.

/-- A mediated call with no canonical witness: the reject route is live even
    under an all-allow verdict list — the block is the canonical gate, not a
    kernel deny. -/
theorem canonicalL0_reject_route_live
    (a : CanonicalAction) (hast : a.ast? = none) (verdicts : List Verdict) :
    stepRouteP .canonicalL0 (.act a) verdicts = .block := by
  simp only [stepRouteP, hast]

/-- A mediated call with a canonical witness and an allowing verdict list: the
    forward route is live, carrying the witness. -/
theorem canonicalL0_forward_route_live
    (a : CanonicalAction) (ast : SealV2.AST) (hast : a.ast? = some ast)
    (verdicts : List Verdict) (hallow : combineVerdicts verdicts = .allow) :
    stepRouteP .canonicalL0 (.act a) verdicts = .forward := by
  simp only [stepRouteP, hast, stepRoute, hallow]

/-- A wire line the V1 view accepts (Lean's `Json.parse` tolerates the
    duplicate key; `Seal.toolsCall?` recognises the call) but the canonical
    parser rejects (`hasDuplicateKey`). Exercised end-to-end in
    `Host/CanonicalL0Liveness.lean`. -/
def nonCanonicalLine : String :=
  "{\"method\":\"tools/call\",\"params\":{\"name\":\"t\",\"arguments\":{\"k\":1,\"k\":1}}}"

/-- The same call in canonical form: no duplicate key. -/
def canonicalLine : String :=
  "{\"method\":\"tools/call\",\"params\":{\"name\":\"t\",\"arguments\":{}}}"

/-- All-allow single-kernel verdict list for the liveness checks: shows the
    reject route is the canonical gate, not a kernel deny. -/
def allowVerdict : Verdict :=
  { kernel := "safety", kind := .allow, reason := "ok", certHash := 0 }

end Host
