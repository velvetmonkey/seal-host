/- SPDX-License-Identifier: Apache-2.0 -/

import SealV2.DecideTheorems
import Host.Audit

/-!
# Non-interference for the SealV2 mediation gate (Goguen–Meseguer)

The gate's observable outputs reveal nothing about the protected
`ApprovalState` beyond ONE authorized bit. Formally: any two states that
agree on `authView raw` — the single bit "this request is authorized" —
produce byte-identical decisions and byte-identical audit records for that
request. Secrets in the state (other sessions' approvals, the public key,
consumed nonces, policy version, TTL caps, the clock) cannot flow into what
an observer of the gate sees, except through that one declassified bit.

## The model (STEP-0, frozen before proving)

* LOW (observable): the request bytes `raw`, the `Decision`, the audit
  record. HIGH (protected): `ApprovalState` modulo `authView` — `session`,
  `now`, `publicKey`, `manifestDigest`, `tools`, `approvals`,
  `policyVersion`, `maxApprovalTtl`, `consumedNonces`, quotiented by the one
  authorization bit for the request at hand.
* `authView raw state : Bool` — the honest declassification: whether this
  request parses and validates against this state. This bit the gate
  legitimately reveals (it IS the decision's success bit); non-interference
  is stated relative to it, as Goguen–Meseguer intransitive/conditional NI.
* `combinedOf : Decision → VerdictKind` and
  `recordView epoch tool verdicts raw state` — the audit record of the gate
  decision (`Host.auditLine` over the combined verdict of `SealV2.decide`).
  The record also carries `request_sha256 = sha256(raw)` — a function of
  `raw` ALONE, i.e. of a LOW input, so by construction it lands on the
  already-permitted side of the declassification boundary and cannot carry
  `ApprovalState` information.
* `observe` — the pair (decision, record): everything downstream sees.

## Theorems (statements frozen with the model)

* `decide_authView_noninterference` (T1, core):
  `authView raw s₁ = authView raw s₂ → decide raw s₁ = decide raw s₂`.
  The Allow payload is a function of `raw` alone: by `decide_emit_unique`
  the emitted bytes are `serialize ⟨ast, witness⟩`, and `serialize`
  discards the witness (`serializeAst` projects the subtype value), so both
  states emit `serializeAstValue ast` for the same parsed `ast`.
* `authView_noninterference_nonvacuous` — non-vacuity witness: two states
  differing in HIGH (the clock) with equal `authView` and equal decision.
* `record_authView_noninterference` (T2): the audit record is
  `authView`-determined. The structural fields (`epoch`, `tool`, combined
  verdict, `request_sha256`) are functions of `(raw, decision)`, hence of
  the declassified bit via T1. When the kernel request commitment was
  added (2026-07-15), T2's STATEMENT and PROOF both survived verbatim:
  the new field is the same term on both sides of the equality.
* `observe_noninterference` (capstone): the full observation pair is
  `authView`-determined — T1 and T2 together.

## The T2 residual, named honestly

`Host.auditLine` also serializes per-kernel `Verdict`s (`reason : String`,
`certHash`). In this codebase those are produced by the `Host.Kernel` layer
(`Kernel.decide : CanonicalAction → Config → Evidence → State → Verdict ×
State`), whose type NEVER receives `SealV2.ApprovalState` — the
reason/certHash channel cannot read the protected state at the type level.
Accordingly `record_authView_noninterference` holds with `verdicts` as a
free (LOW, host-supplied) input on both sides: this is the brief's
"sanitized verdict" option realized by parameterization. A deployment that
routed `ApprovalState`-derived data into a reason string would be a flow
OUTSIDE this theorem — that is the controlled-declassification boundary,
stated here rather than hidden.

## Scope guard

Existing `SealV2.decide` and `Host.auditLine` only; no new kernels; the
timing channel over the `TimedLog` is out of scope by brief; no frozen
module is edited.
-/

namespace Host.NonInterference

open SealV2 (RawBytes ApprovalState Decision parse validate serialize
  serializeAstValue decide)

/-- The honest declassification: the ONE bit of `ApprovalState` the gate
legitimately reveals for a request — whether it parses and validates. -/
def authView (raw : RawBytes) (state : ApprovalState) : Bool :=
  match parse raw with
  | none => false
  | some ast => (validate ast state).isSome

/-- The combined audit verdict of a gate decision — a view, not a kernel. -/
def combinedOf : Decision → VerdictKind
  | .Allow _ => .allow
  | .Block => .deny

/-- The audit record of the gate decision: `auditLine` over the combined
verdict of `SealV2.decide`, committing to the judged bytes via
`request_sha256 = sha256(raw)` — a function of the LOW input `raw` alone.
`verdicts` is a host-supplied LOW input — see the module docstring's
residual note. -/
def recordView (epoch : Nat) (tool : String) (verdicts : List Verdict)
    (raw : RawBytes) (state : ApprovalState) : String :=
  auditLine epoch tool (combinedOf (decide raw state)) verdicts raw

/-- Everything an observer of the gate sees: the decision and its record. -/
def observe (epoch : Nat) (tool : String) (verdicts : List Verdict)
    (raw : RawBytes) (state : ApprovalState) : Decision × String :=
  (decide raw state, recordView epoch tool verdicts raw state)

/-- The Allow payload is a function of the request alone: when validation
succeeds, the emitted bytes are `serializeAstValue ast` — the witness (and
with it every state-dependent fact) is discarded by serialization. -/
theorem decide_allow_of_validate_isSome (raw : RawBytes) (ast : SealV2.AST)
    (s : ApprovalState) (hp : parse raw = some ast)
    (hv : (validate ast s).isSome = true) :
    decide raw s = .Allow (serializeAstValue ast) := by
  obtain ⟨c, hc⟩ := Option.isSome_iff_exists.mp hv
  have hd : decide raw s = .Allow (serialize c) := by
    simp only [SealV2.decide, hp, hc]
  obtain ⟨ast', hp', w, _, hout⟩ := (SealV2.decide_emit_unique raw s (serialize c)).mp hd
  cases Option.some.inj (hp ▸ hp')
  rw [hd, hout]
  rfl

/-- **T1 (core): decision non-interference modulo `authView`.** States that
agree on the one declassified bit produce byte-identical decisions — the
gate's decision channel carries no other information about the protected
state. -/
theorem decide_authView_noninterference (raw : RawBytes)
    (s1 s2 : ApprovalState) (h : authView raw s1 = authView raw s2) :
    decide raw s1 = decide raw s2 := by
  cases hp : parse raw with
  | none => simp only [SealV2.decide, hp]
  | some ast =>
      simp only [authView, hp] at h
      cases hb : (validate ast s1).isSome with
      | false =>
          have h2 : (validate ast s2).isSome = false := by rw [← h, hb]
          have e1 : validate ast s1 = none := Option.not_isSome_iff_eq_none.mp (by simp [hb])
          have e2 : validate ast s2 = none := Option.not_isSome_iff_eq_none.mp (by simp [h2])
          simp only [SealV2.decide, hp, e1, e2]
      | true =>
          have h2 : (validate ast s2).isSome = true := by rw [← h, hb]
          rw [decide_allow_of_validate_isSome raw ast s1 hp hb,
              decide_allow_of_validate_isSome raw ast s2 hp h2]

/-- **Non-vacuity.** The NI theorem is not vacuous: two genuinely different
states — differing in HIGH (the clock) — with equal `authView` and equal
decision. -/
theorem authView_noninterference_nonvacuous :
    ∃ (raw : RawBytes) (s1 s2 : ApprovalState), s1 ≠ s2 ∧
      authView raw s1 = authView raw s2 ∧ decide raw s1 = decide raw s2 := by
  refine ⟨"", ⟨"s", 0, "pk", "md", [], [], "", 300, [], 0⟩,
    ⟨"s", 1, "pk", "md", [], [], "", 300, [], 0⟩, ?_, rfl, rfl⟩
  intro h
  exact absurd (congrArg SealV2.ApprovalState.now h) (by decide)

/-- **T2: record non-interference modulo `authView`.** The audit record's
structural fields (`epoch`, `tool`, combined verdict, and the
`request_sha256` commitment to `raw`) are determined by `(raw, decision)`,
hence by the declassified bit via T1 — `raw` is the same term on both
sides, so its hash is too. Per-kernel `reason`/`certHash` enter only
through the host-supplied `verdicts` input, held on both sides — the named
controlled-declassification boundary (module docstring). -/
theorem record_authView_noninterference (epoch : Nat) (tool : String)
    (verdicts : List Verdict) (raw : RawBytes) (s1 s2 : ApprovalState)
    (h : authView raw s1 = authView raw s2) :
    recordView epoch tool verdicts raw s1 = recordView epoch tool verdicts raw s2 := by
  unfold recordView
  rw [decide_authView_noninterference raw s1 s2 h]

/-- **Capstone: full-observation non-interference.** Everything downstream
sees — the decision and its audit record — is determined by the request and
the one declassified authorization bit. -/
theorem observe_noninterference (epoch : Nat) (tool : String)
    (verdicts : List Verdict) (raw : RawBytes) (s1 s2 : ApprovalState)
    (h : authView raw s1 = authView raw s2) :
    observe epoch tool verdicts raw s1 = observe epoch tool verdicts raw s2 := by
  unfold observe
  rw [decide_authView_noninterference raw s1 s2 h,
      record_authView_noninterference epoch tool verdicts raw s1 s2 h]

end Host.NonInterference
