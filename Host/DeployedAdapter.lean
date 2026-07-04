/- SPDX-License-Identifier: Apache-2.0 -/

import Host.SealAdapter

/-!
# The deployed adapter, by name — O1∧O2 conformance + non-vacuity

`Host/SealAdapter.lean` (W2-T6.1) already proves the Lean model of the
shipped Rust routing core (`rust/src/main.rs`) satisfies the channel
obligations and hence mediates every action: `sealAdapter_O1`,
`sealAdapter_O2`, and `sealAdapter_trace` = the capstone
`channel_preserves_non_bypass` instantiated. This module does NOT build a
second model — two competing "deployed adapter" models in one repo would be
exactly the cross-document drift the coherence audit polices. It closes the
brief under the reviewed ruling (thin extension, security-relevant-path
fidelity — Ben's default):

* `deployedAdapter` — the DEPLOYED-ADAPTER NAME, definitionally
  `sealAdapter`: one model, two entry points, zero duplicated proof.
* `deployed_O1` / `deployed_O2` / `deployed_preserves_non_bypass` — the
  brief's obligations, discharged by the W2-T6.1 theorems at the alias.
* **New content — non-vacuity, previously only build-time `#guard`s:**
  `deployed_nonvacuous` (a run in which a gate-Allow yields an emitted AND
  licensed output — the model is not the degenerate always-deny adapter
  that satisfies O1∧O2 by never emitting), plus the LIVE-gate hypothesis
  forms `deployed_live_emit_of_allow` / `deployed_live_license_of_allow`:
  IF `SealV2.decide` returns `Allow out` for a request THEN the deployed
  model emits exactly `out` and licenses exactly `(raw, out)`. Hypothesis
  form mirrors the NI witness discipline — no live Ed25519 `Allow` is
  constructed (`verifySignature` is not kernel-evaluable); the concrete
  witness runs on the `okGate` stub.

## Fidelity scope (frozen, per ruling)

The model covers the SECURITY-RELEVANT control flow only: emit-gating (the
single gated sink `child_in.write_all`, reachable only past the gate) and
license growth (the allow buffer starts empty and grows only by the
`(raw, out)` pair of an allowed emit). Process/stdio plumbing (P1/P5 client
stdout, P4 operator argv, P6 response egress, P7–P9 telemetry) is a named
abstraction boundary — see the W2-T6.1 docstring's P1–P6 map.

## HONESTY

This proves the LEAN MODEL of the deployed path satisfies O1–O3; it does
NOT verify the Rust source directly. The model↔binary gap is the stated
differential/inspection obligation, discharged operationally by the
four-bodies byte-identical conformance chain (interpreted Lean model /
native `.so` / deployed `seal-host-rs` / rebuilt `seal.wasm` — SHA-256
pinned, `docs/CONFORMANCE-BRIDGE.md`). Said plainly: model theorem here,
binary correspondence there, no conflation.
-/

namespace Host.Channel

/-- The deployed adapter, by name: definitionally the W2-T6.1 model of the
shipped Rust routing core. One model, one set of proofs. -/
def deployedAdapter : Adapter := sealAdapter

/-- **O1 for the deployed profile** — no unlicensed emission
(= `sealAdapter_O1`). -/
theorem deployed_O1 : O1 deployedAdapter := sealAdapter_O1

/-- **O2 for the deployed profile** — no manufactured license
(= `sealAdapter_O2`). -/
theorem deployed_O2 : O2 deployedAdapter := sealAdapter_O2

/-- **The deployed profile mediates every action, every run** — the
capstone with its hypotheses discharged at the deployed adapter. -/
theorem deployed_preserves_non_bypass (state : SealV2.ApprovalState)
    (inputs : List SealV2.RawBytes) :
    precededByAllow
      (run deployedAdapter (fun raw => SealV2.decide raw state) inputs).2 :=
  channel_preserves_non_bypass deployedAdapter deployed_O1 deployed_O2
    state inputs

/-- Concrete run evidence (trace layer, `okGate` stub): an allowed request
emits its allowed bytes. -/
theorem deployed_run_trace :
    (run deployedAdapter okGate ["ok"]).2
      = [ChanEv.emitEv "OK", ChanEv.decideEv "ok" (SealV2.Decision.Allow "OK")] := rfl

/-- Concrete run evidence (state layer): the same run licenses exactly the
allowed `(raw, out)` pair. -/
theorem deployed_run_state :
    (run deployedAdapter okGate ["ok"]).1 = ([("ok", "OK")], true) := rfl

/-- **Non-vacuity.** The deployed model is NOT the trivial always-deny
adapter that satisfies O1∧O2 by never emitting: there is a run in which a
gate-Allow yields an output that is both EMITTED in the trace and LICENSED
in the final state. -/
theorem deployed_nonvacuous :
    ∃ (gate : SealV2.RawBytes → SealV2.Decision)
      (inputs : List SealV2.RawBytes) (out : SealV2.CanonicalBytes),
      ChanEv.emitEv out ∈ (run deployedAdapter gate inputs).2 ∧
      ∃ raw, (raw, out) ∈
        deployedAdapter.licensed (run deployedAdapter gate inputs).1 := by
  refine ⟨okGate, ["ok"], "OK", ?_, "ok", ?_⟩
  · rw [deployed_run_trace]
    exact List.mem_cons_self ..
  · show ("ok", "OK") ∈ (run deployedAdapter okGate ["ok"]).1.1
    rw [deployed_run_state]
    exact List.mem_cons_self ..

/-- **Live-gate hypothesis form (trace half).** IF the real gate allows a
request, THEN the deployed model emits exactly the allowed bytes for it —
no live Ed25519 `Allow` is constructed; the `Allow` is hypothesised,
mirroring the NI witness discipline. -/
theorem deployed_live_emit_of_allow (state : SealV2.ApprovalState)
    (raw : SealV2.RawBytes) (out : SealV2.CanonicalBytes)
    (h : SealV2.decide raw state = .Allow out) :
    (run deployedAdapter (fun r => SealV2.decide r state) [raw]).2
      = [ChanEv.emitEv out, ChanEv.decideEv raw (.Allow out)] := by
  simp [run, List.foldl_cons, List.foldl_nil, step, h,
    deployedAdapter, sealAdapter]

/-- **Live-gate hypothesis form (license half).** IF the real gate allows a
request, THEN the deployed model licenses exactly its `(raw, out)` pair —
the license buffer grows only by allowed emits. -/
theorem deployed_live_license_of_allow (state : SealV2.ApprovalState)
    (raw : SealV2.RawBytes) (out : SealV2.CanonicalBytes)
    (h : SealV2.decide raw state = .Allow out) :
    deployedAdapter.licensed
        (run deployedAdapter (fun r => SealV2.decide r state) [raw]).1
      = [(raw, out)] := by
  simp [run, List.foldl_cons, List.foldl_nil, step, h,
    deployedAdapter, sealAdapter]

end Host.Channel
