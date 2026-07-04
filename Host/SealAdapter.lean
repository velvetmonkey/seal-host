/- SPDX-License-Identifier: Apache-2.0 -/

import Host.ChannelModel

/-!
# W2-T6.1 — The seal adapter model: the obligation set is DISCHARGED

`channel_preserves_non_bypass` (Host/ChannelModel.lean) is conditional: it
assumes its adapter satisfies O1 ∧ O2. The witnesses shipped with it prove the
obligations are satisfiable (`compliantAdapter`) and independently load-bearing
(`rogueAdapter`, `forgerAdapter`), but no adapter modelling the DEPLOYED
routing core was proven compliant. This module closes that named gap:
`sealAdapter` is a Lean model of the deployed adapter's routing discipline
(`rust/src/main.rs`), and `sealAdapter_O1` / `sealAdapter_O2` /
`sealAdapter_trace` discharge the capstone's hypotheses at it.

## STATEMENTS (frozen Day 1, proved after the freeze review)

* `sealAdapter : Host.Channel.Adapter` — state = (license buffer, fresh flag).
  `init` carries an EMPTY license buffer. `onVerdict` prepends exactly the
  pair `(raw, out)` on `Allow out` and marks it fresh; a `Block` licenses
  nothing and clears the flag. `emitsOn` models the gated sink
  (`child_in.write_all` behind the route match): it emits the freshly
  allowed bytes — the head of the license buffer — and only those; in a
  non-fresh state it emits nothing. Every emitted byte string is drawn from
  the license buffer BY CONSTRUCTION, for every state of the state type
  (not merely reachable ones), which is what the step-local obligations
  quantify over.
* `sealAdapter_O1 : O1 sealAdapter` — no unlicensed emission.
* `sealAdapter_O2 : O2 sealAdapter` — no manufactured license.
* `sealAdapter_trace` — `channel_preserves_non_bypass` instantiated at
  `sealAdapter` with both hypotheses discharged: on every run at the live
  gate (`SealV2.decide · state`), every emission is preceded strictly
  earlier in the trace by an `Allow` decide of byte-identical output.

## Fidelity to `rust/src/main.rs` (P1–P6), stated honestly

The model captures the routing DISCIPLINE of the child-input sink: bytes
reach the emission alphabet only as the byte-identical output of the verdict
just received (P2 forward, P3 interactive retry — a second genuine verdict,
which in this model is simply another `Allow` step). What the model does NOT
represent, by design of the seam alphabet: P1 classify-passthrough and P5
kernel block responses (client-stdout side, not the guarded child sink),
P6 response egress (unmediated BY DESIGN, RUST_BRIDGE.md), P4 operator argv
(trusted setup, the child IS the guarded resource), and P7–P9 telemetry and
evidence reads (no effect on the sink).

## TRUST BOUNDARY (residual, stated loud)

The claim is: **the Lean MODEL of the deployed adapter satisfies O1–O2 and
is therefore non-bypassing.** The byte-level refinement `rust/` ↔ model —
that the compiled `seal-host-rs` binary implements `sealAdapter`'s
transition discipline — is NOT proven here and remains named future work;
`rust/` itself, the process boundary, the wall clock and the approval
providers stay in the TCB exactly as inventoried in SEAL-SYSTEM-TCB.md.
This module verifies one component's model, not the surrounding
implementation.
-/

namespace Host.Channel

/-- The seal adapter model. State: the license buffer (newest first) and a
    freshness flag marking whether the last verdict was an `Allow` (whose
    bytes the sink then writes). The buffer grows ONLY by the exact pair of
    an `Allow` verdict; the sink reads ONLY the buffer head. -/
def sealAdapter : Adapter where
  St := List (SealV2.RawBytes × SealV2.CanonicalBytes) × Bool
  init := ([], false)
  onVerdict := fun st raw d =>
    match d with
    | .Allow out => ((raw, out) :: st.1, true)
    | .Block => (st.1, false)
  emitsOn := fun st =>
    if st.2 then
      match st.1 with
      | p :: _ => [p.2]
      | [] => []
    else []
  licensed := fun st => st.1

/-- **O1 at the seal adapter.** The gated sink emits only bytes the
    license buffer covers — structurally, in every state. -/
theorem sealAdapter_O1 : O1 sealAdapter := by
  intro st b hb
  obtain ⟨buf, fresh⟩ := st
  cases fresh with
  | false => nomatch hb
  | true =>
      cases buf with
      | nil => nomatch hb
      | cons p t =>
          have hb' : b ∈ [p.2] := hb
          rcases List.mem_singleton.mp hb' with rfl
          exact ⟨p.1, List.mem_cons_self ..⟩

/-- **O2 at the seal adapter.** The license buffer starts empty and
    grows only by the exact `(raw, out)` pair of the `Allow` verdict just
    received; a `Block` licenses nothing. -/
theorem sealAdapter_O2 : O2 sealAdapter := by
  refine ⟨rfl, ?_⟩
  intro st raw d p hp
  cases d with
  | Block => exact Or.inl hp
  | Allow out =>
      rcases List.mem_cons.mp hp with rfl | hmem
      · exact Or.inr ⟨out, rfl, rfl⟩
      · exact Or.inl hmem

/-- **W2-T6.1.** The capstone with its hypotheses discharged: the
    seal adapter model is non-bypassing on every run at the live gate —
    every emission is preceded, strictly earlier in the trace, by an `Allow`
    decide of byte-identical output. -/
theorem sealAdapter_trace (state : SealV2.ApprovalState)
    (inputs : List SealV2.RawBytes) :
    precededByAllow
      (run sealAdapter (fun raw => SealV2.decide raw state) inputs).2 :=
  channel_preserves_non_bypass sealAdapter sealAdapter_O1 sealAdapter_O2
    state inputs

-- Build-gated fidelity witnesses on the cheap test gate. An allowed line
-- emits its allowed bytes exactly once:
#guard (run sealAdapter okGate ["ok"]).2
  == [ChanEv.emitEv "OK", ChanEv.decideEv "ok" (SealV2.Decision.Allow "OK")]
-- and a subsequent blocked line emits NOTHING (no re-emission of old
-- licenses — the gated-sink discipline, where `compliantAdapter` would
-- re-emit its whole license history):
#guard (run sealAdapter okGate ["ok", "x"]).2
  == [ChanEv.decideEv "x" SealV2.Decision.Block,
      ChanEv.emitEv "OK", ChanEv.decideEv "ok" (SealV2.Decision.Allow "OK")]

end Host.Channel
