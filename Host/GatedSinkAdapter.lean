/- SPDX-License-Identifier: Apache-2.0 -/

import Host.SealAdapter

/-!
# The gated-sink adapter, by name — O1∧O2 conformance + non-vacuity

`Host/SealAdapter.lean` (W2-T6.1) proves the Lean model of the shipped Rust
routing core's GATED CHILD-INPUT SINK satisfies the channel obligations and
hence mediates every action it sees: `sealAdapter_O1`, `sealAdapter_O2`, and
the capstone `sealAdapter_trace`. This module closes the brief under the
reviewed ruling (thin extension, security-relevant-path fidelity) and gives
that adapter its HONEST NAME.

## Naming ruling (K3): renamed from `deployedAdapter`

This adapter was previously named `deployedAdapter`. That name promised
coverage the theorem does not have: the alias models only the gated
child-input sink (P2 forward, P3 interactive retry). It does NOT range over
the P1 classify-passthrough transition — the passthrough perimeter brick
(`Host/PassthroughPerimeter.lean`) puts P1 INSIDE a widened model and proves
non-bypass FAILS there for every escaping line (malformed JSON, BOM-prefixed
JSON, `"TOOLS/CALL"`, and a JSON-RPC batch array). Even that widened model
still omits P4 operator argv, P5 kernel-block client-stdout egress, P6
response egress, and P7–P9 telemetry/evidence. Since NO Lean object in this
repo covers the full deployed alphabet, nothing earns the word "deployed".
The name now states its scope: this is the GATED-SINK adapter, and the
docstrings below state the alphabet each theorem ranges over.

* `gatedSinkAdapter` — the GATED-SINK NAME, definitionally `sealAdapter`:
  one model, two entry points, zero duplicated proof.
* `gatedSink_O1` / `gatedSink_O2` / `gatedSink_preserves_non_bypass` — the
  brief's obligations, discharged by the W2-T6.1 theorems at the alias, over
  the GATED-SINK alphabet only (P2/P3): every emission that reaches the
  gated sink is Allow-preceded.
* `gatedSink_nonvacuous` (a run in which a gate-Allow yields an emitted AND
  licensed output — not the degenerate always-deny adapter), plus the
  LIVE-gate hypothesis forms `gatedSink_live_emit_of_allow` /
  `gatedSink_live_license_of_allow`.

## Alphabet the theorems range over (stated where they are stated)

COVERED: P2 forward and P3 interactive retry — the single gated sink
`child_in.write_all`, reachable only past the gate; and license growth (the
allow buffer starts empty and grows only by the `(raw, out)` pair of an
allowed emit).

NOT COVERED here: P1 classify-passthrough (modelled — and shown to bypass —
in `Host/PassthroughPerimeter.lean`, never at this adapter object), P5
kernel-block client-stdout egress, P6 response egress (unmediated BY DESIGN,
`RUST_BRIDGE.md`), P4 operator argv (trusted setup), P7–P9 telemetry and
evidence reads.

## HONESTY

This proves the LEAN MODEL of the gated-sink path satisfies O1–O3; it does
NOT verify the Rust source directly. The model↔binary gap is the stated
differential/inspection obligation, discharged operationally by the
four-bodies byte-identical conformance chain (`docs/CONFORMANCE-BRIDGE.md`).
Model theorem here, binary correspondence there, no conflation.
-/

namespace Host.Channel

/-- The gated-sink adapter, by name: definitionally the W2-T6.1 model of the
shipped Rust routing core's gated child-input sink (P2 forward, P3 retry).
Renamed from `deployedAdapter` (K3): it does not range over P1 passthrough
or P4/P5/P6/P7–P9, so the name states its scope. One model, one set of
proofs. -/
def gatedSinkAdapter : Adapter := sealAdapter

/-- **O1 for the gated sink** — no unlicensed emission at the gated
child-input sink (= `sealAdapter_O1`). -/
theorem gatedSink_O1 : O1 gatedSinkAdapter := sealAdapter_O1

/-- **O2 for the gated sink** — no manufactured license
(= `sealAdapter_O2`). -/
theorem gatedSink_O2 : O2 gatedSinkAdapter := sealAdapter_O2

/-- **The gated sink mediates every action it sees, every run** — the
    capstone with its hypotheses discharged at the gated-sink adapter. This
    ranges over the GATED-SINK alphabet (P2/P3) only: it says nothing about
    P1 passthrough, which `Host/PassthroughPerimeter.lean` shows escapes. -/
theorem gatedSink_preserves_non_bypass (state : SealV2.ApprovalState)
    (inputs : List SealV2.RawBytes) :
    precededByAllow
      (run gatedSinkAdapter (fun raw => SealV2.decide raw state) inputs).2 :=
  channel_preserves_non_bypass gatedSinkAdapter gatedSink_O1 gatedSink_O2
    state inputs

/-- Concrete run evidence (trace layer, `okGate` stub): an allowed request
emits its allowed bytes. -/
theorem gatedSink_run_trace :
    (run gatedSinkAdapter okGate ["ok"]).2
      = [ChanEv.emitEv "OK", ChanEv.decideEv "ok" (SealV2.Decision.Allow "OK")] := rfl

/-- Concrete run evidence (state layer): the same run licenses exactly the
allowed `(raw, out)` pair. -/
theorem gatedSink_run_state :
    (run gatedSinkAdapter okGate ["ok"]).1 = ([("ok", "OK")], true) := rfl

/-- **Non-vacuity.** The gated-sink model is NOT the trivial always-deny
adapter that satisfies O1∧O2 by never emitting: there is a run in which a
gate-Allow yields an output that is both EMITTED in the trace and LICENSED
in the final state. -/
theorem gatedSink_nonvacuous :
    ∃ (gate : SealV2.RawBytes → SealV2.Decision)
      (inputs : List SealV2.RawBytes) (out : SealV2.CanonicalBytes),
      ChanEv.emitEv out ∈ (run gatedSinkAdapter gate inputs).2 ∧
      ∃ raw, (raw, out) ∈
        gatedSinkAdapter.licensed (run gatedSinkAdapter gate inputs).1 := by
  refine ⟨okGate, ["ok"], "OK", ?_, "ok", ?_⟩
  · rw [gatedSink_run_trace]
    exact List.mem_cons_self ..
  · show ("ok", "OK") ∈ (run gatedSinkAdapter okGate ["ok"]).1.1
    rw [gatedSink_run_state]
    exact List.mem_cons_self ..

/-- **Live-gate hypothesis form (trace half).** IF the real gate allows a
request, THEN the gated-sink model emits exactly the allowed bytes for it —
no live Ed25519 `Allow` is constructed; the `Allow` is hypothesised,
mirroring the NI witness discipline. -/
theorem gatedSink_live_emit_of_allow (state : SealV2.ApprovalState)
    (raw : SealV2.RawBytes) (out : SealV2.CanonicalBytes)
    (h : SealV2.decide raw state = .Allow out) :
    (run gatedSinkAdapter (fun r => SealV2.decide r state) [raw]).2
      = [ChanEv.emitEv out, ChanEv.decideEv raw (.Allow out)] := by
  simp [run, List.foldl_cons, List.foldl_nil, step, h,
    gatedSinkAdapter, sealAdapter]

/-- **Live-gate hypothesis form (license half).** IF the real gate allows a
request, THEN the gated-sink model licenses exactly its `(raw, out)` pair —
the license buffer grows only by allowed emits. -/
theorem gatedSink_live_license_of_allow (state : SealV2.ApprovalState)
    (raw : SealV2.RawBytes) (out : SealV2.CanonicalBytes)
    (h : SealV2.decide raw state = .Allow out) :
    gatedSinkAdapter.licensed
        (run gatedSinkAdapter (fun r => SealV2.decide r state) [raw]).1
      = [(raw, out)] := by
  simp [run, List.foldl_cons, List.foldl_nil, step, h,
    gatedSinkAdapter, sealAdapter]

end Host.Channel
