/- SPDX-License-Identifier: Apache-2.0 -/

import Host.PassthroughPerimeter
import Host.GatedSinkAdapter

/-!
# The egress perimeter — widening the seam alphabet to P5 and P6

`Host/PassthroughPerimeter.lean` (K4) widened the W2-T6 channel alphabet to
include the P1 classify-passthrough transition and proved the honest split:
non-bypass FAILS over P1, the gated sink (P2/P3) survives. This module widens
the alphabet again, to the two CLIENT-BOUND egress transitions of the deployed
seam table (`rust/src/main.rs:13-21`, `RUST_BRIDGE.md:35-43`):

* **P5 — kernel block response → client stdout.** When a gate-decided line is
  BLOCKED, the deployed host writes a kernel-authored block response to the
  CLIENT (`Host/Main.lean:128`, `writeLocked … (Seal.blockResponseLine
  act.requestId (denyReason verdicts))`; Rust twin `rust/src/main.rs` P5 row).
  Modelled here as `EEv.blockEv line bytes`, where `bytes` is produced by a
  fixed AUTHOR function of the classified action — the adapter and the gate
  cannot choose them. Proven: every block emission is preceded strictly
  earlier by a `Block` decide of the SAME line (`client_block_mediated`, for
  EVERY adapter and every gate — the discipline is host-structural, not an
  adapter obligation), and its bytes are exactly the author's
  (`erun_block_authored`).
* **P6 — child stdout → client stdout, relayed verbatim.** UNMEDIATED BY
  DESIGN (`RUST_BRIDGE.md`: requests are mediated, responses are not).
  Modelled as `EEv.relayEv bytes` driven by a `childOut` input. Proven as a
  MACHINE-CHECKED NEGATIVE: `relay_non_bypass_fails` — for every adapter and
  every gate, including the live `SealV2.decide`, a relayed child frame has
  no prior decision of any kind, so response-egress mediation FAILS, exactly
  as the design says. The verbatim characterisation `erun_relay_iff` pins
  that relay is input-copying: independent of gate, adapter and author.

## What this module does NOT cover, stated loud

* **P4 operator argv → `Command::new(...).spawn()`.** Not modelled HERE;
  the no-go is MACHINE-CHECKED AT THE MODEL LEVEL in `Host/SpawnSeam.lean`,
  which adds the `spawnEv` this paragraph calls pointless and proves what
  the extension yields. The real negative: the spawn precedes every event,
  so strict spawn mediation FAILS on every run — every argv, adapter, gate,
  author and input stream (`spawn_non_bypass_fails`). That is a PROVED
  negative, not a failure to prove mediation, and it is not vacuous:
  `srun_spawn_mem` proves the spawn event actually occurs in the trace.
  The vacuity result is NARROWER than "every candidate argv constraint":
  what is vacuous is every constraint of the GUARDED-POSITION form
  `spawnGuardedBy` — "wherever the spawn sits above a nonempty history, its
  argv satisfies `C`" — which holds for every `C`, including
  `C := fun _ => False` (`spawn_constraint_vacuous_false`), because no run
  puts a spawn above a nonempty history. Constraints of OTHER shapes are
  NOT vacuous: a direct `C argv`, or `spawnEv v ∈ tr → C v`, is refuted at
  `C := False` by `srun_spawn_mem`. Argv is also a run PARAMETER the trace
  semantics cannot observe (`srun_argv_parameter` — in THIS model, and with
  the input stream held FIXED), while the P5 capstone below transfers for
  every argv (`srun_client_block_mediated`): argv buys the child selection
  and ONLY the child selection. P4 REMAINS a TRUST ASSUMPTION (operator
  startup authority, `RUST_BRIDGE.md:148`) — and the theorems establish
  that THIS MODEL contains no argv constraint of the guarded form, not that
  no such constraint could exist in another model or in the deployed host.
* **P7 stderr telemetry.** Not in the alphabet HERE; the no-go is
  MACHINE-CHECKED AT THE MODEL LEVEL in `Host/AuditSeam.lean`, which adds
  the `audEv` this paragraph calls pointless and proves what the extension
  yields. The positives: the extension factors THROUGH the unextended run
  (`arun_eq` — telemetry is post-processing, not dynamics), the telemetry
  function is a run PARAMETER nothing in-run can observe
  (`arun_tel_parameter` — in THIS model, with the input stream held FIXED),
  every decide is telemetry-invariant (`arun_decide_tel_invariant`), audit
  mediation is inherited from the driving event rather than created — it
  FAILS on a relay-driven witness run (`aud_non_bypass_fails`, a proved
  negative, non-vacuous: the same `rfl` places the audit line in the trace)
  and HOLDS for decide-driven telemetry on every run
  (`aud_decide_tel_mediated`) — while the P5 capstone below transfers for
  every telemetry function (`arun_client_block_mediated`). The vacuity
  result is NARROWER than "every stderr-feedback constraint": what is
  vacuous is every constraint of the GUARDED form `audGuardedBy` —
  "a decision stderr FED satisfies `C`" — which holds for every `C`,
  including `C := fun _ _ => False` (`aud_constraint_vacuous_false`),
  because this model makes a telemetry-fed decision impossible
  (`aud_no_fed_decision`). Constraints of OTHER shapes are NOT vacuous:
  `audEv s ∈ tr → C s` is refuted at `C := False` on that same witness run.
  The honest asymmetry is also a theorem: stderr is an OUTPUT, and a reader
  of it gets the telemetry image of the ENTIRE seam trace
  (`arun_stderr_image`) — a real, read-only confidentiality residual — but
  nothing beyond the run (`aud_provenance`), and no in-model influence. The
  CONTENT of audit records is governed model-level by the W2 closeout
  non-interference row (`Host/NonInterference.lean`,
  `record_authView_noninterference` / `observe_noninterference`); the Rust
  stderr writes themselves stay TCB, and no theorem connects `arun` to
  them. P7 REMAINS a trust-inventory row — the theorems establish that THIS
  MODEL contains no telemetry-feedback constraint of the guarded form, not
  that none could exist in another model or in the deployed host.
* **P8/P9 evidence reads** (approvals via A3; votes/grants/forecasts files).
  These are GATE-STATE inputs, not emission seams: they influence which
  verdict the gate returns, never whether an emission needs one. Pinned by
  `gatedSink_non_bypass_evidence_universal` / the erun twin below:
  non-bypass holds for EVERY approval state, hence for whatever state any
  evidence parse yields — no evidence value opens an unmediated emission
  path IN THE MODEL. The fail-closed Rust direction ("parse failure drops
  the record ⇒ deny", P8 row) is provider code and remains TCB — this module
  does NOT prove it.

## HONESTY

Model-level, exactly as its two parent modules: the `rust/` ↔ model byte
refinement remains the conformance-bridge obligation. `Lean.Json.parse` is
`partial`, so concrete classifications are compiler-evaluated `#guard`s and
the theorem layer is conditional on the classification — the witness
discipline stated in `Host/PassthroughPerimeter.lean`, unchanged. The
pre-parse refusal's own client-bound response bytes (host-authored constants,
`Host/Main.lean:116`) are represented by `refuseEv` carrying the refused line
only; their byte identity is not modelled here.
-/

namespace Host.Egress

open Lean
open Host.Channel
open Host.Perimeter

/-! ## The extended seam alphabet -/

/-- Extended seam event: the four widened events of
    `Host.Perimeter.WEv`, plus the two client-bound egress transitions —
    `blockEv` (P5: kernel-authored block response for a gate-blocked line)
    and `relayEv` (P6: a child stdout frame relayed verbatim). -/
inductive EEv where
  | decideEv (raw : SealV2.RawBytes) (d : SealV2.Decision)
  | emitEv (bytes : SealV2.CanonicalBytes)
  | fwdEv (raw : SealV2.RawBytes)
  | refuseEv (raw : SealV2.RawBytes)
  | blockEv (raw : SealV2.RawBytes) (bytes : String)
  | relayEv (bytes : String)
  deriving Repr, BEq

/-- Extended trace, most-recent-first (the `ChanTrace` convention). -/
abbrev ETrace := List EEv

/-- One extended-seam input: a client stdin line (the hostile alphabet the
    router judges) or a child stdout frame (the P6 relay source). -/
inductive EIn where
  | clientLine (line : String)
  | childOut (bytes : String)
  deriving Repr, BEq

/-- One extended step. Client lines route by the DEPLOYED
    `Host.classifyLine`, exactly as `Host.Perimeter.wstep`; a gate `Block`
    on an act-classified line additionally emits the P5 client-bound block
    response, whose bytes are the fixed `author` function of the classified
    action — neither the adapter nor the gate picks them. A child frame is
    relayed verbatim (P6): state untouched, no decision. -/
def estep (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String)
    (s : A.St × ETrace) : EIn → A.St × ETrace
  | .childOut c => (s.1, EEv.relayEv c :: s.2)
  | .clientLine line =>
    match Host.classifyLine line with
    | .passthrough => (s.1, EEv.fwdEv line :: s.2)
    | .refuse => (s.1, EEv.refuseEv line :: s.2)
    | .act a =>
      match gate line with
      | .Allow out =>
          (A.onVerdict s.1 line (.Allow out),
            ((A.emitsOn (A.onVerdict s.1 line (.Allow out))).map EEv.emitEv)
              ++ EEv.decideEv line (.Allow out) :: s.2)
      | .Block =>
          (A.onVerdict s.1 line .Block,
            ((A.emitsOn (A.onVerdict s.1 line .Block)).map EEv.emitEv)
              ++ EEv.blockEv line (author a)
                :: EEv.decideEv line SealV2.Decision.Block :: s.2)

/-- An extended run over an interleaved input stream, from the adapter's
    initial state and the empty trace. -/
def erun (A : Adapter) (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    A.St × ETrace :=
  inputs.foldl (estep A gate author) (A.init, ([] : ETrace))

/-! ## Single-step trace shapes (conditional on the classification — the
`Json.parse`-is-`partial` witness discipline) -/

/-- A child frame is relayed verbatim: state untouched, no decision — for
    every adapter, gate and author. The P6 transition, isolated. -/
theorem erun_single_relay (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (c : String) :
    (erun A gate author [EIn.childOut c]).2 = [EEv.relayEv c] := rfl

/-- A passthrough-classified client line: child-bound, no decision (P1,
    unchanged by the egress widening). -/
theorem erun_single_passthrough (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (line : String)
    (h : Host.classifyLine line = .passthrough) :
    (erun A gate author [EIn.clientLine line]).2 = [EEv.fwdEv line] := by
  simp [erun, estep, h]

/-- A refuse-classified client line: client-bound refusal, nothing forwarded,
    nothing decided. -/
theorem erun_single_refuse (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (line : String)
    (h : Host.classifyLine line = .refuse) :
    (erun A gate author [EIn.clientLine line]).2 = [EEv.refuseEv line] := by
  simp [erun, estep, h]

/-- An act-classified line at an allowing gate, at the deployed model: the
    gated-sink emission, strictly after its decide — no P5 block response. -/
theorem erun_single_act_allow (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (line : String) (a : CanonicalAction)
    (out : SealV2.CanonicalBytes)
    (h : Host.classifyLine line = .act a) (hg : gate line = .Allow out) :
    (erun sealAdapter gate author [EIn.clientLine line]).2
      = [EEv.emitEv out, EEv.decideEv line (.Allow out)] := by
  simp [erun, estep, h, hg, sealAdapter]

/-- **The P5 shape.** An act-classified line at a blocking gate, at the
    deployed model: the client-bound block response with AUTHOR-fixed bytes,
    strictly after the `Block` decide — and nothing child-bound. -/
theorem erun_single_act_block (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (line : String) (a : CanonicalAction)
    (h : Host.classifyLine line = .act a) (hg : gate line = .Block) :
    (erun sealAdapter gate author [EIn.clientLine line]).2
      = [EEv.blockEv line (author a),
         EEv.decideEv line SealV2.Decision.Block] := by
  simp [erun, estep, h, hg, sealAdapter]

/-! ## Step-level membership -/

/-- A client-line step adds a block event for `raw` iff `raw` is the line
    processed, the gate blocked it, and the line is act-classified with the
    author's bytes. -/
theorem estep_client_block_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (s : A.St × ETrace)
    (line raw : String) (b : String) :
    EEv.blockEv raw b ∈ (estep A gate author s (EIn.clientLine line)).2 ↔
      EEv.blockEv raw b ∈ s.2
        ∨ (raw = line ∧ gate line = SealV2.Decision.Block
            ∧ ∃ a, Host.classifyLine line = Host.LineClass.act a
                ∧ b = author a) := by
  cases h : Host.classifyLine line with
  | passthrough =>
    have hstep : (estep A gate author s (EIn.clientLine line)).2
        = EEv.fwdEv line :: s.2 := by simp [estep, h]
    rw [hstep]
    constructor
    · intro hm
      rcases List.mem_cons.mp hm with heq | hm'
      · cases heq
      · exact Or.inl hm'
    · rintro (hm | ⟨rfl, -, a, ha, -⟩)
      · exact List.mem_cons_of_mem _ hm
      · cases ha
  | refuse =>
    have hstep : (estep A gate author s (EIn.clientLine line)).2
        = EEv.refuseEv line :: s.2 := by simp [estep, h]
    rw [hstep]
    constructor
    · intro hm
      rcases List.mem_cons.mp hm with heq | hm'
      · cases heq
      · exact Or.inl hm'
    · rintro (hm | ⟨rfl, -, a, ha, -⟩)
      · exact List.mem_cons_of_mem _ hm
      · cases ha
  | act a =>
    cases hg : gate line with
    | Allow out =>
      have hstep : (estep A gate author s (EIn.clientLine line)).2
          = ((A.emitsOn (A.onVerdict s.1 line (.Allow out))).map EEv.emitEv)
              ++ EEv.decideEv line (.Allow out) :: s.2 := by
        simp [estep, h, hg]
      rw [hstep]
      constructor
      · intro hm
        rcases List.mem_append.mp hm with hml | hmr
        · obtain ⟨x, -, hbe⟩ := List.mem_map.mp hml
          cases hbe
        · rcases List.mem_cons.mp hmr with heq | hm'
          · cases heq
          · exact Or.inl hm'
      · rintro (hm | ⟨rfl, hgb, -⟩)
        · exact List.mem_append_right _ (List.mem_cons_of_mem _ hm)
        · cases hgb
    | Block =>
      have hstep : (estep A gate author s (EIn.clientLine line)).2
          = ((A.emitsOn (A.onVerdict s.1 line .Block)).map EEv.emitEv)
              ++ EEv.blockEv line (author a)
                :: EEv.decideEv line SealV2.Decision.Block :: s.2 := by
        simp [estep, h, hg]
      rw [hstep]
      constructor
      · intro hm
        rcases List.mem_append.mp hm with hml | hmr
        · obtain ⟨x, -, hbe⟩ := List.mem_map.mp hml
          cases hbe
        · rcases List.mem_cons.mp hmr with heq | hm'
          · injection heq with h1 h2
            exact Or.inr ⟨h1, rfl, a, rfl, h2⟩
          · rcases List.mem_cons.mp hm' with heq2 | hm''
            · cases heq2
            · exact Or.inl hm''
      · rintro (hm | ⟨rfl, -, a', ha', rfl⟩)
        · exact List.mem_append_right _
            (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hm))
        · injection ha' with haa
          subst haa
          exact List.mem_append_right _ List.mem_cons_self

/-- A child-frame step never adds a block event. -/
theorem estep_child_block_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (s : A.St × ETrace)
    (c raw : String) (b : String) :
    EEv.blockEv raw b ∈ (estep A gate author s (EIn.childOut c)).2 ↔
      EEv.blockEv raw b ∈ s.2 := by
  have hstep : (estep A gate author s (EIn.childOut c)).2
      = EEv.relayEv c :: s.2 := rfl
  rw [hstep]
  constructor
  · intro hm
    rcases List.mem_cons.mp hm with heq | hm'
    · cases heq
    · exact hm'
  · exact fun hm => List.mem_cons_of_mem _ hm

/-- A client-line step adds a relay event never. -/
theorem estep_client_relay_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (s : A.St × ETrace)
    (line cb : String) :
    EEv.relayEv cb ∈ (estep A gate author s (EIn.clientLine line)).2 ↔
      EEv.relayEv cb ∈ s.2 := by
  cases h : Host.classifyLine line with
  | passthrough =>
    have hstep : (estep A gate author s (EIn.clientLine line)).2
        = EEv.fwdEv line :: s.2 := by simp [estep, h]
    rw [hstep]
    constructor
    · intro hm
      rcases List.mem_cons.mp hm with heq | hm'
      · cases heq
      · exact hm'
    · exact fun hm => List.mem_cons_of_mem _ hm
  | refuse =>
    have hstep : (estep A gate author s (EIn.clientLine line)).2
        = EEv.refuseEv line :: s.2 := by simp [estep, h]
    rw [hstep]
    constructor
    · intro hm
      rcases List.mem_cons.mp hm with heq | hm'
      · cases heq
      · exact hm'
    · exact fun hm => List.mem_cons_of_mem _ hm
  | act a =>
    cases hg : gate line with
    | Allow out =>
      have hstep : (estep A gate author s (EIn.clientLine line)).2
          = ((A.emitsOn (A.onVerdict s.1 line (.Allow out))).map EEv.emitEv)
              ++ EEv.decideEv line (.Allow out) :: s.2 := by
        simp [estep, h, hg]
      rw [hstep]
      constructor
      · intro hm
        rcases List.mem_append.mp hm with hml | hmr
        · obtain ⟨x, -, hbe⟩ := List.mem_map.mp hml
          cases hbe
        · rcases List.mem_cons.mp hmr with heq | hm'
          · cases heq
          · exact hm'
      · exact fun hm => List.mem_append_right _ (List.mem_cons_of_mem _ hm)
    | Block =>
      have hstep : (estep A gate author s (EIn.clientLine line)).2
          = ((A.emitsOn (A.onVerdict s.1 line .Block)).map EEv.emitEv)
              ++ EEv.blockEv line (author a)
                :: EEv.decideEv line SealV2.Decision.Block :: s.2 := by
        simp [estep, h, hg]
      rw [hstep]
      constructor
      · intro hm
        rcases List.mem_append.mp hm with hml | hmr
        · obtain ⟨x, -, hbe⟩ := List.mem_map.mp hml
          cases hbe
        · rcases List.mem_cons.mp hmr with heq | hm'
          · cases heq
          · rcases List.mem_cons.mp hm' with heq2 | hm''
            · cases heq2
            · exact hm''
      · exact fun hm => List.mem_append_right _
          (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ hm))

/-- A child-frame step adds exactly its own relay event. -/
theorem estep_child_relay_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (s : A.St × ETrace)
    (c cb : String) :
    EEv.relayEv cb ∈ (estep A gate author s (EIn.childOut c)).2 ↔
      EEv.relayEv cb ∈ s.2 ∨ cb = c := by
  have hstep : (estep A gate author s (EIn.childOut c)).2
      = EEv.relayEv c :: s.2 := rfl
  rw [hstep]
  constructor
  · intro hm
    rcases List.mem_cons.mp hm with heq | hm'
    · injection heq with h1
      exact Or.inr h1
    · exact Or.inl hm'
  · rintro (hm | rfl)
    · exact List.mem_cons_of_mem _ hm
    · exact List.mem_cons_self

/-! ## Fold-level membership and the characterisations -/

/-- Block-event membership over a fold from any start state. -/
theorem erun_from_block_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (raw : String) (b : String) :
    ∀ (inputs : List EIn) (s : A.St × ETrace),
      EEv.blockEv raw b ∈ (inputs.foldl (estep A gate author) s).2 ↔
        EEv.blockEv raw b ∈ s.2
          ∨ (EIn.clientLine raw ∈ inputs
              ∧ gate raw = SealV2.Decision.Block
              ∧ ∃ a, Host.classifyLine raw = Host.LineClass.act a
                  ∧ b = author a) := by
  intro inputs
  induction inputs with
  | nil => intro s; simp
  | cons i rest ih =>
    intro s
    rw [List.foldl_cons, ih (estep A gate author s i)]
    cases i with
    | clientLine line =>
      rw [estep_client_block_mem]
      constructor
      · rintro ((hm | ⟨rfl, hgb, a, ha, rfl⟩) | ⟨hin, hgb, a, ha, rfl⟩)
        · exact Or.inl hm
        · exact Or.inr ⟨List.mem_cons_self, hgb, a, ha, rfl⟩
        · exact Or.inr ⟨List.mem_cons_of_mem _ hin, hgb, a, ha, rfl⟩
      · rintro (hm | ⟨hin, hgb, a, ha, rfl⟩)
        · exact Or.inl (Or.inl hm)
        · rcases List.mem_cons.mp hin with heq | hin'
          · injection heq with h1
            exact Or.inl (Or.inr ⟨h1, h1 ▸ hgb, a, h1 ▸ ha, rfl⟩)
          · exact Or.inr ⟨hin', hgb, a, ha, rfl⟩
    | childOut c =>
      rw [estep_child_block_mem]
      constructor
      · rintro (hm | ⟨hin, hrest⟩)
        · exact Or.inl hm
        · exact Or.inr ⟨List.mem_cons_of_mem _ hin, hrest⟩
      · rintro (hm | ⟨hin, hrest⟩)
        · exact Or.inl hm
        · rcases List.mem_cons.mp hin with heq | hin'
          · cases heq
          · exact Or.inr ⟨hin', hrest⟩

/-- Relay-event membership over a fold from any start state. -/
theorem erun_from_relay_mem (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (cb : String) :
    ∀ (inputs : List EIn) (s : A.St × ETrace),
      EEv.relayEv cb ∈ (inputs.foldl (estep A gate author) s).2 ↔
        EEv.relayEv cb ∈ s.2 ∨ EIn.childOut cb ∈ inputs := by
  intro inputs
  induction inputs with
  | nil => intro s; simp
  | cons i rest ih =>
    intro s
    rw [List.foldl_cons, ih (estep A gate author s i)]
    cases i with
    | clientLine line =>
      rw [estep_client_relay_mem]
      constructor
      · rintro (hm | hin)
        · exact Or.inl hm
        · exact Or.inr (List.mem_cons_of_mem _ hin)
      · rintro (hm | hin)
        · exact Or.inl hm
        · rcases List.mem_cons.mp hin with heq | hin'
          · cases heq
          · exact Or.inr hin'
    | childOut c =>
      rw [estep_child_relay_mem]
      constructor
      · rintro ((hm | rfl) | hin)
        · exact Or.inl hm
        · exact Or.inr List.mem_cons_self
        · exact Or.inr (List.mem_cons_of_mem _ hin)
      · rintro (hm | hin)
        · exact Or.inl (Or.inl hm)
        · rcases List.mem_cons.mp hin with heq | hin'
          · injection heq with h1
            exact Or.inl (Or.inr h1)
          · exact Or.inr hin'

/-- **The P5 characterisation.** An extended run emits a client-bound block
    response for `raw` with bytes `b` IFF `raw` arrived as a client line, the
    gate BLOCKED it, it is act-classified, and `b` is exactly the author's
    bytes for that action — for every adapter: neither the adapter nor the
    gate can inject, suppress-and-substitute, or reword a block response. -/
theorem erun_block_iff (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn)
    (raw : String) (b : String) :
    EEv.blockEv raw b ∈ (erun A gate author inputs).2 ↔
      EIn.clientLine raw ∈ inputs
        ∧ gate raw = SealV2.Decision.Block
        ∧ ∃ a, Host.classifyLine raw = Host.LineClass.act a
            ∧ b = author a := by
  unfold erun
  rw [erun_from_block_mem]
  simp

/-- P5 byte authorship, extracted: a block emission's bytes are the fixed
    author function of the classified action — kernel-authored in the
    deployed host, never adapter- or gate-chosen. -/
theorem erun_block_authored (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn)
    (raw : String) (b : String)
    (h : EEv.blockEv raw b ∈ (erun A gate author inputs).2) :
    gate raw = SealV2.Decision.Block
      ∧ ∃ a, Host.classifyLine raw = Host.LineClass.act a ∧ b = author a :=
  ((erun_block_iff A gate author inputs raw b).mp h).2

/-- **The P6 characterisation: relay is verbatim input-copying.** A relay
    event for `cb` is in the trace IFF `cb` arrived as a child frame —
    independent of the gate, the adapter and the author. This is the honest
    model of "response egress is unmediated BY DESIGN": nothing about the
    relayed bytes is consulted, judged or transformed. -/
theorem erun_relay_iff (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) (cb : String) :
    EEv.relayEv cb ∈ (erun A gate author inputs).2 ↔
      EIn.childOut cb ∈ inputs := by
  unfold erun
  rw [erun_from_relay_mem]
  simp

/-! ## The P5 capstone — every block response is decision-preceded

Host-structural: holds for EVERY adapter and EVERY gate, with NO O1/O2
hypothesis — the P5 emission is inserted by the host step itself, directly
above its own `Block` decide. -/

/-- P5 mediation, trace-global: every client-bound block emission is
    preceded strictly earlier by a `Block` decide of the SAME line. -/
def blocksPrecededByDecide (tr : ETrace) : Prop :=
  ∀ post raw b pre, tr = post ++ EEv.blockEv raw b :: pre →
    EEv.decideEv raw SealV2.Decision.Block ∈ pre

/-- Positional form for the induction (the `Guarded` convention). -/
def BlockGuarded : ETrace → Prop
  | [] => True
  | EEv.blockEv raw _ :: rest =>
      (EEv.decideEv raw SealV2.Decision.Block ∈ rest) ∧ BlockGuarded rest
  | EEv.decideEv _ _ :: rest => BlockGuarded rest
  | EEv.emitEv _ :: rest => BlockGuarded rest
  | EEv.fwdEv _ :: rest => BlockGuarded rest
  | EEv.refuseEv _ :: rest => BlockGuarded rest
  | EEv.relayEv _ :: rest => BlockGuarded rest

theorem blockGuarded_split (post : ETrace) :
    ∀ (raw : String) (b : String) (pre : ETrace),
      BlockGuarded (post ++ EEv.blockEv raw b :: pre) →
      EEv.decideEv raw SealV2.Decision.Block ∈ pre := by
  induction post with
  | nil => intro raw b pre h; exact h.1
  | cons e post ih =>
    intro raw b pre h
    cases e with
    | decideEv r d => exact ih raw b pre h
    | emitEv x => exact ih raw b pre h
    | fwdEv r => exact ih raw b pre h
    | refuseEv r => exact ih raw b pre h
    | blockEv r bb => exact ih raw b pre h.2
    | relayEv x => exact ih raw b pre h

theorem blockGuarded_blocksPreceded (tr : ETrace) (h : BlockGuarded tr) :
    blocksPrecededByDecide tr :=
  fun post raw b pre heq => blockGuarded_split post raw b pre (heq ▸ h)

theorem blockGuarded_append_emits (l : List SealV2.CanonicalBytes)
    (tr : ETrace) (h : BlockGuarded tr) :
    BlockGuarded (l.map EEv.emitEv ++ tr) := by
  induction l with
  | nil => simpa using h
  | cons b bs ih => exact ih

/-- Block-guardedness survives every extended step, for every adapter. -/
theorem erun_blockGuarded (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) :
    ∀ (inputs : List EIn) (s : A.St × ETrace),
      BlockGuarded s.2 →
      BlockGuarded ((inputs.foldl (estep A gate author) s)).2 := by
  intro inputs
  induction inputs with
  | nil => intro s h; exact h
  | cons i rest ih =>
    intro s h
    rw [List.foldl_cons]
    apply ih
    cases i with
    | childOut c =>
      show BlockGuarded (EEv.relayEv c :: s.2)
      exact h
    | clientLine line =>
      cases h1 : Host.classifyLine line with
      | passthrough =>
        have hstep : (estep A gate author s (EIn.clientLine line)).2
            = EEv.fwdEv line :: s.2 := by simp [estep, h1]
        rw [hstep]
        exact h
      | refuse =>
        have hstep : (estep A gate author s (EIn.clientLine line)).2
            = EEv.refuseEv line :: s.2 := by simp [estep, h1]
        rw [hstep]
        exact h
      | act a =>
        cases hg : gate line with
        | Allow out =>
          have hstep : (estep A gate author s (EIn.clientLine line)).2
              = ((A.emitsOn (A.onVerdict s.1 line (.Allow out))).map
                  EEv.emitEv)
                ++ EEv.decideEv line (.Allow out) :: s.2 := by
            simp [estep, h1, hg]
          rw [hstep]
          exact blockGuarded_append_emits _ _ h
        | Block =>
          have hstep : (estep A gate author s (EIn.clientLine line)).2
              = ((A.emitsOn (A.onVerdict s.1 line .Block)).map EEv.emitEv)
                ++ EEv.blockEv line (author a)
                  :: EEv.decideEv line SealV2.Decision.Block :: s.2 := by
            simp [estep, h1, hg]
          rw [hstep]
          exact blockGuarded_append_emits _ _ ⟨List.mem_cons_self, h⟩

/-- **P5 CAPSTONE.** On every extended run, at every adapter, every gate and
    every author: every client-bound block emission is preceded strictly
    earlier in the trace by a `Block` decide of the same line. The block
    response channel cannot fire without its decision. -/
theorem client_block_mediated (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    blocksPrecededByDecide (erun A gate author inputs).2 :=
  blockGuarded_blocksPreceded _
    (erun_blockGuarded A gate author inputs (A.init, []) trivial)

/-- The P5 capstone at the deployed model and the LIVE gate. -/
theorem client_block_mediated_live (state : SealV2.ApprovalState)
    (author : CanonicalAction → String) (inputs : List EIn) :
    blocksPrecededByDecide
      (erun sealAdapter (fun raw => SealV2.decide raw state)
        author inputs).2 :=
  client_block_mediated sealAdapter _ author inputs

/-! ## The P6 verdict — a machine-checked negative

Response egress carries NO decision, for every adapter and every gate,
including the live one. This is the design (`RUST_BRIDGE.md`), now a
theorem instead of prose. -/

/-- Response-egress mediation, in its WEAKEST possible form: every relayed
    child frame has some strictly earlier decision — on ANY line, of ANY
    verdict. Even this fails. -/
def relayMediated (tr : ETrace) : Prop :=
  ∀ post c pre, tr = post ++ EEv.relayEv c :: pre →
    ∃ raw d, EEv.decideEv raw d ∈ pre

/-- **P6 NO-GO, machine-checked.** For every adapter, every gate and every
    author, a relayed child frame breaks egress mediation even in its
    weakest form: the relay carries no prior decision of any kind. Response
    egress is unmediated BY DESIGN, and the model says so instead of hiding
    the transition from the alphabet. -/
theorem relay_non_bypass_fails (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (c : String) :
    ¬ relayMediated (erun A gate author [EIn.childOut c]).2 := by
  intro hmed
  obtain ⟨raw, d, hd⟩ := hmed [] c [] (by rw [erun_single_relay]; rfl)
  nomatch hd

/-- The P6 failure pinned at the deployed model and the LIVE gate. -/
theorem relay_non_bypass_fails_live (state : SealV2.ApprovalState)
    (author : CanonicalAction → String) (c : String) :
    ¬ relayMediated
        (erun sealAdapter (fun raw => SealV2.decide raw state)
          author [EIn.childOut c]).2 :=
  relay_non_bypass_fails sealAdapter _ author c

/-! ## The salvage — the gated sink survives the egress widening

Exactly as in `Host/PassthroughPerimeter.lean`: for any O1∧O2 adapter, every
gated-sink emission in an EXTENDED run is still Allow-preceded. The egress
widening adds client-bound transitions and the verbatim relay; none of them
touches the child-input discipline. -/

/-- Gated-sink mediation over the extended trace. -/
def emitsPrecededByAllowE (tr : ETrace) : Prop :=
  ∀ post b pre, tr = post ++ EEv.emitEv b :: pre →
    ∃ raw, EEv.decideEv raw (SealV2.Decision.Allow b) ∈ pre

/-- Positional form for the induction. -/
def EmitGuardedE : ETrace → Prop
  | [] => True
  | EEv.emitEv b :: rest =>
      (∃ raw, EEv.decideEv raw (SealV2.Decision.Allow b) ∈ rest)
        ∧ EmitGuardedE rest
  | EEv.decideEv _ _ :: rest => EmitGuardedE rest
  | EEv.fwdEv _ :: rest => EmitGuardedE rest
  | EEv.refuseEv _ :: rest => EmitGuardedE rest
  | EEv.blockEv _ _ :: rest => EmitGuardedE rest
  | EEv.relayEv _ :: rest => EmitGuardedE rest

theorem emitGuardedE_split (post : ETrace) :
    ∀ (b : SealV2.CanonicalBytes) (pre : ETrace),
      EmitGuardedE (post ++ EEv.emitEv b :: pre) →
      ∃ raw, EEv.decideEv raw (SealV2.Decision.Allow b) ∈ pre := by
  induction post with
  | nil => intro b pre h; exact h.1
  | cons e post ih =>
    intro b pre h
    cases e with
    | emitEv x => exact ih b pre h.2
    | decideEv r d => exact ih b pre h
    | fwdEv r => exact ih b pre h
    | refuseEv r => exact ih b pre h
    | blockEv r bb => exact ih b pre h
    | relayEv x => exact ih b pre h

theorem emitGuardedE_precededByAllow (tr : ETrace) (h : EmitGuardedE tr) :
    emitsPrecededByAllowE tr :=
  fun post b pre heq => emitGuardedE_split post b pre (heq ▸ h)

theorem emitGuardedE_append_emits (l : List SealV2.CanonicalBytes)
    (tr : ETrace)
    (h : ∀ b ∈ l, ∃ raw, EEv.decideEv raw (SealV2.Decision.Allow b) ∈ tr)
    (htr : EmitGuardedE tr) : EmitGuardedE (l.map EEv.emitEv ++ tr) := by
  induction l with
  | nil => simpa using htr
  | cons b bs ih =>
    refine ⟨?_, ih (fun b' hb' => h b' (List.mem_cons_of_mem _ hb'))⟩
    obtain ⟨raw, hmem⟩ := h b List.mem_cons_self
    exact ⟨raw, List.mem_append_right _ hmem⟩

/-- The license invariant and emit-guardedness survive every extended step,
    given the step-local obligations — the P5 block emission and the P6
    relay touch neither the adapter state nor the emission obligations. -/
theorem erun_emitGuarded (A : Adapter)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String)
    (hO1 : O1 A) (hO2 : O2 A) :
    ∀ (inputs : List EIn) (s : A.St × ETrace),
      (∀ p ∈ A.licensed s.1,
        EEv.decideEv p.1 (SealV2.Decision.Allow p.2) ∈ s.2) →
      EmitGuardedE s.2 →
      (∀ p ∈ A.licensed (inputs.foldl (estep A gate author) s).1,
        EEv.decideEv p.1 (SealV2.Decision.Allow p.2)
          ∈ (inputs.foldl (estep A gate author) s).2) ∧
      EmitGuardedE (inputs.foldl (estep A gate author) s).2 := by
  intro inputs
  induction inputs with
  | nil => intro s h1 h2; exact ⟨h1, h2⟩
  | cons i rest ih =>
    intro s h1 h2
    rw [List.foldl_cons]
    cases i with
    | childOut c =>
      apply ih
      · intro p hp
        exact List.mem_cons_of_mem _ (h1 p hp)
      · show EmitGuardedE (EEv.relayEv c :: s.2)
        exact h2
    | clientLine line =>
      cases h : Host.classifyLine line with
      | passthrough =>
        have hstep : (estep A gate author s (EIn.clientLine line))
            = (s.1, EEv.fwdEv line :: s.2) := by simp [estep, h]
        rw [hstep]
        apply ih
        · intro p hp
          exact List.mem_cons_of_mem _ (h1 p hp)
        · exact h2
      | refuse =>
        have hstep : (estep A gate author s (EIn.clientLine line))
            = (s.1, EEv.refuseEv line :: s.2) := by simp [estep, h]
        rw [hstep]
        apply ih
        · intro p hp
          exact List.mem_cons_of_mem _ (h1 p hp)
        · exact h2
      | act a =>
        cases hg : gate line with
        | Allow out =>
          have hstep : (estep A gate author s (EIn.clientLine line))
              = (A.onVerdict s.1 line (.Allow out),
                  ((A.emitsOn (A.onVerdict s.1 line (.Allow out))).map
                    EEv.emitEv)
                    ++ EEv.decideEv line (.Allow out) :: s.2) := by
            simp [estep, h, hg]
          rw [hstep]
          apply ih
          · intro p hp
            rcases hO2.2 s.1 line (.Allow out) p hp with hold | ⟨o, ho, rfl⟩
            · exact List.mem_append_right _
                (List.mem_cons_of_mem _ (h1 p hold))
            · injection ho with ho'
              subst ho'
              exact List.mem_append_right _ List.mem_cons_self
          · apply emitGuardedE_append_emits
            · intro b hb
              obtain ⟨raw', hlic⟩ :=
                hO1 (A.onVerdict s.1 line (.Allow out)) b hb
              rcases hO2.2 s.1 line (.Allow out) (raw', b) hlic with
                hold | ⟨o, ho, hpair⟩
              · exact ⟨raw', List.mem_cons_of_mem _ (h1 _ hold)⟩
              · have hb2 : b = o := congrArg Prod.snd hpair
                injection ho with ho'
                refine ⟨line, ?_⟩
                rw [hb2, ho']
                exact List.mem_cons_self
            · exact h2
        | Block =>
          have hstep : (estep A gate author s (EIn.clientLine line))
              = (A.onVerdict s.1 line .Block,
                  ((A.emitsOn (A.onVerdict s.1 line .Block)).map EEv.emitEv)
                    ++ EEv.blockEv line (author a)
                      :: EEv.decideEv line SealV2.Decision.Block :: s.2) := by
            simp [estep, h, hg]
          rw [hstep]
          apply ih
          · intro p hp
            rcases hO2.2 s.1 line .Block p hp with hold | ⟨o, ho, -⟩
            · exact List.mem_append_right _
                (List.mem_cons_of_mem _ (List.mem_cons_of_mem _ (h1 p hold)))
            · cases ho
          · apply emitGuardedE_append_emits
            · intro b hb
              obtain ⟨raw', hlic⟩ := hO1 (A.onVerdict s.1 line .Block) b hb
              rcases hO2.2 s.1 line .Block (raw', b) hlic with
                hold | ⟨o, ho, -⟩
              · exact ⟨raw', List.mem_cons_of_mem _
                  (List.mem_cons_of_mem _ (h1 _ hold))⟩
              · cases ho
            · exact h2

/-- **The salvage.** Any O1∧O2 adapter keeps gated-sink mediation on every
    EXTENDED run, at every gate and author: emissions are Allow-preceded.
    The egress widening breaks nothing at the child-input sink. -/
theorem egress_gated_sink_non_bypass (A : Adapter)
    (hO1 : O1 A) (hO2 : O2 A)
    (gate : SealV2.RawBytes → SealV2.Decision)
    (author : CanonicalAction → String) (inputs : List EIn) :
    emitsPrecededByAllowE (erun A gate author inputs).2 := by
  have h := erun_emitGuarded A gate author hO1 hO2 inputs (A.init, [])
    (fun p hp => nomatch (hO2.1 ▸ hp)) trivial
  exact emitGuardedE_precededByAllow _ h.2

/-- The salvage at the deployed model and the live gate. -/
theorem egress_gated_sink_survives (state : SealV2.ApprovalState)
    (author : CanonicalAction → String) (inputs : List EIn) :
    emitsPrecededByAllowE
      (erun sealAdapter (fun raw => SealV2.decide raw state)
        author inputs).2 :=
  egress_gated_sink_non_bypass sealAdapter sealAdapter_O1 sealAdapter_O2
    _ author inputs

/-! ## P8/P9 — evidence is a gate-state input, not an emission seam

Approvals (P8, via A3) and votes/grants/forecasts (P9) reach the model ONLY
through the approval state the gate closes over. Non-bypass is universally
quantified over that state, so NO evidence value — well-formed, malformed,
adversarial — can open an unmediated emission path in the model. Stated as
named corollaries so the coverage is a theorem, not an inference the reader
must make. What this does NOT prove: the Rust fail-closed direction ("parse
failure drops the record ⇒ deny") — provider code, TCB. -/

/-- P8/P9 at the gated sink (the W2-T6.1 alphabet): for EVERY evidence type,
    EVERY parse function and EVERY evidence value, the gated sink mediates
    every action — evidence influences verdicts, never the need for one. -/
theorem gatedSink_non_bypass_evidence_universal {E : Type}
    (parseEvidence : E → SealV2.ApprovalState) (ev : E)
    (inputs : List SealV2.RawBytes) :
    precededByAllow
      (run gatedSinkAdapter
        (fun raw => SealV2.decide raw (parseEvidence ev)) inputs).2 :=
  gatedSink_preserves_non_bypass (parseEvidence ev) inputs

/-- P8/P9 over the EXTENDED alphabet: same universality on extended runs at
    the deployed model. -/
theorem egress_gated_sink_evidence_universal {E : Type}
    (parseEvidence : E → SealV2.ApprovalState) (ev : E)
    (author : CanonicalAction → String) (inputs : List EIn) :
    emitsPrecededByAllowE
      (erun sealAdapter
        (fun raw => SealV2.decide raw (parseEvidence ev)) author inputs).2 :=
  egress_gated_sink_survives (parseEvidence ev) author inputs

/-! ## Non-vacuity

The P5 capstone would be vacuous at an alphabet in which `blockEv` never
occurs, and the salvage at one in which `emitEv` never occurs. Both are
ruled out. `Lean.Json.parse` is `partial`, so the kernel cannot evaluate a
concrete classification: the concrete runs are compiler-evaluated `#guard`s
and the ∃-witnesses are conditional on the classification — the witness
discipline of `Host/PassthroughPerimeter.lean`, unchanged. -/

/-- A constant-allow test gate (no string comparison). -/
def allowGate : SealV2.RawBytes → SealV2.Decision := fun _ => .Allow "OK"

/-- Test author: names the classified tool, so the `#guard`s can pin that
    the emitted block bytes came from the AUTHOR, not the gate or adapter. -/
def testAuthor : CanonicalAction → String := fun a => "BLOCKED:" ++ a.tool

/-- **Non-vacuity of the P5 capstone**, conditional on the classification:
    any act-classified line yields a run whose trace contains an ACTUAL
    client-bound block emission (concrete membership pinned by the `#guard`s
    below). Not the degenerate never-blocking alphabet. -/
theorem egress_block_nonvacuous_of_act (line : String) (a : CanonicalAction)
    (h : Host.classifyLine line = .act a) :
    ∃ (gate : SealV2.RawBytes → SealV2.Decision)
      (author : CanonicalAction → String) (b : String),
      EEv.blockEv line b
        ∈ (erun sealAdapter gate author [EIn.clientLine line]).2 := by
  refine ⟨blockGate, testAuthor, testAuthor a, ?_⟩
  rw [erun_single_act_block blockGate testAuthor line a h rfl]
  exact List.mem_cons_self

/-- **Non-vacuity of the salvage**, conditional on the classification: any
    act-classified line yields an extended run with an ACTUAL gated-sink
    emission that is also licensed. Not the always-deny adapter. -/
theorem egress_emit_nonvacuous_of_act (line : String) (a : CanonicalAction)
    (h : Host.classifyLine line = .act a) :
    ∃ (gate : SealV2.RawBytes → SealV2.Decision)
      (author : CanonicalAction → String) (out : SealV2.CanonicalBytes),
      EEv.emitEv out
        ∈ (erun sealAdapter gate author [EIn.clientLine line]).2 ∧
      ∃ raw, (raw, out) ∈ sealAdapter.licensed
        (erun sealAdapter gate author [EIn.clientLine line]).1 := by
  refine ⟨allowGate, testAuthor, "OK", ?_, line, ?_⟩
  · rw [erun_single_act_allow allowGate testAuthor line a "OK" h rfl]
    exact List.mem_cons_self
  · show (line, "OK") ∈ (erun sealAdapter allowGate testAuthor
      [EIn.clientLine line]).1.1
    simp [erun, estep, h, allowGate, sealAdapter]

-- Concrete runs, compiler-evaluated (the build goes red if any is wrong).
-- The blocked act-line: P5 fires with AUTHOR bytes, after its decide, and
-- nothing is child-bound:
#guard (erun sealAdapter blockGate testAuthor
    [EIn.clientLine mediatedWitness]).2
  == [EEv.blockEv mediatedWitness "BLOCKED:read_file",
      EEv.decideEv mediatedWitness SealV2.Decision.Block]
-- The allowed act-line: the gated sink emits, no P5 block response:
#guard (erun sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness]).2
  == [EEv.emitEv "OK",
      EEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK")]
-- A child frame: relayed verbatim, zero decisions (P6):
#guard (erun sealAdapter allowMediatedGate testAuthor
    [EIn.childOut "{\"result\":1}"]).2
  == [EEv.relayEv "{\"result\":1}"]
-- The full interleaving — mediated allow, verbatim relay, P1 escape,
-- pre-parse refusal — each transition landing in its own class:
#guard (erun sealAdapter allowMediatedGate testAuthor
    [EIn.clientLine mediatedWitness, EIn.childOut "{\"result\":1}",
     EIn.clientLine malformedWitness,
     EIn.clientLine monsterExponentWitness]).2
  == [EEv.refuseEv monsterExponentWitness,
      EEv.fwdEv malformedWitness,
      EEv.relayEv "{\"result\":1}",
      EEv.emitEv "OK",
      EEv.decideEv mediatedWitness (SealV2.Decision.Allow "OK")]

/-! ## Axiom pins

Classical baseline `[propext, Classical.choice, Quot.sound]` or tighter —
no `sorryAx`, no `native_decide`, no custom axiom. `#guard_msgs`-pinned so
drift fails the build here. -/

/-- info: 'Host.Egress.erun_single_relay' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_single_relay
/-- info: 'Host.Egress.erun_single_passthrough' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_single_passthrough
/-- info: 'Host.Egress.erun_single_refuse' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_single_refuse
/-- info: 'Host.Egress.erun_single_act_allow' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_single_act_allow
/-- info: 'Host.Egress.erun_single_act_block' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_single_act_block
/-- info: 'Host.Egress.estep_client_block_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms estep_client_block_mem
/-- info: 'Host.Egress.estep_child_block_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms estep_child_block_mem
/-- info: 'Host.Egress.estep_client_relay_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms estep_client_relay_mem
/-- info: 'Host.Egress.estep_child_relay_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms estep_child_relay_mem
/-- info: 'Host.Egress.erun_from_block_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_from_block_mem
/-- info: 'Host.Egress.erun_from_relay_mem' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_from_relay_mem
/-- info: 'Host.Egress.erun_block_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_block_iff
/-- info: 'Host.Egress.erun_block_authored' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_block_authored
/-- info: 'Host.Egress.erun_relay_iff' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_relay_iff
/-- info: 'Host.Egress.blockGuarded_split' does not depend on any axioms -/
#guard_msgs in #print axioms blockGuarded_split
/-- info: 'Host.Egress.blockGuarded_blocksPreceded' does not depend on any axioms -/
#guard_msgs in #print axioms blockGuarded_blocksPreceded
/-- info: 'Host.Egress.blockGuarded_append_emits' does not depend on any axioms -/
#guard_msgs in #print axioms blockGuarded_append_emits
/-- info: 'Host.Egress.erun_blockGuarded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_blockGuarded
/-- info: 'Host.Egress.client_block_mediated' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms client_block_mediated
/-- info: 'Host.Egress.client_block_mediated_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms client_block_mediated_live
/-- info: 'Host.Egress.relay_non_bypass_fails' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms relay_non_bypass_fails
/-- info: 'Host.Egress.relay_non_bypass_fails_live' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms relay_non_bypass_fails_live
/-- info: 'Host.Egress.emitGuardedE_split' does not depend on any axioms -/
#guard_msgs in #print axioms emitGuardedE_split
/-- info: 'Host.Egress.emitGuardedE_precededByAllow' does not depend on any axioms -/
#guard_msgs in #print axioms emitGuardedE_precededByAllow
/-- info: 'Host.Egress.emitGuardedE_append_emits' does not depend on any axioms -/
#guard_msgs in #print axioms emitGuardedE_append_emits
/-- info: 'Host.Egress.erun_emitGuarded' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms erun_emitGuarded
/-- info: 'Host.Egress.egress_gated_sink_non_bypass' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms egress_gated_sink_non_bypass
/-- info: 'Host.Egress.egress_gated_sink_survives' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms egress_gated_sink_survives
/-- info: 'Host.Egress.gatedSink_non_bypass_evidence_universal' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms gatedSink_non_bypass_evidence_universal
/-- info: 'Host.Egress.egress_gated_sink_evidence_universal' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms egress_gated_sink_evidence_universal
/-- info: 'Host.Egress.egress_block_nonvacuous_of_act' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms egress_block_nonvacuous_of_act
/-- info: 'Host.Egress.egress_emit_nonvacuous_of_act' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms egress_emit_nonvacuous_of_act

end Host.Egress
