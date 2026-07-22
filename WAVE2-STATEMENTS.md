# WAVE 2 — Frozen statements (reviewable batch, Day 1)

Six targets, frozen BEFORE any proof. Conclusions are locked; only hypothesis
plumbing (config record shapes, instance arguments) may adjust during proofs —
never conclusions. Each entry: frozen statement bound to live symbols,
subsumption verdict against the landed L0/L1 stack, trust boundary, and the
non-vacuity plan.

**Labeling.** Targets are `W2-T1 … W2-T6`. The repo's TCB ledger
(`docs/SEAL-SYSTEM-TCB.md`) already uses bare T-numbers for *trusted
assumptions* (its T6 = wall clock + `a3.rs`); wave labels always carry the
`W2-` prefix to avoid collision.

**Build bar (all targets).** Green `lake build`; axioms exactly
`[propext, Classical.choice, Quot.sound]`; zero `sorry`; zero `native_decide`
(pulls `Lean.ofReduceBool`); per-theorem pinned `#guard_msgs in #print axioms`
transcript (Test/Axioms.lean convention — drift fails the build via the
`axiom_check` exe); witnessed non-vacuity per the conventions of
`Host/CanonicalL0.lean:116-150`.

**Build wiring.** Bare `lake build` builds only the `Host.Main` and
`Test.Axioms` import closures (`defaultTargets = ["seal-host", "axiom_check"]`)
— `Host/CanonicalL0*.lean` today builds only under `lake build Ffi`. Every new
Wave-2 module is therefore imported from `Test/Axioms.lean` (where its pins
live anyway): `axiom_check` is both the axiom gate and the build wire. New
modules are NOT added to the `Host.lean`/`Kernels.lean` roots (that would drag
them — and for W2-T4, Mathlib elaboration — into the FFI exe closures).

**Verdict summary.**

| ID | Target | Verdict |
|---|---|---|
| W2-T1 | Record freshness (monotone clock + nonce over L1) | NOVEL; chain spine inherited |
| W2-T2 | Consensus on canonical bytes | NOVEL residual; agreement machinery inherited |
| W2-T3 | Safety residual | CONTENT SUBSUMED, statements absent — two thin corollaries; decidability skipped |
| W2-T4 | Convergence potential | NOVEL, bounded scope |
| W2-T5 | parityN achievable with N heads | **FALSE — refuted by exhaustive search; replacement frozen** |
| W2-T6 | `channel_preserves_non_bypass` | NOVEL capstone; model authored fresh |

---

## W2-T1 — Temporal record freshness (priority 1)

**File:** `Host/RecordTemporal.lean` (new).

**Subsumption check result.** The L1 log (`Host.Record.Log :=
List String`, `Host/Record.lean:32`) has NO index-, epoch-, or
clock-monotonicity theorem; `auditLine` carries an `epoch : Nat`
(`Host/Audit.lean:12`) but nothing proves anything about it. Append-only
(`head_after_append`, `Host/Record.lean:45`, definitional) and tamper-evidence
(`tamper_evident`, `Host/Record.lean:55`, under A-CR + A-GEN) are inherited as
technique and re-instantiated at timed-entry granularity (the same 10-line
induction over a hash `H : Hash → TimedEntry → Hash` with assumptions A-CR-T /
A-GEN-T — same class as the landed A-CR/A-GEN). Everything about clocks,
freshness bounds, and nonces is NOVEL: no nonce exists anywhere in the Lean
model (freshness/nonce/TTL is explicitly TCB, `Ffi.lean:17`, rust `a3.rs`).

**Frozen definitions.**

```lean
structure TimedEntry where
  payload : String   -- the auditLine payload for one mediated decision
  clock   : Nat      -- producing step's logical-clock reading
  nonce   : Nat

abbrev TimedLog := List TimedEntry   -- most-recent-first, mirrors Host.Record.Log

def latestClock : TimedLog → Nat | [] => 0 | e :: _ => e.clock
def nonces (log : TimedLog) : List Nat := log.map (·.nonce)

def admissible (δ now : Nat) (log : TimedLog) (e : TimedEntry) : Bool :=
  e.clock ≤ now && now ≤ e.clock + δ       -- within δ of the producing step
  && latestClock log ≤ e.clock             -- no clock regression vs the log
  && !(nonces log).contains e.nonce        -- no nonce replay

def admit (δ now : Nat) (log : TimedLog) (e : TimedEntry) : Option TimedLog :=
  if admissible δ now log e then some (e :: log) else none
```

**Frozen conclusions.**

1. `admitted_within_bound` : `admit δ now log e = some log' → e.clock ≤ now ∧ now ≤ e.clock + δ`
2. `stale_clock_inadmissible` : `e.clock + δ < now → admit δ now log e = none`
3. `regressed_clock_inadmissible` : `e.clock < latestClock log → admit δ now log e = none`
4. `replayed_nonce_inadmissible` : `e.nonce ∈ nonces log → admit δ now log e = none`
5. `admit_preserves_clock_mono` : `List.Pairwise (fun a b => b.clock ≤ a.clock)` is preserved by `admit`
6. `admit_preserves_nonce_nodup` : `(nonces log).Nodup` is preserved by `admit`
7. Chain-spine inheritance via rendering: `render enc : TimedLog → Log`
   (`l.map enc`); `timed_head_after_append` (definitional, inherited from
   `head_after_append`) and `timed_tamper_evident` — equal chain heads over
   rendered timed logs force equal timed logs, INHERITED from
   `Host.Record.tamper_evident` under A-CR + A-GEN plus one NEW named
   assumption **A-ENC** (entry-encoder injectivity:
   `∀ e₁ e₂, enc e₁ = enc e₂ → e₁ = e₂`). The deployed JSON encoder
   `TimedEntry.line` ships demonstration-grade with A-ENC undischarged —
   documented verbatim in the style of the FNV-1a honesty note
   (`Host/Record.lean:19-23`).

**Trust boundary (stated loud).** Soundness is relative to a MONOTONE
host/logical clock supplying `now` — NOT wall-clock. Nonce *generation*
(uniqueness at the source) and the clock itself remain TCB, exactly as A3
freshness is TCB in `Ffi.lean:17` / `rust/src/a3.rs`. What the model adds: the
*record-side discipline* — given the host's clock readings, no entry outside
the δ-window, no clock-regressed entry, and no replayed nonce is admissible,
and admissible appends keep the log clock-sorted and nonce-unique.

**Non-vacuity.** `#guard` build-gated exemplars: one admissible admit
succeeds; stale-clock, regressed-clock, and replayed-nonce entries each
rejected. Nat/List kernel evaluation — cheap, no leaf module needed.

---

## W2-T2 — Consensus over canonical bytes (priority 2)

**File:** `Kernels/ConsensusBytes.lean` (new). Deployed kernel untouched.

**Operational semantics (frozen first).**
- A *vote* is `(acceptor : Nat, value : String)` — `Consensus.Checker.Votes`
  (Checker.lean:25). The value string IS the canonical byte string
  (`SealV2.CanonicalBytes := String`, SealV2/Parser.lean:6) — the types agree,
  so `Kernels.quorumAccepts` (Kernels/Consensus.lean:35) applies byte-valued
  with zero new checker code.
- The *agreed value* is `(certFor votes out).value` (Kernels/Consensus.lean:28).
- The *threshold* is strict majority exactly as deployed in
  `Consensus.Checker.validB` (Checker.lean:41: Nodup voters, roster
  membership, matching recorded votes, `members.length < 2 * voters.length`).

**Deployed-kernel caveat (stated loud).** The deployed `consensusKernel` votes
on the TOOL NAME (`quorumAccepts cfg.roster votes act.tool`,
Kernels/Consensus.lean:52 — G3 binding granularity). W2-T2 is a model-level
byte-quorum: a new `consensusBytesKernel` whose votes ratify the canonical
OUTPUT BYTES of the action. Same discipline as the compatible-vs-canonicalL0
profile split: additive, deployed path untouched.

**Frozen conclusions** (hypothesis plumbing may adjust; the three claims —
(i) quorum on byte-identical canonical output, (ii) forwarded bytes = agreed
bytes, (iii) byte-uniqueness of agreement — are locked). Canonical bytes of
the forwarded action: `canonicalBytesOf a := a.ast?.map SealV2.serializeAstValue`
(total on `AST`; for `ast?` populated by `classifyLine` the AST is canonical —
`SealV2.parse_returns_canonical` — so this agrees with the subtype
serializer). Factoring:

```lean
def byteQuorumAccepts (roster) (votes) (bytes : SealV2.CanonicalBytes) : Bool :=
  Consensus.Checker.validB roster votes (certFor votes bytes)

def byteConsensusKernel : Host.Kernel   -- gates high-stakes; fail-closed on
  -- missing canonical witness; allow iff byteQuorumAccepts on canonicalBytesOf

theorem byteConsensus_verdict_allow_iff …   -- mirror of Kernels/Consensus.lean:63

-- (iii) uniqueness
theorem byte_quorum_agreement :
    byteQuorumAccepts roster votes b = true →
    byteQuorumAccepts roster votes b' = true → b = b'

-- (i) + (ii), the seam theorem
theorem forward_high_stakes_byte_quorum
    (hclass : classifyLine line = .act act)
    (hmem : (Kernels.byteConsensusKernel.decide act cfg votes ()).1 ∈ verdicts)
    (hfwd : stepRouteP .canonicalL0 (classifyLine line) verdicts = .forward) :
    ∃ ast, act.ast? = some ast ∧
      SealV2.parse line.trimAscii.toString = some ast ∧
      byteQuorumAccepts cfg.roster votes (SealV2.serializeAstValue ast) = true ∧
      (certFor votes (SealV2.serializeAstValue ast)).value
        = SealV2.serializeAstValue ast

-- (iii) at the seam: two forwarded calls, same roster+votes ⇒ byte-identical payloads
theorem composed_byte_agreement : …
```

(i) via `combine_allow_implies_member` (Host/Composition.lean:67) + the
allow-iff bridge; (ii) definitional from `certFor`; (iii) via
`Consensus.Checker.agreement` (Checker.lean:73). Inherited: `validB`,
`certFor`, `agreement`, the witness-on-forward pattern
(`canonicalL0_witness_on_forward`, Host/CanonicalL0.lean:92),
`classifyLine_act_ast` (CanonicalL0.lean:66). Novel: the byte-valued kernel,
its bridge, the seam theorems.

**Trust boundary.** Vote authenticity/transport is TCB (as for the deployed
kernel: roster is trusted config, votes file is evidence). Scoped to the
`canonicalL0` profile — the deployed `compatible` profile does not gate on
canonical bytes (CLAIMS.md).

**Non-vacuity.** `#guard` exemplars: 2-of-3 roster accepts a byte-string cert;
1-of-3 rejected. If a full-wire exemplar (real `SealV2.parse` evaluation) is
added, it goes in a leaf module (12 GiB convention).

---

## W2-T3 — Safety residual: content subsumed; two thin corollaries

**Verdict: all candidate content is subsumed by the landed L0 stack, but the
gate-extension STATEMENTS are absent — and the naive one is FALSE. Ship two
≤5-line corollaries in `Host/Composition.lean`; skip decidability.**

The subsumption check surfaced one semantically non-obvious fact worth
pinning: naive deny-monotonicity under gate extension does NOT hold —
`combineVerdicts [] = .deny` (fail-closed empty), yet appending a first
allowing kernel yields `.allow`. The `vs ≠ []` side-condition is load-bearing
and is the only new content:

```lean
theorem combine_deny_append (vs ws : List Verdict)
    (hne : vs ≠ []) (hdeny : combineVerdicts vs = .deny) :
    combineVerdicts (vs ++ ws) = .deny
theorem combine_allow_restrict (vs ws : List Verdict)
    (hne : vs ≠ []) (hallow : combineVerdicts (vs ++ ws) = .allow) :
    combineVerdicts vs = .allow
```

Non-vacuity: a live deny-append exemplar plus `combine_extension_from_empty`
(the boundary witness showing why `vs ≠ []` is required). Everything else:

- Default-deny + mediation AT THE MODELLED GATE (model-level; not Anderson/Saltzer
  complete mediation, which quantifies over all access paths to the protected
  objects — see the residuals row in `CLAIMS.md`): `step_forward_non_bypass`
  (Host/Composition.lean:203), `combine_empty_deny` (:33), `combine_allow_iff`
  (:45), `SealCore.default_deny_never_allowed` (SealCore/Safety.lean:8).
- Stability under gate composition: `combine_allow_implies_member` (:67) — no
  kernel's verdict can be overridden; `combine_deny_of_member` (:72) — one
  deny forces composed deny; per-gate survival `composed_non_bypass` (:86),
  `composed_no_conflicting_agreement` (:103), `composed_convergent` (:120),
  `composed_temporal_safety` (:134); jointly
  `and_combinator_preserves_invariants` (:146). Deny-stability under gate
  EXTENSION (`vs ++ ws`) is a one-line instance of `combine_deny_of_member` +
  `List.mem_append_left` — not a theorem's worth of novelty.
- Totality/decidability of the default-deny predicate: `combineVerdicts`,
  `stepRoute`, `stepRouteP` are total computable functions (definitional);
  `VerdictKind` derives `DecidableEq` (Host/Kernel.lean:11), so admission
  equalities are already decidable — a bespoke instance is noise. SKIPPED.

Beyond the two corollaries and their boundary witness, nothing novel survives.

---

## W2-T4 — Convergence potential (priority last, stop-early authorized)

**File:** `Kernels/ConvergencePotential.lean` (new), over crdt-lean's
delivery model.

**Semantics (frozen first).** Dynamics = `Crdt.DeliverySystem`
(crdt-lean Crdt/Liveness.lean:60): finite fixed `allUpdates` (quiescence),
per-replica `delivered r t : Finset S` with `mono` (delivery only
accumulates), `sound` (no phantom updates), `fair` (every update eventually
arrives). The potential (novel — no Lyapunov/potential machinery exists
anywhere in the stack):

```lean
def deficit (sys : Crdt.DeliverySystem ι S) (r : ι) (t : ℕ) : ℕ :=
  (sys.allUpdates \ sys.delivered r t).card
```

**Frozen conclusions.**

1. `deficit_antitone` : `Antitone (deficit sys r)` — the non-increasing Lyapunov
2. `deficit_strict_decrease` : delivering a genuinely new update strictly
   decreases the potential — `t ≤ t' → a ∈ sys.allUpdates →
   a ∉ sys.delivered r t → a ∈ sys.delivered r t' →
   deficit sys r t' < deficit sys r t`
3. `deficit_eq_zero_iff` : `deficit sys r t = 0 ↔ sys.delivered r t = sys.allUpdates`
4. `deficit_eventually_zero` : `∃ T, ∀ t, T ≤ t → deficit sys r t = 0`
   (via `DeliverySystem.converges`, Liveness.lean:78)
5. `deficit_zero_converged` : `deficit sys r t = 0 →
   Crdt.replicaState (sys.delivered r t) = sys.convergedState`

**Honesty note (no overclaim).** The potential is non-increasing along time,
NOT strictly decreasing at every tick — delivery can stall between arrivals.
`DeliverySystem` has no per-event "accepted delivery"; deliveries are a
monotone time-indexed set, so "each accepted delivery strictly decreases V" is
modeled as delivery-of-a-new-update (conclusion 2). Stated as-is.

**Admission tie + trust boundary.** The landed `composed_convergent`
(Host/Composition.lean:120) restricts forwarded ops to `provenConvergentOps`
(Kernels/Convergence.lean:33), whose semantics are the crdt-lean
join-semilattice CRDTs. The binding "kernel-admitted op ↔ model update" is an
interpretation, named here, not a proved refinement. Fairness (`sys.fair`) is
the honest network assumption, asserted not derived (crdt-lean's own
discipline, Liveness.lean:24).

**Non-vacuity.** Concrete `DeliverySystem` over `S := Bool` (join = or):
`allUpdates = {true}`, delivery flips at t = 1; `deficit` steps 1 → 0, checked
by `decide`/`#guard`.

**Stop condition (pre-authorized).** If instance friction or Mathlib gaps
balloon the exemplar or the antitone proof into a dynamics project, stop and
hand back this frozen statement plus whatever compiled.

---

## W2-T5 — `parityN_achievable_with_N_heads`: REFUTED

**Verdict: the statement as briefed is FALSE. Nothing to prove; refutation
evidence below; corrected replacement frozen underneath.**

The target — for all n, an n-head hard-attention network with thresholded
affine readout computes parityN, i.e. the positive complement of
`parityN_requires_N_heads` (attention-lean AttentionLean/ParityN.lean:271) at
k = n — fails already at n = 3.

**Method (model-exact).** A head's score depends only on `(i, xᵢ)`
(`scoreVal` / `attentionScore_eq_scoreVal`, Defs.lean:36-40); the winner is
the max-score live literal with min-index tie-break (`argmaxScore`,
Defs.lean:50); the head output is a threshold of the readout at the winner
(`headOutput`, Defs.lean:63). Hence realizable head outputs are exactly the
"priority functions": fix a priority order on the 2n literals `(i, b)` and an
output bit per literal; the output is the bit of the highest-priority live
literal. (Arbitrary (score, read) pairs are realizable at d = 2; ties reduce
to strict orders under the min-index tie-break.)

**Exhaustive search results** (script: `scripts/parity_head_search.py` in
attention-lean, committed as evidence):

- n = 3: realizable head functions = **96** — exactly the repo's own
  `achievable3Raw` mask count (ParitySmall.lean:37), an independent
  cross-check that the enumerated class is the model's. Against ALL 104
  linear-threshold functions on 3 bits (104 = the known exact count):
  **0 of 152,096** head-triples compute parity3. → 3 heads CANNOT compute
  parity3. `parityN_achievable_with_N_heads` is false.
- n = 2: parity2 IS computable with 2 heads (8 solutions; the AND/OR pair —
  matching the existing `andHead`/`orHead` witnesses, AndOr.lean:33).
- n = 3 with 4 heads: **achievable** (≥50 witnesses; odd-point-indicator
  pattern). Exact head complexity: k(2) = 2, k(3) = 4 — both equal 2^(n−1).

**Why the briefed premise was wrong.** The existing `Parity4*`/`ParitySmall`
"achieve" files are mask enumeration FOR THE LOWER BOUND (which single-head
output masks exist), all `native_decide`-gated; no parity upper bound exists
at any n in the repo. There was nothing to generalize.

**Replacement target (frozen).** `AttentionLean/ParityAchieve.lean`, branch
`feat/parity-achievability`, `native_decide`-free, no `Parity4*` imports:

```lean
noncomputable def indicatorHead (a : Fin n → Bool) : HardAttentionHead n 2
theorem indicatorHead_computes [NeZero n] (a) :
    ∀ x, headOutput (indicatorHead a) x = decide (x = a)
theorem card_odd_points [NeZero n] :
    (Finset.univ.filter fun a : Fin n → Bool => parityN a = true).card = 2^(n-1)
theorem parityN_achievable_with_exp_heads [NeZero n] :
    ∃ (h : Fin (2^(n-1)) → HardAttentionHead n 2) (w : Fin (2^(n-1)) → ℝ) (bias : ℝ),
      ∀ x, (if (∑ i, w i * (if headOutput (h i) x then (1:ℝ) else 0)) + bias > 0
            then true else false) = parityN x
```

Readout shape is verbatim the lower bound's (its positive complement at
k = 2^(n−1)). Construction: one indicator head per odd point (score 1 on
disagreeing literals, 0 on agreeing; `x ≠ a` → argmax at least disagreeing
index, read −1 → false; `x = a` → all-tie, min-index 0, read +1 → true);
`Σ_{a odd} [x = a] > 0 ⟺ parityN x` with unit weights, bias 0.

**Corrected pairing (honest).** Formal: n ≤ k(n) ≤ 2^(n−1) (lower bound
theorem + this construction); exact head complexity of parity2 = 2 fully
formal. Empirical: k(3) = 4 = 2^(n−1); the 3-head impossibility stays script
evidence — Lean-formalizing it needs the banned enumeration substrate.
Conjecture: k(n) = 2^(n−1). NOT claimed as theorem.

---

## W2-T6 — `channel_preserves_non_bypass` (capstone)

**File:** `Host/ChannelModel.lean` (new; NOT named `Channel` —
`Seal.Channel` in the deps is the approval back-channel).

**Symbol binding note.** No symbol named `sealDecide` exists anywhere in the
stack. The binding decide entrypoint for this target is `SealV2.decide :
RawBytes → ApprovalState → Decision` with `Decision = Block | Allow (out :
CanonicalBytes)` (SealV2/Decide.lean:12,17) — the canonical-bytes decision
path. "sealDecide" in the wave brief = `SealV2.decide` here.

**Model (frozen).** Adapter = transition machine with a ghost license buffer;
the gate semantics performs the decide itself (so verdict genuineness is
structural, `run_decide_genuine`), the adapter only reacts. The run semantics
is generic over the gate function `gate : SealV2.RawBytes → SealV2.Decision`
and the shipped capstone instantiates `gate := (SealV2.decide · state)` — the
same generic-core + deploy-instance discipline as
`tamper_evident`/`chainHash` (Host/Record.lean). Forced by kernel-evaluation
economics: a REAL `SealV2.decide … = .Allow …` requires an Ed25519-validated
capability and is not kernel-evaluable, so concrete witnesses run on a cheap
test gate while the shipped theorem binds the live symbol:

```lean
inductive ChanEv where
  | decideEv (raw : SealV2.RawBytes) (d : SealV2.Decision)
  | emitEv   (bytes : SealV2.CanonicalBytes)
abbrev ChanTrace := List ChanEv          -- most-recent-first

structure Adapter where
  St        : Type
  init      : St
  onVerdict : St → SealV2.RawBytes → SealV2.Decision → St
  emitsOn   : St → List SealV2.CanonicalBytes
  licensed  : St → List (SealV2.RawBytes × SealV2.CanonicalBytes)
```

**Obligations (step-local — quantify over single states/transitions only, no
trace quantifiers; this is what keeps the separation non-circular):**

```lean
def O1 (A : Adapter) : Prop :=      -- emissions only from licensed bytes
  ∀ st, ∀ b ∈ A.emitsOn st, ∃ raw, (raw, b) ∈ A.licensed st
def O2 (A : Adapter) : Prop :=      -- licenses never manufactured
  A.licensed A.init = [] ∧
  ∀ st raw d p, p ∈ A.licensed (A.onVerdict st raw d) →
    p ∈ A.licensed st ∨ ∃ out, d = SealV2.Decision.Allow out ∧ p = (raw, out)
-- O3 (emitted bytes = decided canonical bytes) is carried by the licensed
-- PAIR (raw, out): an emit of b licensed by (raw, out) forces b = out.
-- Named as its own corollary in the file so this obligation is pointable.
```

**Frozen conclusion.**

```lean
def precededByAllow (tr : ChanTrace) : Prop :=
  ∀ post b pre, tr = post ++ ChanEv.emitEv b :: pre →
    ∃ raw, ChanEv.decideEv raw (SealV2.Decision.Allow b) ∈ pre

theorem channel_preserves_non_bypass
    (A : Adapter) (hO1 : O1 A) (hO2 : O2 A)
    (state : SealV2.ApprovalState) (inputs : List SealV2.RawBytes) :
    precededByAllow (run A (SealV2.decide · state) inputs).2
```

Proof obligation: induction over `inputs` with the load-bearing invariant
"every licensed pair's Allow-decide event is already in the trace" — the
bridge from step-local obligations to the trace-global existential. Proven
generically over `gate`, instantiated at the live symbol.

**Bonus corollary (frozen).** Composing with `SealV2.non_bypass`
(SealV2/DecideTheorems.lean): `channel_emits_only_validated` — every byte
string a compliant adapter emits is the canonical serialization of a
capability that VALIDATED against the approval state:

```lean
theorem channel_emits_only_validated … :
    ∃ (raw : SealV2.RawBytes) (ast : SealV2.AST),
      SealV2.parse raw = some ast ∧
      ∃ w : SealV2.ValidCapability ast state, bytes = SealV2.serialize ⟨ast, w⟩
```

**Separation (anti-circularity, required).** Obligations mention no traces;
the conclusion quantifies over whole runs. Demonstrated formally by
counterexample adapters, each violating exactly one obligation with the
conclusion provably failing on a concrete run:
- `rogueAdapter` (violates O1): `emitsOn _ = ["EXFIL"]`, `licensed _ = []`;
  run on one cheap garbage input → trace where `precededByAllow` FAILS.
- O2-violator (self-stocked license buffer, no Allow ever) → also fails.
If O1 ∧ O2 turn out to definitionally restate `precededByAllow`, the target is
circular: STOP and report (pre-authorized).

**Witnesses (both required).** Compliant adapter (license list as state,
appends on Allow, emits licensed bytes) — obligations hold near-definitionally
and mediation holds on its runs, exercised on a cheap concrete test gate
(`okGate raw := if raw = "ok" then .Allow "OK" else .Block` — kernel-cheap
String equality; no leaf module needed anywhere in W2-T6). Non-compliant
adapter violating exactly O1 whose run shows `precededByAllow` provably
failing (above). The real-gate forward path is covered by the generic-core
instantiation at `SealV2.decide` plus `channel_emits_only_validated` — not by
kernel evaluation, which Ed25519 validation forbids.

**Trust boundary (stated loud).** This governs the adapter-to-gate composition
IN THE MODEL only. Refinement of the real Rust/host adapter
(`rust/src/main.rs` P1–P6 path inventory; gated sink `child_in.write_all`) is
a separate conformance-bridge job — named future work, not claimed. The
canonical-bytes clause aligns with the `SealV2.decide`/canonicalL0 path; the
deployed profile is `compatible` and does not gate on canonical bytes
(CLAIMS.md caveat repeated verbatim).

---

## Execution order

1. this freeze (commit) → 2. W2-T1 (highest priority; first green target
bounces back for review) → 3. W2-T3 corollaries (thin) → 4. W2-T2 →
5. W2-T6 capstone → 6. W2-T5 replacement (attention-lean, parallel-capable)
→ 7. W2-T4 (lowest, stop-early authorized). Each target = one commit: module
+ Test/Axioms.lean pins + CLAIMS.md row, `lake build` green per commit. Also
fixed in this wave: the stale CLAIMS.md canonical-l0 row ("SPEC ONLY" vs the
landed `Host/CanonicalL0.lean`).

## Change-log

Statements above are FROZEN as of this commit. Any post-freeze edit requires a
dated entry here with rationale — conclusions never drift silently.

| date | target | change | why |
|---|---|---|---|
| 2026-07-03 | all | initial freeze | Day-1 batch |
| 2026-07-03 | W2-T1 | `admissible` replay conjunct written `decide (e.nonce ∉ nonces log)` instead of `!(nonces log).contains e.nonce` | proof plumbing (uniform `decide` conjuncts, no BEq lemmas); semantically identical; conclusions unchanged |
| 2026-07-03 | all | EXECUTED: T1 5b4e9f5, T3 cb2be14, T2 56d5c78, T6 7cc9370, T4 e0cc621 (seal-host feat/wave2); T5 replacement ff12a65 (attention-lean feat/parity-achievability). All frozen conclusions shipped verbatim; T4 done before T5 (order swap only, both landed); T4 stop-early never triggered | wave complete |
| 2026-07-03 | W2-T1 hardening | FROZEN (additive, `Host/RecordTemporalCanonical.lean`): (1) `TimedEntry.encCanonical : TimedEntry → String` — length-prefixed, delimiter-safe canonical encoder (decimal digit blocks via `Nat.digits`, `'\|'` separators; payload extent pinned by its length prefix, so payload bytes may contain the separator freely); (2) `TimedEntry.encCanonical_injective : Function.Injective TimedEntry.encCanonical` — pure Lean, no crypto; (3) `timed_tamper_evident_canonical` — `timed_tamper_evident` instantiated at `encCanonical`, SAME conclusion, assumptions EXACTLY A-CR + A-GEN (A-ENC discharged, no encoder side-condition). `TimedEntry.line` untouched, stays demonstration-grade | discharge A-ENC — the only non-crypto assumption in T1's chain inheritance |
| 2026-07-04 | W2-T6.1 | FROZEN + PROVED (additive, `Host/SealAdapter.lean`): `sealAdapter` — a Lean model of the DEPLOYED routing core (`rust/src/main.rs` gated-sink discipline) — discharges the capstone's O1/O2 at the deployed adapter (`sealAdapter_O1`, `sealAdapter_O2`); `sealAdapter_trace` instantiates `channel_preserves_non_bypass` with both hypotheses discharged, so mediation holds unconditionally on every run at the live gate. MODEL-level discharge only; the `rust/` ↔ model byte-level refinement remains named future work | close the W2-T6 named gap — no adapter modelling the DEPLOYED routing core had been proven O1/O2-compliant |
