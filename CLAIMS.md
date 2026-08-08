<!-- SPDX-License-Identifier: Apache-2.0 -->
# seal-host: claims map

Single source of truth for what this repo proves, what it merely runs, and what
it must never claim. Scoped to `seal-host` (the multi-kernel fail-closed host).
Sibling maps: `mcp-seal-dev/CLAIMS.md` (v2 canonical core). Nothing in any
demo, README, or pitch may exceed a row marked "can say publicly = yes".

## The one line

> Policy-covered, unapproved request-effects cannot execute through the
> mediated MCP boundary.

NOT: "the agent is safe" / "the whole stack is verified" / "theorems cannot be
bypassed."

## Profiles

The host runs a **profile**. This is load-bearing for every claim below.

| Profile | Canonical-reject `tools/call` | Forward carries | Status |
|---|---|---|---|
| `compatible` (this repo, today) | mediated on the V1 `Lean.Json` view, `ast? = none`, audit-only | V1 route decision | IMPLEMENTED (`Host/Canonical.lean`) |
| `canonical-l0` | BLOCKS | canonical parse witness | IMPLEMENTED AT THE PROOF LAYER (`Host/CanonicalL0.lean`: `stepRouteP .canonicalL0`, reject-on-parse-failure + witness-on-forward proven); NOT the deployed routing path (`Ffi.stepImpl` still runs `compatible`) |

Do not describe the deployed host as strict canonical-l0. It is `compatible`.
The canonical AST is audit input for kernels, not the mediation gate.

## Claims matrix

| Claim | Artifact | Proof status | Trusted assumptions | Known residuals | Say publicly? |
|---|---|---|---|---|---|
| Registry denies if no kernel gates the call; allows only if every gating kernel allows | `Host/Registry.lean` composition theorem | Lean theorem | Lean kernel/runtime | none | yes |
| Fail-closed AND-composition preserves headline invariants (safety non-bypass, consensus agreement) | composition theorem | Lean theorem | as above | scoped to registered kernels | yes |
| `Forward` is unconstructible without an exact kernel verdict | Rust bridge type | Rust type-level | Rust type soundness | none | yes |
| Lean-panic fail-open risk is closed | abort-on-panic in `rust/` | code + test | abort semantics | none | yes |
| **Conditional single-link non-bypass (deployed `compatible` profile):** whenever this host writes to its spawned child's stdin a line that `Host.classifyLine` recognised as an MCP `tools/call`, that same judged line previously produced an exactly parsed `route: "forward"` result; in the pure Lean routing core a forward implies a non-empty gating-verdict list with EVERY gating verdict Allow (`step_forward_non_bypass`). Inputs refused by framing, resource, UTF-8, envelope, unsafe-number or seam checks never reach the child and need NOT receive a kernel policy decision (fail-closed). A6 closed for the signed-token production channel by the durable Rust replay store | `step_forward_non_bypass` (Lean, pure routing core); `rust/src/route.rs` `Route::Forward` construction and the single `write_child` sink (Rust structure + tests) | mixed: Lean proves the route implication; Rust structure plus differential tests tie that route to the child sink; model-to-binary correspondence is TESTED, NOT PROVED | A1 channel exclusivity; **A2 full per-server translation/parser-equivalence** (not merely malformed or mis-spelled methods: two nominally strict parsers may disagree on duplicate members, numeric precision, argument defaults, Unicode or tool semantics, so the theorem can hold of the host's parsed event while the child executes a different one). **MEASURED unjudged-sibling class (scope of “judged event”):** `Seal.toolsCall?` reads exactly `params.name` and `params.arguments` (`.lake/packages/mcp-seal/Seal/Classify.lean:278-288`); every other member of `params` is unseen by policy matching and every kernel verdict and, on a forward, is sent to the child verbatim through the gated `write_child` sink (`rust/src/main.rs:527`, `:1559`). The six probe lines in `docs/A2-UNJUDGED-SIBLING-EVIDENCE.md` passed all seven pre-parse guards. Each forwarded witness still produced an exactly parsed `route: "forward"` with a non-empty gating-verdict list and EVERY gating verdict Allow, so `step_forward_non_bypass` holds of the judged event; the child received a strict superset. The documented `canonical_request_sha256` projection and receipt filename did not distinguish all six wire lines, but `request_sha256` and `framed_subject_sha256` did; nothing was overwritten, byte commitment is intact, and this is not a receipt-integrity failure. A3-A4; policy/classifier completeness (`THREAT_MODEL.md:50-60`); trusted-origin inputs — config, approval keys, votes, grants, clock, OS permissions (`THREAT_MODEL.md:62-73`, `:95-104`); operator startup authority over which child is spawned (`RUST_BRIDGE.md:38`, `:141`); line framing, Rust transport, FFI, compiler/runtime and model-to-binary correspondence (`RUST_BRIDGE.md:127-155`, `TCB.md`); Rust replay-store TCB. **The absence of bypass paths is an ASSUMPTION, not an enforced property.** | Non-mediated or unmediated routes, documented across `THREAT_MODEL.md`, `RUST_BRIDGE.md`, `TCB.md` and source (NOT all in one file): direct shell/network (`THREAT_MODEL.md:75-79`); alternate MCP configs or endpoints; cached tool handles; in-process orchestrator calls; spawned subprocesses AND autonomous/background/scheduled child effects not surfaced as MCP calls (`THREAT_MODEL.md:75-79`); non-`tools/call` methods (`Host/Canonical.lean:24`, `rust/src/main.rs:1331-1349`); strict-monitor/lenient-child passthrough (`RUST_BRIDGE.md:18-24`, `Host/Canonical.lean:55-60`); response egress relayed verbatim (`TCB.md:78-83`); health/readiness ingress, a separately tested network surface outside the Lean mediation proof (`THREAT_MODEL.md:23-26`, `RUST_BRIDGE.md:44`); legacy control-file channel cross-restart replay, demo-only | yes (verbatim only) |
| W2-T4: convergence potential (MODEL): the undelivered-update count is a Lyapunov function over crdt-lean's `DeliverySystem`: non-increasing, strictly decreased by each delivery of a new update, zero exactly at full delivery, zero ⇒ replica state = converged state, eventually zero under fairness + quiescence | `Kernels/ConvergencePotential.lean` | Lean theorem | fairness + quiescence are `DeliverySystem` hypotheses (asserted network assumptions); kernel-op ↔ model-update binding is interpretive via `composed_convergent` | model-level; per-event acceptance modeled as delivery-of-new-update | yes, "model-level, conditional on fairness" mandatory |
| W2-T6: channel non-bypass (MODEL): any adapter trace meeting step-local obligations O1 (emit only licensed bytes) ∧ O2 (no manufactured licenses) ∧ O3 (byte fidelity via license pairs) mediates every action: each emission has a strictly earlier decide event returning Allow of byte-identical output; at gate = `SealV2.decide`, emitted bytes are kernel-defined serializations of VALIDATED capabilities; rogue (O1-violating) and forger (O2-violating) adapters witnessed failing | `Host/ChannelModel.lean` | Lean theorem | model-level: Rust adapter compliance with O1-O3 is TCB until refined (named future work); gate clause aligned with `SealV2.decide`, not the deployed `compatible` profile | Rust refinement of `rust/` against O1-O3 = named future work | yes, "model-level" mandatory |
| W2-T6.1: seal adapter conformance (MODEL): `sealAdapter`, a Lean model of the DEPLOYED routing core (mirroring `rust/src/main.rs`'s gated-sink discipline), DISCHARGES the capstone's O1/O2 hypotheses (`sealAdapter_O1`, `sealAdapter_O2`), so `channel_preserves_non_bypass` holds unconditionally at it (`sealAdapter_trace`): every emission is preceded strictly earlier by an Allow decide of byte-identical output. Closes the W2-T6 gap that no adapter modelling the deployed core had been proven compliant | `Host/SealAdapter.lean` | Lean theorem | model-level: the byte-level refinement `rust/` ↔ `sealAdapter` (that the compiled binary implements the model's transition discipline) stays TCB, named future work; wall clock + approval providers stay TCB | binary refinement `rust/` ↔ model = named future work; deployed profile still `compatible` (not canonical-l0) | yes, "model-level discharge; binary refinement still future" mandatory |
| W2 closeout: single-request non-interference: for one request, the decision and audit record reveal nothing about `ApprovalState` beyond `authView raw`; landed theorem names are `decide_authView_noninterference`, `record_authView_noninterference`, and `observe_noninterference`, with `authView_noninterference_nonvacuous` as the witness | `Host/NonInterference.lean` | Lean theorem | controlled declassification of exactly the authorization bit; per-kernel verdict strings are LOW host inputs | timing channels and timed logs out of scope; no multi-request secrecy claim | yes, "single request / authView only" mandatory |
| W2 closeout: replay isolation: under a fixed per-request state, stores equal on the observer session's projection produce the same decision trace and preserve that projection; landed theorem names include `store_lowEq_step`, `replay_isolation_trace`, `replay_isolation_nonvacuous`, and `listReplayStore_namespaceLocal` | `Host/ReplayIsolation.lean` | Lean theorem | fixed `ApprovalState`; durable-store seam modeled as a list store | does not prove cross-restart durability or two-state non-interference composition | yes, with fixed-state caveat |
| W2 closeout: gated-sink adapter by name: `gatedSinkAdapter` aliases the `sealAdapter` model and discharges O1/O2 at the gated-sink name (`gatedSink_O1`, `gatedSink_O2`); `gatedSink_preserves_non_bypass` gives the capstone, `gatedSink_nonvacuous` rules out vacuous always-deny, and live-Allow hypothesis forms pin emitted/licensed bytes. RENAMED from `deployedAdapter` (K3): the alias covers only the gated child-input sink (P2 forward, P3 retry), NOT P1 passthrough or P4/P5/P6/P7–P9, so "deployed" is not earned | `Host/GatedSinkAdapter.lean` | Lean theorem | model-level; binary correspondence is tested by the conformance bridge, not proven; ranges over the GATED-SINK alphabet only | Rust/source/binary refinement remains TCB; deployed profile remains `compatible`; P1 passthrough is a bypass (next row), P4/P5/P6/P7–P9 uncovered | yes, "gated-sink alphabet only; name states scope" mandatory |
| K4 passthrough perimeter (MODEL): the widened seam alphabet (`Host/PassthroughPerimeter.lean`) includes the P1 classify-passthrough transition the W2-T6 model excluded. Byte classes `inPerimeter` (S), `refusedClass` (R), `escapes` are decidable predicates on the input bytes, stated independently of the adapter; the deployed `Host.classifyLine` realises them EXACTLY (`classifyLine_act_iff`/`_refuse_iff`/`_passthrough_iff`). Characterisation `mediation_perimeter`: a line is gate-decided IFF it lies in S, forwarded-undecided IFF it escapes. Non-bypass FAILS over the widened alphabet (`widened_non_bypass_fails`/`_live`) for every escaping line — malformed JSON, BOM-prefixed JSON, `"TOOLS/CALL"`, JSON-RPC batch array — this is the honest verdict; the gated sink survives (`wchannel_gated_sink_non_bypass`) | `Host/PassthroughPerimeter.lean` | Lean theorem + runnable control (`Test.PerimeterProbe`) | model-level: the child's own parser strictness (A-strict-child) is an ASSUMPTION, not proven — the perimeter bounds the HOST, not the child; a lenient child executing an escaping line is outside the contract | S excludes top-level arrays BY CONSTRUCTION (`toolsCallShape_arr`); duplicate-key mediation/execution differential and the un-wired strict `canonicalL0` profile (`Host/CanonicalL0.lean`) remain uncovered | yes, "model-level; non-bypass FAILS over P1; child strictness assumed" mandatory |
| K5 egress perimeter (MODEL): the seam alphabet widened again (`Host/EgressPerimeter.lean`) to the two client-bound egress transitions of the deployed P1–P9 table (`rust/src/main.rs:13-21`). P5 kernel-block egress is MEDIATED for CLIENT-BOUND BLOCK EMISSIONS ONLY: each such emission is preceded strictly earlier by a `Block` decide of the same line, for every adapter and gate (`client_block_mediated`/`_live`), and its bytes are exactly the fixed author function of the classified action, never gate- or adapter-chosen (`erun_block_iff`/`erun_block_authored`). This property does not cover arbitrary adapter `emitEv`s or forwarded events; its lack of an O1/O2 hypothesis reflects that narrower scope, not a stronger adapter result. P6 has a machine-checked negative witness: there exists a singleton relayed-frame ABSTRACT-MACHINE run with no prior decision (`relay_non_bypass_fails`/`_live`), and relay is verbatim input-copying independent of gate/adapter/author (`erun_relay_iff`). This proves abstract-machine reachability, not deployed-Rust reachability. The gated sink survives the widening (`egress_gated_sink_non_bypass`/`_survives`). The P8/P9-named evidence-universal corollaries quantify over an arbitrary parse function; they do NOT establish P8/P9 seam-point coverage. Non-vacuity: `egress_block_nonvacuous_of_act`, `egress_emit_nonvacuous_of_act`, plus compiler-evaluated `#guard` runs (blocked act-line, allowed act-line, verbatim relay, full interleaving) | `Host/EgressPerimeter.lean` | Lean theorem | model-level: the `rust/` ↔ model byte refinement stays the conformance-bridge obligation; the P5 author function abstracts `Seal.blockResponseLine act.requestId (denyReason verdicts)` (the deployed response's byte identity is NOT modelled); refusal-response bytes not modelled (`refuseEv` carries the line only); the P8/P9 fail-closed Rust direction (parse failure ⇒ deny) is provider code, TCB | P4 operator argv is a trust assumption, not a theorem (NO-GO, stated in-module); P7 stderr telemetry not in THIS module's alphabet — it is machine-checked at the MODEL level in the K6 row below (`Host/AuditSeam.lean`), which does not discharge this module's residuals (record content still governed by the NI row; Rust stderr writes still TCB); P8/P9 seam-point coverage is not proved; "deployed" name still NOT earned — P4 remains outside every proven alphabet, and P7's alphabet (K6) is model-level only | yes, "model-level; P5 covers client-bound block emissions only; P6 is abstract-machine reachability; P8/P9 seam coverage is unproved" mandatory |
| K6 audit seam (MODEL): the P7 stderr-telemetry NO-GO, machine-checked at the model level (`Host/AuditSeam.lean`). The egress alphabet is extended with the `audEv` the K5 module calls pointless, telemetry being a fixed function `tel : EEv → List String` of each step's own seam events; the INPUT alphabet is unchanged. Structure: the audit-extended run is exactly the egress run decorated (`arun_eq`), and erasure recovers the egress trace (`arun_erase_eq`) — telemetry is post-processing, not dynamics. `tel` is a run PARAMETER (`arun_tel_parameter`) and every decide is `tel`-invariant (`arun_decide_tel_invariant`), for every adapter, gate, author and input stream. VACUITY, SCOPED: every constraint of the GUARDED form `audGuardedBy` ("a decision stderr FED satisfies C") holds for every predicate C including `C := fun _ _ => False` (`aud_constraint_vacuous`, `aud_constraint_vacuous_false`), because this model makes a telemetry-fed decision impossible (`aud_no_fed_decision`). That is the vacuity of ONE form, NOT of every stderr property: `audEv s ∈ tr → C s` is refuted at `C := False` on the witness run. The audit-mediation negative is PROVED and non-vacuous: strict audit mediation fails under relay-driven telemetry (`aud_non_bypass_fails`/`_live`), the audit line's driving event being itself undecided (the P6 negative propagating), while decide-driven telemetry mediates on every run (`aud_decide_tel_mediated`) — mediation is inherited from the driving event, never created by the widening. The K5 P5 capstone transfers for EVERY telemetry function (`arun_client_block_mediated`/`_live`). Output side, stated as theorems: a reader of stderr holds the telemetry image of the ENTIRE seam trace (`arun_stderr_image`) and nothing beyond it (`aud_provenance`). Axiom pins: classical baseline or tighter, no `sorryAx`, no `native_decide` | `Host/AuditSeam.lean` | Lean theorem, plus compiler-evaluated `#guard` runs (woven placement, silent host, erasure agreement, stderr image of a blocked act-line) | the ONE fidelity input: the deployed host writes stderr and never reads it (child stderr is `Stdio::inherit()`, `rust/src/main.rs:1232`), which enters as the SHAPE of `astep`, not as a theorem; the `rust/` ↔ model refinement stays the conformance-bridge obligation; all K5 parent assumptions | the vacuity is scoped to the `audGuardedBy` form — it is NOT proved that every candidate P7 input-edge property must take that form; NO theorem connects `arun` to the deployed Rust `eprintln!`s, which stay TCB; telemetry-invariance of decisions is a property of THIS model's trace semantics and holds `inputs` FIXED, so a stderr reader whose behaviour changes the future input stream is not modelled (the `--channel interactive` operator loop is exactly such a path and re-enters only as gate state, the P8 row); stderr lines not driven by seam events (startup config rejections, `validate` mode, A3 dropped-approval warnings) are outside `tel`; the confidentiality leak `arun_stderr_image` bounds is STATED, not discharged — no theorem says any audit line is safe to disclose (content discipline stays the NI row); P7 REMAINS a trust-inventory row | yes, "model-level; the vacuity is of the `audGuardedBy` form only; the negative `aud_non_bypass_fails` is a proved model-level witness; the stderr confidentiality leak is a stated residual, not discharged" mandatory |
| W2-T2: byte-quorum consensus (MODEL): a `canonicalL0` forward with the byte-consensus verdict among the combined verdicts implies a strict-majority `validB` quorum ratified exactly the forwarded action's canonical bytes, the ratified cert's value IS those bytes, and two such forwards under the same roster+votes agree byte-for-byte | `Kernels/ConsensusBytes.lean`, `Host/CompositionBytes.lean` | Lean theorem | model-level kernel: the DEPLOYED `consensusKernel` votes on `act.tool` (tool-string granularity); byte binding proven under the `canonicalL0` profile, deployed profile is `compatible`; vote authenticity/transport TCB | deployed kernel unchanged; wiring `byteConsensusKernel` into dispatch is future work | yes, "model-level" mandatory |
| W2-T3: composition residual: non-vacuous denies survive gate extension (`combine_deny_append`); allows restrict to any non-empty gate prefix (`combine_allow_restrict`); the `vs ≠ []` empty-deny boundary is stated and witnessed (`combine_extension_from_empty`) | `Host/Composition.lean` | Lean theorem (corollaries of `combine_allow_iff`/`combine_deny_of_member`) | Lean kernel/runtime | decidability candidate skipped: `VerdictKind` DecidableEq already gives it | yes |
| W2-T1: timed record admissibility: accepted entries are δ-fresh against the producing step's monotone clock; stale-clock, clock-regressed, and replayed-nonce entries are inadmissible; admissible appends preserve log clock-sortedness and nonce uniqueness; chain spine (append-only, tamper-evidence) inherited from L1 CORE under A-CR + A-GEN + A-ENC (injective entry encoding) | `Host/RecordTemporal.lean` | Lean theorem (spine inherited) | monotone host/LOGICAL clock feeding `now` (NOT wall clock; wall clock + runtime nonce/TTL remain TCB, `a3.rs`); A-ENC undischarged for the demonstration `TimedEntry.line` encoder (discharged for `encCanonical`, next row) | statement-level: the runtime does not yet enforce `admissible` | yes, with the logical-clock caveat verbatim |
| W2-T1 hardening: A-ENC DISCHARGED: `TimedEntry.encCanonical` (length-prefixed, delimiter-safe) is injective by Lean proof (`encCanonical_injective`, pure structural, no crypto); `timed_tamper_evident_canonical` gives timed tamper-evidence under A-CR + A-GEN ALONE, exactly the landed L1 crypto TCB, no encoder side-condition | `Host/RecordTemporalCanonical.lean` | Lean theorem | A-CR + A-GEN only (the L1 crypto TCB); monotone-clock caveat as above | `TimedEntry.line` remains demonstration-grade (unused by this theorem) | yes |
| Deployed receipt commitment: production audit certificates are chained with SHA-256 (`sha256(prevHeadHex || 0x1f || payload)`) by `rust/src/receipt.rs` and independently by `scripts/seal_log.mjs`; conformance checks a fresh deployed host's emitted head against the model-derived head. The host file-fsyncs and atomically replaces a private prior-head state file, directory-fsyncs it, and the first record after restart names the prior head and process session | Rust host + `scripts/seal_log.mjs` + `scripts/conformance_bridge.mjs` | code + differential evidence | SHA-256 collision resistance is A-CR TCB; `node:crypto`/Rust `sha2`, filesystem `fsync` behavior, OS ownership, and harness are TCB | no Lean proof of SHA-256 CR; evidence over corpus C only; process-session metadata cross-links records but is not itself an authenticated caller identity | yes, "A-CR is TCB, not proven" mandatory |

**Proof build-wire scope (2026-08-05).** “Lean theorem” in this table reports a
theorem declaration and its stated scope; build-backed proof/axiom coverage is
limited to theorem names in the `Test/Axioms.lean` import-and-pin closure.
Measured on this tree: 51 of 53 theorem-bearing modules sit inside that
closure. Outside it (and therefore not axiom-gated by `lake exe axiom_check`):
`Host.CanonicalL0Liveness` (ruled out of the release claim, Ben 2026-08-01) and
`Test.A2DivergenceClassification` (imported by no default target). In
particular, the K5 module `Host.EgressPerimeter` **is** in the closure (direct
import of `Test/Axioms.lean` since `4eb6bb4`); the K5 row's model-level
qualifiers still apply to what the theorems prove, not to build reachability.

## Assumptions and residuals (A1-A7)

- **A2 (numeric/parse fidelity)** minimised by construction (kernel-defined strict subset), not eliminated. Per-server equivalence obligation remains.
- **A4 (atomic consume)** discharged by the host `Mutex` carrying M6 atomic-consume; concurrency-tested 16->1 Allow.
- **A5 (single-use replay)** discharged by construction: the store IS `listReplayStore`.
- **A6 (cross-restart durability)** closed for the host's Ed25519 signed-token
  production channel, two-phase since the G2 cut (a) ruling (Ben,
  2026-08-06): a nonce is durably RESERVED in SQLite (WAL plus
  `synchronous=FULL`) before its approval reaches Lean — the hold blocks any
  second presentation — and the burn is durably COMMITTED only at RECORDED,
  after the authorization-decision receipt persists and before the child
  forward. Startup recovery reclaims holds that never reached RECORDED, so a
  crash before RECORDED leaves the approval usable again with no receipt; a
  committed burn is never reclaimed. The receipt (file store) and the burn
  (SQLite) are two durable acts, not one: a crash exactly between them
  leaves a RECORDED receipt with a reclaimable hold, so the same approval
  can produce a second receipt after restart — never a second forward. The
  legacy control-file/interactive demo channels keep in-memory replay state
  and do not claim cross-restart replay protection.
- **A7 (replay-store instance integrity) RULED AND ACCEPTED by Ben 2026-07-30**
  (council `5c3845e7`, shape (D): application-layer instance binding is not
  achievable against an attacker holding write access to the store path, so this
  is a documented limitation, not a guard). A6 claims
  that accepted nonces are durably recorded; it does NOT claim that the store
  the host opens is the same store instance it last wrote. The host
  authenticates the store's PATH and file properties — non-symlink, host-euid
  owner, mode 0600, and (added here) a non-symlink host-owned 0700 parent
  directory, which narrows the set of principals able to `rename()` a
  different but equally host-owned store into that path to {host euid, root}.
  It does not authenticate the store's IDENTITY: no field of the
  authority-signed config binds a store instance, so a substitution performed
  by the host euid or by root — restoring a backup, a blue/green rollback, a
  prior init left in place — is accepted and every nonce the displaced store
  had consumed is re-accepted within its TTL. This residual is currently
  dissolved into the "OS permissions" and "Rust replay-store TCB" assumptions
  of the A6 row above; A7 names it directly. Pinned in executable form by
  `rust/tests/replay_store_substitution.rs::store_substitution_is_not_detected`,
  which asserts the ACCEPTANCE; retiring A7 requires editing that test in the
  same commit.

## Trusted config signatures

`Host/Config.lean` verifies a real Ed25519 signature over the exact trusted
config `payload` bytes before the host mediates anything. The startup
`--pubkey` is the config-signing trust root and must be separate from the
approval-token key.

- config envelope: real Ed25519 via the existing `SealV2.ed25519Verify` leaf
  over exact trusted-config payload bytes
- v2 approval path: real Ed25519 leaf in `mcp-seal-dev` over kernel-defined
  `(target, session, issuedAt, expiry, nonce)` signed-message bytes
- host NDJSON approval-provider path: real `ed25519-dalek` over exact
  `ApprovalRecord` JSON payload bytes; this is a separate channel, not the
  SealV2 kernel-defined tuple

- durable replay: trusted `replay_store.sqlite_path`, `schema_version`, and
  `namespace_encoding_version` are inside the signed config payload; config
  key custody is therefore part of the TCB. The SQLite singleton lineage
  stamp must match before the host serves

"Kernel-defined" is deliberate: these bytes are not claimed to implement RFC
8785/JCS. The rules and known divergences are stated in
[`docs/CANONICAL-BYTE-CONTRACT.md`](docs/CANONICAL-BYTE-CONTRACT.md).

## Response egress

seal mediates **request-effects**, not responses. Never say "seal prevents
leaks." It prevents unapproved effects through the mediated request boundary.

## Release provenance

GitHub artifact attestations are not available for this user-owned private
repository. Releases instead carry a Sigstore-keyless, in-toto statement whose
SHA-256 subjects are the exact published tarballs, CycloneDX SBOMs, and
`SHA256SUMS`. The release gate verifies the workflow certificate identity, the
signature, the exact subject set, and every digest before publication. Absence
or an unanswerable verification is a refusal.

This claims only that the named GitHub Actions release-workflow identity signed
those byte bindings. It is not a GitHub artifact attestation, not an
independently controlled human or organisation signing key, and not proof of
reproducibility, hermeticity, source-to-binary correspondence, uncompromised
build or signing infrastructure, or theorem-to-binary applicability. The
signed statement repeats these non-claims. See
[`docs/RELEASE-PROVENANCE.md`](docs/RELEASE-PROVENANCE.md).
