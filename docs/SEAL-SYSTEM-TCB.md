<!-- SPDX-License-Identifier: Apache-2.0 -->
# seal — System Trusted Computing Base ledger

**Audience:** reviewers and acquirers (internal). Names the private repositories.
The public, hygiene-clean extract of this document is
`seal-check/docs/SEAL-ASSURANCE-STATEMENT.md`; where the two disagree, this
ledger is authoritative and the public extract is corrected to match.

**Status:** reconciles three previously-partial docs into one system view —
`mcp-seal-dev/ASSURANCE_CASE.md` (proof layer), `seal-host/TCB.md` +
`seal-host/RUST_BRIDGE.md` (bridge layer, hardened at commit `f69ddad`), and
`seal-check/docs/SEAL-MEDIATION-PROFILE-L0.md` (boundary profile).

**Date:** 2026-07-05.

---

## 0. What seal does NOT claim

seal is a mediation kernel with a machine-checked non-bypass property. It is
**not** a proof of agent safety, and it does not certify a whole MCP server,
its transport, or its tool implementations.

The claim seal makes is exactly this, and nothing wider:

> **Policy-covered, unapproved effects cannot execute through the mediated MCP
> boundary, as modelled.**

Every qualifier is load-bearing:

- **policy-covered** — only calls the trusted policy identifies as guarded are
  gated. A call the policy does not cover is out of scope, not "safe"
  (residual: classifier / policy completeness, §4).
- **unapproved** — an effect with a valid, fresh, target-bound approval is
  *admitted*; seal blocks the *unapproved*, not the approved.
- **through the mediated MCP boundary** — effects that never emit a
  `tools/call` through the gate (a side channel, an out-of-band write, a
  lenient child that executes what strict JSON rejects) are outside the
  boundary by construction.
- **as modelled** — the proof is over the Lean model of parse / validate /
  decide. The model's fidelity to the deployed binary rests on the named
  trusted set (§3B), not on further proof.

Specifically, seal does **NOT** claim:

- that "agent safety is solved" or that a seal-mediated agent is safe;
- that "nothing leaks" — **responses are relayed unmediated by design**
  (requests are gated, response egress is not; P6 in §3B);
- **that the deployed wasm provably equals the Lean model** — the equivalence
  is a *trusted compile* (Lean C codegen + emscripten) plus *differential
  testing*, **not** a proof (§3B, §4);
- **that the deployed host runs the strict `canonical-l0` profile** — do not
  describe the deployed host as strict canonical-l0; it is `compatible`
  (CLAIMS.md — `canonical-l0` is implemented at the proof layer, not the
  deployed routing path);
- that a deployment actually routes its calls through the gate (an integration
  property of the operator, not a theorem);
- any third-party endorsement, outcome, or affiliation.

**This posture is the precedent, not a weakness.** seL4 ships a machine-checked
functional-correctness proof *together with* an explicit list of assumptions it
does not discharge (the C compiler, the assembly, the hardware model).
CompCert ships a proved-correct C compiler whose guarantee is stated *relative
to* its formal semantics and its trusted parser / assembler. Both are landmark
results precisely because they state the proof **and** the trusted base with
equal rigor. seal follows that discipline: a narrow proven core, an explicitly
named TCB, and claim discipline that refuses to let the proof's reputation
extend past what was proven.

---

## 1. The claim, in one sentence

> Policy-covered, unapproved effects cannot execute through the mediated MCP
> boundary, as modelled — where "cannot" is the machine-checked `non_bypass`
> theorem over the Lean decide function, and every gap between that model and a
> running deployment is named in §3B and §4, not papered over.

---

## 2. System shape (three layers)

```
   ┌─────────────────────────────────────────────────────────────┐
   │ L1  PROOF          Lean 4 model: parse → validate → decide    │  PROVEN
   │     mcp-seal-dev/SealV2/*.lean   (public mirror: mcp-seal)     │
   ├─────────────────────────────────────────────────────────────┤
   │ L2  COMPILE        Lean → C (Lean codegen) → wasm (emscripten) │  TRUSTED
   │     seal-check/wasm/seal.wasm  (in-browser sha256 self-verify) │  compile
   ├─────────────────────────────────────────────────────────────┤
   │ L3  BRIDGE         Rust host at the tool-call boundary         │  PROVEN
   │     seal-host/rust/*   (enforced-by-construction + oracle)     │  by constr.
   └─────────────────────────────────────────────────────────────┘
```

L1 is machine-checked. L3 is enforced-by-construction and oracle-tested. **L2
is the trusted seam between them** — the binary-equals-model identity is *not*
a theorem (§3B).

---

## 3. TCB ledger — two columns

### 3A. PROVEN (machine-checked / enforced-by-construction)

#### L1 — Lean kernel (machine-checked; `mcp-seal-dev/SealV2/DecideTheorems.lean`)

Zero `sorry`; zero `native_decide` / `Lean.ofReduceBool`. Axiom footprint of
every discharged theorem: **`[propext, Classical.choice, Quot.sound]`** — CI
gates this per commit (`lake exe v2_m4_axiom_check` + grep guards).

| Theorem | Exact statement (paraphrased from source) | Location |
|---|---|---|
| **`non_bypass`** | `decide raw state = Decision.Allow out →` there exists an `ast` with `parse raw = some ast` and a `ValidCapability` witness such that `out = serialize ⟨ast, witness⟩`. **No Allow without a parsed request and a validated capability witness.** | `SealV2/DecideTheorems.lean:67` |
| **`default_deny`** | `parse raw = none ∨ (∃ ast, parse raw = some ast ∧ validate ast state = none) → decide raw state = Decision.Block`. **Unparseable or unvalidated ⇒ Block.** | `SealV2/DecideTheorems.lean:77` |
| **`decide_emit_unique`** | `decide raw state = Decision.Allow out ↔` the full parse-validate-serialize chain holds and `out` is the unique canonical serialization of the witness. **An Allow's bytes are exactly determined by the validated witness — no ambiguity, one emit path.** | `SealV2/DecideTheorems.lean:42` |

Supporting proven lemmas (same footprint): `SealCore/Safety.lean:8`
`default_deny_never_allowed`; `no_allow_guarded_without_matching_approval_in_state`;
`approval_binds_to_target` (`[propext, Classical.choice, Quot.sound]`).

#### L3 — Rust bridge (enforced-by-construction; `seal-host/rust/`, commit `f69ddad`)

These are not Lean theorems; they are properties the Rust type system / control
flow make unconstructible-to-violate, each pinned by a test (§5).

| Property | How it is enforced-by-construction | Location |
|---|---|---|
| **Forward is unconstructible without a kernel verdict** | `route.rs` holds the only kernel-output→action translation; `Route::Forward` is producible only from an exact parse of kernel output with route literally `forward`/`passthrough`, and `ClassifyRoute::Passthrough` only from literal `Ok(0)`. Binary and tests call the *same* functions. | `rust/src/route.rs` |
| **Fail-closed FFI** | Every FFI call returns `Result<_, SeamError>`; NULL / non-string / interior-NUL / invalid-UTF-8 / poisoned-lock / Rust-panic all map to a `SeamError`, and every `SeamError` maps to refuse. Kernel strings read by exact byte length, strict UTF-8. | `rust/src/lean.rs` |
| **Verbatim byte forwarding** | Host reads raw bytes (`read_until`), forwards the client's *original* bytes on allow — no reconstruction, no CRLF rewrite. Only transform is the terminator strip defining the unit of judgment. | `rust/src/main.rs` |
| **Panic → abort (F1 closed)** | `lean_set_exit_on_panic(true)` + `LEAN_ABORT_ON_PANIC=1` armed before runtime init: a Lean panic terminates the process instead of returning the `UInt32` default `0` (= passthrough = fail-open). | `rust/src/lean.rs`, `rust/src/main.rs` |

### 3B. TRUSTED (named, not proven)

| # | Trusted element | Fail direction / note |
|---|---|---|
| T1 | **Lean compiler + runtime + C codegen** — compiles and hosts the proven `decide`. | Compiler bug could diverge binary from model. |
| T2 | **emscripten toolchain** (wasm shape) — Lean-C → wasm. | Same class as T1, extended to wasm. |
| T3 | **wasm-equals-Lean identity** — that `seal.wasm` computes the same function as the proven Lean. **Trusted compile (T1+T2) + differential evidence (§4, Lane C), NOT a proof.** | The load-bearing honest gap. In-browser sha256 proves *which binary ran*, never *that it matches the model*. |
| T4 | **`ffi_shim.c` + `lean.h` static-inline helpers** — string size/cstr/is_string, panic hooks, module init. | Marshalling glue; hardened but trusted. |
| T5 | **OS process model + file permissions + config-signing trust root** (A-origin) — pipes, spawn, write access to config / approval / votes / grants / forecast files, and startup `--pubkey` for real Ed25519 config signatures. | Whoever controls approval files/keys or the config-signing key/argv is trusted. |
| T6 | **Wall clock + A3 state + replay store** (`a3.rs`, `replay_store.rs`) — nonce set, Ed25519 signed-token SQLite durability, TTL, future-skew. | Nonce insert is write-ahead before Lean sees the approval; SQLite runs WAL + `synchronous=FULL`. Legacy control-file replay remains in-memory/demo-only. |
| T7 | **Ed25519 implementations + parsers** — vendored TweetNaCl via `SealV2.ed25519Verify` for config payload signatures; `serde_json` + `ed25519-dalek` + `hex` for host approval records. | Fail direction: reject config at startup or drop approval record ⇒ **deny**. |
| T8 | **P6 — response egress unmediated by design** — child→client bytes relayed verbatim. | Requests gated; responses not. Never restate as "nothing leaks". |
| T9 | **Operator argv** (P4) — the command line names the guarded server. | Operator-trusted setup; the child IS the guarded resource. |
| T10 | **A-strict-child** — routing assumes the child parses its protocol strictly; a lenient child that executes a line strict JSON rejects is outside the contract. | Named limitation of the boundary. |

---

## 4. Residual differentials (named, pinned — not eliminated)

Inherited from the mcp-seal threat model plus the system seams:

1. **Classifier / policy completeness** — the runtime policy must identify the
   calls that matter. Not proven; architectural.
2. **Target-parser equivalence (A2)** — seal's parse of the target vs the
   upstream server's execution. Minimised (canonical arg-tree hash +
   differential fixture), not eliminated. The standing red-team line.
3. **Approval origin** — control-file permissions (v1) / signing-key management
   (v2), and that the human understood what they approved.
4. **wasm-vs-Lean equivalence (T3)** — the conformance bridge drives identical
   inputs through the interpreted Lean model, the native `.so`, the emscripten
   wasm, and the deployed Rust host. **Status: green (R6, 2026-07-05): 15/15
   corpus inputs agree byte-for-byte on decision + audit bytes across model,
   native and wasm, with matching SHA-256 record-chain heads; the deployed host
   record head also agrees with the model.** Scope: corpus C (destructive
   disguises, passthroughs, one approved forward), not exhaustive over all
   inputs. This is *risk-reducing evidence* for T3, never a proof.
5. **Out-of-band effects** — anything that never emits a `tools/call` through
   seal.

---

## 5. Evidence map (one row per claim → re-runnable artefact)

| Claim | Backed by | Artefact (file) | Re-run |
|---|---|---|---|
| No Allow without parsed + validated capability | theorem `non_bypass` | `mcp-seal-dev/SealV2/DecideTheorems.lean:67` | `lake build` + `lake exe v2_m4_axiom_check` |
| Unparseable/unvalidated ⇒ Block | theorem `default_deny` | `SealV2/DecideTheorems.lean:77` | `lake build` |
| Allow bytes uniquely determined; one emit path | theorem `decide_emit_unique` | `SealV2/DecideTheorems.lean:42` | `lake build` |
| Axiom footprint `[propext, Classical.choice, Quot.sound]`, zero sorry | CI axiom check | `mcp-seal-dev` CI (`v2_m*_axiom_check` + grep guards) | `lake exe axiom_check` |
| Forward unconstructible without kernel verdict | proptests (garbage/mutations/all u32/every SeamError never Forward) | `seal-host/rust/tests/differential.rs` (`step_output_*`, `classify_literal_only`, `seam_error_never_forwards`) | `cargo test --test differential` |
| Routing agreement incl. full obfuscation disguise corpus | corpus + property tests | `seal-host/rust/tests/differential.rs` (`corpus_agreement*`, `no_routing_bypass`) | `cargo test --test differential` |
| Panic → abort (F1 closed), fail-open demonstrated + fixed | binary-driven probes | `seal-host/rust/tests/panic_probe.rs` | `cargo test --test panic_probe` |
| Full-path mediation: disguises block, approval one-shot, non-UTF8 refused, verbatim forward | full-binary oracle | `seal-host/rust/tests/host_path.rs` | `cargo test --test host_path` |
| Which binary ran (identity, not equivalence) | wasm sha256 pin | `seal-host/wasm-spike/verified/PROVENANCE.txt` (`seal.wasm` pin `a6a73fa5d3ab…9e35`) | `sha256sum wasm-spike/verified/seal.wasm` |
| wasm computes same function as Lean (T3) | conformance bridge — GREEN (R6, 2026-07-05): 15/15 corpus inputs agree across model/native/wasm; deployed record head agrees too (risk-reducing evidence, not a proof) | `seal-host/scripts/conformance_bridge.mjs` | `node scripts/conformance_bridge.mjs --wasm` |

---

## 6. Reconciliation — how the three partial docs map here

- **`mcp-seal-dev/ASSURANCE_CASE.md`** → §3A L1 (theorems, axiom footprint),
  §4 residuals 1–3, 5. Its "structural claim is machine-checked within the
  boundary" = this ledger's §1 + §0.
- **`seal-host/TCB.md` + `RUST_BRIDGE.md`** → §3A L3 (enforced-by-construction
  properties), §3B T4–T10, §5 host rows. "What seal does NOT claim" in
  RUST_BRIDGE.md is the seed of §0's response-egress and strict-child lines.
- **`seal-check/docs/SEAL-MEDIATION-PROFILE-L0.md`** → the boundary contract
  (default-deny §2, four-gate model §3, receipt schema §4, determinism §5) that
  the L1 proofs and L3 bridge jointly implement; its §7 claim discipline is the
  public face of §0. Its `asserted_provenance.verified_in_browser=false` block
  is the receipt-level statement of T3 (identity ≠ equivalence).
