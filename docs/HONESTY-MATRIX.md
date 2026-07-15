<!-- GENERATED FILE — do not hand-edit.
     Regenerate: node scripts/honesty-matrix.mjs
     CI regenerates and diffs this file; a hand edit goes red. -->

# Honesty matrix — what the shipped gate actually enforces

Per kernel, four facts that must never be conflated: **proven?** · **wired in `registryFor`?** · **reachable via the shipped policy DX?** · **tested at every topology where active?** A capability matrix that only lists what works is marketing; this one prints the eighth row.

## The arithmetic, stated honestly

The proof covers **8 kernels**. The product selects among **7** of them, **2 mandatory** (`safety`, `temporal`) — so **32 deployable topologies**. Not 64. Not 127. The eighth kernel (`consensus-bytes`) is proven and not in the building; wiring it would double the space to 64. All four numbers are computed by `lake exe honesty_matrix` from evaluating `Ffi.activeKernels`, not typed by a human.

## How to read a cell

- **`✅ / ⚙️ / ❌ … derived`** — emitted by machinery. The Lean exe term-binds all nine `FfiSpec.lean` theorems (renaming or deleting one breaks its build, so the matrix cannot regenerate and CI goes red) and evaluates `Ffi.activeKernels` at every deployable config; `Ffi.registryFor_kernels` proves the deployed registry equals that evaluation for every session, clock and evidence bundle. The tested column additionally requires a fail-loud structural parse of the A1 suite and its CI wiring to succeed. All nine theorems are axiom-pinned to `[propext, Classical.choice, Quot.sound]` (`FfiSpec.lean`, re-pinned in `Test/Axioms.lean`).
- **`⚠️ ASSERTED (who, date)`** — a human judgement, not machine evidence. The **reachable** column is the only asserted column: whether a kernel is reachable through the shipped policy-authoring experience is a reading of `CONFIG.md` and of what tooling exists, and no theorem or test can settle it. Full rationale per cell below. If these two cell styles ever look alike, that is a bug in this generator.

Scope of the derivation, stated honestly: the theorem binding catches **rename and delete**, not **restatement** — a weakened theorem that keeps its name still builds. That is exactly the bug class A0 was written to kill (edit `registryFor`, no proof notices), and no more. This matrix cannot go stale against that bug class; it is not a guarantee the theorems say what the prose claims. Read `FfiSpec.lean` for that.

## The matrix

| Kernel | proven? | wired in `registryFor`? | reachable via shipped policy DX? | tested at every topology where active? |
|---|---|---|---|---|
| `safety` | ✅ derived — `Ffi.registryFor_kernels`, `Ffi.safety_always_registered` | ✅ always (32/32) derived — evaluated over all 32 configs | ⚠️ ASSERTED (Monkey, 2026-07-15) — yes — required section of every signed config | ✅ derived — shown denying at all 32 topologies (`rust/tests/topology_matrix.rs`) |
| `temporal` | ✅ derived — `Ffi.registryFor_kernels`, `Ffi.temporal_always_registered` | ✅ always (32/32) derived — evaluated over all 32 configs | ⚠️ ASSERTED (Monkey, 2026-07-15) — yes — optional section; kernel active even when absent | ✅ derived — shown denying at all 32 topologies (`rust/tests/topology_matrix.rs`) |
| `consensus` | ✅ derived — `Ffi.registryFor_kernels`, `Ffi.consensus_registered_iff` | ⚙️ config-gated (16/32) derived — evaluated over all 32 configs | ⚠️ ASSERTED (Monkey, 2026-07-15) — yes — optional `consensus` section, hand-authored | ✅ derived — shown denying at all 16 active topologies and not gating at the 16 inactive ones (`rust/tests/topology_matrix.rs`) |
| `convergence` | ✅ derived — `Ffi.registryFor_kernels`, `Ffi.convergence_registered_iff` | ⚙️ config-gated (16/32) derived — evaluated over all 32 configs | ⚠️ ASSERTED (Monkey, 2026-07-15) — yes — optional `convergence` section, hand-authored | ✅ derived — shown denying at all 16 active topologies and not gating at the 16 inactive ones (`rust/tests/topology_matrix.rs`) |
| `calibration` | ✅ derived — `Ffi.registryFor_kernels`, `Ffi.calibration_registered_iff` | ⚙️ config-gated (16/32) derived — evaluated over all 32 configs; double-gated (present AND enabled) | ⚠️ ASSERTED (Monkey, 2026-07-15) — yes — optional `calibration` section with `enabled` flag, hand-authored | ✅ derived — shown denying at all 16 active topologies and not gating at the 16 inactive ones (`rust/tests/topology_matrix.rs`); disabled-vs-absent exercised at all 16 inactive topologies |
| `linear` | ✅ derived — `Ffi.registryFor_kernels`, `Ffi.linear_registered_iff` | ⚙️ config-gated (16/32) derived — evaluated over all 32 configs | ⚠️ ASSERTED (Monkey, 2026-07-15) — yes — optional `linear` section, hand-authored | ✅ derived — shown denying at all 16 active topologies and not gating at the 16 inactive ones (`rust/tests/topology_matrix.rs`) |
| `budget` | ✅ derived — `Ffi.registryFor_kernels`, `Ffi.budget_registered_iff` | ⚙️ config-gated (16/32) derived — evaluated over all 32 configs | ⚠️ ASSERTED (Monkey, 2026-07-15) — yes — optional `budget` section, hand-authored | ✅ derived — shown denying at all 16 active topologies and not gating at the 16 inactive ones (`rust/tests/topology_matrix.rs`) |
| `consensus-bytes` | ✅ derived — `Ffi.registryFor_kernels`, `Ffi.byteConsensus_never_registered` | ❌ never (0/32) derived — evaluated over all 32 configs | ⚠️ ASSERTED (Monkey, 2026-07-15) — no — no config section exists | ❌ untested in deployment — no deployable topology exists (derived from wired: never) |

## The eighth row, spelled out

`consensus-bytes` (`Kernels/ConsensusBytes.lean`) is **proven, NOT wired, not reachable, untested in deployment**. `Ffi.byteConsensus_never_registered` proves no config, clock or evidence reaches it; no `CONFIG.md` section names it; it has no deployable topology to test at. It appears here because omitting it would make this table marketing.

## Calibration's double gate

`some cfg` with `enabled := false` is a distinct config state from `none`. Both leave calibration inactive — proven (`Ffi.calibration_registered_iff`), evaluated by the exe at all 16 calibration-clear masks (disabled ≡ absent, selection-identical), and exercised behaviourally by the A1 suite (`topology_matrix_calibration_absent_vs_disabled`: the two runs must be call-for-call identical).

## Tested — what is derived and what is record

Derived (re-established on every regeneration): `rust/tests/topology_matrix.rs` exists with the mask partition pin (`topology_masks_partition`, 16+16 = the disjoint `0..32`), both spawning tests, the `CARGO_BIN_EXE_seal-host-rs` forced-binary path, and a `PROBES` table whose kernel names equal the Lean derivation's config-gated set exactly; `ci.yml` runs `cargo test` in `rust/` on every push. If any of that goes away, this file cannot regenerate.

Record (a checkable historical fact, quoted with its date, not re-established here):

- GitHub Actions run 29443393591 (`ci.yml` → `rust-conformance`), green on a clean runner, 2026-07-15 — the A1 suite exercising all 32 topologies plus calibration's 16 disabled variants against the shipped binary.

## Asserted cells in full

Everything below is human judgement from `docs/honesty-assertions.json`. Re-assert (update the date) when the shipped DX changes.

- `safety` — **yes — required section of every signed config**
  ⚠️ ASSERTED by Monkey, 2026-07-15. CONFIG.md documents the `safety` section as a required field of the signed TrustedConfig envelope (verified with --pubkey). The shipped DX is hand-authored JSON: no `seal init` scaffolding exists in this repo (workstream A never happened).
- `temporal` — **yes — optional section; kernel active even when absent**
  ⚠️ ASSERTED by Monkey, 2026-07-15. CONFIG.md: absent `temporal` section = no temporal constraints, but the kernel itself is unconditional. Hand-authored signed JSON; no scaffolding CLI.
- `consensus` — **yes — optional `consensus` section, hand-authored**
  ⚠️ ASSERTED by Monkey, 2026-07-15. CONFIG.md documents the section schema (roster, votes_file, high_stakes). Reachable means writing that JSON by hand and signing it; no `seal init`.
- `convergence` — **yes — optional `convergence` section, hand-authored**
  ⚠️ ASSERTED by Monkey, 2026-07-15. CONFIG.md documents the section schema (replicated tools). Hand-authored signed JSON; no scaffolding CLI.
- `calibration` — **yes — optional `calibration` section with `enabled` flag, hand-authored**
  ⚠️ ASSERTED by Monkey, 2026-07-15. CONFIG.md documents the section including the double gate: a present section with enabled:false is explicitly inactive (CONFIG.md's PRESENT-BUT-INACTIVE label). Hand-authored signed JSON; no scaffolding CLI.
- `linear` — **yes — optional `linear` section, hand-authored**
  ⚠️ ASSERTED by Monkey, 2026-07-15. CONFIG.md documents the section schema (grants_file, tools). Hand-authored signed JSON; no scaffolding CLI.
- `budget` — **yes — optional `budget` section, hand-authored**
  ⚠️ ASSERTED by Monkey, 2026-07-15. CONFIG.md documents the section schema (named caps over tool sets). Hand-authored signed JSON; no scaffolding CLI.
- `consensus-bytes` — **no — no config section exists**
  ⚠️ ASSERTED by Monkey, 2026-07-15. Nothing in CONFIG.md or the config parser (Host/Config.lean) names this kernel; there is no JSON key a user could write that selects it. Consistent with the proof (Ffi.byteConsensus_never_registered) but asserted separately: absence from the DOCUMENTED DX surface is a human reading of CONFIG.md, not a theorem.
