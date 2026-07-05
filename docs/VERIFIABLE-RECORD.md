<!-- SPDX-License-Identifier: Apache-2.0 -->
# The verifiable record (L1) — append-only, tamper-evident decision log

L0 proves the four-gate non-bypass over the deployed step core
(`Host.step_forward_non_bypass`). L1 climbs one level and proves the **log of
those decisions** is a hash-chain that is append-only and tamper-evident. This
is the "be the verifiable record, not just the gate" claim converted from prose
to a machine-checked theorem.

## The theorem (`Host/Record.lean`)

The log is a list of audit payloads (`Host.auditLine` strings). The chain head
is `rollingHead H genesis`, where the newest entry is the outermost commitment.

- **`head_after_append`** — append-only: committing a new decision extends the
  chain; the prior head appears unchanged as a subterm. (No assumption; `rfl`.)
- **`tamper_evident`** — under a collision-free commitment (`A-CR`) and a fresh
  genesis (`A-GEN`), the chain head is an **injective function of the whole
  log**: two logs with equal heads are identical. Contrapositive: any insert,
  reorder, or mutation changes the head and is detected.

Both are `sorry`-free and depend on **no axioms** (a strict subset of the L0
baseline `[propext, Classical.choice, Quot.sound]`). Gate:
`lake env lean Test/AxiomCheckRecord.lean`.

## Honest scope — the commitment is a named assumption, not proven

`tamper_evident` is stated over an **abstract** commitment `H` with two explicit
hypotheses. This is deliberate and load-bearing:

- **`A-CR` (collision-resistance)**: `∀ a b p q, H a p = H b q → a = b ∧ p = q`.
- **`A-GEN` (fresh genesis)**: `∀ a p, H a p ≠ genesis`.

The **structure** is machine-checked; the **primitive's** collision-resistance
is a named TCB assumption — the same discipline as Ed25519-correctness being
TCB(A3) in the L0 proofs.

Why abstract and not over the legacy audit hash: `Seal.auditHashParts` is FNV-1a
into `UInt64`. A 64-bit hash **is not collision-resistant** — `A-CR` is literally
false for it (pigeonhole). A "no-assumption tamper-evidence over auditHashParts"
theorem is therefore not merely hard, it is unprovable because it is false. The
in-Lean `chainHash` (FNV) is kept only as an illustrative instance and is
**demonstration-grade**.

**Deploy decision (exit a).** The receipt verifier (`scripts/seal_log.mjs`)
instantiates `H = SHA-256`, a credible collision-resistant hash, so `A-CR` is a
**credible** assumption for the shipped demo. Production keeps `H = SHA-256`
(or another CR hash); it must never chain the record with FNV.

## Receipt bundle — reproduce cold in under 5 minutes

```sh
bash scripts/receipt_demo.sh
```

What it does, against the **real** Lean-verified gate (no mocks):

1. An agent sends destructive `db.execute` calls (drop / delete / truncate on
   prod) through the mediated MCP boundary.
2. seal **BLOCKS** every one by default-deny (no approval) — nothing reaches
   the database.
3. Each decision's audit certificate is sealed into the SHA-256 hash-chain and
   **verifies** with one command:
   ```sh
   node scripts/seal_log.mjs verify sealed.json     # → VERIFY OK, chain head …
   ```
4. Tamper checks: mutating one entry (deny → allow) and reordering two entries
   are each **REJECTED** — the recorded head no longer matches the recomputed
   chain.

A captured green transcript is in `docs/receipt-ci-transcript.txt`.

## Verifier commands

```
node scripts/seal_log.mjs seal   <audit-lines> <sealed.json>   # build the chain
node scripts/seal_log.mjs verify <sealed.json>                 # recompute + check (exit 1 on tamper)
node scripts/seal_log.mjs head   <sealed.json>                 # print the current chain head
```

## Faithful reflection (STRETCH — proven, `Host/RecordReflection.lean`)

- **`log_reflects_l0_decisions`** — for a log built from a sequence of forwarded
  decisions (most-recent-first), every entry corresponds to a decision that
  passed L0: its verdict list is non-empty and every gate allowed. Proof chain:
  logged ⇒ `stepRoute (.act …) = .forward` ⇒ `combineVerdicts = .allow` ⇒
  (`combine_allow_iff`) every gating kernel allowed. Order-preserving by
  construction (the log is exactly the per-decision audits in reverse order).
- Footprint `[propext, Classical.choice, Quot.sound]` (baseline), zero `sorry`.
- Scope: the record of ADMITTED (forwarded) effects — the security-relevant log.
  Composed with `tamper_evident`, the record is both unforgeable and a faithful
  witness of what passed the gate.

## Not claimed

- Not a claim that FNV/`auditHashParts` is tamper-evident — it is not; the
  chained record uses SHA-256, and the theorem's strength is exactly `H`'s
  collision-resistance.
- Not a claim that the Lean model equals the shipping binary — that is the
  conformance-bridge work (spec ↔ deployed Rust/WASM), scoped separately.
