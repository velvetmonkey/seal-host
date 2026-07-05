<!-- SPDX-License-Identifier: Apache-2.0 -->

# PATH B — closing the capability-theorem residual (runtime `pg` confinement)

**Status: HISTORICAL DESIGN DOC, superseded by Stage 2.** The recommended
CR-hash swap has now shipped in the private kernel (`mcp-seal-dev @ 872ac50`):
`Seal.stableHashParts` is SHA-256 over injective netstring encoding, while
the old FNV path is explicitly named `Seal.auditHashParts` for UInt64 audit
cert/demo hashes. The analysis below is retained as pre-widening rationale.

## The residual being closed

`Host/CapabilityAdequacy.lean` (`approval_authorizes_only_its_target`,
merged @ 687f7f4) proves: a held approval for part-list `pa` authorizes an
action resolving to `pg` only if `pa = pg` — **conditional on `pg ∈ U`**, a
finite policy universe. The honest residual, declared loud in that module:
the frozen classifier `Seal.classifyToolCall → evalTargetParts`
(`Seal/Classify.lean:32-36`) pulls RAW `.argPath` argument scalars into the
hashed part-list, so at runtime `pg` is NOT confined to `U`. FNV-1a-64
(`Seal/Hash.lean:16`) is neither collision- nor preimage-resistant, so an
attacker who holds a legitimate approval for `pa ∈ U` can craft arguments
producing `pg' ∉ U` with `stableHashParts pg' = stableHashParts pa` and ride
the grant. Path B = close that gap for real.

---

## STEP-0 recon (reported first, as required)

### R1 — where can the host enforce `pg ∈ U` before the frozen gate?

**Nowhere, pre-gate.** The deployed Rust host never resolves the target
part-list; it cannot, without re-implementing the frozen classifier. Traced
from `rust/src/main.rs` / `route.rs` / `lean.rs`:

* Rust reads raw bytes and strips only the line terminator + UTF-8-validates
  (`main.rs:189-192, 346-360`); it **never JSON-parses the tool call**. The
  whole raw `line` string is handed to Lean opaquely (`classify(line)`
  `main.rs:375`; `step` with `line` embedded `main.rs:401-409`).
* The FFI seam is string-in / verdict-out (`lean.rs:46-48`,
  `seal_host_classify → u32`, `seal_host_step → JSON`). The returned JSON
  carries only `{route, response, audit}` (`route.rs:79-97`) — **no resolved
  target hash, no target part-list.**
* The config envelope containing each tool's `target` spec
  (`[{literal},{arg}]`) is `read_to_string`'d and passed opaquely to
  `host.init`; `init` returns only file paths + TTL (`main.rs:242-277`) —
  Rust never sees the tool rules.
* Pre-Stage-2, the `target` u64 on the Rust side (`ApprovalRecord.target`,
  `providers.rs:36-44`; used by `a3.rs` for freshness) was the value an
  **approver declared**, not the value the **current call resolved to**.
  Current Rust transports accept only lowercase 64-hex SHA-256 targets.
* The resolved target first becomes visible to Rust **only after** the gate,
  and only on **block**. Before Stage 2 this was a decimal substring of the
  kernel's response; the current kernel emits "`approval required: <64hex>`".
  On the **forward** path it is never exposed.

**Consequence:** a host-layer pre-gate `pg ∈ U` check is not feasible
without duplicating the target-derivation TCB (argument parse +
per-tool `[{literal},{arg}]` application + canonicalization + hash) in
Rust — which also re-introduces exactly the parser differential the design
forbids (`route.rs:104`).

### R2 — is the shipped demo policy's legitimate universe finite?

**No — open-ended by construction.** The shipped policy
(`config/trusted.example.json`) has one guarded tool:

```
db.execute  target = [ {literal:"db"}, {arg:"database"}, {literal:"write"}, {arg:"sql"} ]
```

The `sql` (and `database`) parts are `.argPath` — the resolved part-list
embeds **raw, attacker-influenceable, free-form SQL text**. The legitimate
target universe is therefore every `(database, sql)` an operator might ever
approve: unbounded. A finite allowlist `U` of resolved targets cannot cover
legitimate `db.execute` use without either enumerating all future SQL
(impossible) or degrading to a coarse label (which changes the security
semantics — see option B). `U` is a genuine finite universe ONLY for
policies whose guarded target parts are all `.literal` / drawn from a small
closed value set; the demo policy is not one.

---

## Design fork — all three options

### (A) Host-layer allowlist (host confines resolved target to finite `U` pre-gate)

| dimension | verdict |
|---|---|
| touches frozen mcp-seal? | No — IF it could be built host-side. |
| change surface | Would need a full `evalTargetParts` re-implementation in Rust (arg JSON parse, per-tool target-spec application, exact target encoding/hash) + the allowlist file. |
| breaks `.argPath`? | **Yes.** The demo's `sql` universe is open-ended (R2); any finite allowlist denies legitimate destructive-SQL approvals that don't pre-exist in the list. |
| closes the residual? | **No, and not feasible.** (i) Rust has no resolved target pre-gate (R1) — the check cannot run where it must. (ii) Re-deriving the target in Rust duplicates the frozen TCB and creates a parser differential; a mismatch between the Rust re-derivation and the Lean classifier is a NEW bypass surface, not a fix. (iii) Even granting a perfect re-derivation, an open-ended legitimate universe makes the allowlist either unsound (too permissive) or function-breaking (too strict). |

**Rejected.** Infeasible at the layer it must run, and function-breaking on
the shipped policy even if feasible.

### (B) Arg canonicalization to a finite label domain (before hashing)

| dimension | verdict |
|---|---|
| touches frozen mcp-seal? | **Yes.** The `.argPath` → value resolution is `evalTargetParts` (`Seal/Classify.lean:32-36`, frozen). Mapping raw scalars into a finite label domain before hashing is a change to classifier semantics. |
| change surface | `evalTargetParts` + the label-domain function + every consumer of the resolved target (audit, receipts, the JS `stableHashParts` mirror). |
| breaks `.argPath`? | Changes its MEANING: canonicalizing `sql` to a coarse label (e.g. `"drop"`) makes `U` finite but **weakens binding** — one approval for the label authorizes every call sharing it (approve-one-drop → authorize-all-drops). That is a security regression dressed as confinement. |
| closes the residual? | Technically makes `U` finite, but by discarding the per-call specificity the approval was supposed to bind. Trades a collision residual for a coarsening residual — not honest closure. |

**Rejected for the general case; frozen-edit + semantics change.** (A
label-domain design MAY be right for a *future* policy language where
operators intend coarse grants — but that is a policy-model redesign, not a
residual fix, and it is a council decision.)

### (C) CR-hash swap (FNV-1a-64 → SHA-256) — RECOMMENDED, now shipped

| dimension | verdict |
|---|---|
| touches frozen mcp-seal? | **Yes historically.** The private kernel now carries this change in `mcp-seal-dev`; the public frozen `mcp-seal` was not touched. |
| change surface (blast radius) | Large; Stage 1-3 did the split, repin, and cross-language mirror update. |
| breaks `.argPath`? | **No.** Keeps the exact per-call target semantics; `U` need not be finite. |
| closes the residual? | **Yes, honestly.** Under SHA-256 collision resistance (a *standard, believed* assumption — vs FNV, a *known-false* one), `stableHashParts pg' = stableHashParts pa ⇒ pg' = pa` computationally, so an out-of-universe colliding `pg'` cannot be crafted. The `pg ∈ U` hypothesis of the landed theorem can then be RETIRED in favor of an injective-hash argument that holds for ALL `pg`, not just a finite universe. |

**Honest framing:** neither FNV nor SHA-256 gives *provable-in-Lean*
collision resistance — CR is a cryptographic assumption either way. The
difference is that (C) moves from an assumption known to be FALSE (FNV
collisions are trivially findable) to one believed TRUE and standard for
exactly this use. That is the real closure: the residual is a broken-hash
residual, and (C) fixes the hash.

**Historical blast radius of (C) (what Stage 1-3 executed):**

* Frozen kernel: `Seal/Hash.lean` + every `SealCore`/`Kernels` consumer that
  keys on `Hash` (audit `certHash`, `Std.HashMap Hash Nat` approval state,
  `Host/Record.lean` chain).
* The deployed **wasm changes** → each pinned `seal.wasm` sha256 is invalidated.
  The current private verified seal-host pin is `a6a73fa5…` in
  `wasm-spike/verified/PROVENANCE.txt`; public/runtime repins remain separate,
  audited steps.
* The JS `stableHashParts` mirror (receipt-format.js / seal-config.js /
  decide.cjs — the whole `capabilityTarget` convention in
  `docs/DECISION-RECEIPT-SCHEMA.md`) must swap to SHA-256 in lockstep, or
  the four-bodies conformance chain breaks.
* Target commitments split from `Hash = UInt64` into `TargetHash = Digest256`;
  audit `certHash` remained the legacy UInt64 decimal-string encoding.
* Every landed proof that kernel-`decide`s over concrete FNV values
  (including `Host/CapabilityAdequacy.lean`'s `demoU_mirror_adequate` and
  the SealCore separation lemmas) re-derives against new digests.

---

## Recommendation

**(C) CR-hash swap was the only option that genuinely and honestly closed the
residual** — (A) was infeasible at the host layer and function-breaking on the
shipped policy, (B) was a frozen edit that weakened binding semantics. The
private Stage 1-3 rollout shipped (C) by widening only the target commitment,
leaving UInt64 `certHash` audit/demo hashes explicitly on `Seal.auditHashParts`.
The remaining assumption is the theorem's named A-CR hypothesis over SHA-256,
not the old known-false FNV target story.

## Exact change surface if (C) is approved (for the council)

1. Private kernel `Seal/Hash.lean`: `stableHashString` → SHA-256;
   `SealCore.TargetHash` → 256-bit digest type while `SealCore.Hash` remains
   the UInt64 audit hash.
2. Recheck every `#guard_msgs`-pinned proof that touches target hash values
   without changing the landed capability theorem statements.
3. Rebuild + audited repin of `seal.wasm`; update all four sha-pin sites.
4. Swap the JS `stableHashParts` mirror to SHA-256 across seal-check / kit /
   seal-live-demo; re-run the four-bodies conformance chain.
5. Keep receipt `certHash` as legacy UInt64; only target fields move to hex.

This document records the pre-rollout rationale; the implementation lives in
the Stage 1-3 commits.
