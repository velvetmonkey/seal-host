<!-- SPDX-License-Identifier: Apache-2.0 -->

# PATH B — closing the capability-theorem residual (runtime `pg` confinement)

**Status: DESIGN DOC. No spike shipped — the honest recommendation touches
frozen `mcp-seal`, so this stops at a seal-day / council decision (per the
Path-B brief's stop rule).** No `.lake/packages/mcp-seal` edit, no landed
theorem touched, no Rust code added.

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
* The `target` u64 that DOES exist on the Rust side (`ApprovalRecord.target`,
  `providers.rs:36-44`; used by `a3.rs` for freshness) is the value an
  **approver declared**, not the value the **current call resolves to**.
* The resolved target first becomes visible to Rust **only after** the gate,
  and only on **block**, as a decimal substring of the kernel's response
  ("`approval required: <target>`", `main.rs:426-436`; mirror
  `host_path.rs:172-180`). On the **forward** path it is never exposed.

**Consequence:** a host-layer pre-gate `pg ∈ U` check is not feasible
without duplicating the frozen target-derivation TCB (argument parse +
per-tool `[{literal},{arg}]` application + canonicalization + FNV hash) in
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
| change surface | Would need a full `evalTargetParts` re-implementation in Rust (arg JSON parse, per-tool target-spec application, `"|".intercalate`, FNV-1a-64) + the allowlist file. |
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

### (C) CR-hash swap (FNV-1a-64 → SHA-256) — RECOMMENDED, but frozen-gated

| dimension | verdict |
|---|---|
| touches frozen mcp-seal? | **Yes.** `Seal.stableHashString` / `stableHashParts` (`Seal/Hash.lean:11-17`) is frozen. |
| change surface (blast radius) | Large and enumerated below. |
| breaks `.argPath`? | **No.** Keeps the exact per-call target semantics; `U` need not be finite. |
| closes the residual? | **Yes, honestly.** Under SHA-256 collision resistance (a *standard, believed* assumption — vs FNV, a *known-false* one), `stableHashParts pg' = stableHashParts pa ⇒ pg' = pa` computationally, so an out-of-universe colliding `pg'` cannot be crafted. The `pg ∈ U` hypothesis of the landed theorem can then be RETIRED in favor of an injective-hash argument that holds for ALL `pg`, not just a finite universe. |

**Honest framing:** neither FNV nor SHA-256 gives *provable-in-Lean*
collision resistance — CR is a cryptographic assumption either way. The
difference is that (C) moves from an assumption known to be FALSE (FNV
collisions are trivially findable) to one believed TRUE and standard for
exactly this use. That is the real closure: the residual is a broken-hash
residual, and (C) fixes the hash.

**Blast radius of (C) (why it is a seal-day decision, not a tonight build):**

* Frozen kernel: `Seal/Hash.lean` + every `SealCore`/`Kernels` consumer that
  keys on `Hash` (audit `certHash`, `Std.HashMap Hash Nat` approval state,
  `Host/Record.lean` chain).
* The deployed **wasm changes** → the pinned `seal.wasm` sha256
  (`1cc765c7…`, pinned in `docs/CONFORMANCE-BRIDGE.md`,
  `docs/SEAL-SYSTEM-TCB.md`, `wasm-spike/verified/PROVENANCE.txt`, and the
  seal-check / seal-live-demo / seal-assurance-kit runtimes) is invalidated;
  a full audited repin + rebuild is required.
* The JS `stableHashParts` mirror (receipt-format.js / seal-config.js /
  decide.cjs — the whole `capabilityTarget` convention in
  `docs/DECISION-RECEIPT-SCHEMA.md`) must swap to SHA-256 in lockstep, or
  the four-bodies conformance chain breaks.
* `Hash = UInt64` widens to a 256-bit digest → type change through
  `SealCore.Hash`, the audit format, and the receipt schema (`certHash`
  decimal-string encoding).
* Every landed proof that kernel-`decide`s over concrete FNV values
  (including `Host/CapabilityAdequacy.lean`'s `demoU_mirror_adequate` and
  the SealCore separation lemmas) re-derives against new digests.

---

## Recommendation

**(C) CR-hash swap is the only option that genuinely and honestly closes the
residual** — (A) is infeasible at the host layer and function-breaking on the
shipped policy, (B) is a frozen edit that weakens binding semantics. But (C)
touches frozen `mcp-seal` and carries a repo-wide, cross-artifact,
re-audit-the-wasm blast radius. **Per the Path-B stop rule, this is a
seal-day / council decision, not a tonight build.** No spike is shipped:
(A) — the only host-only, no-frozen-edit option — was shown non-viable by
recon (R1) and function-breaking (R2), so spiking it would be building a
known-wrong thing.

**Interim honest posture (already in place, no code change):** the residual
stays a NAMED, documented policy-coverage boundary in
`Host/CapabilityAdequacy.lean`, with the theorem correctly conditioned on
`pg ∈ U` and the operational detector shipped — the assurance kit's
`seal adequacy check` / `seal adequacy find-collision`
(`seal-assurance-kit`) is the deployment-side probe that FINDS an
out-of-universe collision for a given policy universe. That is the honest
mitigation until (C) is scheduled: the gap is disclosed, bounded, and
detectable, not silently open.

## Exact change surface if (C) is approved (for the council)

1. `mcp-seal` `Seal/Hash.lean`: `stableHashString` → SHA-256; `SealCore.Hash`
   → 256-bit digest type. (Frozen-package change — requires unfreezing.)
2. Re-derive every `#guard_msgs`-pinned proof that touches concrete hash
   values (SealCore separation lemmas; `Host/CapabilityAdequacy.lean` —
   whose `pg ∈ U` hypothesis can then be *dropped* for an all-`pg`
   injective-hash theorem, strengthening the result).
3. Rebuild + audited repin of `seal.wasm`; update all four sha-pin sites.
4. Swap the JS `stableHashParts` mirror to SHA-256 across seal-check / kit /
   seal-live-demo; re-run the four-bodies conformance chain.
5. Widen the receipt-schema `certHash` encoding for the larger digest.

Nothing in this document executes any of the above.
