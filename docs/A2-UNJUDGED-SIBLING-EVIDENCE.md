# LANE `a2differential` — report

**Verdict: DIVERGENCE MEASURED.**

Measured at `seal-host` `main` = `814f6b8`, tree clean (only the two untracked
files `AGENTS.md` / `CLAUDE.md` that were already untracked at lane start). No
tracked file was read-modified; nothing was committed, repinned, or refreshed.

The divergence is **not** a parser disagreement. Host and child parse the same
bytes to the same JSON. The divergence is one of **judged scope**: the host's
judged event is a strict projection of the event the child receives. Concretely
— `Host.classifyLine` builds a `CanonicalAction` from `Seal.toolsCall?`, which
reads exactly `params.name` and `params.arguments`
(`.lake/packages/mcp-seal/Seal/Classify.lean:278-288`). Every other member of
`params` is invisible to policy matching and to every kernel verdict, and is
then forwarded to the child **verbatim** through the gated `write_child` sink
(`rust/src/main.rs:527`, `:1559`). The kernel says so in its own comment:
"Policy matching and target-part selection inspect arguments only"
(`Seal/Classify.lean:68-71`).

This is exactly the second half of the `CLAIMS.md:37` residual — "…argument
defaults, Unicode or **tool semantics**, so the theorem can hold of the host's
parsed event while the child executes a different one" — and it is **not**
covered by the existing A2 classification. `docs/A2-RESIDUAL-PROPOSED.md`
scopes A2 to byte-level parser divergence in three classes (a) surrogates,
(b) binary64 numbers, (c) nesting depth, and its refutation criteria all
require "any real parser [to] extract different `(tool, arguments)`". Here no
parser disagrees and `(tool, arguments)` is identical on both sides. This
finding therefore **does not refute** that classification; it names a
divergence class the classification never ranged over.

`step_forward_non_bypass` remains true. Every forward below carried a
non-empty gating-verdict list with every verdict `Allow`. The theorem holds of
the judged event; the child receives more than the judged event.

---

## The measurement

### The headline A/B

A two-rule policy of an ordinary shape:

```json
[ {"name":"db.execute","mode":"guarded",
   "match":{"type":"contains_any_ci","arg":"sql",
            "needles":["drop","delete","truncate"]},
   "target":[{"full_arguments":true}]},
  {"name":"db.execute","mode":"allow","match":{"type":"always"},"target":[]} ]
```

One needle, `"DROP TABLE users"`, moved between placements. Same host, same
policy, same session, same run.

| # | Placement of the needle | Kernel verdict | Route | Reached child? |
|---|---|---|---|---|
| D0 | `params.arguments.sql` | **deny** | block | no — approval required |
| D1 | `params._meta.sql` | allow | forward | **yes, byte-exact** |
| D2 | `params.requestState.sql` | allow | forward | **yes, byte-exact** |
| D3 | `params.inputResponses.sql` | allow | forward | **yes, byte-exact** |
| D4 | `params.elicitation.sql` (unknown sibling) | allow | forward | **yes, byte-exact** |
| D5 | absent (clean control) | allow | forward | yes |

D1–D4 are judged `explicit policy allow` on `arguments = {"database":"prod",
"sql":"select 1"}`. The recorder child logged, for D1:

```
b'{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"db.execute",
"arguments":{"database":"prod","sql":"select 1"},"_meta":{"sql":"DROP TABLE users"}}}\n'
```

The judged event contains no `DROP`. The delivered event does. The seven
pre-parse guards are irrelevant to all six lines — every one of them passes
all seven (below).

### Full result table

`ast?` is the SealV2 canonical parse attached for audit. Guard numbering
follows `Host/Canonical.lean` (1 `JsonUtil.wireNumbersSafe`:53, 2
`JsonUtil.wireKeysSafe`:61, 3 `UnicodeKeys.wireKeysSafe`:68, 4
`JsonUtil.wireDigitsSafe`:74, 5 `JsonUtil.wireNumbersAgreementSafe`:82, 6
`SurrogateEscapes.wireSurrogatesSafe`:90, 7 `NestingDepth.wireDepthSafe`:97).
Guard results are not inferred from the route — they were evaluated
individually in Lean against the built `.olean`s (the scratch harness's
`guard_attest.lean`).

| Line | 7 guards | Host judgement | Child record | Receipt commitment | Verdict |
|---|---|---|---|---|---|
| A1 baseline `m7.echo` | **7/7 pass**, `act(m7.echo, ast?=some)` | allow, allow; forward | received; unjudged members `[]` | `request_sha256` `5d986c39…`; `canonical_request_sha256` `5d986c39…` | control, no divergence |
| A2 `+ _meta` | **7/7 pass**, `act`, `ast?=some` | allow, allow; forward | received byte-exact; unjudged `['_meta']` | `request_sha256` `e1f5f520…` ✔ distinct; `_meta` projected in cleartext at top level and in `effect_view.effect` ✔; `canonical_request_sha256` `83ec113d…` ✔ distinct | **DIVERGENCE, receipt names it** |
| A3 `+ requestState` | **7/7 pass**, `act`, `ast?=some` | allow, allow; forward | received byte-exact; unjudged `['requestState']` | `request_sha256` `bf828943…` ✔; `requestState` projected ✔; `canonical_request_sha256` distinct ✔ | **DIVERGENCE, receipt names it** |
| A4 `+ inputResponses` | **7/7 pass**, `act`, `ast?=some` | allow, allow; forward | received byte-exact; unjudged `['inputResponses']` | `request_sha256` `17014703…` ✔; `inputResponses` projected ✔; `canonical_request_sha256` distinct ✔ | **DIVERGENCE, receipt names it** |
| A5 `+ elicitation` (unknown sibling) | **7/7 pass**, `act`, `ast?=some` | allow, allow; forward | received byte-exact; unjudged `['elicitation']` | `request_sha256` `812322a2…` ✔ distinct; **no cleartext projection anywhere**; `canonical_request_sha256` `5d986c39…` — **byte-identical to A1's**; receipt filename hash component identical to A1's | **DIVERGENCE, receipt does NOT name it** |
| D0 needle in `arguments` | **7/7 pass**, `act(db.execute)` | deny (guard target `b3a20639…`); block | not delivered | block receipt | fail-closed, correct |
| D1–D4 needle in `_meta`/`requestState`/`inputResponses`/`elicitation` | **7/7 pass** each | allow (`explicit policy allow`); forward | delivered byte-exact | D1–D3 project the member; D4 shares `canonical_request_sha256` `372ce9e0…` with the clean D5 | **DIVERGENCE that matters** |
| D5 clean control | **7/7 pass** | allow; forward | delivered | `canonical_request_sha256` `372ce9e0…` | control |
| B1–B5 guarded, five `_meta`/`requestState`/`inputResponses`/unknown variants | **7/7 pass** each | deny; block. **Guard target identical across all five and the clean line**: `1165ee20…` | not delivered | block receipts | see FAILED ATTEMPTS #2 |
| REF dup-key `{"x":1,"x":2}` | 5/7 — **fails 2 and 3** | `.refuse` | not delivered | — | negative control, fail-closed |
| REF lone surrogate `"\ud800"` | 6/7 — **fails 6** | `.refuse` | not delivered | — | negative control, fail-closed |
| REF monster exponent `1e1000000` | 5/7 — **fails 1 and 5** | `.refuse` | not delivered | — | negative control, fail-closed |
| REF 19-digit int | 5/7 — **fails 4 and 5** | `.refuse` | not delivered | — | negative control, fail-closed |

Every finding line above passes all seven guards. No result here depends on a
guard being absent.

### Precisely which receipt fields fail to commit the difference

The receipt is not blind. `request_sha256` (SHA-256 of the terminator-stripped
line) and `framed_subject_sha256` (SHA-256 of the frame including `\n`)
distinguished **every** line tested — six distinct wire lines, six distinct
values of each. The byte-level commitment is intact.

What does **not** commit the difference:

1. **`canonical_request` / `canonical_request_sha256`.** These are a
   *reconstruction*, not the wire line. `canonical_request()`
   (`rust/src/authorization_decision.rs:108-128`) rebuilds `params` from
   `name`, `arguments`, and only the three named members `_meta`,
   `requestState`, `inputResponses`, and hardcodes `id: 1`
   (`:124`, `request.insert("id".into(), Value::from(1))`). Measured
   consequence: six wire lines differing in `id` (1 / 987654 / `"abc-42"`) and
   in unknown params siblings (`elicitation`, `zz`) all produced the **same**
   `canonical_request_sha256` `5d986c39…`. This projection is **declared** in
   `docs/AUTHORIZATION-DECISION-SCHEMA.md:81-108` — it is documented lossy
   behaviour, not undeclared drift. It is reported here because it is the
   field a verifier reads, and because of item 2.
2. **The receipt filename.** `receipt-{entry:020}-{canonical_request_sha256}`
   (`authorization_decision.rs:553`, `:575`). The six probe lines produced six
   files whose hash component is identical; only the entry counter separates
   them. Nothing is overwritten, but the filename does not identify the line.
3. **`args_hash`.** Identical (`5041bf1f…`) across A1–A5 by construction.
4. **Cleartext record of the smuggled member.** `_meta`, `requestState` and
   `inputResponses` are projected into the receipt in cleartext at top level
   and inside `effect_view.effect`. **Any other params member is not recorded
   anywhere in cleartext.** For A5/D4 the only trace that `elicitation`
   existed is `request_sha256`/`framed_subject_sha256` — opaque digests an
   auditor can use only if they independently retained the original line.

So the honest statement: the receipt **commits** the difference (byte digests)
but does not **name** it outside the three known MRTR members.

---

## Reproduction

Harness: a scratch `a2differential` directory outside the repository.
Binary and Lean core actually exercised, per receipt `host_identity`:
`native_executable_sha256 = be914ee2d257766851155785227961d54a268577aa228ed4be551242c6e1c997`
(`rust/target/release/seal-host-rs`),
`lean_ffi_sha256 = 4cdeb77a49a8484c1abf772af2154e39e06c260e461e28932f8ce697e5d56036`
(`.lake/build/lib/libsealffi.so`).

```bash
# From the scratch a2differential harness directory:
python3 probe_smoke.py      # harness sanity + the four guard negative controls
python3 probe_a2.py         # A-series: unjudged members reach the child; B-series guard targets
python3 probe_smuggle.py    # the headline D-series A/B
python3 probe_canonical.py  # the canonical_request_sha256 collision class
python3 probe_approval.py   # production signed channel: approval substitution (see FAILED ATTEMPTS)

# From the seal-host repository root, with the scratch harness path substituted:
lake env lean --run <scratch-a2differential-dir>/guard_attest.lean  # seven-guard attestation
```

`recorder_child.py` is the instrumented child. It executes nothing; it appends
one NDJSON record per received line containing `received_hex`, `received_repr`
and `would_act_on` (the full `params`), then answers one JSON-RPC result so the
host's lockstep protocol is satisfied. The harness config shape is copied from
`rust/tests/host_path.rs`.

---

## FAILED ATTEMPTS

The most valuable section, per the brief. Three attempts to escalate the
finding failed, each because a real defence held.

**1. Approval substitution across the unjudged members — BLOCKED, correctly.**
The hypothesis: since the guard target ignores `_meta`, an approval issued for
line L should authorize L′ that differs only in `_meta`. On the production
`ed25519` channel with the sqlite replay store: approve L (target
`1165ee20…`, subject = the exact 127-byte frame), then send L′. Result:
`{"approval_drop":{"source":"approval-v2-context","reason":
"target_or_subject_mismatch"}}`, L′ blocked. Control in the same harness —
approve L, send L — forwarded to the child. `ApprovalRecord` v2's
`subject_sha256` binds the exact delimiter-bearing frame, so the guard-target
collision is **not** exploitable. This defence is real and load-bearing.

**2. Guard-target fungibility on its own — measured, but inert.** All five
guarded variants (clean, `_meta`, `requestState`, `inputResponses`, unknown
sibling) produce the **identical** target `1165ee208c95e3fd4a402598a61d43f
97363dcea314d5541af9d8adbf74dd1f9`. The kernel *has* the binding machinery —
`guardTargetWithContext` folds metadata/requestState/inputResponses into the
preimage and `guard_target_separates_inputResponses` proves the separation
(`Seal/Classify.lean:72-86`, `:175-186`) — but the deployed path calls
`Seal.classifyToolCall`, which hardcodes all three to `.absent`
(`Seal/Classify.lean:265-268`, used at `Kernels/Safety.lean:48` and
`Host/Commit.lean:229`). Nothing in `Host/`, `Kernels/` or `Ffi.lean` calls
`classifyToolCallWithContext`. So: the target is fungible, but attempt 1 shows
`subject_sha256` covers the gap. Recorded as a latent single-point dependence,
not an exploit.

**3. Legacy control-file approval replay — BLOCKED by removal, not by
binding.** Writing `{"target":…,"issuedAt":…,"nonce":…}` to the control file
yields `{"approval_drop":{"source":"control-file","reason":
"approval_record_v1_not_supported"}}`. `ControlFileProvider::poll` parses only
`LegacyApprovalRecord` and routes every one through `refuse_v1_approval`
(`rust/src/providers.rs:648-660`), so the control-file channel can no longer
grant any approval at all. Worth knowing: `docs/` and demo material still
describe it as an approval channel.

**4. `NestingDepth.wireDepthSafe` (guard 7) is unreachable in the deployed
binary via depth.** A 200-deep line is refused earlier by a Rust-side resource
limit — `{"seal_host_event":"resource_limit_refusal","limit":"json_depth",
"maximum":64}` — and 64 < the Lean guard's serde-derived 128. Guard 7 never
fires on depth in the deployed host. Not pursued further; noted because it
means the guard-7 column above is attested by the Lean evaluation, not by a
deployed refusal.

**5. Not attempted, deliberately.** No attempt was made to manufacture a
byte-level parser divergence outside classes (a)/(b)/(c). The corpus lane has
already measured that surface (18/18 fail-closed on the unmerged guardstack);
re-deriving it here would have added nothing and risked passing off a guard
gap as a finding.

---

## UNVERIFIED

- **Whether any real MCP server acts on `_meta` / `requestState` /
  `inputResponses` in a security-relevant way.** The child here is a recorder
  of my own construction. It proves the bytes arrive unjudged; it does not
  prove a deployed server does something dangerous with them. The MCP-spec
  reading — `requestState` and `inputResponses` are elicitation state, i.e.
  semantically load-bearing — makes it plausible, and
  `docs/V31-DOWNSTREAM-PARSER-AGREEMENT.md` is the precedent for turning that
  into a witnessed per-server fact. Not done in this lane.
- **`libsealffi.so` vs `814f6b8`.** The `.so` on disk is from 2026-08-03
  07:27; `814f6b8` is 17:05. The only commits in between touch
  `Host/ObjectB.lean` and `Test/Axioms.lean`, neither on the classify or step
  path, and `Host/Canonical.lean` is unchanged since 2026-07-31. I did not
  rebuild to prove byte-equality, so "the `.so` represents `814f6b8` on the
  measured path" is an argument from the diff, not a verified rebuild.
- **The `rust/target/release/seal-host-rs` binary** is from 2026-07-31 06:21.
  It loads `libsealffi.so` dynamically via rpath, so the Lean side is current;
  the Rust side is not proven identical to `814f6b8`'s sources. The Rust files
  I quote (`main.rs`, `providers.rs`, `authorization_decision.rs`) are
  unmodified since well before that build.
- **The brief's citation `ASSUMPTIONS.md:63` does not resolve at `814f6b8`.**
  The only `ASSUMPTIONS.md` is `docs/ASSUMPTIONS.md`, 21 lines, containing no
  A2 text. The quoted wording is at `CLAIMS.md:63`. The primary citation,
  `CLAIMS.md:37`, is verbatim correct.
- **Scope.** Only the `compatible` profile, only stdio, only `tools/call`, only
  the params-sibling axis. Duplicate members, numeric precision and Unicode
  were exercised **only** as negative controls confirming the guards fire; they
  were not probed for new divergences.

---

## Closing

Closing this is a **cheap host change, not the `canonical-l0` profile**:
`canonical-l0` gates on canonical-*reject*, and every divergent line here is
canonical (`ast? = some` on all of them), so the strict profile would forward
them identically — the fix is to stop calling `Seal.classifyToolCall` with
three hardcoded `.absent`s and call the already-proved
`classifyToolCallWithContext` with the real `validatedMetaFromParams` /
`RequestState` / `InputResponses`, plus a ruling on unknown `params` siblings
(refuse, or bind into the target) — but note the blocker before anyone starts:
that switch changes every guard target, and `guardTargetDomainTag` is
`"seal.guard-target/v2-proposed-meta-all"`, an explicitly **unpinned Phase-M
proposal** whose own doc comment says changing it "invalidates every target,
approval, capability, and replay key that depends on it", so this needs Ben's
pin ruling, not a lane's initiative.
