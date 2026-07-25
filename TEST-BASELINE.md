# Test baseline: what is red, why, and since when

> **RESOLVED 2026-07-25 16:00, same day.** Everything below is the state as
> first measured at 11:00, kept verbatim. The outcome:
>
> ```
> 11:00   86 passed / 23 failed   7 red binaries, causes unknown
> 16:00  105 passed /  1 failed   1 red binary, cause known and scheduled
> ```
>
> **R1, the guard-target rule: CLOSED.** It was a shipped-product defect, not a
> test defect. `config/payload.example.json` and the sqlite-sandbox profile
> carried guarded rules the pinned kernel rejects at parse time, so a user
> following our own documentation got a hard error. Fixed in the configs, with a
> negative control driving the real host load path and asserting the exact error
> string. Merged `f2de838`.
>
> **R2, the 0/1 classify contract: CLOSED.** The guards were right; the tests
> encoded the pre-fix contract. Widened to 0/1/2 with
> `refusal_fires_on_the_inputs_it_must` pinning four inputs that MUST refuse, so
> the widening cannot silently absorb a guard that stops firing. Merged
> `d573774`.
>
> **The four SUSPECTED rows resolved as suspected**, all R1, all green:
> `host_path` 0/11 to 12/0, `interactive_path` 0/2 to 2/0, `receipt_identity`
> 0/2 to 2/0, `topology_matrix` 1/2 to 3/0.
>
> **Still red, deliberately: `three_way_agreement`.** The pinned `seal.wasm`
> predates the wire guards, so native and the model refuse unsafe-number cases
> the wasm passes through. Deferred until after the batched `seal.effect/v2`
> plus comprehension shape change so the artifact is rebuilt once, not twice.
> `emcc` installed 2026-07-25, so it is unblocked.
>
> **No assertion was relaxed to get here.** Two of the fixes were product
> defects that happened to surface as test failures.
>
> The original text below is kept rather than rewritten, because a baseline
> edited to match its outcome is not a baseline.

---

Started 2026-07-25. The point of this file is that "the suite passes" was true
and meaningless for four days, because the suite was running against a shared
object that could not be rebuilt. This records what has actually been OBSERVED,
at which commit, against which artifact.

**Rule for this file: a row is only written after the failure was reproduced on
this machine.** No inferred rows. A suspected cause stays labelled SUSPECTED
until someone reproduces the mechanism, not just the symptom.

## The artifact matters as much as the commit

`libsealffi.so` is a build output, not a tracked file, so "the suite at commit
X" is an incomplete statement. Every observation below names both.

| | |
|---|---|
| Repo commit | `ca45844` (main, 13 ahead of `origin/main` = `ad4e5c0`) |
| `libsealffi.so` | rebuilt 2026-07-25 10:08 from the current kernel |
| Previous `.so` | dated 2026-07-20 01:52, **four days stale** |
| Why it was stale | `scripts/build_ffi_so.sh` could not link from 2026-07-25 01:52 onward; `Host/UnicodeKeys` was missing from `PROJECT_MODULES` and UnicodeBasic's hand-written `libunicodeclib.a` was never collected. Fixed in `902a621`. |

Everything below is against the REBUILT object. Against the stale one much of
it passed, which is exactly the problem.

## Observed state, 2026-07-25 11:00

Run with `cargo test --no-fail-fast`. Without that flag cargo stops at the first
failing binary and reports a partial picture, which is how this stayed small in
earlier reports today.

### Passing

| Target | Result |
|---|---|
| `src/lib.rs` unit | 44 passed |
| `src/main.rs` unit | 13 passed |
| `tests/envelope_v23_twin.rs` | 2 passed, 1 ignored |
| `tests/panic_probe.rs` | 2 passed |
| `tests/principal_identity.rs` | 5 passed |
| `tests/python_signed_provider.rs` | 1 passed |

### Failing

| Target | Result | Root cause | Status |
|---|---|---|---|
| `tests/topology_matrix.rs` | 1 passed, rest fail | R1 | **CONFIRMED** |
| `tests/three_way.rs` | 0 passed, 2 failed | R1 | **CONFIRMED** |
| `tests/differential.rs` | 11 passed, 2 failed | R2 | **CONFIRMED** |
| `tests/host_path.rs` | 0 passed | R1 | SUSPECTED |
| `tests/interactive_path.rs` | 0 passed (20s) | R1 | SUSPECTED |
| `tests/parser_boundary.rs` | 0 passed | R2 | SUSPECTED |
| `tests/receipt_identity.rs` | 0 passed | R1 | SUSPECTED |

## R1 — the guard-target restriction rejects the shared test fixture

Observed verbatim from the `seal-host` executable under `topology_matrix`:

```
trusted config rejected: trusted config rejected:
guard mode requires target [{"full_arguments": true}]
```

The rule is real and deliberate: `Seal/Policy.lean:114-138`. A guarded rule may
carry ONLY `target: [{"full_arguments": true}]`; literal parts, arg paths and
the empty list are a hard parse error, because a narrower target binds the
approval to less than the full canonical arguments. `Seal/PolicyLegacy.lean:41`
states the same rule.

`Seal/Policy.lean:218-219` maps BOTH `"guard"` and `"guarded"` to
`ToolMode.guarded`, so the fixture's `"mode":"guarded"` is squarely in scope.

The fixtures across the suite mint configs with mixed literal/arg targets, which
that rule forbids. They pre-date the restriction.

### The suspected divergence inside R1: RESOLVED, there was none

Recorded in full because the wrong version of this was believed for an hour and
acted on, and the correction is more instructive than the finding would have been.

**What was observed at 10:12:** `three_way` reported `native=161 wasm=161
model=0`. The `seal-host` executable rejected the fixture config while the
`.so`-loaded native lane appeared to accept it. That looked like two compiled
artifacts of one kernel source reaching opposite verdicts on config validity,
which would have been a validation bypass in the shipping artifact.

**What settled it:** with a fully current `.so`, native rejects too.

```
native init rejected: {"error":"trusted config rejected:
guard mode requires target [{\"full_arguments\": true}]","ok":false}
```

**Why the earlier observation was wrong.** The `.so` hand-built at 10:08 was
still not fully current. Cargo's build script rebuilt it at 10:53 once
`scripts/build_ffi_so.sh` could link again, and only that object enforces the
rule. So the 10:12 run measured a half-updated artifact. All three lanes agree
once every artifact is genuinely current.

**Two explanations were eliminated on the way, both by evidence rather than
argument.** The lanes are NOT handed different documents: `mint_envelope`
(`three_way.rs:585-601`) builds `envelope` as `{"payload": <that exact payload
string>, "signature": ...}` and returns both, so the signed wrapper carries
byte-identical policy content to the raw payload. And simple staleness was not
visible by inspection either: `strings` found the rule's error text in BOTH the
`.so` and the executable, because the string was present while the enforcing
code path was not yet the linked one.

**Standing lesson.** "I rebuilt the artifact" is not the same as "the artifact
is current". Confirm by observing the artifact enforce something it could not
have enforced before, not by its timestamp and not by a `strings` hit.

## R2 — new wire guards return a third classify outcome

`differential.rs` asserts classify only ever returns 0 or 1. It now returns 2
(`refuse`) for:

```
{"method":"tools/call","params":{"name":"x","arguments":{"a":1,"a":2}}}
{"method":"initialize","method":"tools/call","params":{"name":"x"}}
{"method":"tools/call","params":{"name":"x","arguments":{"v":18446744073709551615}}}
```

Duplicate object keys, duplicate `method` keys, oversized integer. Those are the
`wireKeysSafe` / `wireDigitsSafe` / `wireNumbersSafe` guards added on 2026-07-24
to close the duplicate-key mediation bypass (`Host/Canonical.lean:50-65`).

**The guards are correct. The test encodes the pre-fix contract.** Refusing a
duplicate-key line was the entire point of that fix.

Worth stating plainly: that fix was merged and recorded as green. The test that
drives those guards through the shipping artifact could not have exercised them,
because the artifact could not be rebuilt. The fix was real; the evidence that
it worked was not.

## What this file is for next

For each row above: reproduce the mechanism, not just the symptom, and promote
SUSPECTED to CONFIRMED or correct it. Then, for every check that guards
something, record the ablation that was seen to make it fail. A check never
observed failing is not yet a check.
