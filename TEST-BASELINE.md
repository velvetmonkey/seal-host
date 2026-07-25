# Test baseline: what is red, why, and since when

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

### The open divergence inside R1

Not resolved, and it is the important part:

- the `seal-host` EXECUTABLE rejects the fixture config (`topology_matrix`, above)
- the `.so`-loaded native lane ACCEPTS the same shape and produced 161 verdict
  lines (`three_way`, run at 10:08 AFTER the rebuild)

Two compiled artifacts of the same kernel source reaching opposite verdicts on
config validity. Either the `.so` is still not fully current despite the relink
(archive staleness inside `archive_package_ir`), or the two paths genuinely
differ. **Until this is settled, do not assume the shipping `.so` enforces what
the kernel proves.**

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
