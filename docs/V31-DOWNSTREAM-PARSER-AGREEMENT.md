# V3.1 downstream parser-agreement experiment

Date: 2026-07-27

RUN: `/tmp/seal-v31rest.RUN`

Branch/worktree: `v31run/downstream-parser-agreement` at
`/home/monkey/wt/v31rest`. The lane used a temporary Lake package override to
build and run exact `mcp-seal-dev`
`b83fdffdf09ed2bec38ff2dd813b42961988085c`; it did not change the checked-in
manifest or repin the repository.

## Result

All 18 triaged parser-boundary divergence vectors ran to completion. Nine were
refused before forwarding, and all nine that were forwarded disagreed with at
least one downstream parser. Thus the headline is:

**9 new false-receipt vectors among 9 forwarded divergence vectors.**

The 18-vector result has no `UNKNOWN` cell. The complete matrix is 18 vectors
by 5 configured observers (90 cells), plus a 5-observer negative control.

## Vector table

| Vector | Classification | Observer cells |
|---|---|---:|
| `i_number_neg_int_huge_exp.json` | REFUSED by the guard | 5 refused |
| `i_number_pos_double_huge_exp.json` | REFUSED by the guard | 5 refused |
| `i_number_real_neg_overflow.json` | REFUSED by the guard | 5 refused |
| `i_number_real_pos_overflow.json` | REFUSED by the guard | 5 refused |
| `i_number_real_underflow.json` | REFUSED by the guard | 5 refused |
| `i_number_too_big_neg_int.json` | REFUSED by the guard | 5 refused |
| `i_number_too_big_pos_int.json` | REFUSED by the guard | 5 refused |
| `i_number_very_big_negative_int.json` | REFUSED by the guard | 5 refused |
| `i_string_1st_surrogate_but_2nd_missing.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_string_1st_valid_surrogate_2nd_invalid.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_string_incomplete_surrogate_and_escape_valid.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_string_incomplete_surrogate_pair.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_string_incomplete_surrogates_escape_valid.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_string_invalid_lonely_surrogate.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_string_invalid_surrogate.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_string_inverted_surrogates_U+1D11E.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_string_lone_second_surrogate.json` | **FORWARDED and observers DISAGREE** | 4 extracted differently; 1 rejected |
| `i_structure_500_nested_arrays.json` | REFUSED by the guard | 5 refused |

## New disagreements, verbatim values

Every action below has tool `external.json_corpus`. Values are shown in escaped
code-unit notation: `\uFFFD` is Lean's replacement character; a downstream
`\uD800`–`\uDFFF` token denotes the lone UTF-16 code unit that observer
actually extracted. Roundtable extracted no value because its parser rejected
the exact forwarded frame.

| Vector | Kernel `arguments` | GitHub | Patchright | Flywheel | Roundtable | SQLite demo |
|---|---|---|---|---|---|---|
| `i_string_1st_surrogate_but_2nd_missing.json` | `["\uFFFD"]` | `["\uDADA"]` | `["\uDADA"]` | `["\uDADA"]` | no value; REJECTS: `Invalid JSON: unexpected end of hex escape at line 1 column 107` | `["\uDADA"]` |
| `i_string_1st_valid_surrogate_2nd_invalid.json` | `["\uFFFD\u1234"]` | `["\uD888\u1234"]` | `["\uD888\u1234"]` | `["\uD888\u1234"]` | no value; REJECTS: `Invalid JSON: lone leading surrogate in hex escape at line 1 column 112` | `["\uD888\u1234"]` |
| `i_string_incomplete_surrogate_and_escape_valid.json` | `["\uFFFD\n"]` | `["\uD800\n"]` | `["\uD800\n"]` | `["\uD800\n"]` | no value; REJECTS: `Invalid JSON: unexpected end of hex escape at line 1 column 108` | `["\uD800\n"]` |
| `i_string_incomplete_surrogate_pair.json` | `["\uFFFDa"]` | `["\uDD1Ea"]` | `["\uDD1Ea"]` | `["\uDD1Ea"]` | no value; REJECTS: `Invalid JSON: lone leading surrogate in hex escape at line 1 column 106` | `["\uDD1Ea"]` |
| `i_string_incomplete_surrogates_escape_valid.json` | `["\uFFFD\uFFFD\n"]` | `["\uD800\uD800\n"]` | `["\uD800\uD800\n"]` | `["\uD800\uD800\n"]` | no value; REJECTS: `Invalid JSON: lone leading surrogate in hex escape at line 1 column 112` | `["\uD800\uD800\n"]` |
| `i_string_invalid_lonely_surrogate.json` | `["\uFFFD"]` | `["\uD800"]` | `["\uD800"]` | `["\uD800"]` | no value; REJECTS: `Invalid JSON: unexpected end of hex escape at line 1 column 107` | `["\uD800"]` |
| `i_string_invalid_surrogate.json` | `["\uFFFDabc"]` | `["\uD800abc"]` | `["\uD800abc"]` | `["\uD800abc"]` | no value; REJECTS: `Invalid JSON: unexpected end of hex escape at line 1 column 107` | `["\uD800abc"]` |
| `i_string_inverted_surrogates_U+1D11E.json` | `["\uFFFD\uFFFD"]` | `["\uDD1E\uD834"]` | `["\uDD1E\uD834"]` | `["\uDD1E\uD834"]` | no value; REJECTS: `Invalid JSON: lone leading surrogate in hex escape at line 1 column 106` | `["\uDD1E\uD834"]` |
| `i_string_lone_second_surrogate.json` | `["\uFFFD"]` | `["\uDFAA"]` | `["\uDFAA"]` | `["\uDFAA"]` | no value; REJECTS: `Invalid JSON: lone leading surrogate in hex escape at line 1 column 106` | `["\uDFAA"]` |

These are false receipts because the kernel signed/approved a
`CanonicalAction` containing replacement characters, while four observers
executed an action containing lone surrogate code units and the fifth could not
parse the frame at all.

## Observer inventory

All 5 configured observers ran. None is unavailable, and none silently no-oped.
Each initialized in all 19 lane cells, reached all 10 forwarded frames (the
nine disagreement vectors plus the negative control), and produced a matched
wire-frame observation or an explicit parser rejection.

| Configured observer | Initialize identity | Forwarded outcomes | Diagnosis |
|---|---|---|---|
| `github-mcp-server@2025.4.8` | `github-mcp-server` `0.6.2` | 9 disagree, 1 agree | ran; available |
| `patchright-lite-mcp-server@1.0.0` | `patchright-lite` `1.0.0` | 9 disagree, 1 agree | ran; available |
| `flywheel-memory@2.12.20` | `flywheel-memory` `2.12.20` | 9 disagree, 1 agree | ran; available |
| `roundtable-ai@0.5.1 (Python MCP 1.27.2)` | `roundtable-ai` `1.27.2` | 9 explicit rejects, 1 agree | ran; available |
| `seal sqlite demo@1.0.0 (toy)` | `seal-sqlite-sandbox` `1.0.0` | 9 disagree, 1 agree | ran; available |

The prior “version string” symptom was a response-phase/probe
misconfiguration, not an unavailable observer: an MCP initialize response
legitimately contains `serverInfo.version`. This harness validates and records
that initialize response separately before sending a vector. Every configured
observer then processed the negative-control vector, and every observer either
processed or explicitly rejected each forwarded divergence vector.

## Negative control

`y_object_simple.json` was forwarded end to end through all five observers.
The kernel value and every observer extraction were verbatim
`{"a":[]}`; all five outcomes were `AGREE`.

- judged payload SHA-256:
  `fd57359d82dfb511c80af53a682127881ccb1b0ff5bf5f9c6aacc1f0d674d765`
- LF-framed wire SHA-256:
  `3e635e1f14e157dc0dcd3922a1196ebb43eaf83fc3e3b4e98a3e91d8cb8ec63f`
- Lean approval target:
  `72e479adb500f247830356fc670df7577d7598e6aa7ec22f326cdf27c288622d`

This demonstrates that the harness distinguishes agreement, differing
extraction, parser rejection, and pre-forward refusal.

## Guard effect

The current binary64 round-trip agreement guard now intercepts the four numeric
vectors that were in the pre-guard forwardable (`Lean Act`) set:

- `i_number_neg_int_huge_exp.json`
- `i_number_pos_double_huge_exp.json`
- `i_number_real_neg_overflow.json`
- `i_number_real_pos_overflow.json`

Only `i_number_neg_int_huge_exp.json` was physically forwarded by the old run;
the old early-stop rule prevented the other three from reaching an observer.
The current reproduction shows all four still produce a Lean action at the
classifier boundary and are then refused by the b83 host guard. A pre-b83
counterfactual rerun of the other three was not performed.

The other four numeric refusals were the previously omitted
Rust-Act/Lean-Refuse vectors. The 500-level nesting vector was already rejected
by the production depth guard. Neither group is silently claimed as a newly
covered old forwarding case.

## Coverage and evidence

The configured class is now characterized completely: 18/18 triaged divergence
vectors, 5/5 configured observers, and 90/90 matrix cells have definite
outcomes. No configured vector or observer remains unrun. This does not claim
coverage of parsers outside the five configured observers or inputs outside
the committed 18-vector divergence set.

Primary evidence:

- `/tmp/seal-v31rest.RUN/results.json`
  (`5c001f589a25e3ed31c3056c9a2d7500782bb022ff1502a8cf2c34054eb6ec70`)
- `/tmp/seal-v31rest.RUN/run2.stderr`
  (`fbcaff735bed3be578c98496caaca4aa2447f5ea7b8804b676a7fa4baefcbeab`)
- preserved cell directories: `/tmp/seal-v31rest.bjyje3xt`
- external corpus reproduction:
  `/tmp/v31rest-external-corpus.stdout` and
  `/tmp/v31rest-external-corpus.stderr` (318 vectors, 18 divergences)
- b83 build logs:
  `/tmp/v31rest-leanbuild-oracle-b83.log` and
  `/tmp/v31rest-build-ffi-b83.log`

The primary results file was independently parsed with Node `JSON.parse`
after the run. Its 95 records comprise 45 refusals, 36 differing extractions,
9 explicit parser rejections, and 5 agreements.

Verification after the run:

- exact-b83 `downstream_parser_oracle` build: pass via
  `/home/monkey/bin/leanbuild`
- exact-b83 `libsealffi.so` build, export gate, and `ldd -r` resolution gate:
  pass
- JSONTestSuite boundary test: pass (318/318; 18 observed divergences)
- complete Rust test suite at b83, serial, with hardcoded Lake invocations
  routed through the leanbuild override: pass (one declared soak test ignored)
- `host_path`: pass (13/13), including
  `numeric_agreement_refuses_at_wire_and_preserves_negative_control`
- harness Python compile, build-script `bash -n`, and `git diff --check`: pass
