// SPDX-License-Identifier: Apache-2.0
//
// The load-bearing pin for the PINS gate: the registry, ledger, checker
// implementations, and commands CI actually runs must remain a bijection.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  GATED_ROWS,
  GATED_SECTIONS,
  OUT_OF_SCOPE_ROWS,
  PIN_ROWS,
} from "../scripts/pins_gate_rows.mjs";
import {
  CI_RUN_STEP_MINIMUM,
  CHECKS,
  ROOT,
  ciRunStepFloorFailure,
  matchingRows,
  parseBuildGatedGuardCount,
  parseCiRunSteps,
  parseLedger,
  stripSourceComments,
} from "../scripts/pins_gate.mjs";

test("build-gated guard counts accept numerals and common number words", () => {
  assert.deepEqual(parseBuildGatedGuardCount("9 build-gated guards"), {
    count: 9,
    error: null,
  });
  assert.deepEqual(parseBuildGatedGuardCount("nine build-gated guards"), {
    count: 9,
    error: null,
  });
  assert.deepEqual(parseBuildGatedGuardCount("twenty-one build-gated guards"), {
    count: 21,
    error: null,
  });
});

test("unparseable build-gated guard counts are explicit failures", () => {
  const parsed = parseBuildGatedGuardCount("many build-gated guards");
  assert.equal(parsed.count, null);
  assert.match(parsed.error, /unparseable claim: unknown number word `many`/);
});

test("specification-only search strips comments but preserves code strings", () => {
  const fixtures = new Map([
    [
      ".lean",
      [
        "-- line_only",
        "/- outer block_only /- nested_only -/ still_block_only -/",
        'def string_key := "string_only -- not a comment"',
        "structure Witness where",
        "  field_only : Nat",
      ].join("\n"),
    ],
    [
      ".rs",
      [
        "/// doc_only",
        "/* outer block_only /* nested_only */ still_block_only */",
        'const STRING_KEY: &str = r#\"string_only // not a comment\"#;',
        "struct Witness { field_only: u64 }",
      ].join("\n"),
    ],
    [
      ".cpp",
      [
        "// line_only",
        "/* block_only */",
        'const char *key = R\"tag(string_only // not a comment)tag\";',
        "struct Witness { int field_only; };",
      ].join("\n"),
    ],
    [
      ".mjs",
      [
        "// line_only",
        "/* block_only */",
        "const key = `string_only // not a comment`;",
        "const field_only = 1;",
      ].join("\n"),
    ],
    [
      ".py",
      [
        "# line_only",
        'key = """string_only # not a comment"""',
        "field_only = 1",
      ].join("\n"),
    ],
    [
      ".sh",
      [
        "# line_only",
        "key='string_only # not a comment'",
        "field_only=1",
        "embedded#hash=kept",
      ].join("\n"),
    ],
  ]);

  for (const [extension, fixture] of fixtures) {
    const code = stripSourceComments(fixture, extension);
    assert.doesNotMatch(code, /\b(?:line|doc|block|nested|still_block)_only\b/);
    assert.match(code, /\bstring_only\b/);
    assert.match(code, /\bfield_only\b/);
    assert.equal(
      code.split("\n").length,
      fixture.split("\n").length,
      `${extension} comment stripping changed line numbers`,
    );
  }
});

test("every PINS ledger row is classified exactly once", () => {
  const { rows } = parseLedger();
  const failures = [];

  for (const row of rows) {
    const policies = PIN_ROWS.filter((policy) =>
      row.site.includes(policy.anchor),
    );
    if (policies.length !== 1) {
      failures.push(
        `PINS.md:${row.line} [${row.site.replaceAll("`", "")}] has ${policies.length} registry entries`,
      );
    }
  }
  for (const policy of PIN_ROWS) {
    const matches = matchingRows(rows, policy.anchor);
    if (matches.length !== 1) {
      failures.push(
        `registry row ${policy.id} (${policy.anchor}) matches ${matches.length} PINS.md rows`,
      );
    }
  }

  assert.deepEqual(
    failures,
    [],
    `row/check coverage mismatch:\n${failures.join("\n")}`,
  );
});

test("every row is either checked or explicitly out of scope", () => {
  const malformed = PIN_ROWS.filter((row) => {
    const hasCheck = typeof row.check === "string" && row.check.length > 0;
    const hasReason =
      typeof row.outOfScope === "string" && row.outOfScope.length > 0;
    return hasCheck === hasReason;
  });
  assert.deepEqual(
    malformed.map((row) => row.id),
    [],
    "a row must have exactly one of `check` or `outOfScope`",
  );
  assert.equal(
    GATED_ROWS.length + OUT_OF_SCOPE_ROWS.length,
    PIN_ROWS.length,
    "a registry row disappeared from both derived lists",
  );
});

test("a row with no check or a check with no row is impossible", () => {
  const referenced = new Set([
    ...GATED_ROWS.map((row) => row.check),
    ...GATED_SECTIONS.map((section) => section.check),
  ]);
  const implemented = new Set(Object.keys(CHECKS));
  const rowsWithoutChecks = GATED_ROWS.filter(
    (row) => !implemented.has(row.check),
  );
  const checksWithoutRows = [...implemented].filter(
    (check) => !referenced.has(check),
  );

  assert.deepEqual(
    {
      rowsWithoutChecks: rowsWithoutChecks.map((row) => row.id),
      checksWithoutRows,
    },
    { rowsWithoutChecks: [], checksWithoutRows: [] },
    "gated row/check implementation mismatch",
  );
});

test("CI runs the one checker door and this meta-test", () => {
  const ci = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "ci.yml"),
    "utf8",
  );
  const commands = [...ci.matchAll(/^\s*run:\s*(.+?)\s*$/gm)].map(
    (match) => match[1],
  );
  assert.ok(
    commands.includes("node scripts/pins_gate.mjs --check"),
    "ci.yml does not run the canonical PINS checker door",
  );
  assert.ok(
    commands.includes("node --test test/pins_gate_meta.test.mjs"),
    "ci.yml does not run the PINS row/check meta-test",
  );
  assert.equal(
    commands.filter((command) => command.includes("pins_gate.mjs --check"))
      .length,
    1,
    "CI must invoke the PINS checker once, not copy-paste row checks",
  );
});

test("CI Cargo controls are parsed from id-first workflow steps", () => {
  const steps = parseCiRunSteps();
  assert.equal(
    CI_RUN_STEP_MINIMUM,
    50,
    "review the pinned CI run-step floor explicitly when workflow size changes",
  );
  assert.ok(
    steps.length >= CI_RUN_STEP_MINIMUM,
    `parsed ${steps.length} run steps, below floor ${CI_RUN_STEP_MINIMUM}`,
  );
  assert.ok(
    steps.some(
      (step) =>
        step.run === "cargo test --no-fail-fast" &&
        step.workingDirectory === "rust",
    ),
    "generic Cargo suite is missing from rust/",
  );
  assert.ok(
    steps.some(
      (step) =>
        step.run === "cargo test --test envelope_v23_twin" &&
        step.workingDirectory === "rust",
    ),
    "named envelope_v23_twin suite is missing from rust/",
  );
});

test("CI run-step parsing is invariant under uniform workflow reindent", () => {
  const ci = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "ci.yml"),
    "utf8",
  );
  const reindented = ci
    .split(/\r?\n/)
    .map((line) => `  ${line}`)
    .join("\n");
  const normal = parseCiRunSteps(ci);
  const shifted = parseCiRunSteps(reindented);
  // Reviewed 2026-08-05: retiring both controls' lint-status predicates leaves
  // their `lake test` run steps in place, so the 76-step inventory is unchanged.
  //
  // Reviewed again 2026-08-05 (Ben's ruling, this pulse): 76 -> 82. The runner
  // disk-capacity fix splits the Lean aggregate out of `rust-conformance` into a
  // new `rust-conformance-lean` job, which adds SIX run steps to ci.yml:
  //   1. mcp-seal package fetch      `test -d .lake/packages/mcp-seal || lake update`
  //   2. native mcp-seal C build     `bash .lake/packages/mcp-seal/c/build.sh`
  //   3. Lean aggregate under telemetry
  //                                  `ci_disk_telemetry.py ci-lean-aggregate -- lake ...`
  //   4. the new job's own           `ci_control_aggregate.py` fail-closed step
  //   5. `control_32`, the free-ballast step that makes runner headroom measurable
  //   6. the rust release build under telemetry
  //                                  `ci_disk_telemetry.py ci-rust-release -- cargo ...`
  // Every pre-existing step survives: `control_31` (`lake test`) MOVED to the lean
  // job rather than being deleted, and the real cargo suite stays put. This bump is
  // the tripwire doing its job, not a silenced control. The run-step FLOOR test
  // below is untouched and still guards the real minimum.
  //
  // Reviewed 2026-08-07: 82 -> 83. G1 adds exactly ONE run step, control_33,
  // whose literal block runs both `proof_reach.py` and its fail-closed tests.
  // The parser now decodes all 15 literal `run: |` bodies instead of counting
  // 15 indistinguishable `|` placeholders; 68 inline runs + 15 literal runs
  // derives the honest 83-step inventory. No pre-existing run step was removed.
  //
  // Reviewed 2026-08-07: 83 -> 84. The PyYAML provisioning coverage control
  // adds exactly ONE literal run step: it runs the population guard and its
  // fail-closed negative controls. Provisioning itself is a shared composite
  // action, so it does not add a `run` step to this workflow inventory.
  assert.equal(normal.length, 84, "review the expected run-step inventory explicitly");
  assert.equal(
    shifted.length,
    normal.length,
    "uniform reindent changed the parsed run-step inventory",
  );
  assert.deepEqual(shifted, normal, "uniform reindent changed parsed run-step semantics");
});

test("CI literal run blocks are parsed as commands, not scalar headers", () => {
  const steps = parseCiRunSteps();
  const literalRuns = steps.filter((step) => step.run.includes("\n"));
  assert.equal(literalRuns.length, 16);
  assert.ok(
    literalRuns.every((step) => step.run !== "|"),
    "a literal run block collapsed to its YAML scalar header",
  );
  assert.ok(
    literalRuns.some(
      (step) =>
        step.run ===
        "python3 scripts/proof_reach.py\n" +
          "python3 -m unittest discover -s test -p 'test_proof_reach.py' -v\n",
    ),
    "control_33's two-command literal body was not decoded",
  );
});

test("CI run-step floor fails below its pinned minimum", () => {
  assert.equal(ciRunStepFloorFailure(CI_RUN_STEP_MINIMUM), null);
  assert.match(
    ciRunStepFloorFailure(CI_RUN_STEP_MINIMUM - 1),
    /parsed 49; refusing vacuous CI reachability checks/,
  );
});

test("the live Lean twin prerequisite precedes the generic Cargo suite", () => {
  const steps = parseCiRunSteps();
  const prerequisite = steps.findIndex(
    (step) => step.run === "lake build SealV2.EffectEnvelope",
  );
  const genericSuite = steps.findIndex(
    (step) =>
      step.run === "cargo test --no-fail-fast" &&
      step.workingDirectory === "rust",
  );
  assert.notEqual(prerequisite, -1, "EffectEnvelope build prerequisite is missing");
  assert.notEqual(genericSuite, -1, "generic Cargo suite is missing");
  assert.ok(
    prerequisite < genericSuite,
    "EffectEnvelope must be built before the generic Cargo suite",
  );
});
