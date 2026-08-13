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

const EXPECTED_CI_RUN_STEP_IDENTITIES = [
  "export-surface:control_02",
  "export-surface:control_03",
  "export-surface:control_04",
  "export-surface:control_05",
  "export-surface:name:Require every isolated CI step to pass",
  "build:control_15",
  "build:control_02",
  "build:control_03",
  "build:control_04",
  "build:control_05",
  "build:control_06",
  "build:control_07",
  "build:control_20",
  "build:control_08",
  "build:control_10",
  "build:control_18",
  "build:control_33",
  "build:control_19",
  "build:control_16",
  "build:control_34",
  "build:name:Require every isolated CI step to pass",
  "rust-conformance:control_02",
  "rust-conformance:control_32",
  "rust-conformance:control_03",
  "rust-conformance:control_05",
  "rust-conformance:control_06",
  "rust-conformance:control_08",
  "rust-conformance:control_09",
  "rust-conformance:control_10",
  "rust-conformance:control_11",
  "rust-conformance:control_12",
  "rust-conformance:control_13",
  "rust-conformance:control_27",
  "rust-conformance:control_14",
  "rust-conformance:control_31",
  "rust-conformance:control_15",
  "rust-conformance:control_17",
  "rust-conformance:control_18",
  "rust-conformance:control_19",
  "rust-conformance:control_20",
  "rust-conformance:control_30",
  "rust-conformance:control_21",
  "rust-conformance:control_22",
  "rust-conformance:control_23",
  "rust-conformance:control_24",
  "rust-conformance:control_25",
  "rust-conformance:control_26",
  "rust-conformance:control_28",
  "rust-conformance:control_29",
  "rust-conformance:name:Require every isolated CI step to pass",
  "contract-freeze:control_03",
  "contract-freeze:control_04",
  "contract-freeze:control_05",
  "contract-freeze:control_06",
  "contract-freeze:control_07",
  "contract-freeze:control_08",
  "contract-freeze:control_09",
  "contract-freeze:control_10",
  "contract-freeze:control_11",
  "contract-freeze:name:Require every isolated CI step to pass",
  "cargo-audit:control_03",
  "cargo-audit:control_04",
  "cargo-audit:name:Require every isolated CI step to pass",
  "rust-sbom:control_03",
  "rust-sbom:control_04",
  "rust-sbom:name:Require every isolated CI step to pass",
  "release-evidence:control_02",
  "release-evidence:control_03",
  "release-evidence:control_04",
  "release-evidence:name:Require every isolated CI step to pass",
];

const ciRunStepIdentities = (steps) => steps.map(
  (step) => `${step.job}:${step.id ?? `name:${step.name}`}`,
);

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

test("the canonical PINS door invokes the mcp-seal pin check", () => {
  const gate = fs.readFileSync(path.join(ROOT, "scripts", "pins_gate.mjs"), "utf8");
  assert.match(
    gate,
    /import\s*\{\s*checkMcpSealPin\s*\}\s*from\s*["']\.\/mcp_seal_pin_drift\.mjs["'];/,
    "pins_gate.mjs does not import the mcp-seal pin checker",
  );
  assert.match(
    gate,
    /if\s*\(\s*checkMcpSealPin\(\)\s*!==\s*0\s*\)\s*\{\s*ctx\.failures\.push\(\s*["']mcp-seal three-way pin check failed["']\s*\);\s*\}/,
    "pins_gate.mjs is missing the invoked mcp-seal pin checker call",
  );
});

test("the mcp-seal revision is obtained from Lake against the real package", () => {
  const checker = fs.readFileSync(
    path.join(ROOT, "scripts", "mcp_seal_pin_drift.mjs"),
    "utf8",
  );
  const probe = fs.readFileSync(
    path.join(ROOT, "scripts", "lake_mcp_seal_revision.lean"),
    "utf8",
  );
  assert.match(
    checker,
    /spawnSync\(lakeCommand,\s*\[/,
    "mcp-seal pin checker does not invoke Lake",
  );
  assert.match(
    checker,
    /mkdtempSync\(path\.join\(scratchRoot, "mcp-seal-lake-"\)\)/,
    "mcp-seal pin checker does not isolate its generated probe files in a throwaway workspace",
  );
  assert.doesNotMatch(
    checker,
    /fs\.cpSync\(ROOT/,
    "mcp-seal pin checker must not substitute a package snapshot for the real package",
  );
  assert.match(
    checker,
    /"--dir", ROOT,\s*"translate-config", "toml", normalizedConfig/,
    "mcp-seal revision checker does not ask Lake to load the real package directory",
  );
  assert.match(
    checker,
    /Lake config presentation guard refuses lakefile\.lean in the TOML-declared seal-host package/,
    "mcp-seal pin checker does not refuse a Lean lakefile before invoking Lake",
  );
  assert.match(
    checker,
    /"translate-config", "toml", normalizedConfig/,
    "mcp-seal revision checker does not invoke Lake's package-loading translation",
  );
  assert.match(
    probe,
    /realConfigFile \(pkgDir \/ defaultConfigFile\)/,
    "mcp-seal revision probe does not ask Lake which config file won",
  );
  assert.match(
    probe,
    /loadTomlConfig config/,
    "mcp-seal revision probe does not ask Lake to decode the normalized configuration",
  );
  assert.doesNotMatch(
    checker,
    /parse_lake_requirements|tomllib/,
    "mcp-seal pin checker must not independently parse Lake's TOML",
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
  // Reviewed 2026-08-08: 83 -> 78. Roadmap 8y item 8 moves the
  // kernel-hash-footprint job's FIVE inline run steps (token require, token
  // git config, footprint --check, footprint meta-test, and the job's own
  // ci_control_aggregate.py) out of ci.yml into the reusable
  // .github/workflows/acceptance.yml, which ci.yml `kernel-hash-footprint`
  // and release.yml `fleet-gate` now both invoke via `uses:`. Every command
  // still runs on every push — test/kernel_hash_footprint_meta.test.mjs
  // asserts the commands exist in acceptance.yml and that BOTH callers
  // invoke it — so this is a relocation, not a removal. The run-step FLOOR
  // below is untouched.
  //
  // Reviewed 2026-08-08 (pyyamlpop lane): 78 -> 79. Exactly ONE run step is
  // added to ci.yml: contract-freeze `control_11`, a two-command literal block
  // running `scripts/workflow_pyyaml_gate.py` and its fixture tests. That gate
  // is the population control for the defect that reddened this job -- twenty
  // jobs invoke a script that refuses to run without PyYAML and one of them
  // declared the dependency. The eighteen provisioning steps added by the same
  // change are `uses: ./.github/actions/pyyaml`, not run steps, so they do not
  // enter this inventory; the two other new run steps in that change are in
  // g2-mutation-ablation.yml and public-export.yml, which this test does not
  // parse. No pre-existing run step was removed or relocated. The run-step
  // FLOOR below is untouched.
  //
  // Reviewed 2026-08-08 (the consolidation lane, rebased onto the pyyamlpop
  // line): 79 -> 66.
  // Roadmap 8y item 6 removes exactly thirteen duplicate CI run steps: six
  // aggregate-child reruns in `build`, all six run steps from the same-commit
  // `rust-conformance-lean` duplicate job, and the later default `lake build`
  // rerun in `rust-conformance`. The surviving `build` aggregate now tees its
  // axiom output for the unchanged sorry-axiom grep. The separately guarded A2
  // build and every targeted conformance build remain. The thirteen removals
  // are disjoint from the one step the pyyamlpop lane added -- that step is in
  // `contract-freeze`, which this change does not touch -- so the two reviews
  // compose as 78 + 1 - 13. The run-step floor below is unchanged.
  //
  // Reviewed 2026-08-13: G2 item two adds `build:control_34`. The former guard
  // asserted only the total 66; that named no control and could be satisfied by
  // incrementing a number after an unrelated substitution. The live inventory
  // above now names every job + step id (or the aggregate's unique name), so a
  // new, removed, renamed, reordered, or substituted run step needs an explicit
  // review of its identity rather than a count bump.
  //
  // Reviewed 2026-08-13: the elan second-door conversion changes
  // build:control_04 and rust-conformance:control_06 from uses actions into
  // run steps invoking the pinned installer. Those are the only two new
  // ci.yml run-step identities; all other eight conversions are in other
  // workflows. The named inventory records both explicitly.
  //
  // Reviewed 2026-08-13 (guardwire): 69 -> 70. Exactly ONE run step is
  // added to rust-conformance: control_31, the G2 crash-test fresh-artifact
  // proof. Its continue-on-error result is measured by the existing
  // aggregate; this inventory entry only accounts for the new step identity.
  assert.deepEqual(
    ciRunStepIdentities(normal),
    EXPECTED_CI_RUN_STEP_IDENTITIES,
    "CI run-step identities changed without an explicit inventory review",
  );
  assert.equal(
    shifted.length,
    normal.length,
    "uniform reindent changed the parsed run-step inventory",
  );
  assert.deepEqual(shifted, normal, "uniform reindent changed parsed run-step semantics");
});

test("an undeclared run step fails even when its updated total is accepted", () => {
  const ci = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "ci.yml"),
    "utf8",
  );
  const marker = "      - name: Require every isolated CI step to pass\n";
  const dummy =
    "      - id: control_99\n" +
    "        continue-on-error: true\n" +
    "        name: Undeclared dummy control\n" +
    "        run: echo dummy\n";
  const mutated = ci.replace(marker, `${dummy}${marker}`);
  assert.notEqual(mutated, ci, "dummy control insertion point disappeared");
  const parsed = parseCiRunSteps(mutated);
  const deliberatelyUpdatedTotal = EXPECTED_CI_RUN_STEP_IDENTITIES.length + 1;
  assert.equal(parsed.length, deliberatelyUpdatedTotal, "count control did not model the old weakness");
  assert.notDeepEqual(
    ciRunStepIdentities(parsed),
    EXPECTED_CI_RUN_STEP_IDENTITIES,
    "undeclared dummy control escaped the named identity inventory",
  );
});

test("CI literal run blocks are parsed as commands, not scalar headers", () => {
  const steps = parseCiRunSteps();
  const literalRuns = steps.filter((step) => step.run.includes("\n"));
  // 15 -> 16 alongside the run-step inventory above: contract-freeze
  // `control_11` is itself a literal `run: |` block with two commands.
  //
  // 16 -> 14 for the Lean-execution consolidation: three literal blocks go
  // (`build:control_17`, and `rust-conformance-lean`'s `control_02` and
  // `control_03`), and one arrives (`build:control_20`, now a literal block so
  // it can tee the axiom report the sorry-axiom grep reads).
  // 14 -> 15: guardwire adds the literal control_31 crash-test block.
  assert.equal(literalRuns.length, 15);
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

test("G2 fresh-artifact documentation matches the live control_31 invocation", () => {
  const workflow = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "ci.yml"),
    "utf8",
  );
  const documentation = fs.readFileSync(
    path.join(ROOT, "docs", "CONFORMANCE.md"),
    "utf8",
  );
  const step = workflow.match(
    /\n      - id: control_31\n([\s\S]*?)(?=\n      - id: control_\d+)/,
  );
  assert.ok(step, "control_31 workflow step is missing or cannot be bounded");
  const actual = [...new Set(step[1].match(/g2_[a-z0-9_]+/g) ?? [])].sort();
  const documentedBlock = documentation.match(
    /<!-- g2-fresh-artifact-tests:begin -->\n([\s\S]*?)<!-- g2-fresh-artifact-tests:end -->/,
  );
  assert.ok(
    documentedBlock,
    "docs/CONFORMANCE.md must carry the guarded G2 test inventory markers",
  );
  const documented = [...documentedBlock[1].matchAll(/`(g2_[a-z0-9_]+)`/g)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(
    documented,
    actual,
    "documented G2 fresh-artifact coverage disagrees with ci.yml control_31",
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
