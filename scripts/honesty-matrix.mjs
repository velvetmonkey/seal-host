#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// A2 — renders docs/HONESTY-MATRIX.md from three sources, and gates drift.
//
//   1. DERIVED (machine): `lake exe honesty_matrix` JSON — the proven?/wired?
//      cells and the arithmetic. The exe term-binds the nine FfiSpec theorems
//      (rename/delete breaks its build) and EVALUATES `Ffi.activeKernels`
//      over all 64 deployable configs; nothing in those cells is transcribed.
//   2. DERIVED (machine): fail-loud structural parse of
//      rust/tests/topology_matrix.rs and .github/workflows/ci.yml — the
//      tested? cells. A missing pattern is a hard error, never a silent
//      "tested". PROBES kernel names are cross-joined against the Lean JSON
//      kernel names, so the two layers cannot drift apart quietly.
//   3. ASSERTED (human): docs/honesty-assertions.json — the reachable?
//      column ONLY. Every entry must name who asserted it and when; the
//      renderer refuses entries for any derivable column, so a human opinion
//      can never be laundered as machine evidence.
//
// Usage:
//   node scripts/honesty-matrix.mjs [honesty.json]          # regenerate
//   node scripts/honesty-matrix.mjs --check [honesty.json]  # CI drift gate
//
// Output is byte-stable: no generation timestamps — the only dates in the
// artefact are assertion dates and evidence-record dates.

import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TARGET = join(REPO, "docs", "HONESTY-MATRIX.md");
const ASSERTIONS = join(REPO, "docs", "honesty-assertions.json");
const RUST_TEST = join(REPO, "rust", "tests", "topology_matrix.rs");
const IDENTITY_TEST = join(REPO, "rust", "tests", "receipt_identity.rs");
const CI_YML = join(REPO, ".github", "workflows", "ci.yml");

// Evidence RECORDS: facts about specific past runs, quoted with their date.
// A record is neither a derivation (it is not re-established by this script)
// nor an assertion of judgement (it is a checkable historical fact).
const EVIDENCE_RECORDS = [
  "The A1 suite exercises all 64 topologies (V2.1 adds the principal-budget bit) plus calibration's 32 disabled variants against the shipped binary — green locally on the codec+V2.1 fold; the last green clean-runner run is GitHub Actions 29443393591 (`ci.yml` → `rust-conformance`, 2026-07-15, then 32 topologies), CI rerun pending the post-frisk push.",
];

function die(msg) {
  console.error(`honesty-matrix: FATAL: ${msg}`);
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Source 1: the Lean derivation.
// ---------------------------------------------------------------------------

// A missing, empty or unparseable artefact means the PRODUCER died, not that
// the honesty matrix drifted. Those are opposite findings and this gate exists
// to report the second one, so it must never be able to report a dead producer
// as drift — nor as an unlabelled `SyntaxError` from JSON.parse (2026-08-03,
// CI run 30857266859: `lake build` link crashed, /tmp/honesty.json was left
// 0 bytes, and this gate's whole contribution was
// `SyntaxError: Unexpected end of JSON input`).
function loadLeanJson(argPath) {
  let raw;
  if (argPath) {
    try {
      raw = readFileSync(argPath, "utf8");
    } catch (error) {
      die(
        `PRODUCER FAILURE, not drift: cannot read ${argPath} (${error.code ?? error.message}). ` +
          `The Lean honesty_matrix step did not produce its artefact. Fix that step; this gate has no finding.`,
      );
    }
    if (raw.length === 0)
      die(
        `PRODUCER FAILURE, not drift: ${argPath} is empty (0 bytes). ` +
          `The Lean honesty_matrix step exited without writing its JSON. Fix that step; this gate has no finding.`,
      );
  } else {
    raw = execFileSync("lake", ["exe", "honesty_matrix"], {
      cwd: REPO,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
    });
  }
  let data;
  try {
    data = JSON.parse(raw);
  } catch (error) {
    die(
      `PRODUCER FAILURE, not drift: ${argPath ?? "lake exe honesty_matrix"} is not valid JSON ` +
        `(${error.message}; ${raw.length} bytes). Fix the producer; this gate has no finding.`,
    );
  }
  if (data.schema !== "seal-honesty-matrix/v2")
    die(`unexpected Lean JSON schema: ${data.schema}`);
  for (const key of ["kernels", "arithmetic", "boundTheorems", "mandatory", "identity"])
    if (!(key in data)) die(`Lean JSON missing key: ${key}`);
  for (const key of [
    "signedChannel",
    "unauthenticatedChannels",
    "approverTheorems",
    "callerNogoTheorems",
  ])
    if (!(key in data.identity)) die(`Lean JSON identity block missing key: ${key}`);
  if (data.identity.approverTheorems.length === 0 || data.identity.callerNogoTheorems.length === 0)
    die("Lean JSON identity block has an empty theorem list — nothing is bound");
  if (data.kernels.length !== data.arithmetic.provenKernels)
    die("kernel row count disagrees with arithmetic.provenKernels");
  return data;
}

// ---------------------------------------------------------------------------
// Source 2: structural parse of the A1 suite and its CI wiring.
// Every pattern is REQUIRED; absence is a hard error naming the pattern.
// ---------------------------------------------------------------------------

function requireAll(src, file, patterns) {
  for (const p of patterns)
    if (!src.includes(p)) die(`${file}: required pattern not found: ${p}`);
}

function parseTestedEvidence(lean) {
  const rust = readFileSync(RUST_TEST, "utf8");
  requireAll(rust, "rust/tests/topology_matrix.rs", [
    "fn topology_masks_partition",
    "fn topology_matrix_calibration_enabled",
    "fn topology_matrix_calibration_absent_vs_disabled",
    "(0u8..64)",
    "CARGO_BIN_EXE_seal-host-rs",
    "CalVariant::Absent",
    "CalVariant::Disabled",
    '"safety"',
    '"temporal"',
  ]);

  const probesBlock = rust.match(/const PROBES:[^=]*=\s*\[([\s\S]*?)\n\];/);
  if (!probesBlock) die("rust/tests/topology_matrix.rs: PROBES table not found");
  const probeKernels = [...probesBlock[1].matchAll(/\(\s*BIT_[A-Z_]+,\s*"([a-z_-]+)"/g)].map(
    (m) => m[1],
  );

  const gated = lean.kernels
    .filter((k) => k.wired === "config-gated")
    .map((k) => k.name)
    .sort();
  const probesSorted = [...probeKernels].sort();
  if (JSON.stringify(probesSorted) !== JSON.stringify(gated))
    die(
      `PROBES kernels ${JSON.stringify(probesSorted)} != Lean config-gated kernels ${JSON.stringify(gated)} — the Rust suite and the Lean derivation have drifted apart`,
    );

  const ci = readFileSync(CI_YML, "utf8");
  requireAll(ci, ".github/workflows/ci.yml", [
    "cargo test",
    "working-directory: rust",
  ]);

  // The D3 identity differential: the receipt's approval_identity is the
  // configured trust root, request-independent, checked against the REAL
  // binary — including the planted self-asserted caller. Absence of any of
  // these is a hard error, never a silently confident identity section.
  const identityRust = readFileSync(IDENTITY_TEST, "utf8");
  requireAll(identityRust, "rust/tests/receipt_identity.rs", [
    "fn approval_identity_ignores_self_asserted_caller",
    "fn approval_identity_tracks_trust_root_not_request",
    "PINNED_KEY_ID",
    "CARGO_BIN_EXE_seal-host-rs",
    '"caller_id":"root"',
  ]);

  return { probeKernels };
}

// ---------------------------------------------------------------------------
// Source 3: the human-owned column.
// ---------------------------------------------------------------------------

function loadAssertions(lean) {
  const data = JSON.parse(readFileSync(ASSERTIONS, "utf8"));
  if (data.schema !== "seal-honesty-assertions/v1")
    die(`unexpected assertions schema: ${data.schema}`);
  const kernelNames = lean.kernels.map((k) => k.name);
  const byKernel = new Map();
  for (const e of data.entries) {
    for (const field of ["kernel", "column", "value", "assertedBy", "date", "rationale"])
      if (typeof e[field] !== "string" || e[field].length === 0)
        die(`assertions entry for ${e.kernel ?? "?"}: missing or empty ${field}`);
    if (e.column !== "reachable")
      die(
        `assertions entry for ${e.kernel} asserts column "${e.column}" — only "reachable" may be asserted; every other column is derived`,
      );
    if (!kernelNames.includes(e.kernel))
      die(`assertions entry for unknown kernel: ${e.kernel}`);
    if (byKernel.has(e.kernel)) die(`duplicate assertion for kernel: ${e.kernel}`);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(e.date))
      die(`assertions entry for ${e.kernel}: date must be YYYY-MM-DD, got ${e.date}`);
    byKernel.set(e.kernel, e);
  }
  for (const name of kernelNames)
    if (!byKernel.has(name)) die(`no reachable assertion for kernel: ${name}`);
  return byKernel;
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

function provenCell(k) {
  const thms = k.theorems.map((t) => `\`${t}\``).join(", ");
  return `✅ derived — ${thms}`;
}

function wiredCell(k) {
  const evalNote = `evaluated over all 64 configs`;
  if (k.wired === "always")
    return `✅ always (${k.activeCount}/64) derived — ${evalNote}`;
  if (k.wired === "never")
    return `❌ never (${k.activeCount}/64) derived — ${evalNote}`;
  const dg = k.doubleGate ? "; double-gated (present AND enabled)" : "";
  return `⚙️ config-gated (${k.activeCount}/64) derived — ${evalNote}${dg}`;
}

function reachableCell(a) {
  return `⚠️ ASSERTED (${a.assertedBy}, ${a.date}) — ${a.value}`;
}

function testedCell(k) {
  if (k.wired === "never")
    return "❌ untested in deployment — no deployable topology exists (derived from wired: never)";
  if (k.wired === "always")
    return `✅ derived — shown denying at all 64 topologies (\`rust/tests/topology_matrix.rs\`)`;
  const dg = k.doubleGate
    ? "; disabled-vs-absent exercised at all 16 inactive topologies"
    : "";
  return `✅ derived — shown denying at all ${k.activeCount} active topologies and not gating at the ${64 - k.activeCount} inactive ones (\`rust/tests/topology_matrix.rs\`)${dg}`;
}

function render(lean, assertions) {
  const a = lean.arithmetic;
  const mandatory = lean.mandatory.map((m) => `\`${m}\``).join(", ");
  const lines = [];
  const push = (s) => lines.push(s);

  push("<!-- GENERATED FILE — do not hand-edit.");
  push("     Regenerate: node scripts/honesty-matrix.mjs");
  push("     CI regenerates and diffs this file; a hand edit goes red. -->");
  push("");
  push("# Honesty matrix — what the shipped gate actually enforces");
  push("");
  push(
    "Per kernel, four facts that must never be conflated: **proven?** · **wired in `registryFor`?** · **reachable via the shipped policy DX?** · **tested at every topology where active?** A capability matrix that only lists what works is marketing; this one prints the eighth row.",
  );
  push("");
  push("## The arithmetic, stated honestly");
  push("");
  push(
    `The proof covers **${a.provenKernels} kernels**. The product selects among **${a.selectableKernels}** of them, **${a.mandatoryKernels} mandatory** (${mandatory}) — so **${a.deployableTopologies} deployable topologies**. Not 64. Not 127. The eighth kernel (\`consensus-bytes\`) is proven and not in the building; wiring it would double the space to 64. All four numbers are computed by \`lake exe honesty_matrix\` from evaluating \`Ffi.activeKernels\`, not typed by a human.`,
  );
  push("");
  push("## How to read a cell");
  push("");
  push(
    "- **`✅ / ⚙️ / ❌ … derived`** — emitted by machinery. The Lean exe term-binds all nine `FfiSpec.lean` theorems (renaming or deleting one breaks its build, so the matrix cannot regenerate and CI goes red) and evaluates `Ffi.activeKernels` at every deployable config; `Ffi.registryFor_kernels` proves the deployed registry equals that evaluation for every session, clock and evidence bundle. The tested column additionally requires a fail-loud structural parse of the A1 suite and its CI wiring to succeed. All nine theorems are axiom-pinned to `[propext, Classical.choice, Quot.sound]` (`FfiSpec.lean`, re-pinned in `Test/Axioms.lean`).",
  );
  push(
    "- **`⚠️ ASSERTED (who, date)`** — a human judgement, not machine evidence. The **reachable** column is the only asserted column: whether a kernel is reachable through the shipped policy-authoring experience is a reading of `CONFIG.md` and of what tooling exists, and no theorem or test can settle it. Full rationale per cell below. If these two cell styles ever look alike, that is a bug in this generator.",
  );
  push("");
  push(
    "Scope of the derivation, stated honestly: the theorem binding catches **rename and delete**, not **restatement** — a weakened theorem that keeps its name still builds. That is exactly the bug class A0 was written to kill (edit `registryFor`, no proof notices), and no more. This matrix cannot go stale against that bug class; it is not a guarantee the theorems say what the prose claims. Read `FfiSpec.lean` for that.",
  );
  push("");
  push("## The matrix");
  push("");
  push(
    "| Kernel | proven? | wired in `registryFor`? | reachable via shipped policy DX? | tested at every topology where active? |",
  );
  push("|---|---|---|---|---|");
  for (const k of lean.kernels) {
    push(
      `| \`${k.name}\` | ${provenCell(k)} | ${wiredCell(k)} | ${reachableCell(assertions.get(k.name))} | ${testedCell(k)} |`,
    );
  }
  push("");
  push("## The eighth row, spelled out");
  push("");
  push(
    "`consensus-bytes` (`Kernels/ConsensusBytes.lean`) is **proven, NOT wired, not reachable, untested in deployment**. `Ffi.byteConsensus_never_registered` proves no config, clock or evidence reaches it; no `CONFIG.md` section names it; it has no deployable topology to test at. It appears here because omitting it would make this table marketing.",
  );
  push("");
  push("## Who does a receipt authenticate?");
  push("");
  const ident = lean.identity;
  const approverThms = ident.approverTheorems.map((t) => `\`${t}\``).join(", ");
  const nogoThms = ident.callerNogoTheorems.map((t) => `\`${t}\``).join(", ");
  const devChannels = ident.unauthenticatedChannels.map((c) => `\`${c}\``).join("/");
  push(
    "The per-kernel table above is about enforcement. This section is about IDENTITY — the other question an evaluator asks — and it has an impossible cell that a lesser matrix would have filled in.",
  );
  push("");
  push("| Identity | In the receipt? | Authenticated? | Basis |");
  push("|---|---|---|---|");
  push(
    `| **The approver** (whose key authorized this action) | ✅ \`approval.approval_identity\` — \`{channel, key_id}\` | ✅ on \`--channel ${ident.signedChannel}\` ONLY — \`key_id\` is the SHA-256 fingerprint of the operator-configured approval verifying key, a boot-scoped constant of the trust root; the ${devChannels} channels are DEV-ONLY and UNAUTHENTICATED and their receipts name a channel kind, no key | ✅ derived — ${approverThms}; differential against the real binary in \`rust/tests/receipt_identity.rs\` (a planted \`caller_id\` in the arguments must not move the identity) |`,
  );
  push(
    `| **The caller** (which agent made this call) | ❌ deliberately ABSENT | ❌ IMPOSSIBLE at this topology — stdio mediation carries no transport credential, so every request byte is authored by the gated agent itself; any \`caller_id\` field would be an adversary echo wearing an identity's clothes | ✅ derived — ${nogoThms} |`,
  );
  push("");
  push(
    "The no-go is a theorem, not a scoping choice: with a total send relation (any caller can emit any bytes — the stdio fact), NO function of everything the host holds at dispatch time soundly names the sender. The identity value the receipt DOES carry is provably request-independent: the signed approval token gates whether the `approval` block appears, never what it says.",
  );
  push("");
  push(
    "**What would change the answer (V2.1, the G1 caller/principal axis):** a topology that constrains who can send what — per-caller transport credentials (peer creds on a per-caller socket, an authenticated gateway in front, per-caller approval keys). `Host.ReceiptIdentity.credentialed_topology_authenticates` proves that seam suffices once it exists: on a credential-constrained send relation an authenticator is exhibited. Until then, an honest receipt binds the approver and refuses to name the caller.",
  );
  push("");
  push("## Calibration's double gate");
  push("");
  push(
    "`some cfg` with `enabled := false` is a distinct config state from `none`. Both leave calibration inactive — proven (`Ffi.calibration_registered_iff`), evaluated by the exe at all 16 calibration-clear masks (disabled ≡ absent, selection-identical), and exercised behaviourally by the A1 suite (`topology_matrix_calibration_absent_vs_disabled`: the two runs must be call-for-call identical).",
  );
  push("");
  push("## Tested — what is derived and what is record");
  push("");
  push(
    "Derived (re-established on every regeneration): `rust/tests/topology_matrix.rs` exists with the mask partition pin (`topology_masks_partition`, 32+32 = the disjoint `0..64`), both spawning tests, the `CARGO_BIN_EXE_seal-host-rs` forced-binary path, and a `PROBES` table whose kernel names equal the Lean derivation's config-gated set exactly; `ci.yml` runs `cargo test` in `rust/` on every push. If any of that goes away, this file cannot regenerate.",
  );
  push("");
  push("Record (a checkable historical fact, quoted with its date, not re-established here):");
  push("");
  for (const r of EVIDENCE_RECORDS) push(`- ${r}`);
  push("");
  push("## Asserted cells in full");
  push("");
  push(
    "Everything below is human judgement from `docs/honesty-assertions.json`. Re-assert (update the date) when the shipped DX changes.",
  );
  push("");
  for (const k of lean.kernels) {
    const e = assertions.get(k.name);
    push(`- \`${k.name}\` — **${e.value}**`);
    push(`  ⚠️ ASSERTED by ${e.assertedBy}, ${e.date}. ${e.rationale}`);
  }
  push("");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Main.
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const check = args.includes("--check");
const jsonPath = args.find((x) => x !== "--check");

const lean = loadLeanJson(jsonPath);
parseTestedEvidence(lean);
const assertions = loadAssertions(lean);
const rendered = render(lean, assertions);

if (check) {
  let existing = null;
  try {
    existing = readFileSync(TARGET, "utf8");
  } catch {
    die(`--check: ${TARGET} does not exist — generate it first`);
  }
  if (existing !== rendered) {
    console.error(
      "honesty-matrix: DRIFT — docs/HONESTY-MATRIX.md does not match what the sources derive.",
    );
    const tmp = join(mkdtempSync(join(tmpdir(), "honesty-")), "HONESTY-MATRIX.md");
    writeFileSync(tmp, rendered);
    const d = spawnSync("diff", ["-u", TARGET, tmp], { encoding: "utf8" });
    if (d.stdout) console.error(d.stdout);
    process.exit(1);
  }
  console.log("honesty-matrix: check OK — artefact matches its sources");
} else {
  writeFileSync(TARGET, rendered);
  console.log(`honesty-matrix: wrote ${TARGET}`);
}
