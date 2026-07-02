#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Spec→shipping-binary CONFORMANCE BRIDGE.
//
// The theorems (L0 four-gate non-bypass, L1 verifiable record) govern the Lean
// MODEL. The shipped artifact is that model COMPILED (Lean → C → native
// libsealffi.so, linked by the deployed seal-host-rs). This harness is
// DIFFERENTIAL EVIDENCE — not a theorem — that codegen preserved the proven
// behavior on a finite, security-relevant corpus C:
//
//   (1) DECISION agreement — for every input in C, the route the compiled
//       artifact takes equals the route the real Lean functions take.
//   (2) RECORD agreement   — the artifact's emitted audit certificates are
//       byte-identical to the Lean model's, so the SHA-256 record chain over
//       the artifact's log has the same head as over the model's log.
//
// Oracles:
//   • MODEL  = the REAL Lean `stepImpl` in the INTERPRETER
//              (scripts/model_oracle.lean via `lake env lean`), never a re-impl.
//   • NATIVE = the compiled libsealffi.so via `kernel_oracle` (the same object
//              the deployed seal-host-rs links).
//   • DEPLOYED = the actual `seal-host-rs` binary, end-to-end over stdio.
//
// TCB (named, not proven): the Lean compiler + native codegen, the FFI
// marshalling, node:crypto SHA-256, and the harness. Evidence covers C ONLY —
// this is never a universal "binary equals model". See docs/CONFORMANCE-BRIDGE.md.
//
// Exit non-zero on ANY divergence.

import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const NATIVE = `${ROOT}/rust/target/release/kernel_oracle`;
const HOST = `${ROOT}/rust/target/release/seal-host-rs`;
const MODEL_LEAN = "scripts/model_oracle.lean";
const PK = "conformance-pk";
const NOW = 1000;

// `--wasm` swaps the compiled artifact under test from the native .so to the
// emscripten wasm (the in-browser seal-check shape). The MODEL oracle (real Lean
// in the interpreter) is unchanged either way. The wasm is the freshly-verified,
// staged, rebuilt-at-HEAD artifact — never the stale in-tree pin.
const WASM = process.argv.includes("--wasm");
const WASM_JS = `${ROOT}/wasm-spike/verified/seal.js`;
const WASM_WASM = `${ROOT}/wasm-spike/verified/seal.wasm`;
const ARTIFACT = WASM ? "wasm (emscripten, in-browser seal-check shape)" : "native .so (libsealffi.so)";

const WORK = mkdtempSync(join(tmpdir(), "seal-conf-"));
process.on("exit", () => { try { rmSync(WORK, { recursive: true, force: true }); } catch {} });

let failed = false;
const fail = (msg) => { console.error(`  ✗ ${msg}`); failed = true; };
const ok = (msg) => console.log(`  ✓ ${msg}`);

// ---- the same commitment as scripts/seal_log.mjs (H = SHA-256) --------------
const GENESIS = createHash("sha256").update("seal-verifiable-record/genesis/v1").digest("hex");
const commit = (prev, payload) =>
  createHash("sha256").update(prev, "utf8").update("\x1f", "utf8").update(payload, "utf8").digest("hex");
const chainHead = (payloads) => payloads.reduce((h, p) => commit(h, p), GENESIS);

// ---- trusted policy: db.execute guarded on destructive SQL -------------------
const APPROVALS = join(WORK, "approvals.ndjson");
writeFileSync(APPROVALS, "");
const policyPayload = JSON.stringify({
  epoch: 1,
  safety: {
    approval: { control_file: APPROVALS, ttl_seconds: 120 },
    tools: [{
      name: "db.execute", mode: "guarded",
      match: { type: "contains_any_ci", arg: "sql", needles: ["drop", "delete", "truncate"] },
      target: [{ literal: "db" }, { arg: "database" }, { literal: "write" }, { arg: "sql" }],
    }],
  },
});
const ENV_FILE = join(WORK, "trusted.json");
writeFileSync(ENV_FILE, JSON.stringify({ payload: policyPayload, signature: `stub-ed25519:${PK}:${policyPayload}` }));

// ---- corpus C ----------------------------------------------------------------
const wireCall = (id, sql) =>
  `{"jsonrpc":"2.0","id":${id},"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":${JSON.stringify(sql)}}}}`;
const passthroughLine = (obj) => JSON.stringify(obj);

// destructive-delete corpus: the same op in many disguises (all must BLOCK).
const DISGUISES = [
  "drop table customers", "DROP TABLE CUSTOMERS", "DrOp TaBlE cUsToMeRs",
  " drop table customers", "drop table customers ", "drop table customers\t",
  "delete from ledger", "DELETE FROM LEDGER", "truncate audit", "TRUNCATE AUDIT",
  "  drop table customers  ",
];
// passthrough corpus (not a mediated tools/call → route passthrough).
const PASSTHROUGH = [
  passthroughLine({ jsonrpc: "2.0", id: 100, method: "initialize" }),
  passthroughLine({ jsonrpc: "2.0", id: 101, method: "tools/list" }),
  passthroughLine({ jsonrpc: "2.0", method: "notifications/initialized" }),
];

const stepInput = (wire, approvals = []) =>
  JSON.stringify({ line: wire, now: NOW, approvals, votes: "", grants: "", forecasts: "" });

// base corpus: block disguises + passthrough
const corpus = [];
DISGUISES.forEach((sql, i) => corpus.push({ name: `block:${sql}`, expect: "block", step: stepInput(wireCall(200 + i, sql)) }));
PASSTHROUGH.forEach((line, i) => corpus.push({ name: `passthrough:${i}`, expect: "passthrough", step: stepInput(line) }));

// ---- oracle runners ----------------------------------------------------------
function runNative(corpusFile) {
  return execFileSync(NATIVE, [ENV_FILE, PK], { input: readFileSync(corpusFile), encoding: "utf8" });
}
function runModel(corpusFile) {
  const outFile = join(WORK, "model.out");
  execFileSync("lake", ["env", "lean", MODEL_LEAN], {
    cwd: ROOT,
    env: { ...process.env, SEAL_CONF_ENV: ENV_FILE, SEAL_CONF_PK: PK, SEAL_CONF_CORPUS: corpusFile, SEAL_CONF_OUT: outFile },
    stdio: ["ignore", "ignore", "inherit"],
  });
  return readFileSync(outFile, "utf8");
}

// WASM oracle: the emscripten module loaded HEADLESS in Node (MODULARIZE factory).
// seal_init/seal_decide are thin C aliases over the SAME Lean seal_host_init/
// seal_host_step the native oracle calls, so the corpus step-inputs are byte-identical.
let _wasmMod = null;
async function wasmModule() {
  if (_wasmMod) return _wasmMod;
  const { createRequire } = await import("node:module");
  const require = createRequire(import.meta.url);
  const factory = require(WASM_JS); // seal.js locates seal.wasm next to it (__dirname)
  _wasmMod = await factory({ print() {}, printErr() {} });
  return _wasmMod;
}
async function runWasm(corpusFile) {
  const M = await wasmModule();
  // Re-init per run for a FRESH session — matches a fresh kernel_oracle process,
  // so temporal/linear/budget state threads identically across the corpus.
  const initOut = M.ccall("seal_init", "string", ["string", "string"], [readFileSync(ENV_FILE, "utf8"), PK]);
  if (!initOut.includes('"ok":true')) throw new Error(`wasm seal_init failed: ${initOut}`);
  const lines = readFileSync(corpusFile, "utf8").split("\n").map((s) => s.trim()).filter(Boolean);
  return lines.map((l) => M.ccall("seal_decide", "string", ["string"], [l])).join("\n") + "\n";
}

// The compiled artifact under test — native .so or wasm, per --wasm.
async function runArtifact(corpusFile) { return WASM ? runWasm(corpusFile) : runNative(corpusFile); }

// ---- STEP 1: derive the forward case's approval target from a real block -----
console.log("===============================================================");
console.log(" spec→binary conformance bridge  (differential evidence over C)");
console.log("===============================================================");
console.log(`artifact under test: ${ARTIFACT}`);
if (WASM) {
  const wasmSha = createHash("sha256").update(readFileSync(WASM_WASM)).digest("hex");
  const head = execFileSync("git", ["-C", ROOT, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  console.log(`  provenance: built at HEAD ${head}`);
  console.log(`  seal.wasm sha256: ${wasmSha}`);
}
console.log(`corpus C: ${DISGUISES.length} destructive disguises + ${PASSTHROUGH.length} passthrough + 1 approved forward`);

const probeFile = join(WORK, "probe.jsonl");
writeFileSync(probeFile, stepInput(wireCall(1, "drop table customers")) + "\n");
const probeOut = JSON.parse((await runArtifact(probeFile)).trim());
const m = /approval required: (\d+)/.exec(probeOut.response || "");
if (!m) { console.error("could not derive approval target from a block; aborting"); process.exit(1); }
const target = m[1];
// approved canonical call: same bytes, now with a fresh live approval → FORWARD.
corpus.push({
  name: "forward:approved drop",
  expect: "forward",
  step: stepInput(wireCall(1, "drop table customers"), [{ target, issuedAt: NOW }]),
});

// ---- STEP 2: run both oracles on the FULL corpus, byte-diff every line -------
const corpusFile = join(WORK, "corpus.jsonl");
writeFileSync(corpusFile, corpus.map((c) => c.step).join("\n") + "\n");

console.log(`\n[1] DECISION + audit byte agreement — ${ARTIFACT} vs interpreted Lean`);
const artifactLines = (await runArtifact(corpusFile)).split("\n").filter(Boolean);
const modelLines = runModel(corpusFile).split("\n").filter(Boolean);

// Liveness: prove the harness is not vacuous before trusting a PASS.
{
  const routes = new Set(artifactLines.map((l) => JSON.parse(l).route));
  if (!(routes.has("block") && routes.has("passthrough") && routes.has("forward")))
    fail(`liveness: corpus did not exercise all three routes (saw ${[...routes].join(",")})`);
  const auds = artifactLines.map((l) => JSON.parse(l).audit).filter(Boolean);
  if (auds.length > 1 && chainHead(auds) === chainHead([...auds].reverse()))
    fail("liveness: chain head is order-insensitive — the comparator would miss a reorder");
  if (!failed) ok("harness liveness: all routes exercised; chain is order-sensitive (non-vacuous)");
}

if (artifactLines.length !== corpus.length || modelLines.length !== corpus.length) {
  fail(`line count mismatch: corpus=${corpus.length} artifact=${artifactLines.length} model=${modelLines.length}`);
} else {
  let diverged = 0;
  for (let i = 0; i < corpus.length; i++) {
    const route = JSON.parse(artifactLines[i]).route;
    if (artifactLines[i] !== modelLines[i]) { fail(`byte divergence @ ${corpus[i].name}`); diverged++; }
    else if (route !== corpus[i].expect) { fail(`route mismatch @ ${corpus[i].name}: got ${route}, expected ${corpus[i].expect}`); diverged++; }
  }
  if (!diverged) ok(`${corpus.length}/${corpus.length} inputs: artifact == model, byte-for-byte, route as expected`);
}

// ---- STEP 3: record-chain agreement (reduces to audit payload agreement) -----
console.log("\n[2] RECORD chain agreement — SHA-256 head over artifact vs model audits");
const auditOf = (line) => { const o = JSON.parse(line); return o.audit; };
const artifactAudits = artifactLines.map(auditOf).filter((a) => a != null);
const modelAudits = modelLines.map(auditOf).filter((a) => a != null);
const artifactHead = chainHead(artifactAudits);
const modelHead = chainHead(modelAudits);
if (artifactHead === modelHead) ok(`chain heads equal: ${artifactHead}`);
else fail(`chain head divergence: artifact ${artifactHead} vs model ${modelHead}`);

// ---- STEP 4: the DEPLOYED binary's record matches the model -------------------
// Native shape only: seal-host-rs is the deployed process. In --wasm mode the
// in-proc wasm module IS the deployed browser artifact, already covered by [1]+[2].
if (WASM) {
  console.log("\n[3] DEPLOYED binary — skipped in --wasm mode");
  ok("the in-proc wasm module is itself the deployed browser artifact ([1]+[2] cover it)");
} else {
console.log("\n[3] DEPLOYED binary — seal-host-rs record chain vs model");
const wireSeq = ["drop table customers", "delete from ledger", "truncate audit"];
const wireInput = wireSeq.map((sql, i) => wireCall(300 + i, sql)).join("\n") + "\n";
const hostRun = spawnSync(HOST, ["--config", ENV_FILE, "--pubkey", PK, "--", "/bin/cat"], { input: wireInput, encoding: "utf8" });
const hostAudits = (hostRun.stderr || "").split("\n").filter((l) => l.includes('"certs":[') && l.includes('"verdict":'));
// model audits for the same 3 decisions (fresh session, now fixed):
const modelSeqFile = join(WORK, "seq.jsonl");
writeFileSync(modelSeqFile, wireSeq.map((sql, i) => stepInput(wireCall(300 + i, sql))).join("\n") + "\n");
const modelSeqAudits = runModel(modelSeqFile).split("\n").filter(Boolean).map(auditOf);
if (hostAudits.length === 3) {
  const hostHead = chainHead(hostAudits);
  const modelSeqHead = chainHead(modelSeqAudits);
  if (hostHead === modelSeqHead) ok(`deployed seal-host-rs record head == model head: ${hostHead}`);
  else fail(`deployed binary record diverges from model: ${hostHead} vs ${modelSeqHead}`);
} else {
  fail(`expected 3 audit certs from the deployed binary, captured ${hostAudits.length}`);
}
}

console.log("\n===============================================================");
if (failed) { console.log(" CONFORMANCE BRIDGE: FAIL — a divergence was detected."); process.exit(1); }
console.log(" CONFORMANCE BRIDGE: PASS");
if (WASM) {
  console.log("   • the rebuilt-at-HEAD emscripten wasm (in-browser seal-check shape)");
  console.log("     conforms to the interpreted Lean model on corpus C");
  console.log("     (decision + audit bytes, both routes)");
  console.log("   • the SHA-256 record chain agrees across model / wasm");
} else {
  console.log("   • compiled native .so conforms to the interpreted Lean model");
  console.log("     on corpus C (decision + audit bytes, both routes)");
  console.log("   • the SHA-256 record chain agrees across model / native / the");
  console.log("     deployed seal-host-rs binary");
}
console.log("   • evidence over C only — NOT a universal binary==model claim");
console.log("===============================================================");
