// D3 conformance gate: feed an identical INIT/STEP command stream to BOTH the
// WASM module (in-process) and the native libsealffi.so CLI, then assert
// wasm verdict == native verdict == captured fixture for every step, including
// per-kernel cert hashes (carried inside the audit string). Native is the
// source of truth for the fixture (it is the proven path).
import SealModule from "./build-core/seal.js";
import { scenarios, buildEnvelope, PUBKEY } from "./seal_scenarios.mjs";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, existsSync } from "node:fs";

const envelope = buildEnvelope();

// Build the shared command stream + a flat label list (one per command).
const commands = [], labels = [], expectedRoutes = [];
for (const s of scenarios) {
  commands.push(`INIT\t${envelope}\t${PUBKEY}`);
  labels.push(`${s.name} :: INIT`);
  expectedRoutes.push(null);
  s.steps.forEach((st, i) => {
    commands.push(`STEP\t${st.input}`);
    labels.push(`${s.name} :: step ${i}`);
    expectedRoutes.push(st.expect);
  });
}

// --- WASM target (in-process) ---
const M = await SealModule({ print: () => {}, printErr: () => {} });
const w_init = (e, p) => M.ccall("seal_init", "string", ["string", "string"], [e, p]);
const w_step = (inp) => M.ccall("seal_decide", "string", ["string"], [inp]);
const wasmOut = commands.map((c) => {
  const [cmd, a, b] = c.split("\t");
  return cmd === "INIT" ? w_init(a, b) : w_step(a);
});

// --- Native target (spawn CLI over libsealffi.so) ---
const BIN = "./build-core/conformance_native";
if (!existsSync(BIN)) { console.error(`native CLI missing: ${BIN} (run build step first)`); process.exit(2); }
const proc = spawnSync(BIN, { input: commands.join("\n") + "\n", encoding: "utf-8", maxBuffer: 64 << 20 });
if (proc.status !== 0) { console.error("native CLI failed:\n" + proc.stderr); process.exit(2); }
const nativeOut = proc.stdout.split("\n").filter((l) => l.length > 0);

// --- Fixture (native = truth); capture on first run or when SEAL_UPDATE_FIXTURE=1 ---
const FIX = "conformance_fixture.json";
let fixture;
if (existsSync(FIX) && process.env.SEAL_UPDATE_FIXTURE !== "1") {
  fixture = JSON.parse(readFileSync(FIX, "utf-8"));
} else {
  fixture = nativeOut;
  writeFileSync(FIX, JSON.stringify(nativeOut, null, 2));
  console.log(`[fixture] captured ${nativeOut.length} verdicts from native -> ${FIX}`);
}

// --- Compare ---
let mismatches = 0;
const norm = (s) => { try { return JSON.stringify(JSON.parse(s)); } catch { return s; } };
for (let i = 0; i < commands.length; i++) {
  const w = norm(wasmOut[i]), n = norm(nativeOut[i]), f = norm(fixture[i]);
  let actualRoute = null;
  try { actualRoute = JSON.parse(nativeOut[i]).route ?? null; } catch {}
  const routeMatches = expectedRoutes[i] === null || actualRoute === expectedRoutes[i];
  if (!(w === n && n === f && routeMatches)) {
    mismatches++;
    console.log(`  MISMATCH  ${labels[i]}`);
    console.log(`    wasm:    ${w}`);
    console.log(`    native:  ${n}`);
    console.log(`    fixture: ${f}`);
    if (!routeMatches) console.log(`    route:   ${actualRoute} (expected ${expectedRoutes[i]})`);
  }
}
console.log(`\nconformance: ${commands.length - mismatches}/${commands.length} identical (wasm == native == fixture)`);
process.exit(mismatches === 0 ? 0 : 1);
