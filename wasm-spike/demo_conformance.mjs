// D3 (demo scenarios): prove WASM == native == captured.json for every demo
// scenario, including per-kernel cert hashes. Uses the SAME seal-config.js the
// browser demo uses, so the demo's live verdicts are exactly what's verified here.
import SealModule from "./build-core/seal.js";
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { SCENARIOS, buildEnvelope, buildStepInput, parseVerdict, PUBKEY } from "../../seal-demo/public/seal-config.js";

const keys = Object.keys(SCENARIOS);

// --- WASM (in-process) ---
const M = await SealModule({ print: () => {}, printErr: () => {} });
const wasm = {};
for (const k of keys) {
  const s = SCENARIOS[k];
  JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [buildEnvelope(s.config), PUBKEY]));
  wasm[k] = parseVerdict(M.ccall("seal_decide", "string", ["string"], [buildStepInput(s)]), s.tool);
}

// --- Native (libsealffi.so CLI) ---
const cmds = [];
for (const k of keys) { const s = SCENARIOS[k]; cmds.push(`INIT\t${buildEnvelope(s.config)}\t${PUBKEY}`, `STEP\t${buildStepInput(s)}`); }
const proc = spawnSync("./build-core/conformance_native", { input: cmds.join("\n") + "\n", encoding: "utf-8", maxBuffer: 64 << 20 });
if (proc.status !== 0) { console.error("native CLI failed:\n" + proc.stderr); process.exit(2); }
const out = proc.stdout.split("\n").filter((l) => l.length > 0);
const native = {};
keys.forEach((k, i) => { native[k] = parseVerdict(out[i * 2 + 1], SCENARIOS[k].tool); }); // [init, step] per scenario

// --- captured.json (the demo's published fixture) ---
const capPath = "../../seal-demo/fixtures/captured.json";
const cap = existsSync(capPath) ? JSON.parse(readFileSync(capPath, "utf-8")) : null;
// scenario -> {kernel, certHash} entries that must appear in the verdict's certs
const capExpect = {};
if (cap) {
  for (const d of cap.demo1_determinism || []) capExpect[d.id] = [{ kernel: d.deny_kernel, certHash: d.certHash }];
  if (cap.demo2_policy_swap) {
    capExpect["pay-before"] = cap.demo2_policy_swap.before.certs.map((c) => ({ kernel: c.kernel, certHash: c.certHash }));
    capExpect["pay-after"] = cap.demo2_policy_swap.after.certs.map((c) => ({ kernel: c.kernel, certHash: c.certHash }));
  }
  if (cap.demo3_confident_hallucination) {
    const d3 = cap.demo3_confident_hallucination;
    capExpect["store-safe"] = [{ kernel: "convergence", certHash: d3.safe.convergence.certHash }];
    capExpect["store-subtle"] = [{ kernel: "convergence", certHash: d3.subtle.convergence.certHash }];
  }
}

const certKey = (v) => JSON.stringify(v.certs.map((c) => [c.kernel, c.verdict, c.certHash]));
let bad = 0;
for (const k of keys) {
  const w = wasm[k], n = native[k];
  const wn = certKey(w) === certKey(n) && w.verdict === n.verdict;
  // every captured (kernel,certHash) must be present in the wasm verdict's certs
  const capOk = (capExpect[k] || []).every((e) => w.certs.some((c) => c.kernel === e.kernel && c.certHash === e.certHash));
  const ok = wn && capOk;
  if (!ok) bad++;
  console.log(`  ${ok ? "OK  " : "FAIL"} ${k}  ${w.verdict} (${w.deny_kernel || "all-allow"})  wasm==native:${wn} ==captured:${capOk}`);
  if (!ok) { console.log(`     wasm:   ${certKey(w)}`); console.log(`     native: ${certKey(n)}`); console.log(`     cap:    ${JSON.stringify(capExpect[k])}`); }
}
console.log(`\ndemo conformance: ${keys.length - bad}/${keys.length} scenarios (wasm == native == captured.json)`);
process.exit(bad === 0 ? 0 : 1);
