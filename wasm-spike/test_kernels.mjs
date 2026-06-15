// D1e: drive all 7 verified kernels through the WASM module end-to-end, assert
// the expected route per step, and prove determinism (N runs -> identical certs).
import SealModule from "./build-core/seal.js";
import { scenarios, buildEnvelope, PUBKEY } from "./seal_scenarios.mjs";

const log = [];
const M = await SealModule({ print: (t) => log.push(t), printErr: (t) => log.push("[err] " + t) });

const seal_init = (env, pk) => M.ccall("seal_init", "string", ["string", "string"], [env, pk]);
const seal_decide = (input) => M.ccall("seal_decide", "string", ["string"], [input]);

const envelope = buildEnvelope();

function runScenario(s) {
  const initRes = JSON.parse(seal_init(envelope, PUBKEY));
  if (initRes.ok !== true) throw new Error(`seal_init failed: ${JSON.stringify(initRes)}`);
  const verdicts = [];
  for (let i = 0; i < s.steps.length; i++) {
    const v = JSON.parse(seal_decide(s.steps[i].input));
    verdicts.push(v);
    if (v.route !== s.steps[i].expect) {
      throw new Error(`${s.name} step ${i}: expected route=${s.steps[i].expect}, got ${v.route}` +
        (v.error ? ` (error: ${v.error})` : "") + (v.audit ? ` audit=${v.audit}` : ""));
    }
  }
  return verdicts;
}

let pass = 0;
const kernelsSeen = new Set();
for (const s of scenarios) {
  try {
    runScenario(s);
    kernelsSeen.add(s.kernel);
    console.log(`  PASS  ${s.name}`);
    pass++;
  } catch (e) {
    console.log(`  FAIL  ${s.name}\n        ${e.message}`);
  }
}

// Determinism: same input -> byte-identical audit certs across N runs.
const N = 100;
const detScenario = scenarios.find((s) => s.kernel === "consensus");
const first = JSON.stringify(runScenario(detScenario));
let detOk = true;
for (let i = 1; i < N; i++) {
  if (JSON.stringify(runScenario(detScenario)) !== first) { detOk = false; break; }
}

console.log(`\nkernels exercised: ${[...kernelsSeen].sort().join(", ")} (${kernelsSeen.size}/7)`);
console.log(`scenarios: ${pass}/${scenarios.length} passed`);
console.log(`determinism: ${detOk ? `OK (${N} runs identical)` : "FAILED — nondeterministic certs"}`);

const ok = pass === scenarios.length && kernelsSeen.size === 7 && detOk;
if (!ok && log.length) console.log("\n--- module output ---\n" + log.slice(-20).join("\n"));
process.exit(ok ? 0 : 1);
