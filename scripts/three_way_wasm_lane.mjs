#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// WASM lane runner for the three-way differential (rust/tests/three_way.rs).
//
// Loads the PINNED emscripten artifact (wasm-spike/verified/seal.js + seal.wasm)
// headless in Node and runs a step-input corpus through `seal_decide` — the thin
// C alias over the SAME Lean `seal_host_step` the native .so exports. One output
// line per step input, byte-faithful, streamed to the out file.
//
// Corpus protocol (shared with scripts/three_way_model_lane.lean and the native
// in-process lane in three_way.rs):
//   * one compact-JSON step input per line: {line, now, approvals, votes, grants, forecasts}
//   * the literal control line `#REINIT` re-initialises a FRESH session
//     (steps are stateful; segmentation bounds failure reproduction) and emits
//     NO output line. Real step inputs always start with `{`, so the control
//     token is unambiguous.
//
// This runner is deliberately separate from scripts/conformance_bridge.mjs —
// the bridge is a pinned evidence producer (docs/CONFORMANCE-BRIDGE.md,
// docs/conformance-wasm-ci-transcript.txt) and must not change under it.
//
// Usage:
//   node scripts/three_way_wasm_lane.mjs <envelope-file> <pubkey-hex> <corpus-file> <out-file>
//
// Exit non-zero on any init failure; the Rust harness treats that as a lane
// failure (fail-closed), never a skip.

import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";

const [ENVELOPE_FILE, PK, CORPUS_FILE, OUT_FILE] = process.argv.slice(2);
if (!ENVELOPE_FILE || !PK || !CORPUS_FILE || !OUT_FILE) {
  console.error("usage: three_way_wasm_lane.mjs <envelope-file> <pubkey-hex> <corpus-file> <out-file>");
  process.exit(2);
}

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const WASM_JS = `${ROOT}/wasm-spike/verified/seal.js`;

const require = createRequire(import.meta.url);
const factory = require(WASM_JS); // seal.js locates seal.wasm next to it (__dirname)
const M = await factory({ print() {}, printErr() {} });

const envelope = readFileSync(ENVELOPE_FILE, "utf8");
const init = () => {
  const out = M.ccall("seal_init", "string", ["string", "string"], [envelope, PK]);
  if (!out.includes('"ok":true')) {
    console.error(`three_way_wasm_lane: seal_init failed: ${out}`);
    process.exit(1);
  }
};

// Corpus-protocol trim: ASCII whitespace ONLY ({space, \t, \r, \n}), applied
// identically in all three lanes (JS .trim() is Unicode-aware and would
// diverge from Lean's trimAscii on e.g. U+00A0 — pinned here instead).
const asciiTrim = (s) => s.replace(/^[ \t\r\n]+/, "").replace(/[ \t\r\n]+$/, "");

init();
const lines = readFileSync(CORPUS_FILE, "utf8").split("\n");
const outs = [];
for (const raw of lines) {
  const line = asciiTrim(raw);
  if (!line) continue;
  if (line === "#REINIT") {
    init();
    continue;
  }
  outs.push(M.ccall("seal_decide", "string", ["string"], [line]));
}
writeFileSync(OUT_FILE, outs.join("\n") + (outs.length ? "\n" : ""));
