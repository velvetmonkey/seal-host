// SPDX-License-Identifier: Apache-2.0
// Producer-independent policy-v2 check over the rebuilt public-wasm shape.
import { createRequire } from "node:module";
import { buildEnvelope, guardTarget, PUBKEY } from "./seal_scenarios.mjs";

const require = createRequire(import.meta.url);
const SealModule = require("./build-core/seal.js");
const M = await SealModule({ print: () => {}, printErr: () => {} });

const payload = {
  epoch: 1,
  server: "conformance-server",
  safety: {
    approval: { control_file: "/tmp/unused", ttl_seconds: 120 },
    tools: [
      { name: "fs.call", mode: "allow", match: { type: "all", matches: [
        { type: "equals", arg: "operation", value: "read" },
        { type: "starts_with", arg: "path", value: "/safe/" },
      ] } },
      { name: "fs.call", mode: "guard", match: { type: "equals", arg: "operation", value: "write" },
        target: [{ full_arguments: true }] },
      { name: "fs.call", mode: "deny", match: { type: "starts_with", arg: "path", value: "/safe/secrets/" } },
    ],
  },
};

function init(config = payload) {
  return JSON.parse(M.ccall("seal_init", "string", ["string", "string"], [buildEnvelope(config), PUBKEY]));
}

function rpc(id, args) {
  return JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "fs.call", arguments: args } });
}

function decide(id, args, approvals = []) {
  const raw = M.ccall("seal_decide", "string", ["string"], [JSON.stringify({
    line: rpc(id, args), now: 1000, approvals, votes: "", grants: "", forecasts: "",
  })]);
  return JSON.parse(raw);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

assert(init().ok === true, "policy-v2 config did not initialize");
assert(decide(1, { operation: "read", path: "/safe/readme.txt" }).route === "forward",
  "conditional explicit allow did not forward");
assert(decide(2, { operation: "read", path: "/other/readme.txt" }).route === "block",
  "no-match did not default-deny");
assert(decide(3, { operation: "read", path: "/safe/secrets/key" }).route === "block",
  "deny did not dominate explicit allow");

const write = { operation: "write", path: "/safe/output.txt", content: "one" };
const expected = guardTarget("fs.call", write, "conformance-server");
const blocked = decide(4, write);
assert(blocked.route === "block" && blocked.response.includes(expected),
  "guard target did not bind tool+canonical full arguments and absent request context");
assert(decide(5, write, [{ target: expected }]).route === "forward",
  "exact target approval did not forward");
assert(decide(6, write).route === "block", "approval replay did not block");

const conflicting = structuredClone(payload);
conflicting.safety.server = "different-inner-server";
const conflict = init(conflicting);
assert(conflict.ok === false && /server identity conflicts/.test(conflict.error),
  "conflicting server identities did not fail closed");

console.log("POLICY-V2 WASM CONFORMANCE PASS");
