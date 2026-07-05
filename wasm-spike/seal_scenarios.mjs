// Shared demo/conformance scenarios for the seal verified kernels.
// Mirrors test/integration/test_host.py (same config, same stable_hash, same
// per-kernel cases) but drives the seal_host_step JSON path (evidence injected
// inline) instead of the stdio binary + control files. Reused by the WASM node
// harness (D1e) and the WASM<->native conformance gate (D3).

import { createHash } from "node:crypto";

export const PUBKEY = "test-pk";

// SHA-256 target commitment, exact mirror of Seal.stableHashParts.
export function encodeParts(parts) {
  return parts.map((s) => {
    const p = String(s);
    return `${[...p].length}:${p}`;
  }).join("");
}

export function stableHash(parts) {
  return createHash("sha256").update(encodeParts(parts), "utf8").digest("hex");
}

// Canonical target hashes (tool name prepended to resolved target parts).
export const targets = {
  db:     stableHash(["db.execute", "db", "prod", "write", "drop table users"]),
  revoke: stableHash(["session.revoke", "revoke"]),
  pay:    stableHash(["payments.send", "pay"]),
  store:  stableHash(["store.update", "store"]),
  act:    stableHash(["model.act", "act"]),
  key:    stableHash(["key.use", "key"]),
};

// Trusted-config payload — identical content to test_host.py write_config().
// File paths are inert on the step path (evidence is injected inline) but must
// parse, so dummy paths are fine.
export const configPayload = {
  epoch: 1,
  safety: {
    approval: { control_file: "/tmp/approvals.ndjson", ttl_seconds: 120 },
    tools: [
      { name: "db.execute", mode: "guarded",
        match: { type: "contains_any_ci", arg: "sql", needles: ["drop", "delete", "truncate"] },
        target: [{ literal: "db" }, { arg: "database" }, { literal: "write" }, { arg: "sql" }] },
      { name: "session.revoke", mode: "guarded", match: { type: "always" }, target: [{ literal: "revoke" }] },
      { name: "payments.send", mode: "guarded", match: { type: "always" }, target: [{ literal: "pay" }] },
      { name: "store.update", mode: "guarded", match: { type: "always" }, target: [{ literal: "store" }] },
      { name: "model.act", mode: "guarded", match: { type: "always" }, target: [{ literal: "act" }] },
      { name: "key.use", mode: "guarded", match: { type: "always" }, target: [{ literal: "key" }] },
      { name: "approve", mode: "deny", match: { type: "always" }, target: [] },
    ],
  },
  temporal: { policies: [
    { name: "no-destructive-after-revoke", type: "no_after",
      trigger: ["session.revoke"], forbidden: ["db.execute"] } ] },
  consensus: { roster: [1, 2, 3], votes_file: "/tmp/votes.ndjson", high_stakes: ["payments.send"] },
  convergence: { tools: [{ tool: "store.update", op_arg: "op" }] },
  calibration: { enabled: true, delta_num: 1, delta_den: 20, min_samples: 10,
    records_file: "/tmp/forecasts.ndjson", gated_tools: ["model.act"] },
  linear: { grants_file: "/tmp/grants.ndjson", tools: [{ tool: "key.use", cap_arg: "key" }] },
  budget: { budgets: [{ name: "db-calls", cap: 2, tools: ["db.execute"] }] },
};

// Stub-signed envelope (verifyConfigSignature: signature == `stub-ed25519:<pk>:<payload>`).
export function buildEnvelope(payload = configPayload, pubkey = PUBKEY) {
  const compact = JSON.stringify(payload);
  return JSON.stringify({ payload: compact, signature: `stub-ed25519:${pubkey}:${compact}` });
}

const rpc = (id, name, args) =>
  JSON.stringify({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

const step = (line, extra = {}) =>
  JSON.stringify({ line, now: 1000, approvals: [], votes: "", grants: "", forecasts: "", ...extra });

const approve = (t) => ({ approvals: [{ target: t }] });
const destructive = { database: "prod", sql: "drop table users" };

// Each scenario starts a fresh session (seal_init) then runs ordered steps.
// expect = route the combined verdict must yield.
export const scenarios = [
  { name: "S/safety: guarded call, no approval -> block", kernel: "safety", steps: [
      { input: step(rpc(1, "db.execute", destructive)), expect: "block" } ] },
  // Approval is a one-time event; supplied once, the replay has no fresh approval.
  { name: "S/safety: approval allows once, replay blocked", kernel: "safety", steps: [
      { input: step(rpc(1, "db.execute", destructive), approve(targets.db)), expect: "forward" },
      { input: step(rpc(2, "db.execute", destructive)), expect: "block" } ] },
  { name: "T/temporal: destructive after revoke -> block", kernel: "temporal", steps: [
      { input: step(rpc(1, "db.execute", destructive), approve(targets.db)), expect: "forward" },
      { input: step(rpc(2, "session.revoke", {}), approve(targets.revoke)), expect: "forward" },
      { input: step(rpc(3, "db.execute", destructive), approve(targets.db)), expect: "block" } ] },
  { name: "C/consensus: high-stakes needs quorum", kernel: "consensus", steps: [
      { input: step(rpc(1, "payments.send", { amount: 10 }), approve(targets.pay)), expect: "block" },
      { input: step(rpc(2, "payments.send", { amount: 10 }),
          { ...approve(targets.pay),
            votes: JSON.stringify({ acceptor: 1, value: "payments.send" }) + "\n"
                 + JSON.stringify({ acceptor: 2, value: "payments.send" }) + "\n" }), expect: "forward" } ] },
  { name: "V/convergence: convergent op vs LWW", kernel: "convergence", steps: [
      { input: step(rpc(1, "store.update", { op: "orset.add", key: "k1" }), approve(targets.store)), expect: "forward" },
      { input: step(rpc(2, "store.update", { op: "assign", key: "k1" }), approve(targets.store)), expect: "block" } ] },
  { name: "K/calibration: calibrated vs overconfident", kernel: "calibration", steps: [
      { input: step(rpc(1, "model.act", { action: "send" }),
          { ...approve(targets.act),
            forecasts: Array.from({ length: 20 }, (_, i) =>
              JSON.stringify({ confidence: 0.5, outcome: i % 2 === 0 ? 1 : 0 })).join("\n") + "\n" }), expect: "forward" },
      { input: step(rpc(2, "model.act", { action: "send" }),
          { ...approve(targets.act),
            forecasts: Array.from({ length: 20 }, () =>
              JSON.stringify({ confidence: 0.9, outcome: 0 })).join("\n") + "\n" }), expect: "block" } ] },
  { name: "B/budget: db.execute capped at 2", kernel: "budget", steps: [
      { input: step(rpc(1, "db.execute", destructive), approve(targets.db)), expect: "forward" },
      { input: step(rpc(2, "db.execute", destructive), approve(targets.db)), expect: "forward" },
      { input: step(rpc(3, "db.execute", destructive), approve(targets.db)), expect: "block" } ] },
  // A grant is a one-time issuance event (additive); inject it once, then the
  // second use is a double-spend (0 uses left) and is denied.
  { name: "L/linear: capability spent once", kernel: "linear", steps: [
      { input: step(rpc(1, "key.use", { key: "deploy-key-7" }),
          { ...approve(targets.key), grants: JSON.stringify({ cap: "deploy-key-7", uses: 1 }) + "\n" }), expect: "forward" },
      { input: step(rpc(2, "key.use", { key: "deploy-key-7" }), approve(targets.key)), expect: "block" } ] },
];
