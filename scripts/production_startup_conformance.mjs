#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Production-startup conformance for the deployed host binary. This is kept
// separate from conformance_bridge.mjs because that finite model corpus uses
// an intentionally ephemeral file-approval channel.

import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const HOST = process.env.SEAL_HOST_BIN || `${ROOT}/rust/target/release/seal-host-rs`;
const WORK = mkdtempSync(join(tmpdir(), "seal-production-conformance-"));
process.on("exit", () => {
  try { rmSync(WORK, { recursive: true, force: true }); } catch {}
});

const rawPublicKey = (key) => Buffer
  .from(key.export({ type: "spki", format: "der" }))
  .subarray(-32)
  .toString("hex");
const configKeys = generateKeyPairSync("ed25519");
const approvalKeys = generateKeyPairSync("ed25519");
const configPubkey = rawPublicKey(configKeys.publicKey);
const approvalPubkey = rawPublicKey(approvalKeys.publicKey);
if (configPubkey === approvalPubkey) throw new Error("test keys unexpectedly identical");

const approvals = join(WORK, "approvals.ndjson");
const tokens = join(WORK, "tokens.ndjson");
const replay = join(WORK, "approval-replay.sqlite");
const narrowReplay = join(WORK, "narrow-approval-replay.sqlite");
const receipts = join(WORK, "receipts");
const trusted = join(WORK, "trusted.json");
writeFileSync(approvals, "");
writeFileSync(tokens, "");
mkdirSync(receipts);
chmodSync(approvals, 0o600);
chmodSync(tokens, 0o600);
chmodSync(receipts, 0o700);

const payload = JSON.stringify({
  epoch: 1,
  safety: {
    approval: {
      control_file: approvals,
      ttl_seconds: 120,
      replay_store: {
        sqlite_path: replay,
        schema_version: 2,
        namespace_encoding_version: 1,
      },
    },
    tools: [{
      name: "db.execute",
      mode: "guarded",
      match: { type: "contains_any_ci", arg: "sql", needles: ["drop"] },
      target: [{ full_arguments: true }],
    }],
  },
});
writeFileSync(trusted, JSON.stringify({
  payload,
  signature: sign(null, Buffer.from(payload), configKeys.privateKey).toString("hex"),
}));
chmodSync(trusted, 0o600);

const initRun = spawnSync(HOST, [
  "--config", trusted,
  "--pubkey", configPubkey,
  "--initialize-replay-store",
], { encoding: "utf8" });
if (initRun.error) throw initRun.error;
if (initRun.status !== 0) {
  throw new Error(
    `replay-store initialization exited ${initRun.status}` +
    `\nstdout:\n${initRun.stdout}\nstderr:\n${initRun.stderr}`,
  );
}

const initialize = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" });
const guarded = JSON.stringify({
  jsonrpc: "2.0",
  id: 2,
  method: "tools/call",
  params: { name: "db.execute", arguments: { database: "prod", sql: "drop table startup_probe" } },
});
const run = spawnSync(HOST, [
  "--config", trusted,
  "--pubkey", configPubkey,
  "--channel", "ed25519",
  "--token-file", tokens,
  "--approval-pubkey", approvalPubkey,
  "--receipt-dir", receipts,
  "--", "/bin/cat",
], { input: `${initialize}\n${guarded}\n`, encoding: "utf8" });

if (run.error) throw run.error;
if (run.status !== 0) {
  throw new Error(`production host exited ${run.status}\nstdout:\n${run.stdout}\nstderr:\n${run.stderr}`);
}
if (run.stderr.includes("INSECURE DEVELOPMENT MODE")) {
  throw new Error("production startup emitted the insecure-development warning");
}
const output = run.stdout.trimEnd().split("\n");
if (output[0] !== initialize) {
  throw new Error(`production host never reached child-ready round trip: ${run.stdout}`);
}
if (!output[1]?.includes("approval required: ")) {
  throw new Error(`production host did not emit a guarded denial: ${run.stdout}`);
}
const stderrJson = run.stderr
  .split("\n")
  .filter(Boolean)
  .map((line) => { try { return JSON.parse(line); } catch { return null; } })
  .filter(Boolean);
const records = stderrJson.filter((value) => value.seal_record === "v1");
if (records.length !== 1 || records[0].entry !== 0) {
  throw new Error(`production host did not emit one sequenced record: ${run.stderr}`);
}
const receiptFiles = readFileSync(join(receipts, ".seal-audit-head.state"), "utf8");
if (!receiptFiles.includes(records[0].head)) {
  throw new Error("durable audit head does not contain the emitted record head");
}

const narrowPolicy = {
  epoch: 1,
  safety: {
    approval: {
      control_file: approvals,
      ttl_seconds: 120,
      replay_store: {
        sqlite_path: narrowReplay,
        schema_version: 2,
        namespace_encoding_version: 1,
      },
    },
    tools: [{
      name: "db.execute",
      mode: "guarded",
      match: { type: "contains_any_ci", arg: "sql", needles: ["drop"] },
      target: [{ full_arguments: true }],
    }],
  },
};
const narrowLineagePayload = JSON.stringify(narrowPolicy);
const narrowLineageTrusted = join(WORK, "narrow-lineage-trusted.json");
writeFileSync(narrowLineageTrusted, JSON.stringify({
  payload: narrowLineagePayload,
  signature: sign(null, Buffer.from(narrowLineagePayload), configKeys.privateKey).toString("hex"),
}));
chmodSync(narrowLineageTrusted, 0o600);
const narrowInitRun = spawnSync(HOST, [
  "--config", narrowLineageTrusted,
  "--pubkey", configPubkey,
  "--initialize-replay-store",
], { encoding: "utf8" });
if (narrowInitRun.error) throw narrowInitRun.error;
if (narrowInitRun.status !== 0) {
  throw new Error(
    `narrow replay-store initialization exited ${narrowInitRun.status}` +
    `\nstdout:\n${narrowInitRun.stdout}\nstderr:\n${narrowInitRun.stderr}`,
  );
}

narrowPolicy.safety.tools[0].target = [{ arg: "sql" }];
const narrowPayload = JSON.stringify(narrowPolicy);
const narrowTrusted = join(WORK, "narrow-trusted.json");
writeFileSync(narrowTrusted, JSON.stringify({
  payload: narrowPayload,
  signature: sign(null, Buffer.from(narrowPayload), configKeys.privateKey).toString("hex"),
}));
chmodSync(narrowTrusted, 0o600);
const narrowRun = spawnSync(HOST, [
  "--config", narrowTrusted,
  "--pubkey", configPubkey,
  "--channel", "ed25519",
  "--token-file", tokens,
  "--approval-pubkey", approvalPubkey,
  "--receipt-dir", receipts,
  "--", "/bin/cat",
], { encoding: "utf8" });
const guardTargetError = 'guard mode requires target [{"full_arguments": true}]';
if (narrowRun.error) throw narrowRun.error;
if (narrowRun.status === 0 || !narrowRun.stderr.includes(guardTargetError)) {
  throw new Error(
    `production host did not reject a narrow guarded target with the kernel error` +
    `\nstatus: ${narrowRun.status}\nstdout:\n${narrowRun.stdout}\nstderr:\n${narrowRun.stderr}`,
  );
}

console.log("PASS deployed binary completed a production-mode child round trip");
console.log("PASS production-mode guarded decision emitted a durable audit record");
console.log("PASS narrow policy replay-store config initialized at schema version 2");
console.log(`PASS production host rejected narrow guarded target: ${guardTargetError}`);
