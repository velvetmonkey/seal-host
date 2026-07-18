#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Replay a Seal trace transcript without adding decision semantics.
//
// The harness performs exactly one seal_init, feeds the transcript's canonical
// requests to seal_decide in order, and byte-compares every raw output. Verdicts
// and receipts come only from the frozen kernel/runtime; this file creates none.

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { isDeepStrictEqual } = require("util");

function fail(message) {
  console.error(`FAIL trace transcript: ${message}`);
  process.exit(1);
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const transcript = args.shift();
  if (!transcript) {
    console.error("usage: node demo/trace_replay.cjs <trace-transcript.json> [--kit <seal-assurance-kit>] [--drop-trigger]");
    process.exit(2);
  }
  let kit = process.env.SEAL_ASSURANCE_KIT_ROOT || path.resolve(__dirname, "../../seal-assurance-kit");
  let dropTrigger = false;
  while (args.length) {
    const arg = args.shift();
    if (arg === "--kit") {
      kit = args.shift();
      if (!kit) process.exit(2);
    } else if (arg === "--drop-trigger") {
      dropTrigger = true;
    } else {
      console.error(`unknown argument: ${arg}`);
      process.exit(2);
    }
  }
  return { transcript: path.resolve(transcript), kit: path.resolve(kit), dropTrigger };
}

function routeOf(raw) {
  try { return JSON.parse(raw).route || "unknown"; }
  catch { return "unparseable"; }
}

async function main() {
  const options = parseArgs(process.argv);
  let transcript;
  try { transcript = JSON.parse(fs.readFileSync(options.transcript, "utf8")); }
  catch (error) { fail(`cannot read transcript: ${error.message}`); }
  if (transcript.schema !== "seal-demo-trace-transcript/v1") fail("unsupported schema");
  if (!Array.isArray(transcript.steps) || transcript.steps.length < 2) fail("need at least two ordered steps");
  if (!transcript.signed_config || typeof transcript.signed_config.payload !== "string" ||
      typeof transcript.signed_config.signature !== "string" || typeof transcript.signed_config.pubkey !== "string")
    fail("signed_config absent or malformed");

  const wasmDir = path.join(options.kit, "kernel", "wasm");
  const wasmPath = path.join(wasmDir, "seal.wasm");
  const wasmSha = sha256(fs.readFileSync(wasmPath));
  if (wasmSha !== transcript.wasm_sha256)
    fail(`vendored wasm sha mismatch expected=${transcript.wasm_sha256} actual=${wasmSha}`);

  const configModule = await import("file://" + path.join(options.kit, "kernel", "seal-config.js"));
  const formatModule = await import("file://" + path.join(options.kit, "kernel", "receipt-format.js"));
  globalThis.require = require;
  globalThis.__dirname = wasmDir;
  (0, eval)(fs.readFileSync(path.join(wasmDir, "seal.js"), "utf8"));
  const module = await globalThis.SealModule({
    locateFile: (name) => path.join(wasmDir, name), print() {}, printErr() {},
  });
  const envelope = JSON.stringify({
    payload: transcript.signed_config.payload,
    signature: transcript.signed_config.signature,
  });
  const initialized = JSON.parse(module.ccall(
    "seal_init", "string", ["string", "string"],
    [envelope, transcript.signed_config.pubkey],
  ));
  if (initialized.ok !== true) fail(`seal_init rejected pinned signed config: ${JSON.stringify(initialized)}`);

  const selected = options.dropTrigger ? transcript.steps.slice(1) : transcript.steps;
  for (const step of selected) {
    let receiptBytes, receipt;
    try {
      receiptBytes = Buffer.from(step.receipt_bytes_base64, "base64");
      receipt = JSON.parse(receiptBytes.toString("utf8"));
    } catch (error) {
      fail(`step ${step.sequence} receipt bytes malformed: ${error.message}`);
    }
    if (sha256(receiptBytes) !== step.receipt_sha256)
      fail(`step ${step.sequence} receipt sha mismatch`);
    if (receipt.emitted_bytes !== step.raw_kernel_output)
      fail(`step ${step.sequence} transcript raw output differs from embedded runtime receipt`);
    if (receipt.kernel_identity?.wasm_sha256 !== wasmSha)
      fail(`step ${step.sequence} receipt wasm identity mismatch`);
    if (!isDeepStrictEqual(receipt.signed_config, transcript.signed_config))
      fail(`step ${step.sequence} signed config differs from transcript pin`);

    const canonical = formatModule.canonicalRequest(receipt.tool, receipt.arguments);
    if (canonical !== step.canonical_request || canonical !== receipt.canonical_request)
      fail(`step ${step.sequence} canonical request mismatch`);
    const canonicalSha = sha256(Buffer.from(canonical));
    if (canonicalSha !== step.canonical_request_sha256 || canonicalSha !== receipt.canonical_request_sha256)
      fail(`step ${step.sequence} canonical request sha mismatch`);
    const requestId = JSON.parse(canonical).id;
    const grants = formatModule.capabilityTargetsFromPolicy(
      receipt.kernel_config, receipt.granted_capabilities,
    );
    if (grants.errors.length) fail(`step ${step.sequence} approval derivation: ${grants.errors.join("; ")}`);
    const input = configModule.buildStepInput({
      tool: receipt.tool,
      args: receipt.arguments,
      approvals: grants.approvals,
      now: receipt.now,
      id: requestId,
    });
    const actual = module.ccall("seal_decide", "string", ["string"], [input]);
    if (actual !== step.raw_kernel_output) {
      fail(
        `step ${step.sequence} byte mismatch expected_sha=${sha256(Buffer.from(step.raw_kernel_output))} ` +
        `actual_sha=${sha256(Buffer.from(actual))} expected_route=${routeOf(step.raw_kernel_output)} ` +
        `actual_route=${routeOf(actual)}`,
      );
    }
    console.log(
      `PASS trace step=${step.sequence} tool=${receipt.tool} ` +
      `raw_sha256=${sha256(Buffer.from(actual))}`,
    );
  }
  console.log(
    `PASS trace transcript steps=${selected.length} wasm_sha256=${wasmSha} ` +
    `mode=${options.dropTrigger ? "drop-trigger" : "full"}`,
  );
}

main().catch((error) => fail(error.stack || error.message));
