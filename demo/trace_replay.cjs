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

function canonicalRequestFromReceipt(formatModule, receipt) {
  const value = JSON.parse(formatModule.canonicalRequest(receipt.tool, receipt.arguments));
  if (Object.prototype.hasOwnProperty.call(receipt, "_meta")) {
    value.params._meta = receipt._meta;
  }
  return JSON.stringify(value);
}

function parseArgs(argv) {
  const args = argv.slice(2);
  const transcript = args.shift();
  if (!transcript) {
    console.error(
      "usage: node demo/trace_replay.cjs <trace-transcript.json> " +
      "[--kit <seal-assurance-kit>] [--drop-trigger|--drop-sequence <n>|--variant <name>]",
    );
    process.exit(2);
  }
  let kit = process.env.SEAL_ASSURANCE_KIT_ROOT || path.resolve(__dirname, "../../seal-assurance-kit");
  let dropSequence = null;
  let variant = null;
  while (args.length) {
    const arg = args.shift();
    if (arg === "--kit") {
      kit = args.shift();
      if (!kit) process.exit(2);
    } else if (arg === "--drop-trigger") {
      dropSequence = 1;
    } else if (arg === "--drop-sequence") {
      const raw = args.shift();
      const parsed = Number(raw);
      if (!Number.isInteger(parsed) || parsed < 1) process.exit(2);
      dropSequence = parsed;
    } else if (arg === "--variant") {
      variant = args.shift();
      if (!variant) process.exit(2);
    } else {
      console.error(`unknown argument: ${arg}`);
      process.exit(2);
    }
  }
  if (dropSequence !== null && variant !== null) {
    console.error("--drop-sequence/--drop-trigger cannot be combined with --variant");
    process.exit(2);
  }
  return { transcript: path.resolve(transcript), kit: path.resolve(kit), dropSequence, variant };
}

function routeOf(raw) {
  try { return JSON.parse(raw).route || "unknown"; }
  catch { return "unparseable"; }
}

function replayInput(step, receipt, grants, canonical, variantName) {
  let input = step.step_input;
  if (variantName !== null) {
    const variants = step.input_variants;
    if (variants && Object.prototype.hasOwnProperty.call(variants, variantName)) {
      input = variants[variantName];
    }
  }
  if (input === undefined) return null;
  if (!input || typeof input !== "object" || Array.isArray(input))
    fail(`step ${step.sequence} replay input malformed`);
  const expectedApprovals = grants.approvals.map((target) => ({ target }));
  if (input.line !== canonical) fail(`step ${step.sequence} replay input line differs from receipt`);
  if (input.now !== receipt.now) fail(`step ${step.sequence} replay input clock differs from receipt`);
  const traceApprovalEvents = input.approval_evidence === "trace-events";
  if (input.approval_evidence !== undefined && !traceApprovalEvents)
    fail("step " + step.sequence + " replay approval evidence mode is unsupported");
  if (traceApprovalEvents) {
    if (!Array.isArray(input.approvals))
      fail("step " + step.sequence + " trace approval events must be an array");
    const available = new Set(expectedApprovals.map((approval) => approval.target));
    if (input.approvals.some((approval) =>
      !approval || typeof approval !== "object" ||
      Object.keys(approval).length !== 1 ||
      typeof approval.target !== "string" ||
      !available.has(approval.target)))
      fail("step " + step.sequence + " trace approval event is not bound by the receipt grants");
  } else if (!isDeepStrictEqual(input.approvals, expectedApprovals)) {
    fail("step " + step.sequence + " replay approvals differ from receipt grants");
  }
  for (const field of ["votes", "grants", "forecasts"]) {
    if (typeof input[field] !== "string") fail(`step ${step.sequence} replay input ${field} must be a string`);
  }
  return JSON.stringify({
    line: input.line, now: input.now, approvals: input.approvals,
    votes: input.votes, grants: input.grants, forecasts: input.forecasts,
  });
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
  function initialize() {
    const initialized = JSON.parse(module.ccall(
      "seal_init", "string", ["string", "string"],
      [envelope, transcript.signed_config.pubkey],
    ));
    if (initialized.ok !== true)
      fail(`seal_init rejected pinned signed config: ${JSON.stringify(initialized)}`);
  }
  initialize();

  if (options.dropSequence !== null && !transcript.steps.some((step) => step.sequence === options.dropSequence))
    fail(`drop sequence ${options.dropSequence} is absent`);
  if (options.variant !== null) {
    const owners = transcript.steps.filter(
      (step) => step.input_variants && Object.prototype.hasOwnProperty.call(step.input_variants, options.variant),
    );
    if (owners.length !== 1) fail(`variant ${JSON.stringify(options.variant)} must occur on exactly one step`);
  }
  const selected = options.dropSequence === null
    ? transcript.steps : transcript.steps.filter((step) => step.sequence !== options.dropSequence);
  const committed = [];
  function executeStep(step, variantName, report) {
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

    const canonical = canonicalRequestFromReceipt(formatModule, receipt);
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
    const explicit = replayInput(step, receipt, grants, canonical, variantName);
    const input = explicit || configModule.buildStepInput({
      tool: receipt.tool, args: receipt.arguments, approvals: grants.approvals,
      now: receipt.now, id: requestId,
    });
    const actual = module.ccall("seal_decide", "string", ["string"], [input]);
    if (actual !== step.raw_kernel_output) {
      fail(
        `step ${step.sequence} byte mismatch expected_sha=${sha256(Buffer.from(step.raw_kernel_output))} ` +
        `actual_sha=${sha256(Buffer.from(actual))} expected_route=${routeOf(step.raw_kernel_output)} ` +
        `actual_route=${routeOf(actual)}`,
      );
    }
    if (report) {
      console.log(
        `PASS trace step=${step.sequence} tool=${receipt.tool} ` +
        `raw_sha256=${sha256(Buffer.from(actual))}`,
      );
    }
  }
  for (const step of selected) {
    executeStep(step, options.variant, true);
    if (step.commit === false) {
      initialize();
      for (const prior of committed) executeStep(prior, null, false);
    } else {
      committed.push(step);
    }
  }
  console.log(
    `PASS trace transcript steps=${selected.length} wasm_sha256=${wasmSha} ` +
    `mode=${options.variant !== null ? `variant:${options.variant}` :
      options.dropSequence !== null ? `drop-sequence:${options.dropSequence}` : "full"}`,
  );
}

main().catch((error) => fail(error.stack || error.message));
