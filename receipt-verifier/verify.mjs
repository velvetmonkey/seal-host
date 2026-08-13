#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, statSync } from "node:fs";
import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

export const CLOSED_PROFILE = "seal.single-step-closed/v1";
export const STATEFUL_PROFILE = "seal.single-step-closed-stateful/v1";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const WASM_PATH = `${ROOT}/receipt-verifier/wasm/seal.wasm`;
const WASM_JS = `${ROOT}/wasm-spike/verified/seal.js`;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const unavailable = (reason) => ({
  issuer: `ISSUER NOT EVALUATED — ${reason}`,
  request: `REQUEST SIGNATURE NOT EVALUATED — ${reason}`,
  approval: `APPROVAL SIGNATURE NOT EVALUATED — ${reason}`,
  decision: `DECISION NOT EVALUATED — ${reason}`,
  history: `HISTORY NOT EVALUATED — ${reason}`,
  execution: `EXECUTION NOT EVALUATED — ${reason}`,
});

function signaturePreimage(role, payload) {
  const body = Buffer.from(payload, "utf8");
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(body.length));
  return Buffer.concat([Buffer.from(`seal.${role}-statement/v1\0`), length, body]);
}

function verifyStatement(statement, role, expectedPublicKey) {
  if (!statement || typeof statement !== "object") return false;
  if (typeof statement.payload !== "string" || !statement.signature) return false;
  const signature = statement.signature;
  if (signature.algorithm !== "Ed25519" || signature.encoding !== "base64url-nopad") return false;
  if (typeof signature.public_key !== "string" || signature.public_key !== expectedPublicKey) return false;
  if (!/^[0-9a-f]{64}$/.test(signature.public_key)) return false;
  if (typeof signature.value !== "string") return false;
  try {
    const rawKey = Buffer.from(signature.public_key, "hex");
    const publicKey = createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, rawKey]),
      format: "der",
      type: "spki",
    });
    const bytes = Buffer.from(signature.value, "base64url");
    if (bytes.length !== 64 || bytes.toString("base64url") !== signature.value) return false;
    return verifySignature(null, signaturePreimage(role, statement.payload), publicKey, bytes);
  } catch {
    return false;
  }
}

function sha256Hex(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function parsePayload(statement) {
  try {
    return JSON.parse(statement?.payload);
  } catch {
    return null;
  }
}

let wasmPromise;
async function wasm() {
  if (!wasmPromise) {
    const require = createRequire(import.meta.url);
    const factory = require(WASM_JS);
    wasmPromise = factory({ print() {}, printErr() {} });
  }
  return wasmPromise;
}

function closedConditionsHold(decision) {
  const closure = decision?.standalone_replay_closure;
  return closure?.semantics === "one-init-one-decide"
    && closure?.every_verdict_input_embedded === true
    && closure?.prior_kernel_state_required === false
    && closure?.prior_host_state_required === false
    && closure?.active_kernel_set_bound === true
    && closure?.omitted_state_influences === false;
}

async function reproduceDecision(bundle, decision) {
  if (!closedConditionsHold(decision)) return false;
  if (decision?.kernel_identity?.wasm_sha256 !== sha256Hex(readFileSync(WASM_PATH))) return false;
  const requestPayload = bundle.request_statement?.payload;
  const approvalPayload = bundle.approval_statement?.payload;
  if (typeof requestPayload !== "string" || typeof approvalPayload !== "string") return false;
  if (decision.request_payload_sha256 !== sha256Hex(Buffer.from(requestPayload, "utf8"))) return false;
  if (decision.approval_payload_sha256 !== sha256Hex(Buffer.from(approvalPayload, "utf8"))) return false;
  const replay = decision.replay;
  if (!replay || typeof replay !== "object") return false;
  let approval;
  try {
    approval = JSON.parse(approvalPayload);
  } catch {
    return false;
  }
  const rebuiltInput = JSON.stringify({
    line: requestPayload,
    now: replay.logical_time,
    approvals: [approval],
    votes: replay.votes,
    grants: replay.grants,
    forecasts: replay.forecasts,
  });
  if (rebuiltInput !== replay.step_input) return false;
  if (typeof replay.signed_config !== "string" || typeof replay.config_pubkey !== "string") return false;
  if (typeof replay.raw_kernel_output !== "string") return false;
  try {
    const module = await wasm();
    const init = module.ccall(
      "seal_init", "string", ["string", "string"],
      [replay.signed_config, replay.config_pubkey],
    );
    if (!init.includes('"ok":true')) return false;
    return module.ccall("seal_decide", "string", ["string"], [rebuiltInput])
      === replay.raw_kernel_output;
  } catch {
    return false;
  }
}

export async function evaluateBundle(bundle, trust) {
  if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) {
    return unavailable("RECEIPT UNREADABLE");
  }
  const decision = parsePayload(bundle.issuer_statement);
  const issuerOk = verifyStatement(bundle.issuer_statement, "issuer", trust.issuer);
  const requestOk = verifyStatement(bundle.request_statement, "request", trust.request);
  const approvalOk = verifyStatement(bundle.approval_statement, "approval", trust.approval);
  const profile = decision?.verification_profile?.id;
  let decisionLine;
  let diagnostic;
  if (typeof profile !== "string" || profile.length === 0) {
    decisionLine = "DECISION NOT EVALUATED — VERIFICATION PROFILE ABSENT";
    diagnostic = "VERIFICATION PROFILE ABSENT";
  } else if (profile === STATEFUL_PROFILE) {
    decisionLine = "TRACE REQUIRED";
    diagnostic = "STATEFUL RECEIPT REQUIRES TRACE";
  } else if (profile !== CLOSED_PROFILE) {
    decisionLine = `DECISION NOT EVALUATED — UNKNOWN VERIFICATION PROFILE ${profile}`;
    diagnostic = `VERIFICATION PROFILE UNKNOWN: ${profile}`;
  } else if (await reproduceDecision(bundle, decision)) {
    decisionLine = "DECISION REPRODUCED";
  } else {
    decisionLine = "DECISION NOT REPRODUCED";
  }
  return {
    issuer: issuerOk ? "ISSUER AUTHENTICATED" : "ISSUER NOT AUTHENTICATED",
    request: requestOk ? "REQUEST SIGNATURE VERIFIED" : "REQUEST SIGNATURE NOT VERIFIED",
    approval: approvalOk ? "APPROVAL SIGNATURE VERIFIED" : "APPROVAL SIGNATURE NOT VERIFIED",
    decision: decisionLine,
    history: "HISTORY NOT INDEPENDENTLY VERIFIED",
    execution: "EXECUTION NOT ATTESTED",
    diagnostic,
  };
}

export function emitOutcomes(result, stdout = console.log, stderr = console.error) {
  stdout(result.issuer);
  stdout(result.request);
  stdout(result.approval);
  stdout(result.decision);
  stdout(result.history);
  stdout(result.execution);
  if (result.diagnostic) stderr(result.diagnostic);
}

function processStatus(result) {
  // The process status is only a shell fail-closed signal. It is deliberately
  // derived after, and kept separate from, the six reader-facing facts.
  const established = new Set([
    result.issuer,
    result.request,
    result.approval,
    result.decision,
  ]);
  return established.has("ISSUER AUTHENTICATED")
    && established.has("REQUEST SIGNATURE VERIFIED")
    && established.has("APPROVAL SIGNATURE VERIFIED")
    && established.has("DECISION REPRODUCED")
    ? 0 : 1;
}

function readBundle(path) {
  try {
    const stat = statSync(path);
    if ((stat.mode & 0o444) === 0) return [null, "RECEIPT FILE UNREADABLE"];
    const bytes = readFileSync(path);
    if (bytes.length === 0) return [null, "RECEIPT FILE EMPTY"];
    try {
      return [JSON.parse(bytes.toString("utf8")), null];
    } catch {
      return [null, "RECEIPT JSON UNREADABLE"];
    }
  } catch (error) {
    if (error?.code === "ENOENT") return [null, "RECEIPT FILE ABSENT"];
    if (error?.code === "EACCES" || error?.code === "EPERM") return [null, "RECEIPT FILE UNREADABLE"];
    return [null, "RECEIPT FILE UNREADABLE"];
  }
}

function argumentsOf(argv) {
  const path = argv[0];
  const options = {};
  for (let i = 1; i < argv.length; i += 2) options[argv[i]] = argv[i + 1];
  return {
    path,
    trust: {
      issuer: options["--issuer-pubkey"],
      request: options["--request-pubkey"],
      approval: options["--approval-pubkey"],
    },
  };
}

export async function main(argv = process.argv.slice(2)) {
  const { path, trust } = argumentsOf(argv);
  if (!path) {
    console.error("usage: verify.mjs <receipt.json> --issuer-pubkey <hex> --request-pubkey <hex> --approval-pubkey <hex>");
    return 2;
  }
  const [bundle, error] = readBundle(path);
  const result = error ? unavailable(error) : await evaluateBundle(bundle, trust);
  if (error) result.diagnostic = error;
  emitOutcomes(result);
  return processStatus(result);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await main();
}
