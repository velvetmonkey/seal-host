// SPDX-License-Identifier: Apache-2.0

import test from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  CLOSED_PROFILE,
  STATEFUL_PROFILE,
  evaluateBundle,
} from "../receipt-verifier/verify.mjs";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const VERIFY = `${ROOT}/receipt-verifier/verify.mjs`;
const WASM_JS = `${ROOT}/wasm-spike/verified/seal.js`;
const WASM_PATH = `${ROOT}/receipt-verifier/wasm/seal.wasm`;
const WORK = mkdtempSync(join(tmpdir(), "seal-six-lines-"));
test.after(() => rmSync(WORK, { recursive: true, force: true }));

const key = () => {
  const pair = generateKeyPairSync("ed25519");
  return {
    ...pair,
    publicHex: pair.publicKey.export({ type: "spki", format: "der" }).subarray(-32).toString("hex"),
  };
};
const keys = { issuer: key(), request: key(), approval: key(), config: key() };
const trust = {
  issuer: keys.issuer.publicHex,
  request: keys.request.publicHex,
  approval: keys.approval.publicHex,
};

function preimage(role, payload) {
  const body = Buffer.from(payload);
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(body.length));
  return Buffer.concat([Buffer.from(`seal.${role}-statement/v1\0`), length, body]);
}

function statement(role, payload, signingKey = keys[role]) {
  return {
    payload,
    signature: {
      algorithm: "Ed25519",
      encoding: "base64url-nopad",
      public_key: signingKey.publicHex,
      value: sign(null, preimage(role, payload), signingKey.privateKey).toString("base64url"),
    },
  };
}

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function validBundle() {
  const requestPayload = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.add","arguments":{"text":"six independent facts"}}}';
  const approvalPayload = JSON.stringify({ target: "unused-for-explicit-allow", issuedAt: 1000 });
  const configPayload = JSON.stringify({
    epoch: 1,
    safety: {
      approval: {
        control_file: "/not-read-by-the-offline-verifier/approvals.ndjson",
        ttl_seconds: 120,
        replay_store: {
          sqlite_path: "/not-read-by-the-offline-verifier/replay.sqlite",
          schema_version: 2,
          namespace_encoding_version: 1,
        },
      },
      tools: [{ name: "notes.add", mode: "allow", match: { type: "always" } }],
    },
  });
  const configSignature = sign(null, Buffer.from(configPayload), keys.config.privateKey).toString("hex");
  const signedConfig = JSON.stringify({ payload: configPayload, signature: configSignature });
  const stepInput = JSON.stringify({
    line: requestPayload,
    now: 1000,
    approvals: [JSON.parse(approvalPayload)],
    votes: "",
    grants: "",
    forecasts: "",
  });
  const require = createRequire(import.meta.url);
  const module = await require(WASM_JS)({ print() {}, printErr() {} });
  assert.match(module.ccall("seal_init", "string", ["string", "string"], [signedConfig, keys.config.publicHex]), /"ok":true/);
  const rawKernelOutput = module.ccall("seal_decide", "string", ["string"], [stepInput]);
  const decision = {
    verification_profile: { id: CLOSED_PROFILE },
    request_payload_sha256: sha256(requestPayload),
    approval_payload_sha256: sha256(approvalPayload),
    kernel_identity: { wasm_sha256: sha256(readFileSync(WASM_PATH)) },
    standalone_replay_closure: {
      semantics: "one-init-one-decide",
      every_verdict_input_embedded: true,
      prior_kernel_state_required: false,
      prior_host_state_required: false,
      active_kernel_set_bound: true,
      omitted_state_influences: false,
    },
    replay: {
      signed_config: signedConfig,
      config_pubkey: keys.config.publicHex,
      logical_time: 1000,
      votes: "",
      grants: "",
      forecasts: "",
      step_input: stepInput,
      raw_kernel_output: rawKernelOutput,
    },
  };
  return {
    issuer_statement: statement("issuer", JSON.stringify(decision)),
    request_statement: statement("request", requestPayload),
    approval_statement: statement("approval", approvalPayload),
  };
}

function resignDecision(bundle, mutate) {
  const copy = structuredClone(bundle);
  const decision = JSON.parse(copy.issuer_statement.payload);
  mutate(decision);
  copy.issuer_statement = statement("issuer", JSON.stringify(decision));
  return copy;
}

const lines = (result) => [
  result.issuer,
  result.request,
  result.approval,
  result.decision,
  result.history,
  result.execution,
];

function cli(path, verifier = VERIFY) {
  return spawnSync(process.execPath, [
    verifier,
    path,
    "--issuer-pubkey", trust.issuer,
    "--request-pubkey", trust.request,
    "--approval-pubkey", trust.approval,
  ], { encoding: "utf8" });
}

async function physicalMutation(name, mutate) {
  const path = join(WORK, `${name}.json`);
  const baselineBundle = await validBundle();
  const baselineBytes = Buffer.from(JSON.stringify(baselineBundle));
  writeFileSync(path, baselineBytes);
  const checksumBefore = sha256(readFileSync(path));
  const baseline = cli(path);
  assert.equal(baseline.status, 0, baseline.stderr);
  const mutated = mutate(structuredClone(baselineBundle));
  writeFileSync(path, JSON.stringify(mutated));
  const observed = cli(path);
  writeFileSync(path, baselineBytes);
  const checksumAfter = sha256(readFileSync(path));
  assert.equal(checksumAfter, checksumBefore, "receipt must restore byte-identically after mutation");
  return {
    baseline: baseline.stdout.trim().split("\n"),
    observed: observed.stdout.trim().split("\n"),
    status: observed.status,
  };
}

test("1 valid single-step-closed receipt prints the six honest outcomes", async () => {
  const result = await evaluateBundle(await validBundle(), trust);
  assert.deepEqual(lines(result), [
    "ISSUER AUTHENTICATED",
    "REQUEST SIGNATURE VERIFIED",
    "APPROVAL SIGNATURE VERIFIED",
    "DECISION REPRODUCED",
    "HISTORY NOT INDEPENDENTLY VERIFIED",
    "EXECUTION NOT ATTESTED",
  ]);
  console.log(`[valid-six-lines]\n${lines(result).join("\n")}`);
});

test("2 corrupt request signature flips only its own outcome", async () => {
  const run = await physicalMutation("request-signature", (corrupt) => {
    const bytes = Buffer.from(corrupt.request_statement.signature.value, "base64url");
    bytes[0] ^= 1;
    corrupt.request_statement.signature.value = bytes.toString("base64url");
    return corrupt;
  });
  assert.notEqual(run.status, 0);
  assert.deepEqual(run.observed, run.baseline.map((line, index) => index === 1
    ? "REQUEST SIGNATURE NOT VERIFIED"
    : line));
  console.log(`[test-2-corrupt-request-signature]\n${run.observed.join("\n")}`);
});

test("3 corrupt approval signature flips only its own outcome", async () => {
  const run = await physicalMutation("approval-signature", (corrupt) => {
    const bytes = Buffer.from(corrupt.approval_statement.signature.value, "base64url");
    bytes[0] ^= 1;
    corrupt.approval_statement.signature.value = bytes.toString("base64url");
    return corrupt;
  });
  assert.notEqual(run.status, 0);
  assert.deepEqual(run.observed, run.baseline.map((line, index) => index === 2
    ? "APPROVAL SIGNATURE NOT VERIFIED"
    : line));
});

test("4 replay divergence flips only the decision outcome while signatures hold", async () => {
  const run = await physicalMutation("replay-divergence", (bundle) => {
    const requestPayload = bundle.request_statement.payload.replace(
      "six independent facts", "six independently changed facts",
    );
    bundle.request_statement = statement("request", requestPayload);
    const decision = JSON.parse(bundle.issuer_statement.payload);
    decision.request_payload_sha256 = sha256(requestPayload);
    const stepInput = JSON.parse(decision.replay.step_input);
    stepInput.line = requestPayload;
    decision.replay.step_input = JSON.stringify(stepInput);
    bundle.issuer_statement = statement("issuer", JSON.stringify(decision));
    return bundle;
  });
  assert.notEqual(run.status, 0);
  assert.deepEqual(run.observed, [
    "ISSUER AUTHENTICATED",
    "REQUEST SIGNATURE VERIFIED",
    "APPROVAL SIGNATURE VERIFIED",
    "DECISION NOT REPRODUCED",
    "HISTORY NOT INDEPENDENTLY VERIFIED",
    "EXECUTION NOT ATTESTED",
  ]);
});

test("5 stateful receipt requires a trace and never reproduces a decision", async () => {
  const valid = await validBundle();
  const bundle = resignDecision(valid, (decision) => {
    decision.verification_profile.id = STATEFUL_PROFILE;
  });
  const result = await evaluateBundle(bundle, trust);
  assert.equal(result.decision, "TRACE REQUIRED");
  assert.equal(lines(result).includes("DECISION REPRODUCED"), false);

  const closureMutations = [
    (closure) => { closure.semantics = "two-decides"; },
    (closure) => { closure.every_verdict_input_embedded = false; },
    (closure) => { closure.prior_kernel_state_required = true; },
    (closure) => { closure.prior_host_state_required = true; },
    (closure) => { closure.active_kernel_set_bound = false; },
    (closure) => { closure.omitted_state_influences = true; },
  ];
  for (const mutate of closureMutations) {
    const violated = resignDecision(valid, (decision) => mutate(decision.standalone_replay_closure));
    assert.equal((await evaluateBundle(violated, trust)).decision, "DECISION NOT REPRODUCED");
  }
});

test("6 unknown and absent profiles are distinct non-zero refusals", async () => {
  const valid = await validBundle();
  const unknown = resignDecision(valid, (decision) => { decision.verification_profile.id = "seal.unknown/v1"; });
  const absent = resignDecision(valid, (decision) => { delete decision.verification_profile; });
  assert.match((await evaluateBundle(unknown, trust)).decision, /UNKNOWN VERIFICATION PROFILE seal\.unknown\/v1/);
  assert.equal((await evaluateBundle(absent, trust)).decision, "DECISION NOT EVALUATED — VERIFICATION PROFILE ABSENT");
  for (const [name, bundle] of [["unknown", unknown], ["absent-profile", absent]]) {
    const path = join(WORK, `${name}.json`);
    writeFileSync(path, JSON.stringify(bundle));
    assert.notEqual(cli(path).status, 0);
  }
});

test("7 absent, empty, and unreadable files have distinct messages and six outcomes", () => {
  const empty = join(WORK, "empty.json");
  const unreadable = join(WORK, "unreadable.json");
  writeFileSync(empty, "");
  writeFileSync(unreadable, "{}");
  chmodSync(unreadable, 0o000);
  const cases = [
    [join(WORK, "absent.json"), "RECEIPT FILE ABSENT"],
    [empty, "RECEIPT FILE EMPTY"],
    [unreadable, "RECEIPT FILE UNREADABLE"],
  ];
  for (const [path, message] of cases) {
    const run = cli(path);
    assert.notEqual(run.status, 0);
    assert.match(run.stderr, new RegExp(message));
    assert.equal(run.stdout.trim().split("\n").length, 6);
  }
  chmodSync(unreadable, 0o600);
});

test("8 deleting the emitter call is caught by the physical output test", async () => {
  const path = join(WORK, "valid.json");
  writeFileSync(path, JSON.stringify(await validBundle()));
  const mutant = `${ROOT}/receipt-verifier/.verify-emitter-mutant.mjs`;
  const source = readFileSync(VERIFY, "utf8");
  assert.equal(source.match(/  emitOutcomes\(result\);/g)?.length, 1);
  writeFileSync(mutant, source.replace("  emitOutcomes(result);", "  // emitter deleted by meta-test"));
  try {
    const run = cli(path, mutant);
    assert.notEqual(run.stdout.trim().split("\n").filter(Boolean).length, 6,
      "the mutant must fail the six-line physical output assertion");
  } finally {
    rmSync(mutant, { force: true });
  }
});
