#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// seal-log — the verifiable-record verifier. Concrete instance of the
// machine-checked hash-chain in Host/Record.lean:
//
//   rollingHead H genesis (newest :: older) = H (rollingHead H genesis older) newest
//
// with the commitment H instantiated as SHA-256 (a credible collision-resistant
// hash, so assumption A-CR of `tamper_evident` is credible — NOT the 64-bit FNV
// `stableHashParts`, which is demonstration-grade only). A-GEN (fresh genesis)
// is a domain-separated constant.
//
// The Lean theorem `tamper_evident` proves: under A-CR + A-GEN, the chain head
// is an injective function of the whole log — so any insert / reorder / mutate
// changes the head and is detected. This script is the executable witness of
// that theorem over a real emitted decision log.
//
// Commands:
//   seal   <audit-lines-file> <sealed-out.json>   build the chain
//   verify <sealed.json>                           recompute + check (exit 1 on tamper)
//   head   <sealed.json>                           print the current chain head

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

// A-GEN: a fresh, domain-separated genesis head outside H's range in practice.
const GENESIS = createHash("sha256")
  .update("seal-verifiable-record/genesis/v1")
  .digest("hex");

// The commitment H(prevHead, payload): SHA-256 over the prior head and the
// payload, unit-separated (0x1f) so no payload can span the boundary.
function commit(prevHead, payload) {
  return createHash("sha256")
    .update(prevHead, "utf8")
    .update("\x1f", "utf8")
    .update(payload, "utf8")
    .digest("hex");
}

// Chronological fold: entry i's head commits payload i over entry i-1's head
// (entry 0 over GENESIS). Structurally identical to the Lean rollingHead;
// orientation is chronological here for a human-readable append log.
function chainHeads(payloads) {
  const heads = [];
  let head = GENESIS;
  for (const p of payloads) {
    head = commit(head, p);
    heads.push(head);
  }
  return heads;
}

function readLines(path) {
  return readFileSync(path, "utf8")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

function cmdSeal(inPath, outPath) {
  const payloads = readLines(inPath);
  const heads = chainHeads(payloads);
  const sealed = {
    format: "seal-verifiable-record/v1",
    commitment: "sha256(prevHead || 0x1f || payload)",
    genesis: GENESIS,
    entries: payloads.map((payload, i) => ({ payload, head: heads[i] })),
  };
  writeFileSync(outPath, JSON.stringify(sealed, null, 2) + "\n");
  const finalHead = heads.length ? heads[heads.length - 1] : GENESIS;
  console.log(`sealed ${payloads.length} entr${payloads.length === 1 ? "y" : "ies"} → ${outPath}`);
  console.log(`chain head: ${finalHead}`);
}

function cmdVerify(path) {
  const sealed = JSON.parse(readFileSync(path, "utf8"));
  if (sealed.genesis !== GENESIS) {
    console.error(`VERIFY FAIL: genesis mismatch (log is not rooted at this verifier's fresh genesis)`);
    process.exit(1);
  }
  const payloads = sealed.entries.map((e) => e.payload);
  const recomputed = chainHeads(payloads);
  for (let i = 0; i < sealed.entries.length; i++) {
    if (sealed.entries[i].head !== recomputed[i]) {
      console.error(`VERIFY FAIL: entry ${i} — recorded head does not match recomputed chain.`);
      console.error(`  recorded:   ${sealed.entries[i].head}`);
      console.error(`  recomputed: ${recomputed[i]}`);
      console.error(`  → the log was inserted into, reordered, or mutated at or before entry ${i}.`);
      process.exit(1);
    }
  }
  const finalHead = recomputed.length ? recomputed[recomputed.length - 1] : GENESIS;
  console.log(`VERIFY OK: ${sealed.entries.length} entries, chain intact.`);
  console.log(`chain head: ${finalHead}`);
}

function cmdHead(path) {
  const sealed = JSON.parse(readFileSync(path, "utf8"));
  const heads = chainHeads(sealed.entries.map((e) => e.payload));
  console.log(heads.length ? heads[heads.length - 1] : GENESIS);
}

const [cmd, ...rest] = process.argv.slice(2);
switch (cmd) {
  case "seal":
    if (rest.length !== 2) { console.error("usage: seal_log.mjs seal <audit-lines> <sealed-out.json>"); process.exit(2); }
    cmdSeal(rest[0], rest[1]);
    break;
  case "verify":
    if (rest.length !== 1) { console.error("usage: seal_log.mjs verify <sealed.json>"); process.exit(2); }
    cmdVerify(rest[0]);
    break;
  case "head":
    if (rest.length !== 1) { console.error("usage: seal_log.mjs head <sealed.json>"); process.exit(2); }
    cmdHead(rest[0]);
    break;
  default:
    console.error("usage: seal_log.mjs (seal|verify|head) ...");
    process.exit(2);
}
