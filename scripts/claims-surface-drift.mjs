#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Repository-local claim surface drift guard. Credibility-critical claim text
// is mirrored across surfaces in this checkout; this asserts each mirror is a
// verbatim copy of its canonical block, so local drift fails loudly instead of
// shipping silently. It does not compare claims between repositories.
//
// Two guarded blocks:
//   non-claims (<!-- claims:begin --> ... <!-- claims:end -->)      canonical docs/LIMITATIONS.md
//   truth-box  (<!-- truthbox:begin --> ... <!-- truthbox:end -->)  canonical docs/TRUTH-BOX.md
// The truth-box "Map" line is per-repo (relative vs absolute links) and is
// deliberately OUTSIDE the markers, so only the profile/claim/non-claim lines
// are guarded.
//
// Exit codes: 0 in sync · 1 drift (diff printed) · 2 fatal read/structure error.
// A fatal error and drift together take the more severe code, 2.
// Node only, no dependencies. Run: node scripts/claims-surface-drift.mjs
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const BLOCKS = [
  { begin: "<!-- claims:begin -->", end: "<!-- claims:end -->",
    canonical: "docs/LIMITATIONS.md", mirrors: ["README.md", "docs/THREAT-MODEL.md"] },
  { begin: "<!-- truthbox:begin -->", end: "<!-- truthbox:end -->",
    canonical: "docs/TRUTH-BOX.md", mirrors: ["README.md"] },
];

const CLAIM_MANIFEST = [
  ["docs/SEAL-SYSTEM-TCB.md", "it explicitly allows are gated. A call the policy does not cover is out of scope, not \"safe\""],
];

let fatal = false;

function fatalError(message) {
  fatal = true;
  console.error(message);
}
function extract(file, begin, end) {
  let text;
  try {
    text = readFileSync(resolve(ROOT, file), "utf8");
  } catch (e) {
    fatalError(`ERROR  ${file}: ${e.message}`);
    return null;
  }
  const i = text.indexOf(begin);
  const j = text.indexOf(end);
  if (i === -1 || j === -1 || j < i) {
    fatalError(`ERROR  ${file}: markers missing or malformed (need ${begin} ... ${end})`);
    return null;
  }
  if (text.indexOf(begin, i + 1) !== -1 || text.indexOf(end, j + 1) !== -1) {
    fatalError(`ERROR  ${file}: multiple ${begin} pairs — exactly one region per file`);
    return null;
  }
  return text.slice(i + begin.length, j);
}

// Per-line trim + drop blanks; strip any HTML <pre> wrapper. The claim text
// itself contains no HTML entities or tags, so tag-stripping is safe.
function normalise(block) {
  return block
    .replace(/<pre[^>]*>/g, "")
    .replace(/<\/pre>/g, "")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .join("\n");
}

let drift = false;
for (const blk of BLOCKS) {
  const canonicalBlock = extract(blk.canonical, blk.begin, blk.end);
  const canonical = canonicalBlock === null ? null : normalise(canonicalBlock);
  if (!canonical) {
    if (canonical !== null) {
      fatalError(`ERROR  ${blk.canonical}: canonical block is empty`);
    }
    for (const file of blk.mirrors) extract(file, blk.begin, blk.end);
    continue;
  }
  for (const file of blk.mirrors) {
    const mirrorBlock = extract(file, blk.begin, blk.end);
    if (mirrorBlock === null) continue;
    const got = normalise(mirrorBlock);
    if (got === canonical) {
      console.log(`PASS  ${file} matches ${blk.canonical}`);
      continue;
    }
    drift = true;
    console.error(`FAIL  ${file} diverges from ${blk.canonical}:`);
    const a = canonical.split("\n");
    const b = got.split("\n");
    for (let k = 0; k < Math.max(a.length, b.length); k++) {
      if (a[k] !== b[k]) {
        console.error(`  line ${k + 1}:`);
        console.error(`    canonical : ${a[k] ?? "<missing>"}`);
        console.error(`    ${file.padEnd(12)}: ${b[k] ?? "<missing>"}`);
      }
    }
  }
}

for (const [file, claim] of CLAIM_MANIFEST) {
  let text;
  try { text = readFileSync(resolve(ROOT, file), "utf8"); }
  catch (e) {
    fatalError(`ERROR  claim manifest entry ${file}: ${e.message}`);
    continue;
  }
  if (text.includes(claim)) console.log(`PASS  ${file} contains repaired claim`);
  else { drift = true; console.error(`FAIL  ${file} missing repaired claim: ${claim}`); }
}

if (drift) {
  console.error("\nCLAIMS DRIFT — edit the canonical file first, then mirror verbatim.");
  if (!fatal) process.exitCode = 1;
}
if (fatal) {
  process.exitCode = 2;
}
if (!drift && !fatal) {
  console.log("all claim blocks in sync across repository-local surfaces");
}
