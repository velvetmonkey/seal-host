#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Claims drift guard. Credibility-critical claim text is mirrored across
// surfaces; this asserts each mirror is a verbatim copy of its canonical block,
// so drift fails loudly instead of shipping silently.
//
// Two guarded blocks:
//   non-claims (<!-- claims:begin --> ... <!-- claims:end -->)      canonical docs/LIMITATIONS.md
//   truth-box  (<!-- truthbox:begin --> ... <!-- truthbox:end -->)  canonical docs/TRUTH-BOX.md
// The truth-box "Map" line is per-repo (relative vs absolute links) and is
// deliberately OUTSIDE the markers, so only the profile/claim/non-claim lines
// are guarded.
//
// Exit codes: 0 in sync · 1 drift (diff printed) · 2 markers missing/malformed.
// Node only, no dependencies. Run: node scripts/claims-drift.mjs
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

function extract(file, begin, end) {
  let text;
  try {
    text = readFileSync(resolve(ROOT, file), "utf8");
  } catch (e) {
    console.error(`ERROR  ${file}: ${e.message}`);
    process.exit(2);
  }
  const i = text.indexOf(begin);
  const j = text.indexOf(end);
  if (i === -1 || j === -1 || j < i) {
    console.error(`ERROR  ${file}: markers missing or malformed (need ${begin} ... ${end})`);
    process.exit(2);
  }
  if (text.indexOf(begin, i + 1) !== -1 || text.indexOf(end, j + 1) !== -1) {
    console.error(`ERROR  ${file}: multiple ${begin} pairs — exactly one region per file`);
    process.exit(2);
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
  const canonical = normalise(extract(blk.canonical, blk.begin, blk.end));
  if (!canonical) {
    console.error(`ERROR  ${blk.canonical}: canonical block is empty`);
    process.exit(2);
  }
  for (const file of blk.mirrors) {
    const got = normalise(extract(file, blk.begin, blk.end));
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

if (drift) {
  console.error("\nCLAIMS DRIFT — edit the canonical file first, then mirror verbatim.");
  process.exit(1);
}
console.log("all claim blocks in sync across all surfaces");
