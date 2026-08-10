#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Claims drift guard. Credibility-critical claim text is mirrored across
// surfaces; this asserts each mirror is a verbatim copy of its canonical block,
// so drift fails loudly instead of shipping silently. With --family-root it also
// hashes the canonical truth-box block in every public family repo and rejects
// any cross-repo divergence.
//
// Two guarded blocks:
//   non-claims (<!-- claims:begin --> ... <!-- claims:end -->)      canonical docs/LIMITATIONS.md
//   truth-box  (<!-- truthbox:begin --> ... <!-- truthbox:end -->)  canonical docs/TRUTH-BOX.md
// The truth-box "Map" line is per-repo (relative vs absolute links) and is
// deliberately OUTSIDE the markers, so only the profile/claim/non-claim lines
// are guarded.
//
// Exit codes: 0 in sync · 1 drift (diff printed) · 2 missing/malformed/unreadable input.
// Node only, no dependencies. Run: node scripts/claims-drift.mjs
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const FAMILY_REPOS = [
  "seal",
  "seal-host",
  "seal-check",
  "seal-live-demo",
  "seal-verify-action",
  "seal-assurance-kit",
  "mcp-seal-dev",
];

function parseArgs(argv) {
  if (argv.length === 0) return { familyRoot: null };
  if (argv.length === 2 && argv[0] === "--family-root" && argv[1]) {
    return { familyRoot: resolve(argv[1]) };
  }
  console.error("usage: node scripts/claims-drift.mjs [--family-root FAMILY_ROOT]");
  process.exit(2);
}

const { familyRoot } = parseArgs(process.argv.slice(2));

const BLOCKS = [
  { begin: "<!-- claims:begin -->", end: "<!-- claims:end -->",
    canonical: "docs/LIMITATIONS.md", mirrors: ["README.md", "docs/THREAT-MODEL.md"] },
  { begin: "<!-- truthbox:begin -->", end: "<!-- truthbox:end -->",
    canonical: "docs/TRUTH-BOX.md", mirrors: ["README.md"] },
];

function extract(file, begin, end) {
  let text;
  const path = resolve(ROOT, file);
  try {
    const stat = statSync(path);
    if (!stat.isFile() || (stat.mode & 0o444) === 0) {
      throw new Error("input is not a readable regular file");
    }
    text = readFileSync(path, "utf8");
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

function extractFromRoot(root, file, begin, end) {
  let text;
  const path = resolve(root, file);
  try {
    const stat = statSync(path);
    if (!stat.isFile() || (stat.mode & 0o444) === 0) {
      throw new Error("input is not a readable regular file");
    }
    text = readFileSync(path, "utf8");
  } catch (e) {
    console.error(`ERROR  ${path}: ${e.message}`);
    process.exit(2);
  }
  const i = text.indexOf(begin);
  const j = text.indexOf(end);
  if (i === -1 || j === -1 || j < i) {
    console.error(`ERROR  ${path}: markers missing or malformed (need ${begin} ... ${end})`);
    process.exit(2);
  }
  if (text.indexOf(begin, i + 1) !== -1 || text.indexOf(end, j + 1) !== -1) {
    console.error(`ERROR  ${path}: multiple ${begin} pairs — exactly one region per file`);
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

if (familyRoot) {
  const truthbox = BLOCKS[1];
  const hashes = new Map();
  for (const repo of FAMILY_REPOS) {
    const canonical = normalise(extractFromRoot(
      familyRoot,
      `${repo}/docs/TRUTH-BOX.md`,
      truthbox.begin,
      truthbox.end,
    ));
    if (!canonical) {
      console.error(`ERROR  ${repo}/docs/TRUTH-BOX.md: canonical block is empty`);
      process.exit(2);
    }
    const hash = createHash("sha256").update(canonical, "utf8").digest("hex");
    hashes.set(repo, hash);
    console.log(`PASS  family ${repo} truth-box sha256=${hash}`);
  }
  const expected = hashes.get(FAMILY_REPOS[0]);
  const mismatches = FAMILY_REPOS.filter((repo) => hashes.get(repo) !== expected);
  if (mismatches.length > 0) {
    console.error("\nFAMILY CLAIMS DRIFT — canonical truth-box hashes diverge:");
    for (const repo of mismatches) {
      console.error(`  ${repo}: ${hashes.get(repo)}`);
    }
    console.error(`  expected (${FAMILY_REPOS[0]}): ${expected}`);
    process.exit(1);
  }
  console.log("family truth-box hashes match across all seven repos");
}

console.log("all claim blocks in sync across all surfaces");
