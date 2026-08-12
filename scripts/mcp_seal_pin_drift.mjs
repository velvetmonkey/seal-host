#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Fail-closed three-way check for the mcp-seal source pin.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LAKEFILE = path.join(ROOT, "lakefile.toml");
const MANIFEST = path.join(ROOT, "lake-manifest.json");
const CHECKOUT = path.join(ROOT, ".lake", "packages", "mcp-seal");
const BASELINE = path.join(ROOT, "scripts", "mcp_seal_pin_baseline.json");
const TOML_REQUIRE_PARSER = path.join(ROOT, "scripts", "parse_lake_requirements.py");

function expectedRevision() {
  const baseline = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
  if (!/^[0-9a-f]{40}$/.test(baseline.mcpSealRevision)) {
    throw new Error("mcp-seal expected revision is missing or malformed in scripts/mcp_seal_pin_baseline.json");
  }
  return baseline.mcpSealRevision;
}

function lakefileRevision() {
  let requirements;
  try {
    requirements = JSON.parse(execFileSync("python3", [TOML_REQUIRE_PARSER, LAKEFILE], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }));
  } catch (error) {
    const detail = error.stderr?.trim() || error.message;
    throw new Error(`could not parse lakefile.toml as TOML (${detail})`);
  }
  requirements = requirements.filter((requirement) => requirement.name === "mcp-seal");
  if (requirements.length === 0 || !requirements[0].rev) {
    throw new Error("mcp-seal requirement is missing or malformed in lakefile.toml");
  }
  if (requirements.length > 1) {
    throw new Error(`duplicate mcp-seal require blocks in lakefile.toml at lines ${requirements.map((requirement) => requirement.line).join(", ")}`);
  }
  return requirements[0].rev;
}

function manifestRevision() {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, "utf8"));
  const packageEntry = manifest.packages.find((entry) => entry.name === "«mcp-seal»");
  if (!packageEntry || !/^[0-9a-f]{40}$/.test(packageEntry.rev)) {
    throw new Error("mcp-seal revision is missing or malformed in lake-manifest.json");
  }
  return packageEntry.rev;
}

function checkoutRevision() {
  if (!fs.existsSync(CHECKOUT)) {
    throw new Error("mcp-seal pin check failed: absent checkout .lake/packages/mcp-seal");
  }
  try {
    return execFileSync("git", ["-C", CHECKOUT, "rev-parse", "HEAD"], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch (error) {
    throw new Error(`mcp-seal pin check failed: unreadable checkout .lake/packages/mcp-seal (${error.message})`);
  }
}

export function checkMcpSealPin() {
  let expected;
  let lakefile;
  let manifest;
  try {
    expected = expectedRevision();
    lakefile = lakefileRevision();
    manifest = manifestRevision();
  } catch (error) {
    console.error(`mcp-seal pin drift: ${error.message}`);
    return 1;
  }

  let checkout;
  try {
    checkout = checkoutRevision();
  } catch (error) {
    console.error(`mcp-seal pin absent: ${error.message}`);
    console.error(`mcp-seal pin values: lakefile.toml="${lakefile}" lake-manifest.json="${manifest}" checkout="absent"`);
    return 1;
  }

  const values = [
    ["expected pin", expected],
    ["lakefile.toml", lakefile],
    ["lake-manifest.json", manifest],
    [".lake/packages/mcp-seal HEAD", checkout],
  ];
  const mismatches = [];
  for (let left = 0; left < values.length; left += 1) {
    for (let right = left + 1; right < values.length; right += 1) {
      if (values[left][1] !== values[right][1]) {
        mismatches.push(
          `mcp-seal pin drift: ${values[left][0]}="${values[left][1]}" disagrees with ${values[right][0]}="${values[right][1]}"`,
        );
      }
    }
  }
  if (mismatches.length > 0) {
    for (const mismatch of mismatches) console.error(mismatch);
    console.error(`mcp-seal pin values: lakefile.toml="${lakefile}" lake-manifest.json="${manifest}" checkout="${checkout}"`);
    return 1;
  }
  console.log(`mcp-seal pin PASS: expected="${expected}" lakefile.toml="${lakefile}" lake-manifest.json="${manifest}" checkout="${checkout}"`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkMcpSealPin();
}
