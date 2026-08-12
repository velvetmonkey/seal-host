#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Fail-closed three-way check for the mcp-seal source pin.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MANIFEST = path.join(ROOT, "lake-manifest.json");
const CHECKOUT = path.join(ROOT, ".lake", "packages", "mcp-seal");
const BASELINE = path.join(ROOT, "scripts", "mcp_seal_pin_baseline.json");
const LAKE_REVISION_PROBE = path.join(ROOT, "scripts", "lake_mcp_seal_revision.lean");
const LAKE_RESULT_PREFIX = "MCP_SEAL_LAKE_RESULT=";
const LAKE_TIMEOUT_MS = 120_000;
const SUPPORTED_LAKE_CONFIGS = new Set(["lakefile.lean", "lakefile.toml"]);

function lakeConfigCandidates(directory) {
  return fs.readdirSync(directory, { withFileTypes: true })
    .filter((entry) => entry.name.startsWith("lakefile."))
    .map((entry) => entry.name)
    .sort();
}

function guardPresentedLakeConfigs(packageDir) {
  const candidates = lakeConfigCandidates(ROOT);
  const unexpected = candidates.filter((name) => !SUPPORTED_LAKE_CONFIGS.has(name));
  if (unexpected.length > 0) {
    throw new Error(
      `Lake config presentation guard rejected unsupported config candidate(s): ${unexpected.join(", ")}`,
    );
  }
  const copiedCandidates = lakeConfigCandidates(packageDir);
  const missing = candidates.filter((name) => !copiedCandidates.includes(name));
  if (missing.length > 0) {
    throw new Error(
      `Lake config presentation guard found config file(s) not presented to Lake: ${missing.join(", ")}`,
    );
  }
  for (const name of candidates) {
    const source = fs.readFileSync(path.join(ROOT, name));
    const copy = fs.readFileSync(path.join(packageDir, name));
    if (!source.equals(copy)) {
      throw new Error(
        `Lake config presentation guard found a non-identical config snapshot: ${name}`,
      );
    }
  }
  return candidates;
}

function expectedRevision() {
  const baseline = JSON.parse(fs.readFileSync(BASELINE, "utf8"));
  if (!/^[0-9a-f]{40}$/.test(baseline.mcpSealRevision)) {
    throw new Error("mcp-seal expected revision is missing or malformed in scripts/mcp_seal_pin_baseline.json");
  }
  return baseline.mcpSealRevision;
}

function lakefileRevision() {
  const configuredLake = process.env.MCP_SEAL_LAKE_COMMAND;
  const localBuildWrapper = "/home/monkey/bin/leanbuild";
  const lakeCommand = configuredLake || (fs.existsSync(localBuildWrapper) ? localBuildWrapper : "lake");
  const preferredScratchRoot = "/home/monkey/scratch";
  const scratchRoot = fs.existsSync(preferredScratchRoot) ? preferredScratchRoot : os.tmpdir();
  let scratch;
  try {
    scratch = fs.mkdtempSync(path.join(scratchRoot, "mcp-seal-lake-"));
    const inputDir = path.join(scratch, "input");
    fs.cpSync(ROOT, inputDir, {
      recursive: true,
      dereference: false,
      verbatimSymlinks: true,
      preserveTimestamps: true,
    });
    const presentedConfigs = guardPresentedLakeConfigs(inputDir);
    fs.copyFileSync(path.join(ROOT, "lean-toolchain"), path.join(scratch, "lean-toolchain"));
    fs.writeFileSync(path.join(scratch, "lakefile.toml"), 'name = "mcp-seal-pin-probe"\n');
    const normalizedConfig = path.join(scratch, "normalized-lakefile.toml");

    const translation = spawnSync(lakeCommand, [
      "--dir", inputDir,
      "translate-config", "toml", normalizedConfig,
    ], {
      cwd: scratch,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: LAKE_TIMEOUT_MS,
    });
    if (translation.error?.code === "ETIMEDOUT") {
      throw new Error(`Lake timed out after ${LAKE_TIMEOUT_MS}ms`);
    }
    if (translation.error) {
      throw new Error(`Lake could not be invoked (${translation.error.message})`);
    }
    if (translation.status !== 0) {
      const detail = [translation.stderr.trim(), translation.stdout.trim()].filter(Boolean).join("\n") ||
        `exit ${translation.status}`;
      throw new Error(`Lake failed while selecting package configuration (${detail})`);
    }

    const result = spawnSync(lakeCommand, [
      "--dir", scratch,
      "env", "lean", "--run", LAKE_REVISION_PROBE,
      inputDir, normalizedConfig,
    ], {
      cwd: ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: LAKE_TIMEOUT_MS,
    });
    if (result.error?.code === "ETIMEDOUT") {
      throw new Error(`Lake timed out after ${LAKE_TIMEOUT_MS}ms`);
    }
    if (result.error) {
      throw new Error(`Lake could not be invoked (${result.error.message})`);
    }
    if (result.status !== 0) {
      const detail = [result.stderr.trim(), result.stdout.trim()].filter(Boolean).join("\n") ||
        `exit ${result.status}`;
      throw new Error(`Lake failed while resolving package configuration (${detail})`);
    }
    const resultLines = result.stdout.split(/\r?\n/).filter((line) => line.startsWith(LAKE_RESULT_PREFIX));
    if (resultLines.length !== 1) {
      throw new Error("Lake returned no unique mcp-seal dependency result");
    }
    let decoded;
    try {
      decoded = JSON.parse(resultLines[0].slice(LAKE_RESULT_PREFIX.length));
    } catch (error) {
      throw new Error(`Lake returned an unparseable mcp-seal dependency result (${error.message})`);
    }
    const dependencies = decoded?.dependencies;
    const chosenConfig = decoded?.chosenConfig;
    if (!Array.isArray(dependencies) || typeof chosenConfig !== "string") {
      throw new Error("Lake returned a malformed mcp-seal dependency result");
    }
    if (!presentedConfigs.includes(chosenConfig)) {
      throw new Error(`Lake chose a config file not present in the verified snapshot: ${chosenConfig}`);
    }
    if (dependencies.length === 0) {
      throw new Error(`Lake resolved no mcp-seal requirement in ${chosenConfig}`);
    }
    if (dependencies.length > 1) {
      const blocks = dependencies.map((dependency) =>
        `block ${dependency.block} name=${JSON.stringify(dependency.name)} revision=${JSON.stringify(dependency.revision)}`,
      );
      throw new Error(`Lake resolved duplicate mcp-seal require blocks: ${blocks.join("; ")}`);
    }
    const revision = dependencies[0].revision;
    if (!/^[0-9a-f]{40}$/.test(revision)) {
      throw new Error("Lake resolved an mcp-seal requirement with a missing or malformed revision");
    }
    return { revision, chosenConfig };
  } catch (error) {
    if (error.message.startsWith("Lake ")) throw error;
    throw new Error(`Lake could not resolve package configuration (${error.message})`);
  } finally {
    if (scratch) fs.rmSync(scratch, { recursive: true, force: true });
  }
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
    console.error(`mcp-seal pin values: ${lakefile.chosenConfig}="${lakefile.revision}" lake-manifest.json="${manifest}" checkout="absent"`);
    return 1;
  }

  const values = [
    ["expected pin", expected],
    [lakefile.chosenConfig, lakefile.revision],
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
    console.error(`mcp-seal pin values: ${lakefile.chosenConfig}="${lakefile.revision}" lake-manifest.json="${manifest}" checkout="${checkout}"`);
    return 1;
  }
  console.log(`mcp-seal pin PASS: expected="${expected}" ${lakefile.chosenConfig}="${lakefile.revision}" lake-manifest.json="${manifest}" checkout="${checkout}"`);
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = checkMcpSealPin();
}
