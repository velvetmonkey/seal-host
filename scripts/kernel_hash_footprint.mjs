#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Generate and gate the fleet-wide footprint of plausible kernel identities.
// The fleet lock is the only repository registry: no repository or occurrence
// is hand-listed here.

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const FLEET_LOCK_PATH = path.join(ROOT, "release", "fleet-lock.json");
export const MANIFEST_PATH = path.join(
  ROOT,
  "release",
  "kernel-hash-footprint.json",
);

const HASH_RE = /(?<![0-9a-fA-F])([0-9a-fA-F]{64})(?![0-9a-fA-F])/g;
const SIGNATURE_RE =
  /["']?(?:signature|signed|sig|proof|attestation|dsseEnvelope)["']?\s*[:=]/i;
const SIGNED_PATH_RE =
  /(?:^|[/_.-])(?:receipt|receipts|signed|signature|attestation|provenance)(?:[/_.-]|$)/i;
const PLAIN_TEXT_EXTENSIONS = new Set([
  "",
  ".c",
  ".cjs",
  ".conf",
  ".config",
  ".cpp",
  ".css",
  ".csv",
  ".env",
  ".go",
  ".h",
  ".hpp",
  ".html",
  ".ini",
  ".java",
  ".js",
  ".json",
  ".jsonl",
  ".jsx",
  ".lean",
  ".lock",
  ".md",
  ".mjs",
  ".py",
  ".rs",
  ".sh",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".xml",
  ".yaml",
  ".yml",
]);

function usage() {
  return [
    "usage:",
    "  node scripts/kernel_hash_footprint.mjs --write",
    "  node scripts/kernel_hash_footprint.mjs --check",
    "",
    "diagnostic override:",
    "  --repo-root=<repo>=<checkout>  scan a pinned local checkout",
    "  --manifest=<path>              compare with an alternate manifest",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    mode: null,
    repoRoots: new Map(),
    manifestPath:
      process.env.KERNEL_HASH_FOOTPRINT_MANIFEST ?? MANIFEST_PATH,
    cacheDir:
      process.env.KERNEL_HASH_FOOTPRINT_CACHE ??
      path.join(os.tmpdir(), "seal-kernel-hash-footprint-v1"),
  };
  for (const arg of argv) {
    if (arg === "--write" || arg === "--check") {
      if (options.mode !== null) {
        throw new Error("choose exactly one of --write or --check");
      }
      options.mode = arg.slice(2);
    } else if (arg.startsWith("--repo-root=")) {
      const value = arg.slice("--repo-root=".length);
      const split = value.indexOf("=");
      if (split < 1 || split === value.length - 1) {
        throw new Error(`invalid --repo-root value: ${value}`);
      }
      options.repoRoots.set(
        value.slice(0, split),
        path.resolve(value.slice(split + 1)),
      );
    } else if (arg.startsWith("--cache-dir=")) {
      options.cacheDir = path.resolve(arg.slice("--cache-dir=".length));
    } else if (arg.startsWith("--manifest=")) {
      options.manifestPath = path.resolve(arg.slice("--manifest=".length));
    } else if (arg === "--help" || arg === "-h") {
      console.log(usage());
      process.exit(0);
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  if (options.mode === null) {
    throw new Error("choose exactly one of --write or --check");
  }
  return options;
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    const detail = (result.stderr || result.stdout).trim();
    throw new Error(
      `${command} ${args.join(" ")} exited ${result.status}${
        detail ? `: ${detail}` : ""
      }`,
    );
  }
  return result.stdout;
}

function readFleetLock(lockPath = FLEET_LOCK_PATH) {
  const lock = JSON.parse(fs.readFileSync(lockPath, "utf8"));
  if (
    typeof lock.kernel_sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(lock.kernel_sha256) ||
    typeof lock.repositories !== "object" ||
    lock.repositories === null ||
    Array.isArray(lock.repositories)
  ) {
    throw new Error(`${lockPath} is not a valid fleet lock`);
  }
  return lock;
}

function safeCacheName(name) {
  return name.replaceAll(/[^A-Za-z0-9_.-]/g, "_");
}

function checkoutPinnedRepository(name, repository, options) {
  const override = options.repoRoots.get(name);
  if (override !== undefined) {
    if (!fs.statSync(override, { throwIfNoEntry: false })?.isDirectory()) {
      throw new Error(`local override is not a directory: ${override}`);
    }
    const actualCommit = run("git", ["rev-parse", "HEAD"], {
      cwd: override,
    }).trim();
    if (actualCommit !== repository.commit) {
      throw new Error(
        `local override HEAD ${actualCommit} does not equal pinned commit ${repository.commit}`,
      );
    }
    return override;
  }

  const checkout = path.join(
    options.cacheDir,
    safeCacheName(name),
    repository.commit,
  );
  if (fs.existsSync(path.join(checkout, ".git"))) {
    const actualCommit = run("git", ["rev-parse", "HEAD"], {
      cwd: checkout,
    }).trim();
    if (actualCommit !== repository.commit) {
      throw new Error(
        `cache HEAD ${actualCommit} does not equal pinned commit ${repository.commit}`,
      );
    }
    const dirty = run("git", ["status", "--porcelain"], { cwd: checkout });
    if (dirty !== "") {
      throw new Error(`cached checkout is dirty: ${checkout}`);
    }
    return checkout;
  }

  fs.mkdirSync(checkout, { recursive: true });
  run("git", ["init", "--quiet"], { cwd: checkout });
  run("git", ["remote", "add", "origin", repository.url], { cwd: checkout });
  run(
    "git",
    ["fetch", "--quiet", "--depth=1", "origin", repository.commit],
    { cwd: checkout },
  );
  run("git", ["checkout", "--quiet", "--detach", repository.commit], {
    cwd: checkout,
  });
  return checkout;
}

function walkFiles(root) {
  const files = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (entry.name === ".git") {
        continue;
      }
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        pending.push(absolute);
      } else if (entry.isFile()) {
        files.push(absolute);
      }
    }
  }
  return files.sort();
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

function contextFor(lines, lineIndex, radius = 2) {
  return lines
    .slice(Math.max(0, lineIndex - radius), lineIndex + radius + 1)
    .join("\n");
}

function isProbablyBinary(bytes) {
  const sample = bytes.subarray(0, Math.min(bytes.length, 8192));
  return sample.includes(0);
}

function classifyTextOccurrence(relativePath, text, lines, lineIndex) {
  const signatureContext = contextFor(lines, lineIndex, 20);
  if (
    SIGNED_PATH_RE.test(relativePath) ||
    ([".json", ".jsonl"].includes(
      path.extname(relativePath).toLowerCase(),
    ) &&
      SIGNATURE_RE.test(text)) ||
    SIGNATURE_RE.test(signatureContext)
  ) {
    return "SIGNED";
  }
  if (PLAIN_TEXT_EXTENSIONS.has(path.extname(relativePath).toLowerCase())) {
    return "STRING";
  }
  return "UNKNOWN";
}

function scanTextFile(name, relativePath, text, occurrences) {
  const lines = text.split(/\r?\n/);
  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    HASH_RE.lastIndex = 0;
    for (const match of line.matchAll(HASH_RE)) {
      const hash = match[1].toLowerCase();
      // A bare 32-byte hex constant is indistinguishable from a kernel
      // identity without understanding every downstream schema. Retain all of
      // them: over-reporting is safer than teaching this gate a false negative.
      occurrences.push({
        repo: name,
        path: relativePath,
        line: lineIndex + 1,
        hash,
        classification: classifyTextOccurrence(
          relativePath,
          text,
          lines,
          lineIndex,
        ),
      });
    }
  }
}

function scanBinaryFile(name, relativePath, bytes, occurrences) {
  const ascii = bytes.toString("latin1");
  HASH_RE.lastIndex = 0;
  for (const match of ascii.matchAll(HASH_RE)) {
    const hash = match[1].toLowerCase();
    occurrences.push({
      repo: name,
      path: relativePath,
      line: null,
      hash,
      classification: "UNKNOWN",
    });
  }
}

function occurrenceKey(occurrence) {
  return [
    occurrence.repo,
    occurrence.path,
    occurrence.line ?? "-",
    occurrence.hash,
    occurrence.classification,
  ].join("\u0000");
}

function occurrenceLabel(occurrence) {
  return `${occurrence.repo}:${occurrence.path}:${occurrence.line ?? "-"} ${occurrence.hash} ${occurrence.classification}`;
}

function sortOccurrences(occurrences) {
  occurrences.sort((left, right) => {
    const leftKey = occurrenceKey(left);
    const rightKey = occurrenceKey(right);
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
}

export function scanFleet(lock, options) {
  const repositories = [];
  const occurrences = [];
  const unreachable = [];

  for (const [name, repository] of Object.entries(lock.repositories)) {
    let checkout;
    try {
      checkout = checkoutPinnedRepository(name, repository, options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      repositories.push({
        name,
        url: repository.url,
        commit: repository.commit,
        status: "UNKNOWN",
        error: message,
      });
      unreachable.push({ name, error: message });
      continue;
    }

    const wasmPaths = new Set(repository.wasm ?? []);
    const missingWasmPaths = [...wasmPaths].filter((wasmPath) => {
      const absolute = path.join(checkout, ...wasmPath.split("/"));
      return !fs.statSync(absolute, { throwIfNoEntry: false })?.isFile();
    });
    if (missingWasmPaths.length > 0) {
      const message = `pinned wasm path is missing: ${missingWasmPaths.join(", ")}`;
      repositories.push({
        name,
        url: repository.url,
        commit: repository.commit,
        status: "UNKNOWN",
        error: message,
      });
      unreachable.push({ name, error: message });
      continue;
    }
    for (const wasmPath of wasmPaths) {
      const absolute = path.join(checkout, ...wasmPath.split("/"));
      const hash = sha256(fs.readFileSync(absolute));
      occurrences.push({
        repo: name,
        path: wasmPath,
        line: null,
        hash,
        classification: "BINARY",
      });
    }

    for (const absolute of walkFiles(checkout)) {
      const relativePath = path
        .relative(checkout, absolute)
        .split(path.sep)
        .join("/");
      if (wasmPaths.has(relativePath)) {
        continue;
      }
      const bytes = fs.readFileSync(absolute);
      if (isProbablyBinary(bytes)) {
        scanBinaryFile(name, relativePath, bytes, occurrences);
      } else {
        scanTextFile(name, relativePath, bytes.toString("utf8"), occurrences);
      }
    }
    repositories.push({
      name,
      url: repository.url,
      commit: repository.commit,
      status: "scanned",
    });
  }

  sortOccurrences(occurrences);
  return {
    manifest: {
      schema: 1,
      fleetLock: "release/fleet-lock.json",
      kernelSha256: lock.kernel_sha256,
      repositories,
      occurrences,
    },
    unreachable,
  };
}

function canonicalJson(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function checkManifest(actual, expected) {
  const actualCounts = new Map();
  const expectedCounts = new Map();
  for (const occurrence of actual.occurrences) {
    const key = occurrenceKey(occurrence);
    const value = actualCounts.get(key) ?? { count: 0, occurrence };
    value.count += 1;
    actualCounts.set(key, value);
  }
  for (const occurrence of expected.occurrences) {
    const key = occurrenceKey(occurrence);
    const value = expectedCounts.get(key) ?? { count: 0, occurrence };
    value.count += 1;
    expectedCounts.set(key, value);
  }
  const added = [];
  const removed = [];
  for (const [key, value] of actualCounts) {
    const delta = value.count - (expectedCounts.get(key)?.count ?? 0);
    for (let index = 0; index < delta; index += 1) {
      added.push(value.occurrence);
    }
  }
  for (const [key, value] of expectedCounts) {
    const delta = value.count - (actualCounts.get(key)?.count ?? 0);
    for (let index = 0; index < delta; index += 1) {
      removed.push(value.occurrence);
    }
  }
  const metadataMatches =
    actual.schema === expected.schema &&
    actual.fleetLock === expected.fleetLock &&
    actual.kernelSha256 === expected.kernelSha256 &&
    JSON.stringify(actual.repositories) ===
      JSON.stringify(expected.repositories);

  if (metadataMatches && added.length === 0 && removed.length === 0) {
    return true;
  }

  console.error("KERNEL HASH FOOTPRINT MISMATCH");
  if (
    JSON.stringify(actual.repositories) !==
    JSON.stringify(expected.repositories)
  ) {
    console.error(
      `REPOSITORY METADATA: tree=${JSON.stringify(actual.repositories)} manifest=${JSON.stringify(expected.repositories)}`,
    );
  }
  if (
    actual.kernelSha256 !== expected.kernelSha256 ||
    actual.schema !== expected.schema ||
    actual.fleetLock !== expected.fleetLock
  ) {
    console.error("MANIFEST METADATA DIFFERS FROM THE FLEET SCAN");
  }
  if (added.length > 0) {
    console.error("PRESENT IN TREE, ABSENT FROM MANIFEST:");
    for (const occurrence of added) {
      console.error(`+ ${occurrenceLabel(occurrence)}`);
    }
  }
  if (removed.length > 0) {
    console.error("PRESENT IN MANIFEST, ABSENT FROM TREE:");
    for (const occurrence of removed) {
      console.error(`- ${occurrenceLabel(occurrence)}`);
    }
  }
  return false;
}

function reportUnknown(unreachable, manifest) {
  for (const repository of unreachable) {
    console.error(`UNKNOWN REPOSITORY ${repository.name}: ${repository.error}`);
  }
  for (const occurrence of manifest.occurrences) {
    if (occurrence.classification === "UNKNOWN") {
      console.error(`UNKNOWN OCCURRENCE ${occurrenceLabel(occurrence)}`);
    }
  }
}

function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
    const lock = readFleetLock();
    for (const name of options.repoRoots.keys()) {
      if (!(name in lock.repositories)) {
        throw new Error(`--repo-root names no fleet repository: ${name}`);
      }
    }
    const { manifest, unreachable } = scanFleet(lock, options);
    reportUnknown(unreachable, manifest);
    if (unreachable.length > 0) {
      console.error(
        "REFUSING TO TREAT UNREACHABLE REPOSITORIES AS CLEAN OR WRITE A MANIFEST",
      );
      process.exitCode = 2;
      return;
    }
    if (options.mode === "write") {
      fs.writeFileSync(options.manifestPath, canonicalJson(manifest));
      console.log(
        `WROTE ${path.relative(ROOT, options.manifestPath)}: ${manifest.repositories.length} repos, ${manifest.occurrences.length} occurrences`,
      );
      return;
    }
    const expected = JSON.parse(
      fs.readFileSync(options.manifestPath, "utf8"),
    );
    if (!checkManifest(manifest, expected)) {
      process.exitCode = 1;
      return;
    }
    console.log(
      `PASS kernel hash footprint: ${manifest.repositories.length} repos, ${manifest.occurrences.length} occurrences`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main();
}
