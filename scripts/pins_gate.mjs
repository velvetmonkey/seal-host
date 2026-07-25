#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Anti-drift gate for PINS.md. The ledger is only useful while every cited
// file/test/name still exists and every SPEC-ONLY term is still absent.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PINS = path.join(ROOT, "PINS.md");
const KERNEL = path.join(ROOT, ".lake", "packages", "mcp-seal");
const SOURCE_EXTENSIONS = new Set([
  ".c", ".cc", ".cpp", ".h", ".hpp", ".js", ".jsx", ".lean", ".mjs",
  ".py", ".rs", ".sh", ".ts", ".tsx",
]);
const LEDGER_STATUSES = new Set([
  "PINNED",
  "PINNED-BY-TEST",
  "FROZEN-EXPECTATION",
  "UNPINNED",
  "SPEC-ONLY",
  "CHARACTERISED",
  "TCB",
]);

process.chdir(ROOT);

const ledger = fs.readFileSync(PINS, "utf8");
const lines = ledger.split(/\r?\n/);
const failures = [];

function unquote(value) {
  return value.trim().replace(/^`|`$/g, "");
}

function tableCells(line) {
  return line.slice(1, -1).split("|").map((cell) => cell.trim());
}

function citedPaths(text) {
  const matches = text.match(
    /(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:c|cc|cpp|h|hpp|js|json|jsx|lean|md|mjs|py|rs|sh|toml|ts|tsx|wasm)/g,
  );
  return [...new Set(matches ?? [])];
}

function codeNames(text) {
  const names = [];
  for (const match of text.matchAll(/`([^`]+)`/g)) {
    const value = match[1].trim();
    if (
      /^[A-Za-z_][A-Za-z0-9_]*$/.test(value)
      && !/^[0-9a-f]{7,40}$/i.test(value)
    ) {
      names.push(value);
    }
  }
  return [...new Set(names)];
}

function resolveCitation(citation) {
  for (const base of [ROOT, KERNEL]) {
    const candidate = path.join(base, citation);
    try {
      if (fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      // Report one row-aware failure after trying both repository roots.
    }
  }
  return null;
}

function rowLabel(row) {
  const site = row.site.replace(/`/g, "");
  return `PINS.md:${row.line} [${site}]`;
}

const rows = [];
for (let index = 0; index < lines.length; index += 1) {
  const line = lines[index];
  if (!line.startsWith("|") || !line.endsWith("|")) continue;
  const cells = tableCells(line);
  if (cells.length !== 4) continue;
  const status = unquote(cells[1]);
  if (!LEDGER_STATUSES.has(status)) continue;
  rows.push({
    line: index + 1,
    raw: line,
    site: cells[0],
    status,
    evidence: cells[2],
  });
}

console.log("==> [1/4] every file path cited by a ledger row exists");
for (const row of rows) {
  for (const citation of citedPaths(row.raw)) {
    if (!resolveCitation(citation)) {
      failures.push(`${rowLabel(row)}: cited file does not exist: ${citation}`);
    }
  }
}

console.log("==> [2/4] PINNED and PINNED-BY-TEST evidence still names real artifacts");
for (const row of rows.filter(
  ({ status }) => status === "PINNED" || status === "PINNED-BY-TEST",
)) {
  const evidencePaths = citedPaths(row.evidence);
  const resolvedEvidence = evidencePaths
    .map((citation) => [citation, resolveCitation(citation)])
    .filter(([, resolved]) => resolved !== null);

  if (evidencePaths.length === 0) {
    failures.push(`${rowLabel(row)}: ${row.status} row cites no evidence file`);
    continue;
  }

  // A backticked identifier in the site/evidence is a claimed code name.
  // Require it in at least one cited evidence file, so deleting a named test
  // cannot leave a PINNED-BY-TEST row looking healthy merely because its file
  // still exists.
  const claimedNames = [
    ...(row.status === "PINNED" ? codeNames(row.site) : []),
    ...codeNames(row.evidence),
  ];
  for (const name of new Set(claimedNames)) {
    const found = resolvedEvidence.some(([, resolved]) => {
      const source = fs.readFileSync(resolved, "utf8");
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return new RegExp(`(^|[^A-Za-z0-9_])${escaped}([^A-Za-z0-9_]|$)`).test(source);
    });
    if (!found) {
      failures.push(
        `${rowLabel(row)}: claimed name ${name} is absent from cited evidence file(s): ${evidencePaths.join(", ")}`,
      );
    }
  }
}

console.log("==> [3/4] every cited Lean test is reachable from lakefile.toml defaultTargets");
const lakefile = fs.readFileSync(path.join(ROOT, "lakefile.toml"), "utf8");
const defaultTargetsMatch = lakefile.match(/^defaultTargets\s*=\s*\[([^\]]*)\]/m);
if (!defaultTargetsMatch) {
  failures.push("lakefile.toml: defaultTargets is missing or unreadable");
}
const defaultTargets = new Set(
  [...(defaultTargetsMatch?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((match) => match[1]),
);
const executableForRoot = new Map();
for (const match of lakefile.matchAll(
  /\[\[lean_exe\]\]([\s\S]*?)(?=\n\[\[|\s*$)/g,
)) {
  const block = match[1];
  const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
  const root = block.match(/^\s*root\s*=\s*"([^"]+)"/m)?.[1];
  if (name && root) executableForRoot.set(root, name);
}

for (const row of rows.filter(({ status }) => status === "PINNED-BY-TEST")) {
  for (const citation of citedPaths(row.evidence).filter((item) => item.endsWith(".lean"))) {
    const moduleName = citation.slice(0, -".lean".length).replaceAll("/", ".");
    const target = executableForRoot.get(moduleName);
    if (!target) {
      failures.push(
        `${rowLabel(row)}: Lean test ${citation} has no [[lean_exe]] target in lakefile.toml`,
      );
    } else if (!defaultTargets.has(target)) {
      failures.push(
        `${rowLabel(row)}: Lean test ${citation} target ${target} is outside defaultTargets`,
      );
    }
  }
}

function trackedSourceFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  const output = execFileSync(
    "git",
    ["-C", directory, "ls-files", "-z"],
    { encoding: "utf8" },
  );
  return output
    .split("\0")
    .filter(Boolean)
    .filter((file) => SOURCE_EXTENSIONS.has(path.extname(file)))
    .map((file) => path.join(directory, file));
}

console.log("==> [4/4] every SPEC-ONLY name remains absent from both source trees");
const specHeading = lines.findIndex((line) => line.startsWith("## Specification-only"));
const specEnd = lines.findIndex(
  (line, index) => index > specHeading && line.startsWith("## "),
);
if (specHeading < 0) {
  failures.push("PINS.md: Specification-only section is missing");
}
const specEntries = [];
for (
  let index = specHeading + 1;
  specHeading >= 0 && index < (specEnd < 0 ? lines.length : specEnd);
  index += 1
) {
  for (const match of lines[index].matchAll(/`([^`]+)`/g)) {
    for (const part of match[1].split("/")) {
      const name = part.trim();
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        specEntries.push({ name, line: index + 1 });
      }
    }
  }
}
if (specHeading >= 0 && specEntries.length === 0) {
  failures.push("PINS.md: Specification-only section contains no names");
}

const sourceFiles = [
  ...trackedSourceFiles(ROOT),
  ...trackedSourceFiles(KERNEL),
].filter((file) => file !== PINS);
const specNameLines = new Map(specEntries.map(({ name, line }) => [name, line]));
for (const [name, ledgerLine] of specNameLines) {
  let occurrence = null;
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const namePattern = new RegExp(
    `(^|[^A-Za-z0-9_])${escaped}([^A-Za-z0-9_]|$)`,
  );
  for (const file of sourceFiles) {
    const sourceLines = fs.readFileSync(file, "utf8").split(/\r?\n/);
    const lineIndex = sourceLines.findIndex((line) => namePattern.test(line));
    if (lineIndex >= 0) {
      occurrence = `${path.relative(ROOT, file)}:${lineIndex + 1}`;
      break;
    }
  }
  if (occurrence) {
    failures.push(
      `PINS.md:${ledgerLine} [Specification-only]: ${name} appears in source at ${occurrence}`,
    );
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(`FAIL: ${failure}`);
  console.error(`PINS GATE FAIL (${failures.length} error${failures.length === 1 ? "" : "s"})`);
  process.exit(1);
}

console.log(`    checked ${rows.length} ledger rows and ${specNameLines.size} SPEC-ONLY names`);
console.log("PINS GATE PASS");
