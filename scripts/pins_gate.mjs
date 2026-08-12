#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Read-only anti-drift gate for the mechanically checkable claims in PINS.md.
// The prose and table remain hand-written: this program derives the factual
// side from live source and reports row-aware claimed/actual mismatches. It
// never writes PINS.md.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import {
  GATED_ROWS,
  GATED_SECTIONS,
  OUT_OF_SCOPE_ROWS,
} from "./pins_gate_rows.mjs";
import { checkMcpSealPin } from "./mcp_seal_pin_drift.mjs";

export const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
export const CI_RUN_STEP_MINIMUM = 50;

const SMALL_NUMBER_WORDS = Object.freeze({
  zero: 0,
  one: 1,
  two: 2,
  three: 3,
  four: 4,
  five: 5,
  six: 6,
  seven: 7,
  eight: 8,
  nine: 9,
  ten: 10,
  eleven: 11,
  twelve: 12,
  thirteen: 13,
  fourteen: 14,
  fifteen: 15,
  sixteen: 16,
  seventeen: 17,
  eighteen: 18,
  nineteen: 19,
});
const TENS_NUMBER_WORDS = Object.freeze({
  twenty: 20,
  thirty: 30,
  forty: 40,
  fifty: 50,
  sixty: 60,
  seventy: 70,
  eighty: 80,
  ninety: 90,
});

const PINS = path.join(ROOT, "PINS.md");
const KERNEL = path.join(ROOT, ".lake", "packages", "mcp-seal");
const SOURCE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".h",
  ".hpp",
  ".js",
  ".jsx",
  ".lean",
  ".mjs",
  ".py",
  ".rs",
  ".sh",
  ".ts",
  ".tsx",
]);
const C_STYLE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".h",
  ".hpp",
  ".js",
  ".jsx",
  ".mjs",
  ".rs",
  ".ts",
  ".tsx",
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

function unquote(value) {
  return value.trim().replace(/^`|`$/g, "");
}

function tableCells(line) {
  return line.slice(1, -1).split("|").map((cell) => cell.trim());
}

export function parseLedger(markdown = fs.readFileSync(PINS, "utf8")) {
  const lines = markdown.split(/\r?\n/);
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
      note: cells[3],
    });
  }
  return { markdown, lines, rows };
}

export function matchingRows(rows, anchor) {
  return rows.filter((row) => row.site.includes(anchor));
}

function citedPaths(text) {
  const matches = text.match(
    /(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:c|cc|cpp|h|hpp|js|json|jsx|lean|md|mjs|py|rs|sh|toml|ts|tsx|wasm)/gi,
  );
  return [...new Set(matches ?? [])];
}

function resolveCitation(citation) {
  for (const base of [ROOT, KERNEL]) {
    const candidate = path.join(base, citation);
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // A single row-aware claimed/actual failure is emitted by the caller.
    }
  }
  return null;
}

function sourceLines(file) {
  return fs.readFileSync(file, "utf8").split(/\r?\n/);
}

function commentProfile(extension) {
  if (extension === ".lean") {
    return {
      line: "--",
      block: ["/-", "-/"],
      nestedBlock: true,
      quotes: ['"'],
    };
  }
  if (C_STYLE_EXTENSIONS.has(extension)) {
    return {
      line: "//",
      block: ["/*", "*/"],
      nestedBlock: extension === ".rs",
      quotes:
        extension === ".rs"
          ? ['"']
          : [extension === ".js" ||
              extension === ".jsx" ||
              extension === ".mjs" ||
              extension === ".ts" ||
              extension === ".tsx"
              ? "`"
              : null, '"', "'"].filter(Boolean),
    };
  }
  if (extension === ".py") {
    return {
      line: "#",
      block: null,
      nestedBlock: false,
      quotes: ['"""', "'''", '"', "'"],
    };
  }
  if (extension === ".sh") {
    return {
      line: "#",
      block: null,
      nestedBlock: false,
      quotes: ['"', "'", "`"],
      shellHash: true,
    };
  }
  throw new Error(`no comment syntax registered for source extension ${extension}`);
}

function blankCommentCharacter(character) {
  return character === "\n" || character === "\r" ? character : " ";
}

function rustRawStringAt(text, index) {
  const match = text
    .slice(index)
    .match(/^(?:b|c)?r(#{0,255})"/);
  if (!match) return null;
  return {
    length: match[0].length,
    end: `"${match[1]}`,
  };
}

function cppRawStringAt(text, index) {
  const match = text
    .slice(index)
    .match(/^(?:u8|u|U|L)?R"([^ ()\\\t\v\f\r\n]{0,16})\(/);
  if (!match) return null;
  return {
    length: match[0].length,
    end: `)${match[1]}"`,
  };
}

function rustCharLiteralAt(text, index) {
  return /^'(?:[^'\\\r\n]|\\(?:.|u\{[0-9a-fA-F_]+\}))'/u.test(
    text.slice(index),
  );
}

function shellHashStartsComment(text, index) {
  if (text[index] !== "#") return false;
  if (index === 0) return true;
  return /[\s;&|()<>\u0000]/.test(text[index - 1]);
}

/**
 * Remove comments while preserving strings, newlines, and character offsets.
 *
 * This is deliberately a language-profiled lexical pass, not a prose
 * allow-list. It covers every extension admitted by SOURCE_EXTENSIONS:
 * Lean (--, nested /- -/), Rust (//, nested block comments, raw strings),
 * C/C++ headers and sources, JavaScript/TypeScript, Python, and shell.
 * String literals remain code because protocol field names frequently live
 * in strings. The pass does not claim to parse arbitrary unlisted languages.
 */
export function stripSourceComments(text, extension) {
  const profile = commentProfile(extension);
  const output = text.split("");
  let blockDepth = 0;
  let lineComment = false;
  let quote = null;
  let quoteAllowsEscape = false;
  let rawEnd = null;

  for (let index = 0; index < text.length; ) {
    if (lineComment) {
      output[index] = blankCommentCharacter(text[index]);
      if (text[index] === "\n") lineComment = false;
      index += 1;
      continue;
    }

    if (blockDepth > 0) {
      const [blockStart, blockEnd] = profile.block;
      if (
        profile.nestedBlock &&
        text.startsWith(blockStart, index)
      ) {
        for (let offset = 0; offset < blockStart.length; offset += 1) {
          output[index + offset] = " ";
        }
        blockDepth += 1;
        index += blockStart.length;
        continue;
      }
      if (text.startsWith(blockEnd, index)) {
        for (let offset = 0; offset < blockEnd.length; offset += 1) {
          output[index + offset] = " ";
        }
        blockDepth -= 1;
        index += blockEnd.length;
        continue;
      }
      output[index] = blankCommentCharacter(text[index]);
      index += 1;
      continue;
    }

    if (rawEnd !== null) {
      if (text.startsWith(rawEnd, index)) {
        index += rawEnd.length;
        rawEnd = null;
      } else {
        index += 1;
      }
      continue;
    }

    if (quote !== null) {
      if (text[index] === "\\" && quoteAllowsEscape) {
        index += Math.min(2, text.length - index);
        continue;
      }
      if (text.startsWith(quote, index)) {
        index += quote.length;
        quote = null;
        quoteAllowsEscape = false;
      } else {
        index += 1;
      }
      continue;
    }

    if (extension === ".rs") {
      const raw = rustRawStringAt(text, index);
      if (raw) {
        rawEnd = raw.end;
        index += raw.length;
        continue;
      }
      if (text[index] === "'" && rustCharLiteralAt(text, index)) {
        quote = "'";
        quoteAllowsEscape = true;
        index += 1;
        continue;
      }
    } else if (
      extension === ".c" ||
      extension === ".cc" ||
      extension === ".cpp" ||
      extension === ".h" ||
      extension === ".hpp"
    ) {
      const raw = cppRawStringAt(text, index);
      if (raw) {
        rawEnd = raw.end;
        index += raw.length;
        continue;
      }
    }

    const openingQuote = profile.quotes.find((candidate) =>
      text.startsWith(candidate, index),
    );
    if (openingQuote) {
      quote = openingQuote;
      quoteAllowsEscape = !(extension === ".sh" && openingQuote === "'");
      index += openingQuote.length;
      continue;
    }

    if (
      profile.line &&
      text.startsWith(profile.line, index) &&
      (!profile.shellHash || shellHashStartsComment(text, index))
    ) {
      for (let offset = 0; offset < profile.line.length; offset += 1) {
        output[index + offset] = " ";
      }
      lineComment = true;
      index += profile.line.length;
      continue;
    }

    if (profile.block && text.startsWith(profile.block[0], index)) {
      for (let offset = 0; offset < profile.block[0].length; offset += 1) {
        output[index + offset] = " ";
      }
      blockDepth = 1;
      index += profile.block[0].length;
      continue;
    }

    index += 1;
  }

  return output.join("");
}

function sourceCodeLines(file) {
  const extension = path.extname(file);
  return stripSourceComments(fs.readFileSync(file, "utf8"), extension).split(
    /\r?\n/,
  );
}

function lineNumber(lines, pattern) {
  const index = lines.findIndex((line) => pattern.test(line));
  return index < 0 ? null : index + 1;
}

function escaped(name) {
  return name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function leanDeclarationLine(lines, name) {
  return lineNumber(
    lines,
    new RegExp(
      `^\\s*(?:def|abbrev|opaque|structure|inductive|theorem|lemma)\\s+${escaped(name)}(?:\\s|\\{|\\()`,
    ),
  );
}

function leanDefinitionCode(file, name) {
  const lines = sourceCodeLines(file);
  const start = lines.findIndex((line) =>
    new RegExp(`^def\\s+${escaped(name)}(?:\\s|\\()`).test(line),
  );
  if (start < 0) return null;
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (
      /^(?:def|abbrev|opaque|structure|inductive|theorem|lemma|end)\b/.test(
        lines[index],
      )
    ) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join("\n");
}

function leanStructure(lines, name) {
  const start = lineNumber(
    lines,
    new RegExp(`^\\s*structure\\s+${escaped(name)}\\s+where\\s*$`),
  );
  if (start === null) return null;
  const fields = [];
  for (let index = start; index < lines.length; index += 1) {
    const line = lines[index];
    if (/^\s+deriving\b/.test(line)) break;
    const match = line.match(/^\s{2}([A-Za-z_][A-Za-z0-9_]*)\s*:/);
    if (match) fields.push(match[1]);
  }
  return { line: start, fields };
}

function leanStringDefinition(lines, name) {
  const pattern = new RegExp(
    `^\\s*def\\s+${escaped(name)}\\s*:\\s*String\\s*:=\\s*"([^"]*)"\\s*$`,
  );
  for (let index = 0; index < lines.length; index += 1) {
    const match = lines[index].match(pattern);
    if (match) return { line: index + 1, value: match[1] };
  }
  return null;
}

function parseLakefile() {
  const text = fs.readFileSync(path.join(ROOT, "lakefile.toml"), "utf8");
  const defaultMatch = text.match(/^defaultTargets\s*=\s*\[([^\]]*)\]/m);
  const defaultTargets = new Set(
    [...(defaultMatch?.[1] ?? "").matchAll(/"([^"]+)"/g)].map(
      (match) => match[1],
    ),
  );
  const executableForRoot = new Map();
  for (const match of text.matchAll(
    /\[\[lean_exe\]\]([\s\S]*?)(?=\n\[\[|\s*$)/g,
  )) {
    const block = match[1];
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    const root = block.match(/^\s*root\s*=\s*"([^"]+)"/m)?.[1];
    if (name && root) executableForRoot.set(root, name);
  }
  return { text, defaultTargets, executableForRoot };
}

function indentation(line) {
  const prefix = line.match(/^[ \t]*/)[0];
  if (prefix.includes("\t")) {
    throw new Error("ci.yml uses a tab for YAML indentation");
  }
  return prefix.length;
}

function parseInlineRunScalar(value, lineNumber) {
  const withoutComment = value.replace(/\s+#.*$/, "").trim();
  if (withoutComment.startsWith('"')) {
    try {
      return JSON.parse(withoutComment);
    } catch (error) {
      throw new Error(
        `ci.yml:${lineNumber} has an invalid double-quoted run scalar: ${error.message}`,
      );
    }
  }
  if (withoutComment.startsWith("'")) {
    if (!withoutComment.endsWith("'") || withoutComment.length === 1) {
      throw new Error(`ci.yml:${lineNumber} has an invalid single-quoted run scalar`);
    }
    return withoutComment.slice(1, -1).replaceAll("''", "'");
  }
  return withoutComment;
}

function parseCiRunValue(lines, lineIndex, fieldIndent, sourceValue) {
  const value = sourceValue.trim();
  const header = value.match(/^\|([1-9]?)([+-]?)(?:\s+#.*)?$/);
  if (!header) {
    if (/^[|>]/.test(value)) {
      throw new Error(
        `ci.yml:${lineIndex + 1} uses an unsupported run block scalar; ` +
          "only YAML literal scalars (`|`, with optional indentation/chomping indicators) are accepted",
      );
    }
    return {
      value: parseInlineRunScalar(value, lineIndex + 1),
      lastLine: lineIndex,
    };
  }

  const explicitIndent = header[1] === "" ? null : Number(header[1]);
  const chomp = header[2];
  let contentIndent =
    explicitIndent === null ? null : fieldIndent + explicitIndent;
  const content = [];
  let cursor = lineIndex + 1;
  for (; cursor < lines.length; cursor += 1) {
    const line = lines[cursor];
    if (/^\s*$/.test(line)) {
      content.push("");
      continue;
    }
    const indent = indentation(line);
    if (indent <= fieldIndent) break;
    if (contentIndent === null) contentIndent = indent;
    if (indent < contentIndent) {
      throw new Error(
        `ci.yml:${cursor + 1} is under-indented inside the run block opened at line ${lineIndex + 1}`,
      );
    }
    content.push(line.slice(contentIndent));
  }

  let body = content.length === 0 ? "" : `${content.join("\n")}\n`;
  if (chomp === "-") {
    body = body.replace(/\n+$/, "");
  } else if (chomp !== "+" && body !== "") {
    body = `${body.replace(/\n+$/, "")}\n`;
  }
  return { value: body, lastLine: cursor - 1 };
}

export function parseCiRunSteps(
  text = fs.readFileSync(path.join(ROOT, ".github", "workflows", "ci.yml"), "utf8"),
) {
  const lines = text.split(/\r?\n/);
  const steps = [];
  for (let index = 0; index < lines.length; index += 1) {
    const stepsKey = lines[index].match(/^(\s*)steps:\s*(?:#.*)?$/);
    if (!stepsKey) continue;

    const stepsIndent = stepsKey[1].length;
    let stepIndent = null;
    let current = null;
    const finishCurrent = () => {
      if (current && current.run !== null) {
        steps.push({
          run: current.run,
          workingDirectory: current.workingDirectory,
        });
      }
      current = null;
    };

    let cursor = index + 1;
    for (; cursor < lines.length; cursor += 1) {
      const line = lines[cursor];
      if (/^\s*(?:#.*)?$/.test(line)) continue;
      const indent = line.match(/^\s*/)[0].length;
      if (indent <= stepsIndent) break;

      const sequenceItem = line.match(/^(\s*)-\s+(.*)$/);
      if (sequenceItem && stepIndent === null) {
        stepIndent = sequenceItem[1].length;
      }
      if (sequenceItem && sequenceItem[1].length === stepIndent) {
        finishCurrent();
        current = {
          indent: stepIndent,
          mappingIndent: null,
          run: null,
          workingDirectory: null,
        };
        const inlineRun = sequenceItem[2].match(/^run:\s*(.*)$/);
        if (inlineRun) {
          const parsed = parseCiRunValue(
            lines,
            cursor,
            stepIndent + 2,
            inlineRun[1],
          );
          current.run = parsed.value;
          cursor = parsed.lastLine;
        }
        continue;
      }
      if (!current || indent <= stepIndent) continue;
      if (current.mappingIndent === null) current.mappingIndent = indent;
      if (indent !== current.mappingIndent) continue;

      const field = line.trim();
      const run = field.match(/^run:\s*(.*)$/);
      if (run) {
        const parsed = parseCiRunValue(lines, cursor, indent, run[1]);
        current.run = parsed.value;
        cursor = parsed.lastLine;
      }
      const working = field.match(/^working-directory:\s*(\S+)\s*$/);
      if (working) current.workingDirectory = working[1];
    }
    finishCurrent();
    index = cursor - 1;
  }
  return steps;
}

function cargoCiStep(command) {
  return parseCiRunSteps().find(
    (step) => step.run === command && step.workingDirectory === "rust",
  );
}

export function ciRunStepFloorFailure(count) {
  if (count >= CI_RUN_STEP_MINIMUM) return null;
  return (
    "ci.yml [run-step inventory]\n" +
    `  claimed: at least ${CI_RUN_STEP_MINIMUM} parsed run steps\n` +
    `  actual:  parsed ${count}; refusing vacuous CI reachability checks`
  );
}

function numberWordValue(token) {
  if (Object.hasOwn(SMALL_NUMBER_WORDS, token)) {
    return SMALL_NUMBER_WORDS[token];
  }
  if (Object.hasOwn(TENS_NUMBER_WORDS, token)) {
    return TENS_NUMBER_WORDS[token];
  }
  const parts = token.split("-");
  if (
    parts.length === 2 &&
    Object.hasOwn(TENS_NUMBER_WORDS, parts[0]) &&
    Object.hasOwn(SMALL_NUMBER_WORDS, parts[1]) &&
    SMALL_NUMBER_WORDS[parts[1]] > 0 &&
    SMALL_NUMBER_WORDS[parts[1]] < 10
  ) {
    return TENS_NUMBER_WORDS[parts[0]] + SMALL_NUMBER_WORDS[parts[1]];
  }
  return null;
}

export function parseBuildGatedGuardCount(evidence) {
  const claims = [
    ...evidence.matchAll(/\b([A-Za-z]+(?:-[A-Za-z]+)?|[0-9]+)\s+build-gated\b/gi),
  ];
  if (claims.length !== 1) {
    return {
      count: null,
      error:
        claims.length === 0
          ? "unparseable claim: expected exactly one count immediately before `build-gated`"
          : `unparseable claim: found ${claims.length} counts before \`build-gated\``,
    };
  }
  const token = claims[0][1].toLowerCase();
  if (/^[0-9]+$/.test(token)) {
    const count = Number(token);
    if (Number.isSafeInteger(count)) return { count, error: null };
    return {
      count: null,
      error: `unparseable claim: numeral ${token} is outside the safe integer range`,
    };
  }
  const count = numberWordValue(token);
  if (count !== null) return { count, error: null };
  return {
    count: null,
    error:
      `unparseable claim: unknown number word \`${token}\`; ` +
      "use an ASCII numeral or a number word from zero to ninety-nine",
  };
}

function markdownRowLabel(row) {
  return `PINS.md:${row.line} [${row.site.replaceAll("`", "")}]`;
}

function reportMismatch(ctx, row, claimed, actual) {
  ctx.failures.push(
    `${markdownRowLabel(row)}\n  claimed: ${claimed}\n  actual:  ${actual}`,
  );
}

function reportMissingArtifact(ctx, row, claimed, actual) {
  reportMismatch(ctx, row, claimed, actual);
}

function checkCitedPaths(ctx, row) {
  for (const citation of citedPaths(row.raw)) {
    if (!resolveCitation(citation)) {
      reportMissingArtifact(
        ctx,
        row,
        `cited artifact ${citation}`,
        "no such file in seal-host or the pinned mcp-seal source tree",
      );
    }
  }
}

function requireText(ctx, row, text, pattern, claimed, actual) {
  if (!pattern.test(text)) reportMismatch(ctx, row, claimed, actual);
}

function checkCosignExecutableBytes(ctx, row) {
  const files = {
    release: ".github/workflows/release.yml",
    publicExport: ".github/workflows/public-export.yml",
    provenance: "scripts/release_provenance.py",
    exporter: "scripts/export_public.sh",
    publicVerifier: "scripts/verify_public_export.sh",
    provenanceTests: "test/test_release_provenance.py",
  };
  const text = Object.fromEntries(
    Object.entries(files).map(([name, relative]) => [
      name,
      fs.readFileSync(path.join(ROOT, relative), "utf8"),
    ]),
  );
  const x86 = "c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74";
  const arm = "bedac92e8c3729864e13d4a17048007cfafa79d5deca993a43a90ffe018ef2b8";
  requireText(ctx, row, text.release, new RegExp(x86), "x86_64 cosign digest", "release.yml does not assert the recorded x86_64 digest");
  requireText(ctx, row, text.release, new RegExp(arm), "aarch64 cosign digest", "release.yml does not assert the recorded aarch64 digest");
  requireText(ctx, row, text.publicExport, new RegExp(x86), "public-export x86_64 cosign digest", "public-export.yml does not assert the recorded x86_64 digest");
  for (const [name, source] of Object.entries(text)) {
    requireText(ctx, row, source, /COSIGN_BIN|--cosign/, `${name} names the established cosign binary`, `${files[name]} has no established cosign binary reference`);
  }
  requireText(ctx, row, text.provenance, /--cosign-sha256/,
    "provenance verification requires --cosign-sha256",
    `${files.provenance} does not require a cosign digest argument`);
  requireText(ctx, row, text.provenanceTests, /test_cosign_digest_mismatch_refuses/,
    "the provenance test physically refuses altered cosign bytes",
    `${files.provenanceTests} has no executable-byte mismatch test`);
}

function checkIssuedTimeUnit(ctx, row) {
  const mainFile = path.join(KERNEL, "Seal", "Main.lean");
  const envelopeFile = path.join(KERNEL, "SealV2", "EffectEnvelope.lean");
  if (!fs.existsSync(mainFile) || !fs.existsSync(envelopeFile)) {
    reportMismatch(
      ctx,
      row,
      "PINNED epoch/unit implementation",
      "pinned kernel time/envelope source is unavailable",
    );
    return;
  }
  const main = fs.readFileSync(mainFile, "utf8");
  const envelope = fs.readFileSync(envelopeFile, "utf8");
  const envelopeCode = stripSourceComments(envelope, ".lean");
  const flattenedEnvelopeCode = envelopeCode.replaceAll("\n", " ");
  const actual = [];
  if (main.includes("toMillisecondsSinceUnixEpoch")) {
    actual.push("Unix-epoch milliseconds");
  }
  const directTimePair =
    /u64be e\.issuedAt\s*\+\+\s*u64be e\.expiresAt/.test(
      flattenedEnvelopeCode,
    );
  const unixSecondsWrapper =
    /def\s+unixSecondsBE\s*\(\s*t\s*:\s*UnixSeconds\s*\)\s*:\s*ByteArray\s*:=\s*u64be\s+t\b/.test(
      flattenedEnvelopeCode,
    );
  const wrappedTimePair =
    /unixSecondsBE e\.issuedAt\s*\+\+\s*unixSecondsBE e\.expiresAt/.test(
      flattenedEnvelopeCode,
    );
  if (directTimePair || (unixSecondsWrapper && wrappedTimePair)) {
    actual.push("u64be(issuedAt), u64be(expiresAt)");
  }
  if (actual.length !== 2) {
    reportMismatch(
      ctx,
      row,
      "status PINNED for issuedAt/expiresAt epoch and unit",
      actual.length === 0
        ? "no live epoch/unit binding found"
        : `only ${actual.join(" + ")} is live`,
    );
  }
}

function checkEffectMessage(ctx, row) {
  const citation = "SealV2/EffectEnvelope.lean";
  const file = path.join(KERNEL, citation);
  if (!fs.existsSync(file)) {
    reportMismatch(
      ctx,
      row,
      `live ${citation}`,
      "pinned kernel source is unavailable",
    );
    return;
  }
  const lines = sourceLines(file);
  const envelope = leanStructure(lines, "EffectEnvelope");
  const countClaim = row.site.match(/\b(\d+)-field\b/);
  if (!envelope) {
    reportMismatch(
      ctx,
      row,
      "EffectEnvelope field count",
      `${citation} has no EffectEnvelope structure`,
    );
  } else if (!countClaim || Number(countClaim[1]) !== envelope.fields.length) {
    reportMismatch(
      ctx,
      row,
      countClaim
        ? `${countClaim[1]} fields`
        : "no field count stated in the site column",
      `${envelope.fields.length} fields at ${citation}:${envelope.line} (${envelope.fields.join(", ")})`,
    );
  }

  const tag = leanStringDefinition(lines, "effectTag");
  const tagClaim = row.site.match(/`(seal\.effect\/v[0-9]+)`/);
  const sourceTag = tag?.value.replace(/\\x00$/, "");
  if (!tag || !tagClaim || tagClaim[1] !== sourceTag) {
    reportMismatch(
      ctx,
      row,
      tagClaim ? `domain tag ${tagClaim[1]}` : "no domain tag stated",
      tag
        ? `${sourceTag} at ${citation}:${tag.line}`
        : `${citation} has no effectTag String definition`,
    );
  }

  for (const name of ["effectMessage", "effect_message_injective"]) {
    const line = leanDeclarationLine(lines, name);
    if (line === null) {
      reportMismatch(
        ctx,
        row,
        `declaration ${name}`,
        `${citation} has no such declaration`,
      );
    }
  }
}

function checkKernelRawGuard(ctx, row, name) {
  const kernelCitation = "Seal/JsonUtil.lean";
  const kernelFile = path.join(KERNEL, kernelCitation);
  if (!fs.existsSync(kernelFile)) {
    reportMismatch(
      ctx,
      row,
      `${kernelCitation} declaration ${name}`,
      "pinned kernel source is unavailable",
    );
    return;
  }
  const declaration = leanDeclarationLine(sourceLines(kernelFile), name);
  if (declaration === null) {
    reportMismatch(
      ctx,
      row,
      `${kernelCitation} declaration ${name}`,
      `${kernelCitation} has no such declaration`,
    );
  }
  checkJsonWireGuardReachability(ctx, row, `Seal.JsonUtil.${name}`);
}

function checkJsonWireGuardReachability(ctx, row, guard) {
  const hostCitation = "Host/Canonical.lean";
  const hostFile = path.join(ROOT, hostCitation);
  const boundaryCitation = "Host/JsonWire.lean";
  const boundaryFile = path.join(ROOT, boundaryCitation);
  const host = stripSourceComments(fs.readFileSync(hostFile, "utf8"), ".lean");
  const classifyLine = leanDefinitionCode(hostFile, "classifyLine");
  const safe = leanDefinitionCode(boundaryFile, "safe");
  requireText(
    ctx,
    row,
    host,
    /^import\s+Host\.JsonWire\s*$/m,
    `${guard} is reached by Host.classifyLine`,
    `${hostCitation} does not import ${boundaryCitation}`,
  );
  requireText(
    ctx,
    row,
    classifyLine ?? "",
    /Host\.JsonWire\.safe\s+trimmed/,
    `${guard} is reached by Host.classifyLine`,
    `${hostCitation} classifyLine does not call Host.JsonWire.safe`,
  );
  requireText(
    ctx,
    row,
    safe ?? "",
    new RegExp(`${escaped(guard)}\\s+text`),
    `${guard} is reached by Host.classifyLine`,
    `${boundaryCitation} safe does not call ${guard}`,
  );
}

function checkLeanClassifyEncoding(ctx, row) {
  const citation = "Test/ClassifyEncoding.lean";
  const file = path.join(ROOT, citation);
  const text = fs.readFileSync(file, "utf8");
  const guardCount = [...text.matchAll(/^#guard\b/gm)].length;
  const countClaim = parseBuildGatedGuardCount(row.evidence);
  if (countClaim.error) {
    reportMismatch(
      ctx,
      row,
      countClaim.error,
      `${guardCount} #guard declarations in ${citation}`,
    );
  } else if (countClaim.count !== guardCount) {
    reportMismatch(
      ctx,
      row,
      `${countClaim.count} build-gated real-input guards`,
      `${guardCount} #guard declarations in ${citation}`,
    );
  }

  const ffi = fs.readFileSync(path.join(ROOT, "Ffi.lean"), "utf8");
  const actualMapping = [
    [".passthrough", "0"],
    [".act _", "1"],
    [".refuse", "2"],
  ];
  const mappingIsLive = actualMapping.every(([variant, value]) =>
    ffi.includes(`| ${variant} => ${value}`),
  );
  const claimedValues = [...row.note.matchAll(/`([0-9]+)`/g)].map(
    (match) => match[1],
  );
  if (!mappingIsLive || claimedValues.join("/") !== "0/1/2") {
    reportMismatch(
      ctx,
      row,
      claimedValues.length
        ? `.passthrough/.act/.refuse = ${claimedValues.join("/")}`
        : "no 0/1/2 mapping stated",
      mappingIsLive
        ? ".passthrough/.act/.refuse = 0/1/2 in Ffi.lean"
        : "Ffi.lean no longer contains the 0/1/2 mapping",
    );
  }

  const lake = parseLakefile();
  const target = lake.executableForRoot.get("Test.ClassifyEncoding");
  if (!target || !lake.defaultTargets.has(target)) {
    reportMismatch(
      ctx,
      row,
      `${citation} is build-gated`,
      target
        ? `Lake target ${target} exists but is outside defaultTargets`
        : "no [[lean_exe]] target has root Test.ClassifyEncoding",
    );
  }
}

function checkRustClassifyRouting(ctx, row) {
  const routeCitation = "rust/src/route.rs";
  const route = fs.readFileSync(path.join(ROOT, routeCitation), "utf8");
  const flattened = route.replace(/\s+/g, " ");
  const mappingPattern =
    /Ok\(0\)\s*=>\s*ClassifyRoute::Passthrough,\s*Ok\(1\)\s*=>\s*ClassifyRoute::Mediate,\s*Ok\(_\)\s*\|\s*Err\(_\)\s*=>\s*ClassifyRoute::Refuse/;
  if (!mappingPattern.test(flattened)) {
    reportMismatch(
      ctx,
      row,
      "literal 0 passthrough, literal 1 mediate, every other value/error refuse",
      `${routeCitation} no longer has that total match`,
    );
  }

  const testCitation = "rust/tests/differential.rs";
  const test = fs.readFileSync(path.join(ROOT, testCitation), "utf8");
  requireText(
    ctx,
    row,
    test,
    /fn\s+classify_literal_only\s*\(\s*c\s+in\s+any::<u32>\(\)\s*\)/,
    "classify_literal_only ranges over u32 inputs",
    `${testCitation} has no classify_literal_only u32 property`,
  );
  if (!cargoCiStep("cargo test --no-fail-fast")) {
    reportMismatch(
      ctx,
      row,
      "classify_literal_only is reached by CI",
      "ci.yml has no `cargo test --no-fail-fast` step in rust/",
    );
  }
}

function checkLeanPanicDefault(ctx, row) {
  const leanCitation = "rust/src/lean.rs";
  const lean = fs.readFileSync(path.join(ROOT, leanCitation), "utf8");
  requireText(
    ctx,
    row,
    lean,
    /seal_lean_set_exit_on_panic\(1\)/,
    "the host arms lean_set_exit_on_panic",
    `${leanCitation} has no production call with flag 1`,
  );

  const testCitation = "rust/tests/panic_probe.rs";
  const test = fs.readFileSync(path.join(ROOT, testCitation), "utf8");
  for (const name of [
    "guarded_lean_panic_kills_the_process",
    "unguarded_lean_panic_returns_the_fail_open_default",
  ]) {
    requireText(
      ctx,
      row,
      test,
      new RegExp(`fn\\s+${name}\\s*\\(`),
      `real-binary probe ${name}`,
      `${testCitation} has no such test`,
    );
  }
  requireText(
    ctx,
    row,
    test,
    /CARGO_BIN_EXE_seal-host-rs/,
    "panic probes drive the built production binary",
    `${testCitation} does not use CARGO_BIN_EXE_seal-host-rs`,
  );
  if (!cargoCiStep("cargo test --no-fail-fast")) {
    reportMismatch(
      ctx,
      row,
      "panic_probe is reached by CI",
      "ci.yml has no `cargo test --no-fail-fast` step in rust/",
    );
  }
}

function manifestRevision(packageName) {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(ROOT, "lake-manifest.json"), "utf8"),
  );
  return manifest.packages.find((item) => item.name.replaceAll("«", "").replaceAll("»", "") === packageName)
    ?.rev;
}

function lakeRequirementRevision(packageName) {
  const lakefile = fs.readFileSync(path.join(ROOT, "lakefile.toml"), "utf8");
  for (const match of lakefile.matchAll(
    /\[\[require\]\]([\s\S]*?)(?=\n\[\[|\s*$)/g,
  )) {
    const block = match[1];
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m)?.[1];
    if (name === packageName) {
      return block.match(/^\s*rev\s*=\s*"([^"]+)"/m)?.[1];
    }
  }
  return null;
}

function checkUnicodeDuplicateKeys(ctx, row) {
  const citation = "Host/UnicodeKeys.lean";
  const file = path.join(ROOT, citation);
  const lines = sourceLines(file);
  for (const name of ["nfd", "wireKeysSafe"]) {
    if (leanDeclarationLine(lines, name) === null) {
      reportMismatch(
        ctx,
        row,
        `declaration ${name}`,
        `${citation} has no such declaration`,
      );
    }
  }
  checkJsonWireGuardReachability(ctx, row, "Host.UnicodeKeys.wireKeysSafe");

  const lakeRev = lakeRequirementRevision("UnicodeBasic");
  const manifestRev = manifestRevision("UnicodeBasic");
  if (!lakeRev || !manifestRev || lakeRev !== manifestRev) {
    reportMismatch(
      ctx,
      row,
      "one pinned UnicodeBasic revision",
      `lakefile.toml=${lakeRev ?? "missing"}, lake-manifest.json=${manifestRev ?? "missing"}`,
    );
  }
}

function extractIgnoredTest(text, testName) {
  const pattern = new RegExp(
    `#\\[test\\]\\s*\\n#\\[ignore\\s*=\\s*"([\\s\\S]*?)"\\]\\s*\\nfn\\s+${escaped(testName)}\\s*\\(`,
  );
  const match = text.match(pattern);
  return match?.[1].replace(/\\\s*\n\s*/g, "").replace(/\s+/g, " ").trim() ?? null;
}

function checkEffectMessageTwin(ctx, row) {
  const citation = "rust/tests/envelope_v23_twin.rs";
  const text = fs.readFileSync(path.join(ROOT, citation), "utf8");
  requireText(
    ctx,
    row,
    text,
    /fn\s+rust_encoder_matches_lean_generated_expectation\s*\(/,
    "layer 1 frozen expectation test",
    `${citation} has no rust_encoder_matches_lean_generated_expectation test`,
  );
  requireText(
    ctx,
    row,
    text,
    /fn\s+live_lean_diff_over_shared_corpus\s*\(/,
    "layer 2 live differential test",
    `${citation} has no live_lean_diff_over_shared_corpus test`,
  );

  const shaClaim = row.note.match(/pinned `([0-9a-f]{7,40})`/i)?.[1];
  const liveSha = manifestRevision("mcp-seal");
  if (!shaClaim || !liveSha?.startsWith(shaClaim)) {
    reportMismatch(
      ctx,
      row,
      shaClaim ? `pinned mcp-seal ${shaClaim}` : "no pinned mcp-seal SHA stated",
      liveSha ? `lake-manifest.json pins ${liveSha}` : "mcp-seal revision is missing",
    );
  }

  if (!cargoCiStep("cargo test --test envelope_v23_twin")) {
    reportMismatch(
      ctx,
      row,
      "the named envelope_v23_twin target is reached by CI",
      "ci.yml has no `cargo test --test envelope_v23_twin` step in rust/",
    );
  }

  const ignoreReason = extractIgnoredTest(text, "live_lean_diff_over_shared_corpus");
  const claimedUnblocked = /\blayer 2 is unblocked\b/i.test(row.note);
  if (claimedUnblocked && ignoreReason) {
    reportMismatch(
      ctx,
      row,
      "layer 2 is unblocked",
      `live_lean_diff_over_shared_corpus is #[ignore]: ${ignoreReason}`,
    );
  } else if (!claimedUnblocked && !ignoreReason && /#\[ignore\]/.test(row.note)) {
    reportMismatch(
      ctx,
      row,
      "layer 2 is ignored",
      "live_lean_diff_over_shared_corpus is active",
    );
  }
}

function checkNonceConsumeOrdering(ctx, row) {
  const a3Citation = "rust/src/a3.rs";
  const a3 = fs.readFileSync(path.join(ROOT, a3Citation), "utf8");
  const withStore = a3.indexOf("pub fn with_store(");
  const reclaim = a3.indexOf(".reclaim_uncommitted()?", withStore);
  const load = a3.indexOf(".load_unexpired(now_ms)?", withStore);
  const construct = a3.indexOf("Ok(Self {", withStore);
  const reserve = a3.indexOf("fn reserve_nonce(");
  const durableReserve = a3.indexOf(".reserve_returning_is_new(", reserve);
  const filter = a3.indexOf("pub fn filter(", reserve);
  const survivor = a3.indexOf("ok.push(r);", filter);
  const startupReclaimsBeforeRebuild =
    withStore >= 0 && reclaim > withStore && load > reclaim && construct > load;
  const reservationBeforeSurvivor =
    reserve >= 0 && durableReserve > reserve && filter > durableReserve && survivor > filter;
  if (!startupReclaimsBeforeRebuild || !reservationBeforeSurvivor) {
    reportMismatch(
      ctx,
      row,
      "startup reclamation before cache rebuild plus durable reservation before record survival",
      `${a3Citation}: startupReclaimsBeforeRebuild=${startupReclaimsBeforeRebuild}, reservationBeforeSurvivor=${reservationBeforeSurvivor}`,
    );
  }

  const replayCitation = "rust/src/replay_store.rs";
  const replay = fs.readFileSync(path.join(ROOT, replayCitation), "utf8");
  requireText(
    ctx,
    row,
    replay,
    /INSERT INTO nonces \(nonce, issued_at, expiry_at, committed_at\)\s+VALUES \(\?1, \?2, \?3, NULL\)/,
    "phase 1 stores an open reservation",
    `${replayCitation} no longer inserts a NULL committed_at reservation`,
  );
  requireText(
    ctx,
    row,
    replay,
    /UPDATE nonces SET committed_at = \?2\s+WHERE nonce = \?1 AND committed_at IS NULL/,
    "phase 2 commits only an open reservation",
    `${replayCitation} no longer commits only a NULL committed_at reservation`,
  );
  requireText(
    ctx,
    row,
    replay,
    /DELETE FROM nonces WHERE committed_at IS NULL/,
    "startup recovery reclaims only open reservations",
    `${replayCitation} no longer limits reclamation to open reservations`,
  );
  requireText(
    ctx,
    row,
    replay,
    /"synchronous",\s*"FULL"/,
    "the SQLite replay store requests FULL synchronous durability",
    `${replayCitation} no longer configures synchronous=FULL`,
  );

  // The two-phase host ordering (reservation before Lean, then receipt, burn
  // commit, child forward) is witnessed BEHAVIOURALLY by the G2 crash suite,
  // not by grepping variable names in main.rs. The gate cannot run the suite,
  // so it establishes reachability instead: the tests exist, none is ignored,
  // each arms a crash point the host really implements, and a CI cargo test
  // step actually selects them.
  const mainCitation = "rust/src/main.rs";
  const main = fs.readFileSync(path.join(ROOT, mainCitation), "utf8");
  const hostPathCitation = "rust/tests/host_path.rs";
  const hostPath = fs.readFileSync(path.join(ROOT, hostPathCitation), "utf8");
  const ciSteps = parseCiRunSteps().filter(
    (step) => step.workingDirectory === "rust",
  );

  const injector = extractFunction(main, "maybe_test_crash");
  if (!injector || !injector.includes("std::process::abort()")) {
    reportMismatch(
      ctx,
      row,
      "maybe_test_crash aborts the process at an armed crash point",
      `${mainCitation}: maybe_test_crash is ${injector ? "present but no longer calls std::process::abort()" : "missing"}`,
    );
  }

  for (const test of G2_CRASH_TESTS) {
    const witness = extractG2TestWitness(hostPath, test.name);
    if (!witness) {
      reportMismatch(
        ctx,
        row,
        `live G2 crash control ${test.name}`,
        `${hostPathCitation} no longer declares ${test.name}`,
      );
      continue;
    }
    if (!/#\[test\]/.test(witness.attributes)) {
      reportMismatch(
        ctx,
        row,
        `${test.name} is a #[test]`,
        `${hostPathCitation}: ${test.name} carries no #[test] attribute, so no harness runs it`,
      );
    }
    if (/#\[\s*ignore\b/.test(witness.attributes)) {
      reportMismatch(
        ctx,
        row,
        `${test.name} runs unconditionally`,
        `${hostPathCitation}: ${test.name} is #[ignore]d; an ignored test is not a witness`,
      );
    }
    if (test.crashPoint) {
      const arming = new RegExp(
        `\\(\\s*"SEAL_TEST_CRASH_POINT"\\s*,\\s*"${escaped(test.crashPoint)}"\\s*\\)`,
      );
      if (!arming.test(witness.body)) {
        reportMismatch(
          ctx,
          row,
          `${test.name} arms SEAL_TEST_CRASH_POINT=${test.crashPoint}`,
          `${hostPathCitation}: ${test.name} no longer sets that crash point in its spawn environment`,
        );
      }
      const injection = new RegExp(
        `maybe_test_crash\\([^;]*"${escaped(test.crashPoint)}"\\s*\\)`,
      );
      if (!injection.test(main)) {
        reportMismatch(
          ctx,
          row,
          `crash point ${test.crashPoint} is a real injection site`,
          `${mainCitation} has no maybe_test_crash(..., "${test.crashPoint}") call; the armed test would pass by never crashing`,
        );
      }
    }
    if (
      !ciSteps.some((step) =>
        cargoTestRunReachesTest(step.run, "host_path", test.name),
      )
    ) {
      reportMismatch(
        ctx,
        row,
        `a CI cargo test step in rust/ selects ${test.name}`,
        `no ci.yml run step reaches --test host_path with ${test.name} unfiltered; the behavioural witness would not execute`,
      );
    }
  }
}

const G2_CRASH_TESTS = Object.freeze([
  {
    name: "g2_t1_crash_between_reserve_and_recorded_recovers_the_approval",
    crashPoint: "g2-before-record",
  },
  {
    name: "g2_t2_second_presentation_fails_while_reservation_open",
    crashPoint: null,
  },
  {
    name: "g2_t3_crash_after_recorded_keeps_burn_and_receipt",
    crashPoint: "g2-after-burn",
  },
]);

// Slice of `source` from `fn name(` to the next top-level `fn`, or null.
function extractFunction(source, name) {
  const start = source.search(new RegExp(`^fn\\s+${escaped(name)}\\s*\\(`, "m"));
  if (start === -1) return null;
  const rest = source.slice(start + 1);
  const next = rest.search(/^fn\s/m);
  return source.slice(start, next === -1 ? source.length : start + 1 + next);
}

// A test's attribute block (contiguous #[...] / doc-comment lines above the
// fn) and its body (up to the next #[test] or end of file), or null.
function extractG2TestWitness(source, testName) {
  const lines = source.split("\n");
  const header = new RegExp(`^\\s*fn\\s+${escaped(testName)}\\s*\\(`);
  const fnLine = lines.findIndex((line) => header.test(line));
  if (fnLine === -1) return null;
  let attrStart = fnLine;
  while (attrStart > 0 && /^\s*(#\[|#!\[|\/\/)/.test(lines[attrStart - 1])) {
    attrStart -= 1;
  }
  const attributes = lines.slice(attrStart, fnLine).join("\n");
  const bodyStart = lines.slice(0, fnLine).join("\n").length;
  const nextTest = source.indexOf("\n#[test]", bodyStart + 1);
  const body = source.slice(bodyStart, nextTest === -1 ? source.length : nextTest);
  return { attributes, body };
}

const CARGO_VALUE_FLAGS = new Set([
  "--package",
  "-p",
  "--exclude",
  "--features",
  "--profile",
  "--target",
  "--target-dir",
  "--manifest-path",
  "--jobs",
  "-j",
  "--message-format",
  "--color",
  "--bin",
  "--example",
  "--bench",
]);
const CARGO_NON_TEST_TARGET_FLAGS = new Set([
  "--lib",
  "--bins",
  "--bin",
  "--doc",
  "--examples",
  "--example",
  "--benches",
  "--bench",
]);
const HARNESS_VALUE_FLAGS = new Set([
  "--test-threads",
  "--logfile",
  "--format",
  "--color",
  "-Z",
]);

// Would `run` (one CI step's script) execute `testName` inside the named
// integration test target? Conservative: anything unparseable counts as NOT
// reaching the test, so novel CI shapes fail closed and must be classified.
function cargoTestRunReachesTest(run, targetName, testName) {
  return run
    .split("\n")
    .some((line) => cargoTestLineReachesTest(line.trim(), targetName, testName));
}

function cargoTestLineReachesTest(line, targetName, testName) {
  let tokens = line.split(/\s+/).filter(Boolean);
  while (tokens.length > 0 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[0])) {
    tokens.shift();
  }
  if (tokens[0] !== "cargo" || tokens[1] !== "test") return false;
  tokens = tokens.slice(2);
  const separator = tokens.indexOf("--");
  const cargoArgs = separator === -1 ? tokens : tokens.slice(0, separator);
  const harnessArgs = separator === -1 ? [] : tokens.slice(separator + 1);

  const testTargets = [];
  const filters = [];
  let allTargets = false;
  let nonTestTargetOnly = false;
  for (let i = 0; i < cargoArgs.length; i += 1) {
    const arg = cargoArgs[i];
    if (arg === "--test") {
      testTargets.push(cargoArgs[++i]);
    } else if (arg === "--all-targets") {
      allTargets = true;
    } else if (CARGO_NON_TEST_TARGET_FLAGS.has(arg)) {
      nonTestTargetOnly = true;
      if (CARGO_VALUE_FLAGS.has(arg)) i += 1;
    } else if (arg.startsWith("-")) {
      if (CARGO_VALUE_FLAGS.has(arg)) i += 1;
    } else {
      filters.push(arg);
    }
  }
  const targetSelected =
    allTargets ||
    testTargets.includes(targetName) ||
    (testTargets.length === 0 && !nonTestTargetOnly);
  if (!targetSelected) return false;

  const exact = harnessArgs.includes("--exact");
  const matches = (pattern) =>
    exact ? pattern === testName : testName.includes(pattern);
  if (harnessArgs.includes("--ignored")) return false;
  for (let i = 0; i < harnessArgs.length; i += 1) {
    const arg = harnessArgs[i];
    if (arg === "--skip") {
      if (matches(harnessArgs[++i])) return false;
    } else if (arg.startsWith("--skip=")) {
      if (matches(arg.slice("--skip=".length))) return false;
    } else if (arg.startsWith("-")) {
      if (HARNESS_VALUE_FLAGS.has(arg)) i += 1;
    } else {
      filters.push(arg);
    }
  }
  if (filters.length > 0 && !filters.some(matches)) return false;
  return true;
}

function trackedSourceFiles(directory) {
  if (!fs.existsSync(directory)) return [];
  const output = execFileSync("git", ["-C", directory, "ls-files", "-z"], {
    encoding: "utf8",
  });
  return output
    .split("\0")
    .filter(Boolean)
    .filter((file) => SOURCE_EXTENSIONS.has(path.extname(file)))
    .map((file) => path.join(directory, file));
}

function checkSpecificationOnlyInventory(ctx) {
  const heading = ctx.lines.findIndex((line) =>
    line.startsWith("## Specification-only"),
  );
  const end = ctx.lines.findIndex(
    (line, index) => index > heading && line.startsWith("## "),
  );
  if (heading < 0) {
    ctx.failures.push(
      "PINS.md [Specification-only]\n  claimed: specification-only inventory exists\n  actual:  section is missing",
    );
    return;
  }

  const entries = [];
  for (
    let index = heading + 1;
    index < (end < 0 ? ctx.lines.length : end);
    index += 1
  ) {
    for (const match of ctx.lines[index].matchAll(/`([^`]+)`/g)) {
      for (const part of match[1].split("/")) {
        const name = part.trim();
        if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
          entries.push({ name, line: index + 1 });
        }
      }
    }
  }
  if (entries.length === 0) {
    ctx.failures.push(
      `PINS.md:${heading + 1} [Specification-only]\n  claimed: at least one absent identifier\n  actual:  inventory is empty`,
    );
    return;
  }

  const sourceFiles = [
    ...trackedSourceFiles(ROOT),
    ...trackedSourceFiles(KERNEL),
  ].filter((file) => file !== PINS);
  for (const { name, line } of entries) {
    const pattern = new RegExp(
      `(^|[^A-Za-z0-9_])${escaped(name)}([^A-Za-z0-9_]|$)`,
    );
    let occurrence = null;
    for (const file of sourceFiles) {
      const index = sourceCodeLines(file).findIndex((sourceLine) =>
        pattern.test(sourceLine),
      );
      if (index >= 0) {
        occurrence = `${path.relative(ROOT, file)}:${index + 1}`;
        break;
      }
    }
    if (occurrence) {
      ctx.failures.push(
        `PINS.md:${line} [Specification-only: ${name}]\n  claimed: absent from both source trees\n  actual:  present at ${occurrence}`,
      );
    }
  }
  ctx.specificationOnlyCount = entries.length;
}

export const CHECKS = Object.freeze({
  "issued-time-unit": checkIssuedTimeUnit,
  "effect-message": checkEffectMessage,
  "raw-duplicate-keys": (ctx, row) =>
    checkKernelRawGuard(ctx, row, "wireKeysSafe"),
  "significant-digit-bound": (ctx, row) =>
    checkKernelRawGuard(ctx, row, "wireDigitsSafe"),
  "pathological-exponent-guard": (ctx, row) =>
    checkKernelRawGuard(ctx, row, "wireNumbersSafe"),
  "lean-classify-encoding": checkLeanClassifyEncoding,
  "rust-classify-routing": checkRustClassifyRouting,
  "lean-panic-default": checkLeanPanicDefault,
  "unicode-duplicate-keys": checkUnicodeDuplicateKeys,
  "effect-message-twin": checkEffectMessageTwin,
  "nonce-consume-ordering": checkNonceConsumeOrdering,
  "cosign-executable-bytes": checkCosignExecutableBytes,
  "specification-only-inventory": checkSpecificationOnlyInventory,
});

export function runGate() {
  process.chdir(ROOT);
  const parsed = parseLedger();
  const ciRunSteps = parseCiRunSteps();
  const ctx = {
    ...parsed,
    failures: [],
    specificationOnlyCount: 0,
    ciRunStepCount: ciRunSteps.length,
  };
  if (checkMcpSealPin() !== 0) {
    ctx.failures.push("mcp-seal three-way pin check failed");
  }
  const ciFloorFailure = ciRunStepFloorFailure(ciRunSteps.length);
  if (ciFloorFailure) ctx.failures.push(ciFloorFailure);

  for (const policy of GATED_ROWS) {
    const matches = matchingRows(ctx.rows, policy.anchor);
    if (matches.length !== 1) {
      ctx.failures.push(
        `PINS.md [${policy.id}]\n  claimed: exactly one row anchored by ${policy.anchor}\n  actual:  found ${matches.length}`,
      );
      continue;
    }
    const row = matches[0];
    checkCitedPaths(ctx, row);
    const check = CHECKS[policy.check];
    if (!check) {
      reportMismatch(
        ctx,
        row,
        `registered check ${policy.check}`,
        "no implementation exists (the meta-test should also reject this)",
      );
      continue;
    }
    check(ctx, row);
  }

  for (const policy of GATED_SECTIONS) {
    const check = CHECKS[policy.check];
    if (!check) {
      ctx.failures.push(
        `PINS.md [${policy.id}]\n  claimed: registered check ${policy.check}\n  actual:  no implementation exists`,
      );
      continue;
    }
    check(ctx);
  }
  return ctx;
}

export function printCanonicalList() {
  console.log("GATED ROWS");
  for (const row of GATED_ROWS) {
    console.log(`${row.id}\t${row.anchor}\t${row.fact}`);
  }
  for (const section of GATED_SECTIONS) {
    console.log(`${section.id}\t${section.anchor}\t${section.fact}`);
  }
  console.log("OUT OF SCOPE");
  for (const row of OUT_OF_SCOPE_ROWS) {
    console.log(`${row.id}\t${row.anchor}\t${row.outOfScope}`);
  }
}

function main(argv) {
  const flags = new Set(argv);
  if (flags.has("--list")) {
    printCanonicalList();
    return 0;
  }
  if (flags.size > 0 && !flags.has("--check")) {
    console.error("usage: node scripts/pins_gate.mjs [--check|--list]");
    return 2;
  }

  const ctx = runGate();
  if (ctx.failures.length > 0) {
    for (const failure of ctx.failures) console.error(`FAIL ROW: ${failure}`);
    console.error(
      `PINS GATE FAIL (${ctx.failures.length} offending fact${ctx.failures.length === 1 ? "" : "s"})`,
    );
    return 1;
  }
  console.log(
    `PINS GATE PASS (${GATED_ROWS.length} rows, ${ctx.specificationOnlyCount} SPEC-ONLY names)`,
  );
  return 0;
}

const invokedAsScript =
  process.argv[1] &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) process.exitCode = main(process.argv.slice(2));
