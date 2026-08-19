// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { scanFleet } from "../scripts/kernel_hash_footprint.mjs";
import { tmpdir } from "./tmpdir.mjs";

function git(root, ...args) {
  const result = spawnSync("git", args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

function makeRepository() {
  const root = tmpdir("kernel-footprint-subject-");
  git(root, "init", "--quiet");
  fs.writeFileSync(path.join(root, ".gitignore"), "ignored.txt\n");
  fs.writeFileSync(path.join(root, "kernel.wasm"), "audited kernel\n");
  fs.writeFileSync(
    path.join(root, "identity.txt"),
    `${"a".repeat(64)}\n`,
  );
  git(root, "add", ".");
  git(
    root,
    "-c",
    "user.name=Footprint Test",
    "-c",
    "user.email=footprint@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "fixture",
  );
  return { root, commit: git(root, "rev-parse", "HEAD") };
}

function scanLocal(root, expectedCommit, allowLocalRepoRoots = true) {
  return scanFleet(
    {
      schema: 1,
      kernel_sha256: "b".repeat(64),
      repositories: {
        fixture: {
          url: "https://example.invalid/fixture.git",
          commit: expectedCommit,
          wasm: ["kernel.wasm"],
        },
      },
    },
    {
      repoRoots: new Map([["fixture", root]]),
      allowLocalRepoRoots,
      cacheDir: path.join(root, "unused-cache"),
    },
  );
}

function refusal(result) {
  assert.equal(result.unreachable.length, 1);
  return result.unreachable[0].error;
}

test("local repository overrides require explicit opt-in", () => {
  const { root, commit } = makeRepository();
  const message = refusal(scanLocal(root, commit, false));
  assert.match(message, /requires explicit --allow-local-repo-roots opt-in/);
  assert.match(message, new RegExp(`expected commit ${commit}`));
  assert.match(message, new RegExp(`observed commit ${commit}`));
  assert.match(message, new RegExp(`path ${root}`));
});

test("a clean local checkout at the pinned commit is scanned", () => {
  const { root, commit } = makeRepository();
  const result = scanLocal(root, commit);
  assert.deepEqual(result.unreachable, []);
  assert.equal(result.manifest.repositories[0].status, "scanned");
});

test("a local checkout at another commit is refused with subject identity", () => {
  const { root, commit } = makeRepository();
  fs.appendFileSync(path.join(root, "identity.txt"), `${"c".repeat(64)}\n`);
  git(root, "add", "identity.txt");
  git(
    root,
    "-c",
    "user.name=Footprint Test",
    "-c",
    "user.email=footprint@example.invalid",
    "commit",
    "--quiet",
    "-m",
    "wrong commit",
  );
  const observed = git(root, "rev-parse", "HEAD");
  const message = refusal(scanLocal(root, commit));
  assert.match(message, new RegExp(`expected commit ${commit}`));
  assert.match(message, new RegExp(`observed commit ${observed}`));
  assert.match(message, new RegExp(`path ${root}`));
});

test("tracked, untracked, and ignored residue are all refused", () => {
  for (const [name, writeResidue] of [
    ["tracked", (root) => fs.appendFileSync(path.join(root, "identity.txt"), "dirty\n")],
    ["untracked", (root) => fs.writeFileSync(path.join(root, "extra.txt"), "extra\n")],
    ["ignored", (root) => fs.writeFileSync(path.join(root, "ignored.txt"), "ignored\n")],
  ]) {
    const { root, commit } = makeRepository();
    writeResidue(root);
    const message = refusal(scanLocal(root, commit));
    assert.match(
      message,
      /checkout is dirty or contains untracked\/ignored files/,
      name,
    );
    assert.match(message, new RegExp(`expected commit ${commit}`), name);
    assert.match(message, new RegExp(`observed commit ${commit}`), name);
    assert.match(message, new RegExp(`path ${root}`), name);
  }
});
