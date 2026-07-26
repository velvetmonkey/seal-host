// SPDX-License-Identifier: Apache-2.0
//
// The fleet registry and generated footprint must remain a bijection. Adding a
// repository to the fleet without regenerating the footprint is a test failure.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..",
);
const fleetLockPath =
  process.env.FLEET_LOCK_PATH ?? path.join(ROOT, "release", "fleet-lock.json");
const manifestPath =
  process.env.KERNEL_HASH_FOOTPRINT_MANIFEST ??
  path.join(ROOT, "release", "kernel-hash-footprint.json");

test("the generated footprint covers exactly the fleet-lock repositories", () => {
  const fleetLock = JSON.parse(fs.readFileSync(fleetLockPath, "utf8"));
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  const fleetRepositories = Object.keys(fleetLock.repositories).sort();
  const scannedRepositories = manifest.repositories
    .map((repository) => repository.name)
    .sort();

  assert.deepEqual(
    scannedRepositories,
    fleetRepositories,
    "fleet-lock repository list and scanned footprint repository list differ; regenerate release/kernel-hash-footprint.json",
  );
});

test("CI and release run the footprint gate and its fleet-list meta-test", () => {
  for (const workflow of ["ci.yml", "release.yml"]) {
    const ci = fs.readFileSync(
      path.join(ROOT, ".github", "workflows", workflow),
      "utf8",
    );
    const commands = [...ci.matchAll(/^\s*run:\s*(.+?)\s*$/gm)].map(
      (match) => match[1],
    );

    assert.ok(
      commands.includes("node scripts/kernel_hash_footprint.mjs --check"),
      `${workflow} does not run the generated footprint gate`,
    );
    assert.ok(
      commands.includes(
        "node --test test/kernel_hash_footprint_meta.test.mjs",
      ),
      `${workflow} does not run the footprint fleet-list meta-test`,
    );
  }
});
