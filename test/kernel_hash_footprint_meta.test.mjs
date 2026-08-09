// SPDX-License-Identifier: Apache-2.0
//
// The fleet registry and generated footprint must remain a bijection. Adding a
// repository to the fleet without regenerating the footprint is a test failure.

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

// The acceptance workflow invokes this file explicitly, so keep the scanner's
// subject-identity refusal tests in the same fail-closed test entrypoint.
import "./kernel_hash_footprint_subject_identity.test.mjs";

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
  // The footprint commands live exactly once, in the reusable acceptance
  // workflow (roadmap 8y item 8). Both the push path (ci.yml) and the tag
  // path (release.yml) must invoke that workflow, with secrets, so the same
  // gate runs on both paths and the two copies cannot drift.
  const acceptance = fs.readFileSync(
    path.join(ROOT, ".github", "workflows", "acceptance.yml"),
    "utf8",
  );
  const commands = [...acceptance.matchAll(/^\s*run:\s*(.+?)\s*$/gm)].map(
    (match) => match[1],
  );
  assert.ok(
    commands.includes("node scripts/kernel_hash_footprint.mjs --check"),
    "acceptance.yml does not run the generated footprint gate",
  );
  assert.ok(
    commands.includes("node --test test/kernel_hash_footprint_meta.test.mjs"),
    "acceptance.yml does not run the footprint fleet-list meta-test",
  );

  for (const workflow of ["ci.yml", "release.yml"]) {
    const caller = fs.readFileSync(
      path.join(ROOT, ".github", "workflows", workflow),
      "utf8",
    );
    assert.ok(
      caller.includes("uses: ./.github/workflows/acceptance.yml"),
      `${workflow} does not invoke the reusable acceptance workflow`,
    );
    assert.ok(
      !caller.includes("uses: ./.github/workflows/acceptance.yml\n    secrets: inherit"),
      `${workflow} passes secrets to the credential-free acceptance workflow`,
    );
  }
});
