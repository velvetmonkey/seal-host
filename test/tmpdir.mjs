// SPDX-License-Identifier: Apache-2.0
// Test-fixture temp directories. Removed after the file's tests finish,
// including assertion failures. Set KEEP_TMP=1 to retain them as evidence.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir as osTmpdir } from "node:os";
import { join } from "node:path";
import { after } from "node:test";

const owned = new Set();
let hooked = false;

function keep() {
  const value = process.env.KEEP_TMP;
  return value === "1" || value === "true";
}

function rm(dir) {
  if (keep() || !dir) return;
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    /* best-effort */
  }
}

function hook() {
  if (hooked) return;
  hooked = true;
  after(() => {
    for (const dir of owned) rm(dir);
    owned.clear();
  });
  process.on("exit", () => {
    for (const dir of owned) rm(dir);
    owned.clear();
  });
}

export function track(dir) {
  owned.add(dir);
  hook();
  return dir;
}

export function tmpdir(prefix) {
  return track(mkdtempSync(join(osTmpdir(), prefix)));
}

hook();

export { keep };
