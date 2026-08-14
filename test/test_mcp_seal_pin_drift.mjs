// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import test from "node:test";

import { comparePinValues } from "../scripts/mcp_seal_pin_drift.mjs";

const PIN = "316d74126b4cb164d501fea21738d6880469bcb4";

test("pin mismatch is a named negative result", () => {
  const result = comparePinValues({
    expected: PIN,
    lakefile: { chosenConfig: "lakefile.toml", revision: PIN },
    manifest: PIN,
    checkout: "0000000000000000000000000000000000000000",
  });

  assert.equal(result.ok, false);
  assert.match(result.mismatches[0], /mcp-seal pin drift/);
  assert.match(result.mismatches[0], /\.lake\/packages\/mcp-seal HEAD/);
});

test("matching manifest and checkout are accepted", () => {
  const result = comparePinValues({
    expected: PIN,
    lakefile: { chosenConfig: "lakefile.toml", revision: PIN },
    manifest: PIN,
    checkout: PIN,
  });

  assert.deepEqual(result, { ok: true, mismatches: [] });
});
