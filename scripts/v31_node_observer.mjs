// SPDX-License-Identifier: Apache-2.0
//
// Loaded into an otherwise unmodified Node MCP server. It observes the value
// produced by that server's own JSON.parse call; it does not parse, rewrite, or
// forward the request itself.

import { createHash } from "node:crypto";

const originalParse = JSON.parse;

function semantic(value) {
  if (typeof value === "number" && !Number.isFinite(value)) {
    return { "$nonFiniteNumber": String(value) };
  }
  if (Array.isArray(value)) {
    return value.map(semantic);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, semantic(item)]));
  }
  return value;
}

JSON.parse = function observedParse(text, reviver) {
  const value = originalParse.call(this, text, reviver);
  if (value && value.method === "tools/call") {
    const raw = typeof text === "string" ? Buffer.from(text, "utf8") : Buffer.from(text);
    const record = {
      event: "v31_server_json_parse",
      request_sha256: createHash("sha256").update(raw).digest("hex"),
      // The Node MCP stdio transport strips the LF frame delimiter before
      // calling JSON.parse. Reconstruct its exact on-wire frame commitment so
      // the harness cannot associate an observation with a different request.
      wire_frame_sha256: createHash("sha256").update(raw).update("\n").digest("hex"),
      accepted: true,
      tool: value.params?.name,
      arguments: semantic(value.params?.arguments),
    };
    process.stderr.write(`V31_SERVER_OBSERVATION ${JSON.stringify(record)}\n`);
  }
  return value;
};
