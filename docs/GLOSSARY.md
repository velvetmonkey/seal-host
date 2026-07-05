# Glossary

**MCP**: Model Context Protocol, the tool-call boundary Seal mediates.

**PDP**: Policy decision point. In Seal, the Lean kernel is the core PDP for guarded calls.

**Approval target**: The structured pieces of a tool call that a human approval is meant to bind: usually the tool name plus policy-selected argument fields.

**Target commitment**: The deployed digest of an approval target. Seal uses lowercase 64-hex SHA-256 over the injective `encodeParts` netstring encoding.

**`certHash`**: A legacy UInt64 per-kernel audit seal. It is not the target commitment and not the production record-chain hash.

**Hash chain**: A sequence where each record head commits to the previous head and the new payload. Seal uses this to make decision records tamper-evident.

**TCB**: Trusted computing base, the pieces that must be trusted rather than proven by the Lean theorem.

**A-CR**: The named assumption that the deployed target commitment is collision-resistant for the relevant inputs.

**Conformance corpus**: The finite set of traces used to compare model, native, wasm, Rust, and JavaScript behavior byte-for-byte.
