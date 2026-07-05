# Architecture

`seal-host` is the deployable guard at the MCP boundary.

## Components

- Lean host modules under `Host/` and `Kernels/`: composition, audit, records, non-interference, replay isolation, and FFI entry points.
- `Ffi.lean`: exported Lean functions called by native and wasm wrappers.
- `rust/`: the deployed host process, approval providers, A3 freshness/replay filtering, and MCP stdio transport.
- `wasm-spike/verified/`: browser wasm and JavaScript wrapper pinned by provenance.
- `scripts/conformance_bridge.mjs`: differential bridge across model, native `.so`, wasm, deployed Rust, and JS-format expectations.

## Data flow

1. MCP traffic reaches the Rust host.
2. Ordinary traffic passes through. Guarded `tools/call` traffic is sent to the Lean kernel.
3. Approval records are parsed as lowercase 64-hex SHA-256 targets and filtered for freshness and replay.
4. The Lean decision returns forward or block plus audit bytes.
5. Forwarded calls go to the child MCP server; blocks return JSON-RPC errors.
6. Decisions can be appended to the SHA-256 production record chain.

## Trust boundaries

The Lean theorem covers the model. Rust transport, filesystem permissions, OS process isolation, toolchains, keys, and downstream tools remain in the TCB. See `docs/SEAL-SYSTEM-TCB.md`, `docs/CONFORMANCE-BRIDGE.md`, and `docs/VERIFIABLE-RECORD.md` for deeper host-specific notes.
