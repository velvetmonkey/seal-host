# Assumptions

## A-CR: target commitment collision resistance

Seal's deployed target commitment is SHA-256 over the injective `encodeParts` netstring encoding. Lean proves the encoding is injective in `seal-host`; it does not prove SHA-256 collision resistance. A-CR is a named cryptographic assumption.

## Approval issuance

A human or trusted approval provider must mint approvals for the intended target. Seal checks that a target commitment matches; it does not decide whether the human should have approved it.

## Integration

The MCP host must route guarded tool calls through Seal before the downstream tool can execute. A tool path that bypasses Seal is outside the kernel claim.

## Key management

Signing keys, control files, CI secrets, browser delivery, and operator workstations must be protected by ordinary operational controls. Seal does not remove that TCB.

## Build and artifact identity

Rust, wasm, and JavaScript artifacts must be built from the intended source and pinned by SHA-256. Conformance tests reduce integration risk over the corpus; they are not universal compiler correctness proofs.
