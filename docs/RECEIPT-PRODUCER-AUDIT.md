<!-- SPDX-License-Identifier: Apache-2.0 -->

# V2 receipt producer field-availability audit

This audit was the first Gate 0A check: determine whether native v2 receipt
production required widening the Lean/Rust decision FFI. It did not. Every
decision-bearing receipt field was already present at the mediation point.

| Receipt material | Exact source at emission | FFI change? |
|---|---|---|
| `tool`, `arguments`, canonical request and their hashes | The unchanged MCP line passed to `sealHostStep`, parsed directly as structured JSON | No |
| `verdict`, `reason`, `deny_kernel`, `certs`, `emitted_bytes` | The exact structured `sealHostStep` output used by `route_of_step_output` | No |
| Guarded target consumed by ALLOW | Safety certificate reason plus the already-filtered approval records supplied to the same step | No |
| `now` | The same host clock value supplied to the step | No |
| `kernel_config`, policy hash and approval TTL | The verified signed configuration payload already held by the host | No |
| Approval identity, nonce and issue time | The authenticated provider record after A3 freshness/replay filtering | No |
| `kernel_identity.wasm_sha256` | Bytes of the separately shipped re-derivation wasm | No |
| Native `host_identity` | SHA-256 of the running executable and the actually loaded Lean FFI shared object located with `dladdr` | No decision FFI; provenance-only host inspection |

The producer is therefore assembled from the exact machine-readable decision
material. It never scrapes the human-facing block/error string to reconstruct a
receipt. The only text inspection remaining in the host is approval-UI routing
after a receipt has already been persisted; it does not determine receipt
verdict, certificates, or authorization.

`host_identity` identifies the native executor. It does not prove that native
code equivalent to `kernel_identity`'s wasm ran. A verifier re-derives against
the named wasm; the native/wasm equivalence is the still-open Lane C claim.

Receipt persistence is part of the forwarding seam. If the directory cannot be
created, written, renamed, or synced, the host returns the static seam error and
does not forward the guarded call. This deliberately trades availability for
safety: a full filesystem or broken receipt mount can stop all guarded effects.
