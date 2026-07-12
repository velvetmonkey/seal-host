<!-- SPDX-License-Identifier: Apache-2.0 -->

# Policy-v2 promotion gate

Policy-v2 source can be tested from a sibling checkout, but it is not a
release until the proven core has an immutable published revision and every
executor/verifier names artifacts built from that revision.

## Local compatibility probe

Temporarily use a Lake path dependency for `mcp-seal`, then:

```bash
lake update mcp-seal
lake --old build +Ffi
SEAL_LAKE_OLD=1 scripts/build_ffi_so.sh
(cd rust && cargo build)
python3 scripts/policy_v2_native_conformance.py

(cd wasm-spike && \
  ./build_runtime_wasm.sh && \
  ./build_core.sh && \
  ./build_base.sh && \
  ./build_closure.sh && \
  ./build_wasm.sh strict && \
  node policy_v2_conformance.mjs)
```

`--old` is permitted only for this compatibility probe. It avoids rebuilding
unchanged heavyweight host theorem modules when switching the same dependency
source from Git to a local path. It is finite execution evidence, not a release
build or a source-equivalence proof.

## Immutable release gate

1. Commit and publish the reviewed `mcp-seal-dev` policy-v2 source.
2. Replace the host's `mcp-seal` revision with that full commit and regenerate
   `lake-manifest.json`.
3. On a clean, memory-adequate release runner, build without `--old`; run the
   mcp-seal and host axiom gates plus all native tests.
4. Rebuild wasm from empty ignored object directories using all five explicit
   stages above. Run strict linking and `policy_v2_conformance.mjs`.
5. Copy the exact wasm and glue into seal-check, the assurance kit, the GitHub
   Action, live demo and host receipt verifier. Update every audited SHA pin.
6. Generate an explicit-policy-ALLOW receipt from the native host. The exact
   receipt must verify in seal-check, `seal verify`, and the CI Action. Argument
   tampering must fail in all three.
7. Record both identities honestly: verifiers re-derive against the wasm;
   `host_identity` identifies the native executor but does not prove native/wasm
   equivalence.

No public artifact or documentation may claim policy-v2 deployment before all
seven steps pass. The local compatibility probe exists to find ABI, config and
schema seams early; it is not permission to publish an untraceable binary.

## Resource note

On the current developer box, invalidating the whole host proof library caused
one Lean process to peak around 7.5 GiB while the machine had no swap and other
services were resident; the kernel OOM-killed it. `lake build +Ffi` names the
runtime module closure, whereas `lake build Ffi` names the whole globbed library
including heavyweight proof-only modules. Release CI must provision enough
memory (or swap) for the clean axiom build rather than silently using `--old`.
