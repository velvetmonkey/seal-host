# Evidence Wrapper

`scripts/evidence.sh` is the local Phase 0 re-checkable evidence chain for the
private Seal product-family repos. It assumes sibling checkouts under
`/home/monkey/src`:

- `mcp-seal-dev`
- `seal-host`
- `seal-check`
- `seal-assurance-kit`

The script runs the Lean builds and axiom gates, Rust host tests, the native +
wasm conformance bridge, and the JavaScript checker/assurance suites. It fails
on the first error and prints a PASS/FAIL summary naming the failed step.

What this proves: the checked private repos, at their local commits, still pass
the proof gates and the finite integration/conformance evidence chain.

What this does not prove: universal compiler correctness, exhaustive equivalence
for all inputs, or that a downstream deployment is wired through Seal. The
conformance bridge remains corpus evidence over the checked artifacts, not a
theorem about every compiled instruction.

Run:

```sh
bash scripts/evidence.sh
```

JavaScript audit follow-ups: `seal-check` has no package manifest, and
`seal-assurance-kit` currently has no lockfile. Add `npm audit` gates there only
after those repos have stable package metadata/lockfiles to audit.
