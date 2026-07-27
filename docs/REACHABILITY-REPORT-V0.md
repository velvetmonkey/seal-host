<!-- SPDX-License-Identifier: Apache-2.0 -->

# Unbrokered reachability report v0

`seal-reachability-report` emits a signed inventory of effect paths declared
for a seal-host deployment. It classifies each path as `BROKERED`,
`UNBROKERED`, or `UNKNOWN`.

The v0 report deliberately says its denominator is unsound. It enumerates seal
policy tool names, deployment-declared paths, and a named UNKNOWN sentinel for
every incomplete category. One sentinel may hide many paths, so v0 does not
emit a coverage percentage and does not claim its record count is total
reachability.

## Inventory categories

Every inventory must account for all seven categories:

- tool handles;
- transport;
- subprocess or shell;
- outbound network;
- filesystem;
- scheduled execution; and
- in-process handles.

An incomplete category must provide both a stable UNKNOWN id and a plain
language reason. Omitting a category is an error.

`THROUGH_SEAL`, `DIRECT`, and `UNKNOWN` route declarations map mechanically to
the three classifications. Effect-capable tool names in the referenced seal
policy are added as BROKERED, conditional on the deployment precondition stated
by the inventory. An entry with `mode: deny` and `match.type: always` is
excluded because that configured route cannot cause an effect.

## Signing and verification

The signed artifact uses the same Ed25519 exact-payload convention as the
existing signed config and approval envelopes: the signature covers the exact
UTF-8 bytes in `payload`; it does not depend on JSON canonicalisation. The
verifier calls the production approval-signature verification helper.

The current `main` base has no authorization-decision-level signature producer. Native
authorization decisions are re-derived and audit records are SHA-256 chained.
Therefore v0 reuses the existing signed-envelope cryptographic path, not a
nonexistent authorization-decision signer. The report records this distinction explicitly.

Verification requires an expected public key. The artifact embeds a public key
so it is portable, but an embedded key alone proves integrity, not who owns the
key.

```sh
export PATH=/home/monkey/.cargo/bin:$PATH
cd rust
cargo run --bin seal-reachability-report -- \
  issue --config ../config/reachability-v0.deployment.json \
  --signing-key-file /secure/path/reachability-seed.hex \
  --out /tmp/reachability-report.signed.json

cargo run --bin seal-reachability-report -- \
  verify --report /tmp/reachability-report.signed.json \
  --expected-pubkey <64-hex-public-key>
```

## v0 does not

- prove the inventory equals total agent reachability;
- discover undeclared direct handles;
- inspect live process state, credentials, environment, file descriptors,
  namespaces, container boundaries, or network policy;
- determine how many concrete paths one UNKNOWN sentinel represents;
- equate BROKERED with safe or allowed;
- authenticate a signer without an external expected-public-key trust anchor;
  or
- reuse an authorization-decision-level signer, because the base branch has none.
