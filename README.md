# seal-host

<!-- current-release: v0.1.6 -->

[![CI](https://github.com/velvetmonkey/seal-host/actions/workflows/ci.yml/badge.svg)](https://github.com/velvetmonkey/seal-host/actions/workflows/ci.yml)
[![Golden Path](https://github.com/velvetmonkey/seal-host/actions/workflows/golden-path.yml/badge.svg)](https://github.com/velvetmonkey/seal-host/actions/workflows/golden-path.yml)

**Put one gate between an agent and the effect it wants to cause.**

`seal-host` is Seal's deployed effect-boundary adapter for MCP `tools/call`.
A guarded request without a matching live approval is stopped before the real
MCP server receives it. Approve that exact request once and the identical call
can flow once. Every decision leaves replayable evidence.

Seal enforces authorization at the effect boundary; it does not claim to read
agent intent. The family decision rule is machine-checked, effect-commitment
sufficiency is tested, and sibling verifier surfaces independently re-derive
deployed decisions against pinned kernel bytes.

## Your first gate

```text
blocked → approved once → executed → separately checked → tamper rejected
```

**Published onboarding:** `seal-host` v0.1.6 exists with signed provenance,
checksums, two Linux archives, two SBOMs, and the standalone verifier. Verify
the release before unpacking it, then block, approve, flow, and verify a receipt
yourself with [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md). The source
build remains a separate alternative.

To wire the host into Claude Code, Claude Desktop, Cursor, or VS Code and run
the real destructive SQLite sandbox, start with [CONFIG.md](CONFIG.md).

Follow one route: [Getting started](docs/GETTING-STARTED.md). It puts the host
in front of `/bin/cat`, sends a destructive MCP frame, captures the real
`approval required: <64-hex>` response, signs an ApprovalRecord v2 while the
host session remains live, retries the identical bytes, verifies the resulting
chain, and demonstrates rejection after changing a recorded verdict.

Observed locally on 2026-08-09, the key responses were:

```text
approval required: 2a01d25406f0fc82751a66ddaeb8e79d2104efc4b67699400003704e67c0c565
signed allow for target=2a01d25406f0fc82751a66ddaeb8e79d2104efc4b67699400003704e67c0c565
VERIFY OK: 2 entries, chain intact.
VERIFY FAIL: entry 0 — recorded head does not match recomputed chain.
```

The approved second response was the original JSON-RPC request with only the
host-added `operation_id`; that echo is the positive observation that the
child received it.

**Available now:** `seal-host` v0.1.5 was the project's first published release;
v0.1.6 is the current release. Its eight assets include x86_64 and aarch64 Linux
archives, their SBOMs, checksums, and signed provenance. The
[getting-started guide](docs/GETTING-STARTED.md)
records a real download, checksum, provenance-verification, and extraction run.
The Windows/WSL2 route remains untested, and the 20m55s source-build path is a
separate branch rather than a fallback hidden inside release onboarding.

## Know the boundary

The deployed runtime profile is `compatible`; strict `canonical-l0` is proved
and modelled but is not the deployed route. The host itself is not proved end
to end. Rust, wasm, and JavaScript are connected to the Lean kernel by finite
byte-exact conformance tests. Seal verifies configured authorization evidence;
whether its key holder is the intended person or service is a custody
assumption.

Start with the family [claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md)
for proven/tested/assumed/not-claimed status, then read
[Limitations](docs/LIMITATIONS.md). Effect-commitment sufficiency is **tested,
not proven**; the private/proprietary `witness-check` analyzer is not part of
this repository.

<!-- truthbox:begin -->
> **Runtime profile: `compatible`.** Strict `canonical-l0` is proved and modelled, not the deployed route yet.
> **Claim:** policy-covered request-effects recognised by the compatible MCP boundary reach the downstream child MCP server only after every applicable Lean kernel returns Allow. Effects configured as guarded additionally require a matching live approval record. Seam failures block; every mediated decision emits replayable evidence.
> **Non-claim:** the deployed host is not proved end to end, and canonical parser rejection is not currently the runtime gate. Host `ApprovalRecord` tokens are a separate signed channel from the v2 kernel-defined approval tuple. “Canonical” in Seal names the pinned kernel byte rule, not RFC 8785/JCS. Seal verifies the configured authorization evidence. Whether that evidence represents the intended human, device or service is an identity and key-custody assumption, not a proved property.
<!-- truthbox:end -->

<!-- claims:begin -->
- Seal proves properties of the mediation KERNEL, not of the whole deployed system.
- Seal does NOT prove SHA-256 collision resistance in Lean; it is a named, scoped cryptographic assumption (A-CR).
- The deployed Rust / wasm / JS are NOT proven bug-free; they are tied to the proof by byte-exact conformance testing over a corpus, not for every possible input.
- Seal guarantees AUTHORIZATION match, not INTENT match: if a human approves a malicious-but-valid request, Seal will execute it.
- Seal does NOT prevent compromise of hosts, browsers, build systems, keys, operators, or downstream tools.
- Seal's audit chain is tamper-EVIDENT, not tamper-IMPOSSIBLE.
- Seal does NOT make the AI smarter or prevent hallucinations; it stops an unapproved effect.
- The `{propext, Classical.choice, Quot.sound}` axiom-footprint claim is scoped to theorem names imported and pinned by `Test/Axioms.lean`; it is not repository-wide (see “Proof build-wire residual” in the canonical limitations document).
<!-- claims:end -->

## Next

- [Getting started](docs/GETTING-STARTED.md) — the single developer journey.
- [Configuration](CONFIG.md) — Claude Code, Claude Desktop, Cursor, and VS Code.
- [Deployment](docs/DEPLOY.md) — production preflight, replay storage, approval
  channels, and real child servers.
- [Front-page reference](docs/FRONT-PAGE-REFERENCE.md) — moved proof, fleet,
  alternative-demo, evaluator, family, and non-claim detail.

## License

Apache-2.0. See [LICENSE](LICENSE).
