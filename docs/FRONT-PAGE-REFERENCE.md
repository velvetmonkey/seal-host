<!-- current-release: v0.1.6 -->
# Front-page reference

This page holds the proof, evaluator, alternative-demo, and repository-map
detail moved out of the developer front page. The only onboarding route is
[Getting started](GETTING-STARTED.md).

## Alternative demonstrations and their measured status

The receipt/tamper replay is the only demonstration observed passing in this
already-built checkout. It is not a clean-machine start. It needs Bash, Python
3 with `cryptography`, Node, and an existing local host binary; if that binary is
absent or stale, the script also needs the repository's pinned Rust toolchain
and Cargo to build it. From the repository root:

```bash
bash scripts/receipt_demo.sh
```

That command was run on 2026-08-09 and exited 0. It blocked all three
destructive requests, independently reconstructed the deployed chain head,
printed `VERIFY OK: 3 entries, chain intact.`, rejected a mutated middle
entry, rejected reordered entries, and ended with `RECEIPT DEMO PASSED`.

The older one-command showcase and fail-closed dogfood paths are retained as
known defects, not starts. On 2026-08-09 both exited 1 with `BrokenPipeError`
after their helper launched a host that could not open its uninitialized replay
store. `docs/DEPLOY.md` records the same `demo/see_the_loop.py` defect. The CLI
and Telegram demos share that helper state and require a built debug host plus
its Lean shared-library closure.

### Telegram prerequisites

The Telegram demo additionally needs a Telegram account, network access, a bot
token created with `@BotFather`, and the numeric Telegram user ID that will be
allowed to approve. Before running it: create the bot in `@BotFather`, copy the
token, send the new bot `/start`, and obtain your numeric ID (the demo suggests
`@userinfobot`). Only then does the relocated command have defined values:

```bash
TELEGRAM_BOT_TOKEN=<BotFather token> SEAL_TG_ALLOWED=<numeric user ID> python3 demo/dogfood_telegram.py
```

This command was not run with credentials in the 2026-08-09 documentation pass.
Running it without either value was observed to exit 2 and print those three
setup steps. More importantly, approvals remain broken on this revision:
`demo/approve_telegram.py` calls the legacy `sign_approval_token`, while the
host refuses legacy allows as `approval_record_v1_not_supported`. Signed
declines remain fail-closed. See [Deployment](DEPLOY.md) for the code evidence.

## What the host does

The Rust host proxies ordinary MCP traffic. For a guarded `tools/call`, it
collects fresh approval records, rejects replay, and asks the Lean kernel for a
decision through the FFI surface. A matching approval forwards the original
call; otherwise it returns a refusal before the downstream tool receives the
request. It writes both schema-v2 authorization decisions and a SHA-256-linked
audit stream. Per-kernel `certHash` values are legacy UInt64 audit seals, not
the target commitment or record-chain commitment.

## Proof and deployment boundary

The deployed host uses the `compatible` profile. Strict `canonical-l0` is
proved and modelled but is not the deployed route. Lean covers the mediation
kernel and selected model properties; the Rust host, wasm, and JavaScript are
connected by finite byte-exact conformance tests, not an end-to-end theorem.
Host `ApprovalRecord` tokens are a separate signed channel from the v2
kernel-defined tuple.

The machine-checked model also includes non-interference results: approval
states agreeing on the authorized bit produce identical decisions and audit
records, with the durable replay-routing namespace explicitly declassified.
Timing and size side channels are out of scope. The record-chain theorem takes
an injective hash step; SHA-256 collision resistance and genesis freshness are
explicit assumptions.

For exact theorem names and scopes, use [Proof reference](PROOF-REFERENCE.md),
[Conformance](CONFORMANCE.md), [Trusted computing base](TCB.md), and
[Limitations](LIMITATIONS.md). The source verification sequence previously on
the front page lives with its prerequisites in [Conformance](CONFORMANCE.md);
it is not a first-run path.

## Distributed boundary

The repository carries the TTL-scoped application of the coordination-free
no-double-spend lower bound to the gate's consume seam. It proves which modelled
fleet deployment shapes preserve single-use authorization. Published releases:
**2**. Release v0.1.5 was first; v0.1.6 is current and ships the Linux host gate. Coordinated mesh deployment is a separate architecture. See
[Proof reference](PROOF-REFERENCE.md) and the family
[authorization mesh](https://github.com/velvetmonkey/seal/blob/main/docs/AUTHORIZATION-MESH.md).

## Mandatory non-claims

The canonical list remains [Limitations](LIMITATIONS.md). In short: Seal proves
kernel properties, not the whole deployed system; assumes SHA-256 collision
resistance; does not prove Rust/wasm/JavaScript bug-free; guarantees
authorization match rather than intent match; does not prevent compromised
hosts, browsers, builds, keys, operators, or downstream tools; provides
tamper-evidence rather than tamper-impossibility; and does not make an AI
smarter. The axiom-footprint ceiling is scoped to the theorem names imported
and pinned by `Test/Axioms.lean`, not the repository as a whole.

## Documentation and family map

- [Deployment](DEPLOY.md): production posture, client configuration, approval
  channels, replay storage, receipts, and known demo defects.
- [Operations](OPERATIONS.md): health, retention, rotation, secrets, and
  recovery.
- [Architecture](ARCHITECTURE.md), [threat model](THREAT-MODEL.md),
  [assumptions](ASSUMPTIONS.md), [glossary](GLOSSARY.md), and
  [security policy](../SECURITY.md).
- [Family claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md)
  and [what Seal is not](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/WHAT-SEAL-IS-NOT.md).

<!-- FLEET-CLAIM:BEGIN -->
The public family consists of the `seal` umbrella, `mcp-seal-dev` rulebook,
this deployed host, `seal-check`, `seal-live-demo`, `seal-assurance-kit`, and
`seal-verify-action`. `witness-check`, the sufficiency analyzer, is the named
private/proprietary exception.
<!-- FLEET-CLAIM:END -->

The before-and-after claim and caveat inventory is the
[README content map](README-CONTENT-MAP.md).
