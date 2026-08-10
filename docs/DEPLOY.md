# Deployment — v0.1.5 host published

Published `seal-host` releases: **1** — `v0.1.5`, with **8** downloadable
assets. Supported production deployment paths remain **0**: publishing and
verifying a host archive does not establish an end-to-end production rollout.
Windows/WSL2 end-to-end runs remain **0**. This page records local development
evidence and the controls a production route still needs.

> **Runtime profile: `compatible`.** This guide stands up the `compatible`-profile host.
> That is the right profile for integration and deployment evaluation. It is **not** the
> stricter `canonical-l0` proof-covered route. This walkthrough makes **operational** claims
> only: you will get a working gated MCP call that emits a replayable authorization decision. It does **not**
> claim end-to-end proof. For the exact claim boundary read the truthbox in
> [`../README.md`](../README.md), [`../PROFILE.md`](../PROFILE.md), and the family
> [claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md).

---

## What you are building

```
  agent / MCP client            seal-host                 your real MCP server
  (e.g. Claude Desktop)   --->  (the guard)      -->      (filesystem, sqlite, db, ...)
                                   |
                                   | guarded tools/call with no live approval => BLOCKED
                                   | every decision => an authorization decision
                                   v
                          approval channel (NDJSON file of SIGNED approval records)
```

seal-host is a transparent MCP proxy. Ordinary traffic passes through unchanged. A
`tools/call` that your policy marks **guarded** is stopped unless a human has put a matching
one-shot approval into the approval channel — a signed `ApprovalRecord` v2 bound to that
exact request.

## 0. Prerequisites for the recorded local path

- Bash on Linux.
- A checkout of this repository, Lean `4.28.0`, Rust `1.96.0`, and a native
  C/C++ linker toolchain. No step in this guide requires `systemd`.
- GitHub CLI authenticated to GitHub for the release download.
- The verified v0.1.5 Linux archive install from
  [Getting started](GETTING-STARTED.md#install-and-verify-the-published-host),
  with its `SEAL_BIN` value still set.
- Python 3 with the `cryptography` package (for the config signer). If it is
  absent, follow the [official installation guide](https://cryptography.io/en/latest/installation/)
  before continuing.
- Node.js (a current LTS) for the audit-chain verifier; use the
  [official download page](https://nodejs.org/en/download).
- A child MCP server to guard. Anything stdio works; a filesystem or sqlite MCP server
  makes the destructive-call demo obvious.

## 1. Install and verify the released host

`v0.1.5` is published. Download every signed subject and verify provenance
before unpacking or running the host:

```sh
mkdir -p .seal/release
chmod 700 .seal .seal/release
cd .seal/release
tag=v0.1.5
gh release download "$tag" --repo velvetmonkey/seal-host \
  --pattern "seal-host-${tag}-linux-*" \
  --pattern release_provenance.py \
  --pattern SHA256SUMS \
  --pattern SEAL-RELEASE-PROVENANCE.json \
  --pattern SEAL-RELEASE-PROVENANCE.sigstore.json
python3 release_provenance.py verify \
  --release-dir . --release-version "$tag" \
  --statement SEAL-RELEASE-PROVENANCE.json \
  --bundle SEAL-RELEASE-PROVENANCE.sigstore.json \
  --certificate-identity "https://github.com/velvetmonkey/seal-host/.github/workflows/release.yml@refs/tags/${tag}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
tar xzf "seal-host-${tag}-linux-x86_64.tar.gz"
export SEAL_BIN="$PWD/seal-host-${tag}-linux-x86_64/bin/seal-host-rs"
cd ../..
```

Expected verification output: `PASS release provenance: valid signature and 6
exact subject digests`. Do not unpack or run an artifact if verification fails.
To build from source instead, use `time bash scripts/build_all.sh` with the
documented Lean/Rust prerequisites, then set `SEAL_BIN="$PWD/rust/target/debug/seal-host-rs"`.

Release v0.1.5 published x86_64 and aarch64 Linux archives, both SBOMs,
`SHA256SUMS`, `release_provenance.py`, and the provenance statement and bundle.
The release evidence pass downloaded all eight assets, checked the manifest,
verified the Sigstore-backed six-subject statement, opened both archives, and
extracted the x86_64 host. It did not run this page's entire deployment
walkthrough from the release archive.

## 2. Generate separate signing keypairs

seal-host only loads a config that carries a valid Ed25519 signature, and its
approval channel uses a separate trust root. Mint both keypairs once:

```sh
umask 077
python3 scripts/generate_keys.py --out-dir .seal
mkdir -m 700 .seal/store .seal/receipts
: > .seal/approval-tokens.ndjson
```

Observed in a fresh checkout with the published v0.1.5 host:

```text
.seal/approval.key
.seal/config.key
.seal/config.pub
.seal/approval.pub
```

The generator validates both Ed25519 pairs before publishing any file and
refuses to overwrite an existing key. `.seal/config.key` signs your config;
`.seal/config.pub` is the host's `--pubkey`. The separate approval-channel pair
is `.seal/approval.key` and `.seal/approval.pub`. Keep both private files secret
and never commit them.

## 3. Write your policy (`payload.json`)

The policy names the tools you guard and what each approval binds to. Start from the
annotated example in [`../config/payload.example.json`](../config/payload.example.json).
Full field semantics (`mode`, `match`, `target`, the approval block) live in the schema
reference: [`mcp-seal-dev/docs/POLICY.md`](https://github.com/velvetmonkey/mcp-seal-dev/blob/main/docs/POLICY.md).

For the repository's disposable SQLite MCP server, paste this block exactly;
the shell expands the current checkout path into the signed policy:

```sh
cat > payload.json <<EOF
{
  "epoch": 1,
  "safety": {
    "approval": {
      "control_file": "$PWD/.seal/approval-tokens.ndjson",
      "ttl_seconds": 120,
      "replay_store": {
        "sqlite_path": "$PWD/.seal/store/replay.sqlite",
        "schema_version": 2,
        "namespace_encoding_version": 1
      }
    },
    "tools": [
      {
        "name": "execute_sql",
        "mode": "guarded",
        "match": { "type": "contains_any_ci", "arg": "sql", "needles": ["drop", "delete", "truncate"] },
        "target": [ {"full_arguments": true} ]
      }
    ]
  }
}
EOF
```

`sqlite_path` must be in a durable, service-owned directory with mode `0700`;
the durable store is what makes replay survive a host restart.

For production mode, put the config, approval-token file, authorization-decision directory,
and replay database in a service-owned directory with mode `0700`; files must
be mode `0600`. Do not place the replay database directly in `/tmp`.

The replay database's parent directory mode is **enforced, not advised**: on every
`--channel ed25519` launch the host refuses to start unless that directory is a
non-symlink, host-owned, mode-`0700` directory (`rust/src/replay_store.rs`
`SqliteReplayStore::open`). A writable parent would let any principal holding that
write bit `rename()` a different — but equally host-owned and mode-`0600` — store
into the signed path, handing back nonces the live store had already consumed.
The guard bounds who can do that to `{host euid, root}`; it does not detect a
substitution by those two (residual A7 in [`../CLAIMS.md`](../CLAIMS.md)).

A **guarded** rule may carry only `target: [{"full_arguments": true}]`. A narrower
target — literal parts, `arg` paths, or the empty list — binds the approval to less
than the full canonical arguments and is a hard config parse error
(`Seal/Policy.lean:114-138`); the host exits 3 with `guard mode requires target
[{"full_arguments": true}]`.

Key facts (from the schema reference, not invented here):
- A tool **not listed** is blocked — the policy is a fail-closed allowlist for `tools/call`.
- `mode: "guarded"` needs a live approval; `mode: "deny"` is always blocked.
- The tool name is **prepended automatically** before hashing, so an approval never
  transfers between tools.
- `ttl_seconds` is **clamped to 300**; longer values are silently shortened, never lengthened.

## 4. Sign it into `trusted.json`

```sh
SEAL_CONFIG_SIGNING_KEY_HEX="$(tr -d '\r\n' < .seal/config.key)" \
  python3 test/tools/sign_config.py payload.json > trusted.json
```

This command exited 0 and produced no terminal output; `trusted.json` was
created and used by the host commands below.

The signer serializes the parsed payload with Python `json.dumps(...,
separators=(",", ":"))`, preserving parsed insertion order, and wraps those
exact compact bytes as `{"payload": "...", "signature": "<ed25519 hex>"}`.
This is the trusted-config byte contract, not RFC 8785/JCS; see
[`CANONICAL-BYTE-CONTRACT.md`](CANONICAL-BYTE-CONTRACT.md). The host rejects any config whose
signature does not verify against `--pubkey`.

The checked-in [`trusted.example.json`](../config/trusted.example.json) is a real
signed envelope. Its out-of-band example trust root is
[`trusted.example.pub`](../config/trusted.example.pub), and
`scripts/policy_schema_gate.sh` verifies the signature over the exact payload
bytes. The example public key is only a verification specimen: generate your
own keypair for deployment; no matching private key is shipped.

## 5. Initialize the replay store

The signed approval channel requires a durable store so one-shot approvals
remain spent across restarts. Now that `trusted.json` exists, deliberately
initialize a genuinely absent store from that authority-signed config:

```sh
"$SEAL_BIN" --insecure-development-mode \
  --config trusted.json \
  --pubkey "$(cat .seal/config.pub)" \
  --channel ed25519 \
  --token-file .seal/approval-tokens.ndjson \
  --approval-pubkey "$(cat .seal/approval.pub)" \
  --initialize-replay-store
```

Observed output:

```text
WARNING: INSECURE DEVELOPMENT MODE ENABLED; production preflight is disabled
replay store initialized: /home/monkey/scratch/releaseistrue-deploy.GhCnOU/worktree/.seal/store/replay.sqlite (schema_version=2, namespace_encoding_version=1)
```

This action creates both the nonce schema and its lineage stamp, then exits.
It refuses if the path already exists. Ordinary host startup never creates,
adopts, or stamps a store, so deleting the SQLite file and redeploying does
not silently create an empty replay history.

## 6. Run the host in front of your server

```sh
"$SEAL_BIN" \
  --insecure-development-mode \
  --config trusted.json \
  --pubkey "$(cat .seal/config.pub)" \
  --channel ed25519 \
  --token-file .seal/approval-tokens.ndjson \
  --approval-pubkey "$(cat .seal/approval.pub)" \
  -- python3 demo/sqlite_mcp_server.py --database .seal/sandbox.sqlite
```

### Executed v0.1.5 SQLite and approval evidence

The step 6 command was launched inside a Bash coprocess in a fresh checkout so
the same host session could receive multiple MCP frames. The published x86_64
binary returned this `initialize` response:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"seal-sqlite-sandbox","version":"1.0.0"}}}
```

The real SQLite child then returned its tool catalog:

```json
{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"execute_sql","description":"Execute arbitrary SQL against a disposable SQLite sandbox.","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}},"required":["sql"],"additionalProperties":false}},{"name":"search_objects","description":"List SQLite objects whose names contain query.","inputSchema":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}}]}}
```

For the exact request `drop table if exists receipt_sandbox`, the first
response was:

```json
{"id":3,"jsonrpc":"2.0","result":{"content":[{"text":"approval required: 63e7b1bb1aba1db39fe3fb30836aa6c14a37ac23034198e0bb3d83883f62e740","type":"text"}],"isError":true,"framed_subject":{"encoding":"base64","length":138,"sha256":"2b572e7e4c0976baf1b7d4f596dec6ebd725208c77956e2f58666eebdd39b03f","base64":"eyJqc29ucnBjIjoiMi4wIiwiaWQiOjMsIm1ldGhvZCI6InRvb2xzL2NhbGwiLCJwYXJhbXMiOnsibmFtZSI6ImV4ZWN1dGVfc3FsIiwiYXJndW1lbnRzIjp7InNxbCI6ImRyb3AgdGFibGUgaWYgZXhpc3RzIHJlY2VpcHRfc2FuZGJveCJ9fX0K"}}}
```

After the step 9 signer command and an identical retry in that same host
session, SQLite returned:

```json
{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"{\"rows\": [], \"rowcount\": -1}"}],"isError":false}}
```

This closes the published-bundle SQLite-server and direct CLI approval paths.
It is not evidence for Claude Code, Claude Desktop, Windows/WSL2, or production
deployment.

- `--config` / `--pubkey`: the signed policy and the key that verifies it.
- `--channel ed25519`: approvals arrive as NDJSON lines carrying a **signed `ApprovalRecord`
  v2**. This is the only channel that can grant an approval from a file. There is **no keyless
  file channel any more**: `--channel file` still starts, but every approval written to it is
  refused (see "Control-file channel" below).
- `--token-file`: that file (match `control_file` in your policy).
- `--approval-pubkey`: the approval trust root — `.seal/approval.pub` from step 2. Distinct
  from `--pubkey`, which verifies the config.
- everything after `--`: the child MCP server. seal-host spawns it and proxies to it.

`--channel ed25519` requires the `replay_store` block and an initialized store; without them
the host exits 3 before spawning the child.

The walkthrough above explicitly opts into insecure development mode, which
prints an uppercase warning on startup. Production preflight is the default; a
production launch omits `--insecure-development-mode`, switches to `--channel
ed25519`, supplies separate config and approval public keys, names a durable
replay database in the signed policy, and supplies an explicit `--receipt-dir`.
The legacy `--production` spelling remains accepted as a redundant declaration.
Startup refuses if any one of those conditions or the ownership/mode checks is
missing. Resource limits are always active in both modes.

## 7. Point your agent at the host

**Client wiring boundary:** Claude Code 2.1.226 accepted the fresh project MCP
entry and invoked the released host. Claude Desktop was unavailable on the
Linux evidence host, so its configuration remains unverified.

Wherever your MCP client is configured to launch the server directly, launch **seal-host**
instead and pass the original server command after `--`. Pattern (confirm against your
specific client during setup):

```jsonc
{
  "mcpServers": {
    "guarded-db": {
      "command": "/abs/path/to/seal-host-rs",
      "args": ["--insecure-development-mode",
               "--config", "/abs/path/to/trusted.json", "--pubkey", "<hex>",
               "--channel", "ed25519", "--token-file", "/abs/path/to/.seal/approval-tokens.ndjson",
               "--approval-pubkey", "<approval-hex>",
               "--", "<your-mcp-server-cmd>", "<args...>"]
    }
  }
}
```

## 8. Watch it block

**Agent-client boundary:** Claude Code issued the exact destructive call and
displayed `approval required:
d9a6565b5652c8ff0b68546c2d89a283f3e5fa09a04fab9ef033dc5fdc552f41`.
It did not expose the raw refusal JSON required by the signer. The complete
structured refusal below came from the executed direct MCP harness.

Have the agent call the guarded `execute_sql` tool with SQL containing `drop`. The
call is blocked before the child server sees it, and the block message prints the exact
**approval challenge** (a 64-hex SHA-256). Copy that hex.

Where you see it: the block goes back to the **caller** as the JSON-RPC error on the MCP
wire (your agent client will surface it, `approval required: <64-hex>`), and the decision's
audit line lands on the **host's stderr**. The hex appears in both — whichever surface is
in front of you works.

The refusal on the wire also carries `result.framed_subject`, the exact request frame the
approval must be bound to (`{encoding, length, sha256, base64}`,
`rust/src/main.rs:269-301`). **Save that whole refusal JSON to a file** — it is the input to
the approver, and the target hex alone is not enough. Save or export the raw
client response as `.seal/blocked-response.json` before continuing. If your
client does not expose raw JSON, use the exact `coproc` capture in
[Getting started](GETTING-STARTED.md#recorded-evidence-approve-that-exact-call-and-watch-it-flow)
instead; do not reconstruct the refusal from the target alone.

## 9. Approve, one shot

An approval is a **signed `ApprovalRecord` v2** bound to the target *and* to the exact
request frame. The approver reads the refusal you just saved and appends one signed line to
the token file:

```sh
python3 demo/approve_cli.py \
  --token-file .seal/approval-tokens.ndjson \
  --refusal-file .seal/blocked-response.json \
  --key-file .seal/approval.key \
  --approve --yes
```

Observed output for the refusal above:

```text
Seal approval request
target: 63e7b1bb1aba1db39fe3fb30836aa6c14a37ac23034198e0bb3d83883f62e740
exact MCP request frame (including delimiter):
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_sql","arguments":{"sql":"drop table if exists receipt_sandbox"}}}
signed allow for target=63e7b1bb1aba1db39fe3fb30836aa6c14a37ac23034198e0bb3d83883f62e740
  nonce=b7a5f0229c8b4dab9a2a177e7b574156 authorizedAt=1786327294970
  appended to .seal/approval-tokens.ndjson
  using pubkey=51e2063618d0f54ec2222e5aeea9ab3c2fd42be2b1dbad729cfc598a2e13042b
```

Two properties of the block make the timing non-negotiable, so **approve while the blocked
session is still running**:

- The target challenge is scoped to the **live host session** that issued it. A record
  signed after that session exits is dropped with `target_or_subject_mismatch`
  (`filter_approval_context`, `rust/src/providers.rs:494-522`, applied at
  `rust/src/main.rs:1825-1830`).
- The record commits to the frame's bytes, so an approval minted for one call does not
  admit a different one — a changed argument is a different frame and stays blocked.

The approval is **one-shot** (consumed by the first matching call) and expires after the
policy's ttl. Malformed lines are skipped fail-closed.

> **Changed: the unsigned one-liner is gone.** Earlier versions of this page told you to
> approve with `echo '{"target": "<hex>", "issuedAt": ...}' >> /tmp/seal-approvals.ndjson`.
> The host no longer admits that record in any channel. If you follow the old procedure you
> get `approval_record_v1_not_supported` on stderr, the response stays
> `approval required: …` with `isError: true`, and **the child process receives nothing** —
> a silent drop, not an error at the point of use. Approvals now require the v2 record above.

## 10. Re-run and read the audit record

The identical retry itself was executed in the direct harness and its SQLite
response is quoted under step 6. The client UI, log-redirection example, and
log-sealing commands in this section were **not run** in this execution pass.

Re-issue the same call. It now passes to the child server. What the child receives is your
request frame with one host-added field, `operation_id`, appended as the correlator; the
approval is bound to the bytes **you** sent, not to the forwarded form. The host records the
decision on **its stderr** — two lines per decision: the raw audit line, then a
tamper-evident chain record as a single JSON line
(`{"seal_record":"v1","entry":N,"session":"...","prev_head":"...","head":"..."}`).
The first record of a process also names the prior process session, and its
`prev_head` is the safely persisted prior head. To keep the stream, redirect
stderr when you start the host (e.g. append `2>>/tmp/seal-audit.log` to the command in
step 6).

That chain record is an append-only audit chain: each `head` is
`sha256(prevHead || 0x1f || payload)`, so it commits to every prior decision. You can
check the log two ways, and they prove different things:

- **The log is intact.** Seal the chain records out of the stderr stream, then verify the
  sealed file — the executable witness of the `tamper_evident` theorem (`Host/Record.lean`):
  ```sh
  grep '"certs":\[' /tmp/seal-audit.log > /tmp/audit-lines.ndjson
  scripts/seal_log.mjs seal /tmp/audit-lines.ndjson /tmp/sealed.json
  scripts/seal_log.mjs verify /tmp/sealed.json
  ```
  The `certs` lines are the decision payloads independently sealed by this
  command. The separate `seal_record` lines in host stderr are the host's
  already-linked deployed chain; comparing their final head with the
  independently sealed head checks that the two constructions agree.
  `verify` takes the **sealed** file, not the raw audit lines; handed the raw lines it exits
  1. It rebuilds the SHA-256 head chain from the
  audit lines and exits non-zero if any line was inserted, reordered, or mutated. The head
  is an injective function of the whole log, so tampering is always detected. This is the
  deployed host's own audit trail; nothing external is needed to check its integrity.
- **A single decision is correct.** That is the schema-v2 *authorization decision*, where you
  re-derive the verdict from the request bytes and check it with `seal-check` / `seal verify`.
  The compatible-profile host writes this authorization decision in `--receipt-dir` **and** emits the
  distinct audit/chain pair on stderr. Do not present either artifact as the other.

That is the full loop: a guarded call blocked, a human approval, the identical call allowed
once, and every decision written to a tamper-evident audit chain you can verify yourself.

## Developer ingress: two approval channels (CLI + Telegram)

For rapid local iteration you can stand up the approval loop in minutes over a synthetic
ledger (no real MCP server, no external accounts).

**Known broken on this revision.** The command below exits 1 with a
`BrokenPipeError`: its driver signs the config's `replay_store` block but never
runs `--initialize-replay-store`, so the spawned host exits 3 with `cannot open
replay store` before the loop starts. It is retained as defect reproduction,
not as an onboarding command:

```sh
python3 demo/see_the_loop.py
```

It is meant to print:
- `approval required: <64-hex target>`
- CLI approver signs a **request-bound** `ApprovalRecord` v2 (target + exact frame digest)
- signed NDJSON appended to the token file
- provider accepts (sig verified)
- action flows (observable `SYNTHETIC_LEDGER_ACTION`) **or** explicit `refused` (for deny)
- audit / authorization-decision lines

Until that is fixed, use the step 6–10 walkthrough above, which does initialize
the store. The defect is in `test/integration/approval_loop.py`, not the host.

The CLI and Telegram approvers live in `demo/`. They are **not** the signing key; they are
intent delivery. The key does the signature.

### The two channels and their trust boundaries

**ed25519-token (recommended for anything beyond throwaway)**

- Wire (approvals): NDJSON `{"payload":"<canonical ApprovalRecord v2 JSON>",
  "signature_algorithm":"Ed25519","signature_encoding":"base64url-nopad",
  "signer_key_id":"<sha256 of the approval pubkey>","signature":"<base64url-nopad>"}`.
  The payload names `approval_record_version: 2`, the target, the `subject_sha256`/
  `subject_length` of the exact request frame, and the renderer that displayed it; the
  signature covers `"seal.approval-record/v2" ‖ 0x00 ‖ canonical-payload`
  (`rust/src/providers.rs:760-811`).
- Wire (declines only): the older `{"payload":"<target+issuedAt+nonce+decision>",
  "signature":"<hex>"}` shape is still read, but **only** for `decision: "deny"`. The same
  shape meaning *allow* is refused as `approval_record_v1_not_supported`
  (`rust/src/providers.rs:1055-1087`).
- The approver (CLI/TG) only collects intent; the bridge/CLI holds the key and emits the
  signed token.
- **Trusted set (CLI):** seal-host process + CLI process + the local key file on the same machine.
  A co-resident attacker who can read the key, ptrace the signer, or tamper the token file
  before the next poll can forge approvals for any target.
- **Trusted set (Telegram demo bridge):** seal-host + bridge process + its signing key + your
  allowlisted from.id list + Telegram's delivery for those users. The callback is HMAC-bound
  to `(target, nonce, decision)` so a tampered button press is rejected. The bridge still
  holds the key (demo-grade). **Approvals from this bridge no longer land:**
  `demo/approve_telegram.py:136` still emits the legacy signed shape, which the host refuses
  as `approval_record_v1_not_supported`. Its **declines** still work. Use the CLI approver
  until the bridge is moved to v2.
- **Production tightening for Telegram:** device-held key via deep-link / mini-app / custom
  client. The user's device signs; the bridge only relays the already-signed token. The
  origin trust boundary shrinks to the audited device client.

**Control-file channel (`--channel file`): REMOVED as an approval channel**

- **This channel no longer accepts unauthenticated records.** It was the keyless path that let
  the first ~30 seconds of a local smoke test run without key material:
  `echo '{"target":"<hex>"}' >> /tmp/seal-approvals.ndjson`, a plain NDJSON record with no
  signature and no origin. That capability is gone.
- **What happens if you write one now.** `--channel file` still starts and still consumes the
  file, but its parser reads *only* the legacy record shape and routes every one to a refusal
  (`ControlFileProvider::poll`, `rust/src/providers.rs:652-667`, via `refuse_v1_approval`,
  `:452-465`). You get `{"approval_drop":{"source":"control-file","reason":
  "approval_record_v1_not_supported"}}` on stderr; the call stays blocked and the child
  process receives nothing. **There is no record you can write to this file that will approve
  a call** — the provider has no v2 acceptance path at all, so signing the line does not help
  either. The same refusal governs the CLI approver's `--plain` mode, which now refuses to
  emit an allow.
- **What it still does:** unauthenticated **declines**. A `{"target":"<hex>",
  "decision":"deny"}` line is still read and still refuses the call
  (`rust/src/providers.rs:623-636`). Failing closed on nothing but a file write is safe in the
  direction that blocks; it was never safe in the direction that admits.
- **Approvals now require the ed25519-token channel.** Every approval must carry a valid
  Ed25519 `ApprovalRecord` v2 signature from the key behind `--approval-pubkey`, over
  `"seal.approval-record/v2" ‖ 0x00 ‖ canonical-payload`, and the payload must name the exact
  request frame. An unsigned, tampered, or legacy-shaped line is dropped with a warning on
  stderr (`approval_record_v1_not_supported`, `bad_signature`) and the call stays blocked:
  ```sh
  seal-host-rs --config trusted.json --pubkey <config-hex> \
    --channel ed25519 --token-file /path/tokens.ndjson --approval-pubkey <approval-pub-hex> \
    -- <your-mcp-server-cmd> <args...>
  ```
- **The one remaining keyless path is `--channel interactive`**, and it is not a file. The host
  opens its own controlling `/dev/tty` (`rust/src/main.rs:1242-1248`), prompts
  `approve target <hex>? [y/N]` on stderr, and a `y` typed at that terminal admits the call
  (`rust/src/providers.rs:1150-1162`). The authority is possession of the host's terminal, not
  a signature: it is a local-only convenience with the same "not a production channel" caveat
  the control file used to carry, and it binds to the target, not to the request frame.

### ORDERING vs ORIGIN (what is Lean-proven)

- **ORDERING / consumption / one-shot / TTL / A3 freshness / non-interference** — these are
  Lean-proven in the kernels (`SealCore`, `Host.*`). A matching live approval for the exact
  target is required; it is consumed exactly once within the TTL; the audit is deterministic.
- **ORIGIN (who was allowed to mint the token)** — this is channel key custody, **not**
  proven by Lean. The demo proves the wire format and the host accept/decline short-circuit
  paths work with real signatures. It does **not** prove that the key never left a particular
  device, that Telegram delivery is uncompromised, or that the human intended the bytes.

### What this demo proves / does NOT prove

**Proves (with the shipped code):**
- The Rust providers accept and verify request-bound ed25519 signed `ApprovalRecord` v2 allows
  and explicit signed declines (decision:"deny").
- Explicit decline produces "refused" in audit (not a timeout or generic deny).
- The CLI approver emits exactly the envelope the provider verifies.
- The step 5–9 walkthrough drives block → signed v2 record → flow → authorization decision.
  (The one-command `see_the_loop.py` path does not currently run; see the note above.)

**Does NOT prove:**
- End-to-end correctness of a production deployment.
- That the key was held only on a user device (demo bridge holds it).
- Absence of all bugs in the Rust host or the approver scripts.
- That "approval" equals "the human understood and wanted the real-world effect".
- Tamper-proofing (only tamper-evidence via the chain).

No unqualified "verified", "proven", or "trustless" is used for the channel origin.

See also `demo/approve_cli.py`, `demo/approve_telegram.py`, `demo/see_the_loop.py` (and the
Rust provider tests) for the honest labels and trust-boundary statements.

## Release container profile

Published native archives: **2**. Published SBOMs: **2**. Published provenance
statements: **1**, with **1** Sigstore bundle, **1** checksum manifest, and **1**
standalone verifier. The two archives contain the host, runtime closure, licences,
and `libsealffi.so`; both archives were opened, while only x86_64 was extracted on
the evidence host. The release uses a Seal-specific Sigstore provenance statement,
not GitHub build-provenance attestations. `scripts/runtime_dependency_gate.sh`
checks build-workspace paths, missing libraries, and private-repository runtime
dependencies in the publication path.

`deploy/container/Dockerfile.release` expects a local unpacked archive and runs as UID/GID
65532 with no root fallback. `deploy/container/compose.yaml` is the hardened example:
read-only root filesystem, no capabilities, no network, and production-mode startup.
Before starting it, create `deploy/container/{secrets,state/receipts,state/replay}`, make
each directory mode `0700`, make configuration and approval files mode `0600`, and assign
them to UID/GID 65532. The host intentionally refuses the example if those ownership or
mode requirements are not satisfied.

The source-publication path is `scripts/export_public.sh EMPTY_DIRECTORY`,
where `EMPTY_DIRECTORY` means a caller-supplied path to a new empty output
directory. It
assembles a Git revision, scrubs identity and leak patterns, runs source-only
tests, rebuilds and tests the exported tree, asserts the verifier pin, generates
a CycloneDX SBOM, and signs every output with Sigstore. CI invokes the exporter
in two separate runs and byte-compares their source archives, SBOMs, and
relative-path checksum manifests. Drift or any missing prerequisite fails the
workflow.

---

<details>
<summary><strong>For evaluators: what this deployment does and does not prove</strong></summary>

This guide stands up the **`compatible`** profile. What that means precisely:

- **Enforced at runtime:** a policy-covered `tools/call` forwards only after every
  applicable kernel returns Allow; a call configured as guarded additionally requires a
  matching live approval record (an explicit-policy Allow consumes none and is labelled
  `authorization: "explicit_policy_allow"`); seam failures block; every decision emits
  replayable evidence.
- **NOT the deployed runtime gate:** strict `canonical-l0` canonical-parser rejection is
  proved and modelled but is not the route this host runs. The host is not proved
  end-to-end; the Rust is tied to the kernel by byte-exact conformance testing over a
  corpus, not by a theorem over every input.
- Host `ApprovalRecord` tokens are a separate signed channel from the v2 kernel-defined
  approval tuple.

Do not read "it worked in 5 minutes" as "end-to-end verified." For the authoritative
boundary: [`../README.md`](../README.md) truthbox, [`../PROFILE.md`](../PROFILE.md),
[claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md),
[what Seal is NOT](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/WHAT-SEAL-IS-NOT.md).

</details>
