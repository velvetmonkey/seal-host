# Deploy: seal-host in front of your own agent

The shortest path from a clean checkout to watching seal-host **block** an unapproved
tool call, then let it through once you approve it, and hand you an authorization decision.

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
                          approval channel (NDJSON file a human writes to)
```

seal-host is a transparent MCP proxy. Ordinary traffic passes through unchanged. A
`tools/call` that your policy marks **guarded** is stopped unless a human has written a
matching one-shot approval into the approval channel.

## 0. Prerequisites

- The Lean toolchain (`lean-toolchain` pins the version; install via [`elan`](https://github.com/leanprover/elan)) and Rust (stable) for building.
- Python 3 with the `cryptography` package (for the config signer).
- A child MCP server to guard. Anything stdio works; a filesystem or sqlite MCP server
  makes the destructive-call demo obvious.

## 1. Build the host

One-shot, from the repo root:

```sh
scripts/build_all.sh          # runs all four steps below in order
```

The first `lake build` is the long pole of this whole guide — the Lean core compiles from
source. Good use of that time: read the family's proved-vs-deployed map,
[EVALUATOR-START.md](https://github.com/velvetmonkey/seal/blob/main/EVALUATOR-START.md) —
by the time the build finishes you will know exactly what this host does and does not claim.

Or run the steps by hand:

```sh
lake build                    # Lean core + FFI
lake exe axiom_check          # confirm pinned footprints in the Test/Axioms import closure
scripts/build_ffi_so.sh       # build the FFI shared object the Rust host loads
cd rust && cargo build && cd ..
# binary: rust/target/debug/seal-host-rs
```

## 2. Generate separate signing keypairs

seal-host only loads a config that carries a valid Ed25519 signature, and its
approval channel uses a separate trust root. Mint both keypairs once:

```sh
umask 077
python3 scripts/generate_keys.py --out-dir .seal
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

Minimal shape:

```json
{
  "epoch": 1,
  "safety": {
    "approval": {
      "control_file": "/tmp/seal-approvals.ndjson",
      "ttl_seconds": 120,
      "replay_store": {
        "sqlite_path": "/var/lib/seal-host/replay.sqlite",
        "schema_version": 1,
        "namespace_encoding_version": 1
      }
    },
    "tools": [
      {
        "name": "db.execute",
        "mode": "guarded",
        "match": { "type": "contains_any_ci", "arg": "sql", "needles": ["drop", "delete", "truncate"] },
        "target": [ {"literal": "db"}, {"arg": "database"}, {"literal": "write"}, {"arg": "sql"} ]
      }
    ]
  }
}
```

`sqlite_path` must be in a durable, service-owned directory with mode `0700`;
the durable store is what makes replay survive a host restart.

Before the first ordinary start, deliberately initialize a genuinely absent
store from the authority-signed config:

```sh
rust/target/debug/seal-host-rs \
  --config trusted.json \
  --pubkey <config-pubkey-hex> \
  --initialize-replay-store
```

This action creates both the nonce schema and its lineage stamp, then exits.
It refuses if the path already exists. Ordinary host startup never creates,
adopts, or stamps a store, so deleting the SQLite file and redeploying does
not silently create an empty replay history.

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

## 5. Run the host in front of your server

```sh
rust/target/debug/seal-host-rs \
  --insecure-development-mode \
  --config trusted.json \
  --pubkey <config-pubkey-hex> \
  --channel file \
  --token-file /tmp/seal-approvals.ndjson \
  -- <your-mcp-server-cmd> <args...>
```

- `--config` / `--pubkey`: the signed policy and the key that verifies it.
- `--channel file`: approvals arrive as NDJSON lines in a file a human writes. **This is the
  unauthenticated DEV-ONLY channel** used here to keep the walkthrough keyless — anyone who can
  write the file can approve any call. For anything past a local smoke test, switch to
  `--channel ed25519` (see "Control-file channel" below for the exact swap and why).
- `--token-file`: that file (match `control_file` in your policy).
- everything after `--`: the child MCP server. seal-host spawns it and proxies to it.

The walkthrough above explicitly opts into insecure development mode, which
prints an uppercase warning on startup. Production preflight is the default; a
production launch omits `--insecure-development-mode`, switches to `--channel
ed25519`, supplies separate config and approval public keys, names a durable
replay database in the signed policy, and supplies an explicit `--receipt-dir`.
The legacy `--production` spelling remains accepted as a redundant declaration.
Startup refuses if any one of those conditions or the ownership/mode checks is
missing. Resource limits are always active in both modes.

## 6. Point your agent at the host

Wherever your MCP client is configured to launch the server directly, launch **seal-host**
instead and pass the original server command after `--`. Pattern (confirm against your
specific client during setup):

```jsonc
{
  "mcpServers": {
    "guarded-db": {
      "command": "/abs/path/to/seal-host-rs",
      "args": ["--config", "/abs/trusted.json", "--pubkey", "<hex>",
               "--channel", "file", "--token-file", "/tmp/seal-approvals.ndjson",
               "--", "<your-mcp-server-cmd>", "<args...>"]
    }
  }
}
```

## 7. Watch it block

Have the agent call a guarded tool (e.g. a `db.execute` whose SQL contains `drop`). The
call is blocked before the child server sees it, and the block message prints the exact
**target commitment** (a 64-hex SHA-256). Copy that hex.

Where you see it: the block goes back to the **caller** as the JSON-RPC error on the MCP
wire (your agent client will surface it, `approval required: <64-hex>`), and the decision's
audit line lands on the **host's stderr**. The hex appears in both — whichever surface is
in front of you works.

## 8. Approve, one shot

Append one line to the approval file. `target` is the hex from the block message;
`issuedAt` is optional epoch **milliseconds**:

```sh
# DEV-ONLY / UNAUTHENTICATED — use only for the first 10 seconds of local smoke.
# This line has NO signature: anyone who can write the file can approve any call.
# Real work uses the signed ed25519-token channel (CLI or Telegram approver below).
# Full disclosure + the exact swap to --channel ed25519: "Control-file channel" section below.
echo '{"target": "<64-hex-from-block-message>", "issuedAt": '"$(date +%s000)"'}' \
  >> /tmp/seal-approvals.ndjson
```

The approval is **one-shot** (consumed by the first matching call) and expires after the
policy's ttl. Malformed lines are skipped fail-closed.

## 9. Re-run and read the audit record

Re-issue the same call. It now passes to the child server, and the host records the
decision on **its stderr** — two lines per decision: the raw audit line, then a
tamper-evident chain record as a single JSON line
(`{"seal_record":"v1","entry":N,"session":"...","prev_head":"...","head":"..."}`).
The first record of a process also names the prior process session, and its
`prev_head` is the safely persisted prior head. To keep the stream, redirect
stderr when you start the host (e.g. append `2>>/tmp/seal-audit.log` to the command in
step 5).

That chain record is an append-only audit chain: each `head` is
`sha256(prevHead || 0x1f || payload)`, so it commits to every prior decision. You can
check the log two ways, and they prove different things:

- **The log is intact.** Run `scripts/seal_log.mjs verify` — the executable witness of the
  `tamper_evident` theorem (`Host/Record.lean`). It rebuilds the SHA-256 head chain from the
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

One-command (CLI path, zero external setup):

```sh
python3 demo/see_the_loop.py
```

It prints:
- `approval required: <64-hex target>`
- CLI approver signs a **target-bound** record (`target ‖ nonce ‖ issuedAt` [ + `decision:"deny"` ])
- signed NDJSON appended to the token file
- provider accepts (sig verified)
- action flows (observable `SYNTHETIC_LEDGER_ACTION`) **or** explicit `refused` (for deny)
- audit / authorization-decision lines

The CLI and Telegram approvers live in `demo/`. They are **not** the signing key; they are
intent delivery. The key does the signature.

### The two channels and their TCB

**ed25519-token (recommended for anything beyond throwaway)**

- Wire: NDJSON `{"payload":"<compact JSON of target+issuedAt+nonce[+decision]>","signature":"<hex>"}`
- The approver (CLI/TG) only collects intent; the bridge/CLI holds the key and emits the
  signed token.
- **TCB (CLI):** seal-host process + CLI process + the local key file on the same machine.
  A co-resident attacker who can read the key, ptrace the signer, or tamper the token file
  before the next poll can forge approvals for any target.
- **TCB (Telegram demo bridge):** seal-host + bridge process + its signing key + your
  allowlisted from.id list + Telegram's delivery for those users. The callback is HMAC-bound
  to `(target, nonce, decision)` so a tampered button press is rejected. The bridge still
  holds the key (demo-grade).
- **Production tightening for Telegram:** device-held key via deep-link / mini-app / custom
  client. The user's device signs; the bridge only relays the already-signed token. The
  origin TCB shrinks to the audited device client.

**Control-file channel (`--channel file`): unauthenticated, DEV-ONLY, NEVER a production approval channel**

- `echo '{"target":"<hex>"}' >> /tmp/seal-approvals.ndjson` — a plain NDJSON record with **no
  signature, no origin, positional seen counter only**.
- **What "unauthenticated" means, plainly:** the host accepts the record on nothing but its
  presence in the file. No signature, no key, no origin check — so **anyone (or anything) that
  can write that file can approve any call.** The 64-hex `target` is **not a secret**: it is
  printed in the block message, on the MCP wire and on stderr, so knowing it grants no
  authority. The *only* thing between an attacker and an approval is filesystem write access to
  the token file — and that is a permission, not authentication.
- **Why it exists:** a keyless path so the first ~30 seconds of a local smoke test need no key
  material. That is its entire purpose.
- **Do not mistake it for a guard.** It is a disclosed dev convenience, not a weak security
  control. There is nothing to harden here and no flag makes it safe — the same goes for the
  CLI approver's `--plain` mode, which writes exactly one of these unsigned records. Never
  point either at anything that matters.
- **Production MUST use the ed25519-token channel instead.** Select it by swapping the channel
  flags — `--channel file --token-file F` becomes:
  ```sh
  seal-host-rs --config trusted.json --pubkey <config-hex> \
    --channel ed25519 --token-file /path/tokens.ndjson --approval-pubkey <approval-pub-hex> \
    -- <your-mcp-server-cmd> <args...>
  ```
  Now every approval must carry a valid Ed25519 signature over `(target ‖ issuedAt ‖ nonce)`
  from the key behind `--approval-pubkey`; an unsigned or tampered line is dropped with a
  `bad_signature` warning on stderr and the call stays blocked. Labeled everywhere in code,
  docs, and demos; use the control-file only for the absolute first 30 seconds of local smoke.

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
- The Rust providers accept and verify target-bound ed25519 signed allows and explicit
  signed declines (decision:"deny").
- Explicit decline produces "refused" in audit (not a timeout or generic deny).
- The CLI approver emits exactly the envelope the provider verifies.
- The one-command path (synthetic) drives block → signed record → (flow | refused) → authorization decision.

**Does NOT prove:**
- End-to-end correctness of a production deployment.
- That the key was held only on a user device (demo bridge holds it).
- Absence of all bugs in the Rust host or the approver scripts.
- That "approval" equals "the human understood and wanted the real-world effect".
- Tamper-proofing (only tamper-evidence via the chain).

No unqualified "verified", "proven", or "trustless" is used for the channel origin.

See also `demo/approve_cli.py`, `demo/approve_telegram.py`, `demo/see_the_loop.py` (and the
Rust provider tests) for the honest labels and TCB statements.

## Release container profile

Tag releases build native x86-64 and ARM64 archives. Each archive contains the Rust host,
the FFI and Lean shared-library runtime closure, licences, a SHA-256 checksum, a CycloneDX
SBOM, and GitHub build-provenance attestations. `scripts/runtime_dependency_gate.sh`
rejects build-workspace paths, missing libraries, and private-repository runtime
dependencies before an archive can be uploaded.

`deploy/container/Dockerfile.release` consumes the unpacked archive and runs as UID/GID
65532 with no root fallback. `deploy/container/compose.yaml` is the hardened example:
read-only root filesystem, no capabilities, no network, and production-mode startup.
Before starting it, create `deploy/container/{secrets,state/receipts,state/replay}`, make
each directory mode `0700`, make configuration and approval files mode `0600`, and assign
them to UID/GID 65532. The host intentionally refuses the example if those ownership or
mode requirements are not satisfied.

The source-publication path is `scripts/export_public.sh EMPTY_DIRECTORY`. It
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
