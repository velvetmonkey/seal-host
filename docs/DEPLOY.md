# Deploy: seal-host in front of your own agent

The shortest path from a clean checkout to watching seal-host **block** an unapproved
tool call, then let it through once you approve it, and hand you a receipt.

> **Runtime profile: `compatible`.** This guide stands up the `compatible`-profile host.
> That is the right profile for integration and deployment evaluation. It is **not** the
> stricter `canonical-l0` proof-covered route. This walkthrough makes **operational** claims
> only: you will get a working gated MCP call that emits a replayable receipt. It does **not**
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
                                   | every decision => a receipt
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
lake exe axiom_check          # confirm the axiom footprint (the one-shot script always runs it)
scripts/build_ffi_so.sh       # build the FFI shared object the Rust host loads
cd rust && cargo build && cd ..
# binary: rust/target/debug/seal-host-rs
```

## 2. Generate a config-signing keypair

seal-host only loads a config that carries a valid Ed25519 signature. Mint a keypair once:

```sh
python3 - <<'PY'
from test.tools.sign_config import generate_keypair
priv, pub = generate_keypair()
print("SEAL_CONFIG_SIGNING_KEY_HEX=", priv)   # 32-byte seed — keep secret, never commit
print("config pubkey (--pubkey)   =", pub)    # give this to the host at run time
PY
```

The private seed signs your config; the public hex is what the host verifies against. The
signing key is **separate** from any approval-channel key.

> Run this from the **repo root** (same for step 4): `test.tools.sign_config` is imported
> as a package path, so `python3` must see `test/` on its path or the import fails.

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
      "replay_store": { "sqlite_path": "/tmp/seal-host-replay.sqlite" }
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

`sqlite_path` here points at `/tmp` so the walkthrough runs on a fresh box with no
`sudo`/`mkdir`. For a real deployment use a durable, service-owned path (e.g.
`/var/lib/seal-host/replay.sqlite`); the durable store is what makes replay survive a
host restart.

Key facts (from the schema reference, not invented here):
- A tool **not listed** is blocked — the policy is a fail-closed allowlist for `tools/call`.
- `mode: "guarded"` needs a live approval; `mode: "deny"` is always blocked.
- The tool name is **prepended automatically** before hashing, so an approval never
  transfers between tools.
- `ttl_seconds` is **clamped to 300**; longer values are silently shortened, never lengthened.

## 4. Sign it into `trusted.json`

```sh
SEAL_CONFIG_SIGNING_KEY_HEX=<the-32-byte-seed> \
  python3 test/tools/sign_config.py payload.json > trusted.json
```

The signer compacts the payload to canonical JSON and wraps it as
`{"payload": "...", "signature": "<ed25519 hex>"}`. The host rejects any config whose
signature does not verify against `--pubkey`.

## 5. Run the host in front of your server

```sh
rust/target/debug/seal-host-rs \
  --config trusted.json \
  --pubkey <config-pubkey-hex> \
  --channel file \
  --token-file /tmp/seal-approvals.ndjson \
  -- <your-mcp-server-cmd> <args...>
```

- `--config` / `--pubkey`: the signed policy and the key that verifies it.
- `--channel file`: approvals arrive as NDJSON lines in a file a human writes.
- `--token-file`: that file (match `control_file` in your policy).
- everything after `--`: the child MCP server. seal-host spawns it and proxies to it.

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
echo '{"target": "<64-hex-from-block-message>", "issuedAt": '"$(date +%s000)"'}' \
  >> /tmp/seal-approvals.ndjson
```

The approval is **one-shot** (consumed by the first matching call) and expires after the
policy's ttl. Malformed lines are skipped fail-closed.

## 9. Re-run and read the audit record

Re-issue the same call. It now passes to the child server, and the host records the
decision on **its stderr** — two lines per decision: the raw audit line, then a
tamper-evident chain record as a single JSON line
(`{"seal_record":"v1","entry":N,"commitment":"...","head":"..."}`). To keep them, redirect
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
- **A single decision is correct.** That is the schema-v2 *decision* receipt, where you
  re-derive the verdict from the request bytes and check it with `seal-check` / `seal verify`.
  It is shown end-to-end in [seal-live-demo](https://github.com/velvetmonkey/seal-live-demo).
  The compatible-profile host emits the audit chain above, not this v2 receipt.

That is the full loop: a guarded call blocked, a human approval, the identical call allowed
once, and every decision written to a tamper-evident audit chain you can verify yourself.

---

<details>
<summary><strong>For evaluators: what this deployment does and does not prove</strong></summary>

This guide stands up the **`compatible`** profile. What that means precisely:

- **Enforced at runtime:** a policy-covered `tools/call` requires a matching live human
  approval and an allowing kernel verdict; seam failures block; every decision emits
  replayable evidence.
- **NOT the deployed runtime gate:** strict `canonical-l0` canonical-parser rejection is
  proved and modelled but is not the route this host runs. The host is not proved
  end-to-end; the Rust is tied to the kernel by byte-exact conformance testing over a
  corpus, not by a theorem over every input.
- Host `ApprovalRecord` tokens are a separate signed channel from the v2 canonical
  approval tuple.

Do not read "it worked in 5 minutes" as "end-to-end verified." For the authoritative
boundary: [`../README.md`](../README.md) truthbox, [`../PROFILE.md`](../PROFILE.md),
[claims matrix](https://github.com/velvetmonkey/seal/blob/main/docs/CLAIMS-MATRIX.md),
[what Seal is NOT](https://github.com/velvetmonkey/seal-assurance-kit/blob/main/docs/WHAT-SEAL-IS-NOT.md).

</details>
