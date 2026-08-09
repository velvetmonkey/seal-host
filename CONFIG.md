<!-- SPDX-License-Identifier: Apache-2.0 -->

# Put Seal in front of a stdio MCP server

Seal is a transparent stdio parent. The reusable transformation is:

```text
before: MCP client → real-server arg…
after:  MCP client → seal-host [Seal options] -- real-server arg…
```

The client still speaks MCP to one command. Seal receives each request first
and forwards the original bytes only after the Lean gate allows. This guide
uses a disposable SQLite MCP server in the repository. It performs a real
`DROP TABLE`, but only against `.seal/sandbox.sqlite`.

## Trusted configuration reference

The host authenticates one whole `Host.TrustedConfig` payload with Ed25519.
The signature covers the exact payload string bytes in the envelope; the
startup `--pubkey` is the trust root and is not read from that envelope. The
top-level keys understood by the host are `epoch`, optional `server`, and the
seven kernel sections below. The host's parser itself — not just the
authoring tools — rejects any other key, at the payload, section, and entry
levels: a typo such as `temporral` must not silently leave a kernel off.
(`seal policy sign` and `seal scan` apply the same top-level discipline when
authoring.)

`epoch` is a required natural number greater than zero. `server`, when
present, is a string. `safety` is required; the other six sections are
optional and absence means that no configured, non-vacuous guarantee from
that kernel participates. Every optional section also accepts an `enabled`
boolean: it defaults to `true`, and `enabled:false` is equivalent to deleting
the section — except Calibration, whose `enabled` defaults to `false` and
whose present-but-disabled state is deliberately distinct (EXPERIMENTAL,
opt-in twice; the `calibration_registered_iff` theorem pins the double gate).
Safety accepts no `enabled` key and Temporal can only be emptied, never
de-registered: S and T are registered unconditionally
(`safety_always_registered` / `temporal_always_registered`). A present
section can still be ineffective: an empty tool/policy set enforces nothing.
The authoring tools report these separately as `ACTIVE`,
`PRESENT-BUT-INACTIVE`, and `ABSENT/OFF`.

The vocabulary and parser are the policy-v2 bundle,
`Seal.parsePolicyBundle` (`mcp-seal-dev/Seal/PolicyBundle.lean`) — one
verified config parser across the native `.so`, wasm, and Lean-model lanes;
`Host.ofBundle` maps the parsed bundle onto the kernel config types, and the
`bundle_*_registered_iff` tripwires (`FfiSpec.lean`) pin that a bundle
activates exactly the kernels it configures. The schemas below follow those
parsers. A “natural” is a non-negative JSON integer. Dotted argument paths
are split on `.` and empty path components are discarded. Inside `safety`,
`approval` additionally accepts `replay_store` — the replay-store pointer
consumed by the Rust host layer (`rust/src/main.rs`), not by the kernel.

### Safety (S) — required

```json
{
  "safety": {
    "server": "optional/server-identity",
    "approval": {
      "control_file": "/path/to/approvals.ndjson",
      "ttl_seconds": 120,
      "replay_store": {
        "sqlite_path": "/var/lib/seal-host/replay.sqlite",
        "schema_version": 2,
        "namespace_encoding_version": 1
      }
    },
    "tools": [
      {
        "name": "tool_name",
        "mode": "allow | guard | guarded | deny",
        "match": { "type": "always" },
        "target": [{ "full_arguments": true }]
      }
    ]
  }
}
```

- `approval`, `approval.control_file` (string), and `tools` (array) are
  required. `ttl_seconds` is an optional natural, defaults to 120, and is
  clamped to at most 300 seconds by the parser.
- The production Ed25519 channel requires `replay_store`. Its
  `schema_version` and `namespace_encoding_version` are expected lineage from
  the authority-signed payload; this release supports exactly `2` and `1`
  (schema 2 is the G2 two-phase burn: a nonce row is reserved before Lean and
  committed at RECORDED; schema 1's single-phase burn is obsolete and
  refused — re-initialize the store). The SQLite store carries the same pair
  in its singleton `replay_store_lineage` metadata table. Missing,
  unsupported, transitional, or unequal values refuse startup.
- Normal startup never creates or stamps a replay database. On a genuinely
  absent path, an operator must first run the host with the signed config,
  trust-root `--pubkey`, and `--initialize-replay-store`. Initialization
  refuses any existing path, including an empty or legacy unstamped file.
- `safety.server` is an optional string. If both top-level `server` and
  `safety.server` are present they must be equal. If only the top-level value
  is present, the host supplies it to Safety.
- Every tool rule requires string `name` and one of the four displayed modes.
  `match` is optional and defaults to `always`. Other matcher schemas are
  `{type:"equals"|"starts_with", arg:string, value:string}`,
  `{type:"contains_any_ci", arg:string, needles:string[]}`, and recursive
  `{type:"all"|"any", matches:match[]}`.
- `target` is optional and defaults to `[]`. Target parts parse as a string
  `literal`, a string dotted `arg` path, or `full_arguments:true`. The host
  parser checks `literal` first; without it, `arg` and `full_arguments` must
  be exclusive. The authoring signer deliberately applies the stricter safe
  subset: guarded rules need a non-empty target, target parts must be
  unambiguous, rule names and matcher argument paths must be non-empty, and
  `all`/`any` need at least one child. The signer also requires a non-empty
  top-level `server` when that optional field is supplied.

**Guarantee:** a composed allow for a Safety-guarded call implies a live,
matching approval for its classified target. Safety gates every tool call and
remains effective even when its rule list is empty because unmatched calls
deny by default.

### Temporal (T) — optional

```json
{
  "temporal": {
    "policies": [
      {
        "name": "freeze-after-revoke",
        "type": "no_after",
        "trigger": ["revoke"],
        "forbidden": ["write_item"]
      }
    ]
  }
}
```

`policies` is a required array when the section is present. Each policy
requires string `name`, the exact type `no_after`, and string arrays `trigger`
and `forbidden`. A section with no policy having both trigger and forbidden
tools is present but vacuous.

**Guarantee:** a composed allow implies no configured `no_after` policy
forbids the call in the current executed-call trace.

### Consensus (C) — optional

```json
{
  "consensus": {
    "roster": [1, 2, 3],
    "votes_file": "/path/to/votes.ndjson",
    "high_stakes": ["deploy"]
  }
}
```

All three fields are required: `roster` is an array of naturals,
`votes_file` is a string, and `high_stakes` is a string array. An empty
`high_stakes` list is present but vacuous. An empty roster is accepted by the
parser but cannot supply a quorum.

**Guarantee:** two composed allows against the same trusted roster and votes
ratify the same tool-name value. The deployed certificate binds the tool
name, not its full argument bytes.

### Convergence (V) — optional

```json
{
  "convergence": {
    "tools": [{ "tool": "store.update", "op_arg": "operation.kind" }]
  }
}
```

`tools` is required when present. Every entry requires string `tool` and
string dotted `op_arg`. An empty list is present but vacuous. The admissible
operation set is fixed in code: `gset.add`, `gcounter.inc`, `pncounter.inc`,
`pncounter.dec`, `orset.add`, `orset.remove`, `rga.insert`, and `rga.remove`.

**Guarantee:** a composed allow for a V-gated call implies the resolved
operation is in that fixed, kernel-checked convergent set.

### Calibration (K) — optional, EXPERIMENTAL

```json
{
  "calibration": {
    "enabled": false,
    "delta_num": 1,
    "delta_den": 20,
    "min_samples": 100,
    "records_file": "/path/to/forecasts.ndjson",
    "gated_tools": ["auto_publish"]
  }
}
```

`enabled` is an optional boolean defaulting to `false`. All other displayed
fields remain required even while disabled: `delta_num`, `delta_den`, and
`min_samples` are naturals; `records_file` is a string; `gated_tools` is a
string array. The fraction must satisfy `0 < delta_num/delta_den < 1`. K is
active only when enabled and at least one tool is gated.

**Guarantee:** a composed allow for a K-gated call implies the executable
Float calibration check passed. The statistical delta theorem is **not**
formally connected to that Float computation. K is EXPERIMENTAL and is not
part of recommended configuration recipes.

### Linear resources (L) — optional

```json
{
  "linear": {
    "grants_file": "/path/to/grants.ndjson",
    "tools": [{ "tool": "spend", "cap_arg": "capability.id" }]
  }
}
```

`grants_file` (string) and `tools` (array) are required when present. Every
tool entry requires string `tool` and string dotted `cap_arg`. An empty tool
list is present but vacuous.

**Guarantee:** a composed allow for an L-gated call implies the spend was
backed by a held capability and consumed exactly one use; denied calls spend
nothing.

### Budget/rate (B) — optional

```json
{
  "budget": {
    "budgets": [
      {
        "name": "write-units",
        "cap": 100,
        "tools": ["write_item"],
        "cost_arg": "usage.units"
      }
    ]
  }
}
```

`budgets` is required when the section is present. Every entry requires
string `name`, natural `cap`, and string-array `tools`; string dotted
`cost_arg` is optional. Without `cost_arg`, each covered call costs 1. The
section is present but vacuous when no budget covers any tool.

**Guarantee:** a composed allow for a B-gated call implies every covering
budget resolved its cost and admitted it without exceeding its cap.

### Principals (PB) — optional, V2.1

```json
{
  "principals": {
    "keys": [
      {
        "id": "alice",
        "pubkey": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
      }
    ],
    "budgets": [
      { "name": "alice-writes", "cap": 10, "tools": ["write_item"] }
    ]
  }
}
```

The V2.1 signed-envelope principal registry plus per-principal budget specs
(the same budget-spec shape as B; state is keyed per (principal id, budget
name)). `keys` and `budgets` are required when the section is present.
Every key entry requires a non-empty string `id` and a 64-hex-char Ed25519
verifying key `pubkey` — both linted at parse/signing time (the schema
states the same bounds). The key→principal binding is operator-pinned
INSIDE the signed config; a principal is never a request-supplied identity
field. A PB-gated call without a verified principal envelope is denied
outright ("principal envelope required" — mixed-mode fail-closed); optional
`enabled: false` collapses the section to absent. Authoring is hand-written
JSON for now (`seal validate` lints it); the assurance-kit DX has no PB
recipe yet.

**Guarantee:** a composed allow for a PB-gated call implies the request
carried a fresh envelope verified against the registry key of the named
principal, and that principal's own covering budgets all admitted the
call's cost.

### Budget × Linear: composition proven; IO shell and caller dimension pinned

PROVEN (`Host/Commit.lean`, `Host/CommitRegistry.lean`), over the full
7-kernel registry — `commitInstsFor_kernels` binds the pure commit instances
to exactly `Ffi.activeKernels`, the same selection spec `registryFor_kernels`
proves the deployed step dispatches:

- A call denied by ANY kernel — one gating kernel's deny forces the combined
  deny (`pureCommit_deny_of_member`) — commits no decide-phase state anywhere
  (`registry_deny_ingest_only`). Budget counters are byte-identical
  (`registry_deny_no_budget_spend`), the temporal trace gains no event
  (`registry_deny_temporal_frozen`), and no linear capability is consumed —
  committed holds can only grow, by exactly this call's ingested grants
  (`registry_deny_no_capability_consumed`; the deployed grants parse emits
  grant events only, `parseGrantsText_grant_only`). The only states that move
  on a deny are the spec-allowed ingests, and the theorem says which: Safety's
  approval fold and Linear's grant fold (evidence must survive a deny).
- Committed traces stay within caps
  (`budget_committed_trace_within_cap_of_consistent`) and never double-spend
  (`linear_committed_trace_no_double_spend`).
- The dispatch loop's per-call computation — the verdicts it combines, the
  states it writes immediately, the states it holds and replays only on
  allow — is proven equal to the model's `pureCommit` in the loop's own
  vocabulary (`dispatch_plan`, over the `phase1Held` triple the loop calls).
- The mirror's wiring against the deployed registry is proven instance by
  instance, not inspected: under the common projection (kernel identity and
  order, config section, evidence source — each deployed `gather` equals the
  constant returning the mirror's evidence — and pre-call state slot, for
  every pure reading of the session refs consistent with the mirror's state
  arguments), `commitInstsFor` EQUALS `registryFor`
  (`commitInstsFor_wiring`); every gating decision follows
  (`commitInstsFor_gates`).

- The IO shell is spelled: the deployed `dispatch` `do`-block equals its
  explicit recursion — desugaring, accumulator order, queued-held-write
  content and order, allow-only replay (`dispatch_spelled`); one mediation
  step equals the pure plan around its two IO leaves, so the field-to-parser
  marshalling and fail-closed branches are pinned (`stepImpl_spelled`);
  every deployed gather is a pure constant, so executing it is the monad
  law (`registryFor_gather_pure`); and no config registers a kernel twice
  (`registryFor_kernels_nodup`).

NOT proven (the irreducible IO core, named and justified in
`docs/POLICY-ASSURANCE-BOUNDARY.md`): the VALUE semantics of the opaque
`IO.Ref` primitives (get returns the current value, sets land, `mkRef` is
fresh — `opaque` externs in Lean core, nothing to unfold), the typed-runtime
trust that covers ref distinctness (the five session refs carry
pairwise-distinct state types; C, V and K share one `Unit` ref, inert by
`State = Unit`), and the `unsafeBaseIO`/FFI/Rust/OS boundary. And no caller
dimension — budget
counters and linear grants are global, so one caller can exhaust another's
allowance (characterized end-to-end in `Test/DxSurface.lean`); that is a
feature gap, not a proof gap. Read B and L guarantees as per-config-global,
never per-caller.

### Composed guarantee and boundary

A mediated host ALLOW requires Safety and every configured kernel whose gate
covers that call to allow. For every effectively active kernel, the matching
guarantee above rides the composed allow. Absent, disabled, and vacuous
sections add no non-vacuous protection. These are safety implications, not
liveness promises; the trusted config, runtime evidence gathering, and IO
realization remain in the TCB. See
[`docs/PROOF-REFERENCE.md`](docs/PROOF-REFERENCE.md) for theorem names, axiom
footprints, and the full non-claims.

## Manifest-aware authoring recipes

Recipes are scaffolding strategies applied to the real names in a captured
`tools/list` manifest. They are not generic policy templates. Every emitted
kernel section references at least one real manifest tool and `seal init`
refuses to emit a recipe when it cannot create a non-vacuous section.

Safety always starts from the proven exact-name scaffold: server-described
read-only tools are visible unverified `allow` suggestions, while destructive,
unknown, and conflicting tools are guarded. Recipe placeholders deliberately
fail closed. A budget `cap:0`, empty consensus roster, placeholder evidence
file, or unresolved argument path can block the covered call until edited.
Review every `EDIT-ME` before signing.

When the manifest has no literal archetype match, the CLI chooses a
deterministic guarded best-fit tool and prints the same warning into the
policy, for example:

```text
EDIT-ME: best-fit mapping: role 'deploy' → tool 'execute_sql'.
Review whether this recipe suits this server at all.
```

That mapping proves only that the section is wired to a real tool. It is not
an endorsement that a deploy recipe belongs on a database server. One tool
may fill multiple roles on a sparse manifest.

### `prod-db` — Safety + Temporal + Budget (S + T + B)

```bash
seal init --recipe prod-db profiles/manifests/dbhub-0.23.0.tools.json
```

Safety guards every destructive or unknown tool. Budget covers that same
guarded set, initially with `cap:0`. Temporal uses the real guarded tool set
as both the trigger and forbidden set, so after the first mapped destructive
or unknown call, subsequent mapped calls freeze. Edit the cap and narrow the
trigger set if a different lifecycle event should start the freeze.

### `deploy` — Linear + Consensus + Safety (L + C + S)

```bash
seal init --recipe deploy profiles/manifests/github-mcp-v1.0.5.tools.json
```

Linear requires a capability for the selected deploy tool, Consensus marks it
`high_stakes`, and Safety visibly marks the guarded rollback role. Edit
`capability.id`, `EDIT-ME/seal-grants.ndjson`, the empty roster, and
`EDIT-ME/seal-votes.ndjson`. Until then the Linear and Consensus placeholders
fail closed.

### `token-governor` — Budget + Safety (B + S)

```bash
seal init --recipe token-governor captured.tools.json
```

Budget caps the selected token/LLM role and wires the placeholder cost path
`usage.tokens`; Safety visibly marks the guarded payment role. Edit the
initial `cap:0` and verify `cost_arg` against the server's actual argument
schema before use.

### `mesh` — Convergence + Safety (V + S)

```bash
seal init --recipe mesh captured.tools.json
```

Convergence covers the selected shared-state tool and Safety visibly marks
the guarded publish role. Edit `operation.kind` to the real operation argument
path and confirm the server emits one of V's fixed admissible convergent
operations.

### Add one kernel incrementally

`add-kernel` edits the sibling policy created by `seal init` by default:

```bash
seal add-kernel B captured.tools.json
```

For a moved or hand-authored policy, select it explicitly:

```bash
seal add-kernel V captured.tools.json --policy config/reviewed-policy.json
```

The command validates the whole result before writing and refuses malformed
policies, server-identity conflicts, or an already-present section rather
than overwriting edits. S, T, C, V, L, and B use the same real-tool selection
and fail-closed placeholder rules as the catalog above.

Calibration K is EXPERIMENTAL, excluded from every recipe, and outside the
recommended path. The only authoring route requires explicit consent and
prints a loud warning:

```bash
seal add-kernel K captured.tools.json --policy config/policy.json --experimental
```

**Evidence tier:** dev-box deterministic-tested against snapshots of the
three shipped manifests; the standing `npm test` CI gate is configured but
has not run remotely for this change; operator verification is not applicable
to this non-model authoring surface.

## 1. Build the host and prepare the sandbox

From the `seal-host` checkout:

```bash
export SEAL_HOST_ROOT="$PWD"
time bash scripts/build_all.sh
export SEAL_BIN="$SEAL_HOST_ROOT/rust/target/debug/seal-host-rs"
umask 077
mkdir -p "$PWD/.seal/receipts"
touch "$PWD/.seal/approval-tokens.ndjson" "$PWD/.seal/unused-approvals.ndjson"
```

No binary release is currently published. See
[Release provenance](docs/RELEASE-PROVENANCE.md) for the contract that applies
when one exists; `SHA256SUMS` alone is not an authenticity check.

Generate separate config-signing and approval-signing keys:

```bash
python3 scripts/generate_keys.py --out-dir .seal
```

The generator validates both Ed25519 pairs before publishing any key. It exits
non-zero without leaving a key file if its imports, generation, validation, or
write fails, and refuses to overwrite an existing key.

Render and sign the starter policy:

```bash
sed "s#/ABS/PATH#$PWD#g" \
  profiles/policies-v1/sqlite-sandbox.payload.json > .seal/payload.json
SEAL_CONFIG_SIGNING_KEY_HEX="$(tr -d '\r\n' < .seal/config.key)" \
  python3 test/tools/sign_config.py .seal/payload.json > .seal/trusted.json
chmod 600 .seal/trusted.json
"$SEAL_BIN" --insecure-development-mode \
  --config .seal/trusted.json --pubkey "$(cat .seal/config.pub)" \
  --channel ed25519 --token-file .seal/approval-tokens.ndjson \
  --approval-pubkey "$(cat .seal/approval.pub)" \
  --initialize-replay-store
```

The signer validates the policy shape and signs the exact compact payload.
Use `.seal/config.pub` for `CONFIG_PUBLIC_KEY_HEX` below and
`.seal/approval.pub` for `APPROVAL_PUBLIC_KEY_HEX`.

The starter is intentionally conservative: every declared tool is guarded and
everything else denies. Current policy-v1 cannot express “allow these reads but
guard these writes.” Do not mistake this for policy-v2 safe-allow composition.

## 2. Manual Claude Code wiring

Claude Code project configuration lives in `.mcp.json`; user configuration is
stored in `~/.claude.json`. Project scope is easiest to review and roll back.
Claude’s stdio format is documented at <https://code.claude.com/docs/en/mcp>.
On Windows 11, run Claude Code inside Ubuntu WSL2 for this block: every command
and path then stays Linux-native, and no `systemd` service is involved.

Before Seal, an entry directly launches its implementation:

```json
{
  "mcpServers": {
    "sqliteSandbox": {
      "type": "stdio",
      "command": "python3",
      "args": ["/ABS/PATH/demo/sqlite_mcp_server.py", "--database", "/ABS/PATH/.seal/sandbox.sqlite"]
    }
  }
}
```

After Seal, the real command moves behind `--`:

```json
{
  "mcpServers": {
    "sealSqliteSandbox": {
      "type": "stdio",
      "command": "/ABS/PATH/rust/target/debug/seal-host-rs",
      "args": [
        "--config", "/ABS/PATH/.seal/trusted.json",
        "--pubkey", "CONFIG_PUBLIC_KEY_HEX",
        "--channel", "ed25519",
        "--token-file", "/ABS/PATH/.seal/approval-tokens.ndjson",
        "--approval-pubkey", "APPROVAL_PUBLIC_KEY_HEX",
        "--receipt-dir", "/ABS/PATH/.seal/receipts",
        "--production",
        "--", "python3", "/ABS/PATH/demo/sqlite_mcp_server.py",
        "--database", "/ABS/PATH/.seal/sandbox.sqlite"
      ]
    }
  }
}
```

The copy-and-edit version is
[`profiles/hosts/claude-code.json`](profiles/hosts/claude-code.json). Replace
`/ABS/PATH`, `CONFIG_PUBLIC_KEY_HEX`, and `APPROVAL_PUBLIC_KEY_HEX`, then
put it at `.mcp.json`. Run `claude mcp list` and use `/mcp` inside Claude
Code to check the connection.

From the `seal-host` checkout, the assurance kit selects that starter profile,
fills the checkout path and public keys from `.seal`, performs the merge
atomically, and prints its rollback:

```bash
node ../seal-assurance-kit/bin/seal connect --client claude \
  --profile profiles/hosts/claude-code.json
# printed rollback:
node ../seal-assurance-kit/bin/seal disconnect --client claude
```

`connect` stores the exact prior bytes and is idempotent. `disconnect` restores
those bytes exactly. If the MCP configuration changes after connection,
rollback refuses to overwrite the overlapping edit and points to its recovery
record instead.

Rollback:

1. Save the Seal entry as `.mcp.json.seal-backup` if wanted.
2. Restore the original `command` and `args`, or run
   `claude mcp remove --scope project sealSqliteSandbox`.
3. Run `claude mcp list` and confirm the direct server is the only entry.

## 3. Manual Claude Desktop wiring

On macOS the file is:

```text
~/Library/Application Support/Claude/claude_desktop_config.json
```

Open Claude Desktop → Settings → Developer → Edit Config. Back it up first:

```bash
cp "$HOME/Library/Application Support/Claude/claude_desktop_config.json" \
   "$HOME/Library/Application Support/Claude/claude_desktop_config.json.before-seal"
```

Merge the `mcpServers` entry from
[`profiles/hosts/claude-desktop.json`](profiles/hosts/claude-desktop.json),
replace its placeholders, save, and fully quit/restart Claude Desktop. The MCP
project's Desktop instructions and log locations are at
<https://modelcontextprotocol.io/docs/develop/connect-local-servers>.

The automated equivalent is:

```bash
node ../seal-assurance-kit/bin/seal connect --client claude --desktop \
  --profile profiles/hosts/claude-desktop.json
# printed rollback:
node ../seal-assurance-kit/bin/seal disconnect --client claude --desktop
```

For Windows-side Claude Desktop with the host inside Ubuntu WSL2, use
`wsl.exe` as the command. The executable and every later path are Linux paths
inside the named distribution:

```json
{
  "mcpServers": {
    "sealSqliteSandbox": {
      "command": "wsl.exe",
      "args": [
        "--distribution", "Ubuntu", "--exec",
        "/home/<wsl-user>/seal-host/rust/target/debug/seal-host-rs",
        "--config", "/home/<wsl-user>/seal-host/.seal/trusted.json",
        "--pubkey", "CONFIG_PUBLIC_KEY_HEX",
        "--channel", "ed25519",
        "--token-file", "/home/<wsl-user>/seal-host/.seal/approval-tokens.ndjson",
        "--approval-pubkey", "APPROVAL_PUBLIC_KEY_HEX",
        "--receipt-dir", "/home/<wsl-user>/seal-host/.seal/receipts",
        "--production",
        "--", "python3", "/home/<wsl-user>/seal-host/demo/sqlite_mcp_server.py",
        "--database", "/home/<wsl-user>/seal-host/.seal/sandbox.sqlite"
      ]
    }
  }
}
```

Confirm the distribution name with `wsl.exe --list --quiet`; replace `Ubuntu`
if it differs. This repository's Linux CI cannot execute Windows-side Claude
Desktop or `wsl.exe`, so this is an explicit unverified integration surface,
not part of the Linux-native evidence below.

Rollback restores the backup and restarts Desktop:

```bash
cp "$HOME/Library/Application Support/Claude/claude_desktop_config.json.before-seal" \
   "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
```

## 4. Approval loop in the real Claude UI

Ask Claude to call `execute_sql` with exactly:

```sql
DROP TABLE receipt_sandbox
```

Seal returns `approval required: <64 lowercase hex target>` plus a structured
`result.framed_subject` object containing the exact request frame as base64,
its byte length, and SHA-256 digest. Save that one-line JSON refusal, then sign
the exact framed subject it carries:

```bash
python3 demo/approve_cli.py \
  --token-file .seal/approval-tokens.ndjson \
  --refusal-file /tmp/blocked-response.json \
  --key-file .seal/approval.key \
  --approve --yes
```

Reissue the identical call. It flows once. Repeating it blocks again because
the approval was consumed.

For mismatch rejection, approve the original target but ask Claude to run
`DROP TABLE a_different_table` first. The changed SQL remains blocked; the
original approval does not widen.

For expiry without waiting, mint a deliberately stale token:

```bash
python3 demo/approve_cli.py \
  --token-file .seal/approval-tokens.ndjson \
  --refusal-file /tmp/blocked-response.json \
  --key-file .seal/approval.key \
  --issued-at 1 --approve --yes
```

The exact call stays blocked and host telemetry records `expired`.

The CLI key is device-local but not hardware-backed. The host, CLI, key file,
and same-user machine are in this channel’s TCB. A future device-held/passkey
signer should make channels relay-only.

**Who the authorization decision authenticates (scope, normative):** the authorization decision's
`approval_identity` names the APPROVER's trust root — the channel kind plus,
on `--channel ed25519` only, the SHA-256 fingerprint of `--approval-pubkey`.
It is a boot-scoped constant of the configuration, provably independent of
the request bytes. It never names the CALLER: stdio mediation carries no
transport credential, so no authorization-decision field can authenticate which agent made
a call — proven, not pending (`Host/ReceiptIdentity.lean`, and the "Who does
an authorization decision authenticate?" section of `docs/HONESTY-MATRIX.md`). The `file`
and `interactive` channels are DEV-ONLY and unauthenticated: their authorization decisions
name a channel kind and make no identity claim at all. Binding a caller is a
V2.1 topology change (per-caller transport credentials), not an authorization-decision
field.

## 5. Authorization-decision lifecycle

Every mediated BLOCK or ALLOW writes one v2 authorization decision before an ALLOW can reach
the server:

```bash
RECEIPT="$(ls -t .seal/receipts/receipt-*.json | head -1)"
node ../seal-check/test/verify-file.cjs "$RECEIPT"
node ../seal-assurance-kit/bin/seal verify "$RECEIPT"
```

For CI:

```yaml
- uses: velvetmonkey/seal-verify-action@v1
  with:
    receipts: '.seal/receipts/*.json'
```

The action fails closed when no receipts match or any receipt is invalid.

Tamper with a copy; both local verifiers and the action must reject it:

```bash
cp "$RECEIPT" .seal/tampered.json
python3 -c 'import json; p=".seal/tampered.json"; r=json.load(open(p)); r["arguments"]["sql"]="DROP TABLE another_table"; open(p,"w").write(json.dumps(r,indent=2)+"\n")'
node ../seal-check/test/verify-file.cjs .seal/tampered.json       # exit 1
node ../seal-assurance-kit/bin/seal verify .seal/tampered.json   # exit 1
```

`kernel_identity.wasm_sha256` names the wasm used to re-derive the authorization decision.
`host_identity` separately hashes the native executable and Lean FFI that
made the decision. Those hashes identify the two bodies; they do not prove
them equivalent. That is the open Lane C gap.

## 6. Fail-closed authorization-decision availability

Authorization-decision persistence is part of the gate. A full filesystem,
lost mount, invalid permissions, or unwritable authorization-decision directory blocks forwarding.
Safety is preserved at the cost of availability.

```bash
chmod 500 .seal/receipts
# restart the client and attempt execute_sql: no SQL reaches SQLite
chmod 700 .seal/receipts
```

Operators must monitor free space and writeability and define authorization-decision
retention. “The agent stopped working” may correctly mean “Seal could not
persist evidence, so it refused to act.”

Authorization-decision directories must be owned by the service user with mode `0700`;
authorization-decision files and the SQLite replay database must be owned by that user with
mode `0600`. Existing unsafe modes, foreign ownership, and symlinks are
rejected rather than repaired. After each authorization decision is written and file-fsynced,
the host atomically renames it and fsyncs the authorization-decision directory.

The exact crash-consistency claim is deliberately narrow: after `persist`
returns success, the complete authorization-decision bytes and its directory entry have been
submitted through file `fsync`, atomic rename, and parent-directory `fsync`.
They are expected to survive an ordinary process or OS crash on a local
filesystem that honors those calls. This is not a claim against faulty storage,
filesystems that ignore `fsync`, administrator deletion, or every power-loss
failure mode; backups and off-host retention remain operator responsibilities.

## 7. Other stdio MCP clients

- Cursor: project `.cursor/mcp.json` or user `~/.cursor/mcp.json`; starter
  [`profiles/hosts/cursor.json`](profiles/hosts/cursor.json). See
  <https://docs.cursor.com/context/model-context-protocol>.
- VS Code: workspace `.vscode/mcp.json`, using top-level `servers`; starter
  [`profiles/hosts/vscode.json`](profiles/hosts/vscode.json). See
  <https://code.visualstudio.com/docs/agents/reference/mcp-configuration>.

Rollback is structural: replace the Seal command with the original server
command and remove Seal’s prefixed arguments. Do not delete unrelated client
configuration while rolling back one server.

Production health/readiness, retention, key rotation, secret storage, and
replay backup/recovery are specified in [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Honesty rails

- The v2 authorization decision and audit chain are distinct artifacts.
- Policy-v1 substring matching is not a SQL parser.
- Starter profiles require coverage and adequacy review before trust.
- Seal controls recognized MCP `tools/call` ingress. Child responses are not
  mediated, and compromise of the host, signer, client, or downstream tool
  remains outside the kernel theorem.
