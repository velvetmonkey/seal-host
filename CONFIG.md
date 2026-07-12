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

## 1. Build and prepare the sandbox

From the `seal-host` checkout:

```bash
bash scripts/build_all.sh
export SEAL_HOST_ROOT="$PWD"
mkdir -p "$PWD/.seal/receipts"
touch "$PWD/.seal/approval-tokens.ndjson" "$PWD/.seal/unused-approvals.ndjson"
```

Generate separate config-signing and approval-signing keys:

```bash
umask 077
read CONFIG_PRIVATE CONFIG_PUBLIC <<EOF
$(python3 -c 'from test.tools.sign_config import generate_keypair; print(*generate_keypair())')
EOF
read APPROVAL_PRIVATE APPROVAL_PUBLIC <<EOF
$(python3 -c 'from test.tools.sign_approval import generate_approval_keypair; print(*generate_approval_keypair())')
EOF
printf '%s\n' "$APPROVAL_PRIVATE" > .seal/approval.key
printf '%s\n' "$CONFIG_PRIVATE" > .seal/config.key
printf '%s\n' "$CONFIG_PUBLIC" > .seal/config.pub
printf '%s\n' "$APPROVAL_PUBLIC" > .seal/approval.pub
```

Render and sign the starter policy:

```bash
sed "s#/ABS/PATH#$PWD#g" \
  profiles/policies-v1/sqlite-sandbox.payload.json > .seal/payload.json
node ../seal-assurance-kit/bin/seal policy sign .seal/payload.json \
  --key .seal/config.key --out .seal/trusted.json
unset CONFIG_PRIVATE APPROVAL_PRIVATE
```

The signer validates the policy shape, signs the exact compact payload, and
prints the policy hash and public key. Compare the printed public key with
`.seal/config.pub`; use that value for `CONFIG_PUBLIC_KEY_HEX` below.

The starter is intentionally conservative: every declared tool is guarded and
everything else denies. Current policy-v1 cannot express “allow these reads but
guard these writes.” Do not mistake this for policy-v2 safe-allow composition.

## 2. Manual Claude Code wiring

Claude Code project configuration lives in `.mcp.json`; user configuration is
stored in `~/.claude.json`. Project scope is easiest to review and roll back.
Claude’s stdio format is documented at <https://code.claude.com/docs/en/mcp>.

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
node ../seal-assurance-kit/bin/seal connect --client claude
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
node ../seal-assurance-kit/bin/seal connect --client claude --desktop
# printed rollback:
node ../seal-assurance-kit/bin/seal disconnect --client claude --desktop
```

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

Seal returns `approval required: <64 lowercase hex target>`. The target binds
the configured server literal, tool, and complete SQL value. Sign it:

```bash
python3 demo/approve_cli.py \
  --token-file .seal/approval-tokens.ndjson \
  --target <PASTE_64_HEX_TARGET> \
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
  --target <PASTE_64_HEX_TARGET> \
  --key-file .seal/approval.key \
  --issued-at 1 --approve --yes
```

The exact call stays blocked and host telemetry records `expired`.

The CLI key is device-local but not hardware-backed. The host, CLI, key file,
and same-user machine are in this channel’s TCB. A future device-held/passkey
signer should make channels relay-only.

## 5. Receipt lifecycle

Every mediated BLOCK or ALLOW writes one v2 receipt before an ALLOW can reach
the server:

```bash
RECEIPT="$(ls -t .seal/receipts/receipt-*.json | head -1)"
node ../seal-check/test/verify-file.cjs "$RECEIPT"
node ../seal-assurance-kit/bin/seal verify "$RECEIPT"
```

For CI:

```yaml
- uses: velvetmonkey/seal-verify-action@main
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

`kernel_identity.wasm_sha256` names the wasm used to re-derive the receipt.
`host_identity` separately hashes the native executable and Lean FFI that
made the decision. Those hashes identify the two bodies; they do not prove
them equivalent. That is the open Lane C gap.

## 6. Fail-closed receipt availability

Receipt persistence is part of the gate. A full filesystem, lost mount,
invalid permissions, or unwritable receipt directory blocks forwarding.
Safety is preserved at the cost of availability.

```bash
chmod 500 .seal/receipts
# restart the client and attempt execute_sql: no SQL reaches SQLite
chmod 700 .seal/receipts
```

Operators must monitor free space and writeability and define receipt
retention. “The agent stopped working” may correctly mean “Seal could not
persist evidence, so it refused to act.”

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

## Honesty rails

- The v2 decision receipt and audit chain are distinct artifacts.
- Policy-v1 substring matching is not a SQL parser.
- Starter profiles require coverage and adequacy review before trust.
- Seal controls recognized MCP `tools/call` ingress. Child responses are not
  mediated, and compromise of the host, signer, client, or downstream tool
  remains outside the kernel theorem.
