<!-- SPDX-License-Identifier: Apache-2.0 -->
# Getting started — not built yet

## Current availability: zero

- Repository package version: **v0.1.5** (not a published release).
- Published `seal-host` releases: **0**.
- Supported clean-machine onboarding paths: **0**.
- Windows/WSL2 end-to-end runs: **0**.

There is no honest install or first-run command today. A Git tag is not a
release, and a local source build is not a substitute for a published binary.
Do not continue into the recorded local evidence below unless you already have
a working host binary from this exact checkout; this document does not tell a
new reader how to obtain one.

## What seal-host is

Your agent talks to real tools over MCP. Nothing in that pipeline stops it
from executing `drop table customers` on prod — the model decides, the server
obeys. seal-host is a single binary you put between the MCP client and the
MCP server. Ordinary traffic passes through unchanged. A `tools/call` your
policy marks **guarded** is refused before it reaches the server unless a
matching, live, signed approval exists for that exact request. Every decision
— allow or deny — is written as a receipt in a hash chain you can re-verify
offline. The decision core is a Lean theorem; what is proved, tested, and
assumed is listed at the bottom of this page, precisely.

## Recorded local evidence — not an onboarding path

The remaining sequence was observed with a pre-existing local build on
2026-08-09. It is retained as evidence for the block/approve/flow/verify loop,
not as a supported setup route.

Prerequisites are Bash on Linux, a checkout of this repository, an already
working host binary from that checkout, Python 3 with `cryptography`, Node.js,
and the host's local Lean/FFI shared-library closure. Set the two local paths:

```sh
export SEAL_REPO=/path/to/seal-host
export SEAL_BIN=/path/to/already-built/seal-host-rs
```

Work in a fresh directory. Generate the two keypairs (config-signing and
approval-signing — deliberately separate trust roots), and write a minimal
policy that guards destructive SQL:

```sh
mkdir seal-quickstart && cd seal-quickstart
umask 077
python3 "$SEAL_REPO/scripts/generate_keys.py" --out-dir keys
mkdir -m 700 store receipts
: > approvals.ndjson

cat > payload.json <<EOF
{
  "epoch": 1,
  "safety": {
    "approval": {
      "control_file": "$PWD/approvals.ndjson",
      "ttl_seconds": 120,
      "replay_store": {
        "sqlite_path": "$PWD/store/replay.sqlite",
        "schema_version": 2,
        "namespace_encoding_version": 1
      }
    },
    "tools": [{
      "name": "db.execute",
      "mode": "guarded",
      "match": { "type": "contains_any_ci", "arg": "sql", "needles": ["drop", "delete", "truncate"] },
      "target": [{ "full_arguments": true }]
    }]
  }
}
EOF
```

The host only loads a config wrapped in a valid Ed25519 envelope, and it
refuses a config file that is group- or world-readable — hence the
`chmod 600`:

```sh
SEAL_CONFIG_SIGNING_KEY_HEX=$(cat keys/config.key) \
  python3 "$SEAL_REPO/test/tools/sign_config.py" payload.json > trusted.json
chmod 600 trusted.json
```

The signed approval channel requires a durable replay store (one-shot
approvals must survive a restart). Initialize it explicitly from the signed
config — this is a deliberate separate step, not something the host does
silently on first run:

```sh
"$SEAL_BIN" --insecure-development-mode \
  --config trusted.json --pubkey "$(cat keys/config.pub)" \
  --channel ed25519 --token-file approvals.ndjson \
  --approval-pubkey "$(cat keys/approval.pub)" \
  --initialize-replay-store
```

(`--insecure-development-mode` is what it says: it disables the production
preflight and prints an uppercase warning to remind you. The production
posture — ownership checks, explicit `--receipt-dir`, durable store paths —
is in [DEPLOY.md](DEPLOY.md).)

Now play the agent. Send one destructive `tools/call` through the gate, with
`/bin/cat` standing in as the "real" MCP server (anything that echoes stdio
works — the point is the call must *reach* it):

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table customers"}}}' > call.jsonl

"$SEAL_BIN" --insecure-development-mode \
  --config trusted.json --pubkey "$(cat keys/config.pub)" \
  --channel ed25519 --token-file approvals.ndjson \
  --approval-pubkey "$(cat keys/approval.pub)" \
  -- /bin/cat < call.jsonl > response.jsonl 2> audit.log

cat response.jsonl
```

Measured: 0.6 seconds. The response is a refusal, not an echo — the call
never reached `/bin/cat`:

```json
{"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"approval required: 2a01d254…c565","type":"text"}],"isError":true,"framed_subject":{…}}}
```

That 64-hex value is the **approval challenge**: a SHA-256 value derived
from the exact request. An approval is bound to it — approve *this* drop on
*this* database, not "approve db.execute".

## Recorded evidence: approve that exact call and watch it flow

Approvals are Ed25519-signed records that bind the target *and* the exact
framed request bytes, and they are scoped to the live host session that
issued the challenge. The host must therefore remain running between the
refusal and retry. The block below uses Bash's `coproc` to keep that one host
session live, read its first response before signing, and then send the
identical frame again. It was run successfully on 2026-08-09 against the local
built host; the published-bundle variant remains blocked by the absent release.

```sh
coproc SEAL_GATE { "$SEAL_BIN" --insecure-development-mode \
  --config trusted.json --pubkey "$(cat keys/config.pub)" \
  --channel ed25519 --token-file approvals.ndjson \
  --approval-pubkey "$(cat keys/approval.pub)" \
  --receipt-dir receipts -- /bin/cat 2> audit2.log; }
GATE_IN=${SEAL_GATE[1]}
GATE_OUT=${SEAL_GATE[0]}

printf '%s\n' "$(cat call.jsonl)" >&"$GATE_IN"
IFS= read -r REFUSAL <&"$GATE_OUT"
printf '%s\n' "$REFUSAL" | tee refusal.json

python3 "$SEAL_REPO/demo/approve_cli.py" \
  --token-file approvals.ndjson --refusal-file refusal.json \
  --key-file keys/approval.key --approve --yes

printf '%s\n' "$(cat call.jsonl)" >&"$GATE_IN"
IFS= read -r ALLOWED <&"$GATE_OUT"
printf '%s\n' "$ALLOWED" | tee allowed.json
exec {GATE_IN}>&-
wait "$SEAL_GATE_PID"
```

Observed output begins with the full refusal shown above. The signer then prints
the exact displayed frame and:

```text
signed allow for target=2a01d25406f0fc82751a66ddaeb8e79d2104efc4b67699400003704e67c0c565
```

The second response is the original request echoed by `/bin/cat`, with the
host-added `operation_id`. The child received the bytes. That echo is the whole
product in one line: without the approval the call never arrives; with it, it
does.

Things this page deliberately did wrong first, so you know they fail closed
(each was run; each refuses): an unsigned `{"target":"…"}` approval line is
dropped (`approval_record_v1_not_supported` — the legacy unauthenticated
channel no longer admits approvals); the `ed25519` channel refuses to start
without a `replay_store` in the signed policy; a `trusted.json` with mode
`0664` is rejected at startup; and an approval signed *after* the blocking
host session exited is dropped (`target_or_subject_mismatch`) because the
challenge died with the session.

## Recorded evidence: verify a receipt and see verification fail

The two decisions from the live `coproc` session emitted evidence in two forms:
a JSON receipt per decision in `./receipts/`, because that host command passed
`--receipt-dir receipts`, and an audit line carrying per-kernel certificates in
`audit2.log`. The earlier one-shot block in step 2 used the development default
`./seal-receipts/`; it is not an input to the verification below. Look at a
receipt from the canonical live session:

```sh
python3 -m json.tool "$(ls receipts/receipt-* | tail -1)"
```

Fields worth reading on your first one: `verdict` (`ALLOW` here — the last
decision was the approved flow; the earlier receipts in the same directory
say `BLOCK`), `authorization: "approval"`, `approval.approval_identity`
(which channel and which key fingerprint authorized it — identity is only
authenticated on the `ed25519` channel), `canonical_request_sha256` and
`framed_subject_sha256` (byte commitments to what was judged), and `reason:
"every gating kernel allows"`.

Now the chain. Seal the audit certificates into the tamper-evident hash
chain and verify it (this is the concrete instance of the
`Host.Record.tamper_evident` theorem, with SHA-256 as the commitment):

```sh
grep -h '"certs":\[' audit2.log > audit.lines
node "$SEAL_REPO/scripts/seal_log.mjs" seal audit.lines sealed.json
node "$SEAL_REPO/scripts/seal_log.mjs" verify sealed.json
```

```text
VERIFY OK: 2 entries, chain intact.
chain head: 373946b394d9ae567bd1917093a64ae479217c9e2b4568e37afbd04c918d1126
```

Exit code 0. A green check you have never seen fail teaches nothing about
trust, so break it. Flip one recorded verdict — the exact forgery an
attacker who edited the log would want — and re-verify:

```sh
python3 - <<'EOF'
import json
sealed = json.load(open("sealed.json"))
entry = sealed["entries"][0]
entry["payload"] = entry["payload"].replace('"verdict":"deny"', '"verdict":"allow"', 1)
json.dump(sealed, open("tampered.json", "w"))
EOF
node "$SEAL_REPO/scripts/seal_log.mjs" verify tampered.json
```

```text
VERIFY FAIL: entry 0 — recorded head does not match recomputed chain.
  recorded:   8f024a313462fd758925f720e7886679963d9e05bb0e4c5d0d6dbe68bb49a2d0
  recomputed: 01117c22cd8310c3a9dc1a1022022de580d5daed8b865dea0f35f4bf56762f4c
  → the log was inserted into, reordered, or mutated at or before entry 0.
```

Exit code 1. One flipped bit in one verdict and the head no longer
recomputes. That is what "tamper-evident" buys you — and note what it does
not: the chain proves the log was not altered, it does not prevent someone
with write access from truncating it. Evident, not impossible.

## What is proven, what is tested, what is assumed

This estate keeps its claims vocabulary in [`../CLAIMS.md`](../CLAIMS.md)
(the claims map), [`LIMITATIONS.md`](LIMITATIONS.md), and
[`HONESTY-MATRIX.md`](HONESTY-MATRIX.md) (machine-**derived** cells vs
human-**ASSERTED** cells). Using that vocabulary, not a new one:

**The one claim** (from `CLAIMS.md`): *policy-covered, unapproved
request-effects cannot execute through the mediated MCP boundary.* Not "the
agent is safe", not "the whole stack is verified".

- **Lean theorem (proved):** the fail-closed registry composition (deny if no
  kernel gates, allow only if every gating kernel allows); forward-implies-
  all-allow in the pure routing core (`step_forward_non_bypass`); the record
  chain's append-only and tamper-evidence (`Host/Record.lean`). All pinned to
  the axiom footprint `[propext, Classical.choice, Quot.sound]` via
  `Test/Axioms.lean`, and that claim is scoped to the pinned symbols, not
  repository-wide.
- **Tested, not proved:** that the Rust body corresponds to the
  Lean model (differential and conformance tests over a corpus, byte-exact —
  not a proof over every input); the recorded local evidence above exercises
  the tested layer around the proven core.
- **Named assumptions:** SHA-256 collision resistance (`A-CR`);
  channel exclusivity (nothing reaches the tool except through the host —
  **an assumption, not an enforced property**); per-server parser
  equivalence (A2); key custody — seal verifies the configured authorization
  evidence, whether the key holder is the intended human is your problem;
  approval means *authorization* match, not *intent* match: an approved
  malicious request executes.
- **Profile honesty:** the deployed host runs the `compatible` profile. The
  stricter `canonical-l0` route is proved at the proof layer and is **not**
  what routed your calls today. Do not repeat this page's demo as an
  end-to-end proof claim.

## Where to go next

- [CONFIG.md](../CONFIG.md) — policy authoring and the current host-integration
  gap; it does not claim a released binary or Windows route.
- [DEPLOY.md](DEPLOY.md) — development evidence and the production controls
  that remain unshipped.
- [`CLAIMS.md`](../CLAIMS.md) — the full claims map, row by row, with what
  may and may not be said publicly.

## No source-build fallback

A source build installs the pinned Lean and Rust toolchains and can take hours.
The required clean `scripts/build_all.sh` verification had not completed when
this guide was regenerated on 2026-08-09. Until an end-to-end result is
recorded, source build is not a supported substitute for the absent release.
