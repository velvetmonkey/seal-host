<!-- SPDX-License-Identifier: Apache-2.0 -->
# Getting started — install v0.1.5 or build from source

This is the onboarding path: install the published v0.1.5 host or build from
source, watch it block a destructive call, approve that exact call, watch it
flow, then verify the receipt yourself — including what a tampered receipt
looks like. The released install and source build are separate alternatives;
neither is evidence for the other.

## Current availability

- Published `seal-host` releases: **1** — `v0.1.5`, published
  `2026-08-10T00:38:06Z`.
- Downloadable assets: **8** — two Linux archives, two CycloneDX SBOMs,
  `SHA256SUMS`, the provenance statement, its Sigstore bundle, and the
  standalone verifier.
- Verified Linux release-install paths: **1**. The x86_64 path below was run
  through download, checksum, provenance verification, extraction, and an
  executable-file check. Both architecture archives were opened.
- Windows/WSL2 end-to-end runs: **0**.

The release install is real. The later block/approve/flow demonstration remains
recorded local evidence: it was not rerun end to end with the published archive,
so this page does not relabel that older observation as a release-bundle run.

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

## Install and verify the published host

The release path requires Linux x86_64, GitHub CLI authenticated to GitHub,
Python 3, tar, and cosign. A checkout is needed for the configuration helpers
used after installation.

For the source path below:

- A checkout of this repository.
- Lean `4.28.0` (pinned in `lean-toolchain`) and Rust `1.96.0` (pinned in
  `rust/rust-toolchain.toml`), plus the usual native C/C++ linker toolchain
  required by Lean and Rust dependencies. Docker is not used by this path.
- `python3` with the `cryptography` package (config and approval signing).
- `node` (any current LTS; used only by the receipt verifier).
- On this shared development host, `leanbuild` must be on `PATH`; it is the
  required one-at-a-time, resource-bounded wrapper for every Lean invocation.
  `scripts/build_all.sh` uses it automatically when present. On an ordinary
  single-user machine without that wrapper, it uses `lake` directly.

`v0.1.5` is published. For the released install path, download all signed
subjects and verify them before unpacking:

```sh
mkdir -p .seal/release && cd .seal/release
tag=v0.1.5
gh release download "$tag" --repo velvetmonkey/seal-host \
  --pattern "seal-host-${tag}-linux-*" \
  --pattern release_provenance.py --pattern SHA256SUMS \
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

The source path below remains fully exercised. Run it only when choosing the
source alternative; it is not a substitute for provenance verification of a
release artifact.

## 1. Build the host from this checkout (source alternative)

This is not a quick download: a cold Lean build can take about twenty-one
minutes through the documented tamper check. The first-verdict timing is
recorded by the command below instead of promised here.

```sh
time bash scripts/build_all.sh
```

Expected: it finishes with `==> done: rust/target/debug/seal-host-rs`. Do not
continue if it exits non-zero. This command serializes Lean work through
`leanbuild` when that wrapper is available; do not wrap it in an additional
`flock`.

## 2. Stand up a gate and watch it block

Set the checkout. If you installed the release above, it already set
`SEAL_BIN`; if you chose the source alternative, set the source binary path:

```sh
export SEAL_REPO="$PWD"
# Source alternative only:
export SEAL_BIN="$SEAL_REPO/rust/target/debug/seal-host-rs"
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
works — the point is the call must *reach* it). Keep this shell and host
process alive through the next section: the approval is bound to the session
that issued the refusal.

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"database":"prod","sql":"drop table customers"}}}' > call.jsonl

mkfifo request.pipe

"$SEAL_BIN" --insecure-development-mode \
  --config trusted.json --pubkey "$(cat keys/config.pub)" \
  --channel ed25519 --token-file approvals.ndjson \
  --approval-pubkey "$(cat keys/approval.pub)" \
  -- /bin/cat < request.pipe > loop.jsonl 2> audit.log &
SEAL_HOST_PID=$!

# Keep the FIFO writer open: EOF would end the host session before approval.
exec 3> request.pipe
cat call.jsonl >&3
for _ in $(seq 1 100); do
  test -f loop.jsonl && grep -q 'approval required:' loop.jsonl && break
  sleep 0.1
done
grep -q 'approval required:' loop.jsonl
head -1 loop.jsonl > refusal.json

cat loop.jsonl
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
issued the challenge. The host above is still running; sign that live refusal,
then re-send the identical frame to its still-open request pipe. In real use
those are two terminals (that is exactly what `demo/dogfood_cli.py` walks you
through, host built from source or bundle alike). Scripted in this shell:

```sh
python3 "$SEAL_REPO/demo/approve_cli.py" --token-file approvals.ndjson \
  --refusal-file refusal.json --key-file keys/approval.key --yes > approve.log 2>&1
cat call.jsonl >&3
exec 3>&-
wait "$SEAL_HOST_PID"
```

Observed signer output includes:

```text
signed allow for target=2a01d25406f0fc82751a66ddaeb8e79d2104efc4b67699400003704e67c0c565
```

Measured: about 0.2 seconds after the human approves. Two lines come back:
first the same `approval required` refusal, then — after the signed approval landed —
**the request itself, echoed by `/bin/cat`**. The child received the bytes.
That echo is the whole product in one line: without the approval the call
never arrives; with it, it does.

Things this page deliberately did wrong first, so you know they fail closed
(each was run; each refuses): an unsigned `{"target":"…"}` approval line is
dropped (`approval_record_v1_not_supported` — the legacy unauthenticated
channel no longer admits approvals); the `ed25519` channel refuses to start
without a `replay_store` in the signed policy; a `trusted.json` with mode
`0664` is rejected at startup; and an approval signed *after* the blocking
host session exited is dropped (`target_or_subject_mismatch`) because the
challenge died with the session.

## Recorded evidence: verify a receipt and see verification fail

The two decisions from the live FIFO session emitted evidence in two forms:
a JSON receipt per decision in `./receipts/`, because that host command passed
`--receipt-dir receipts`, and an audit line carrying per-kernel certificates in
`audit.log`. Look at a receipt from the live session:

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
grep '"certs":\[' audit.log > audit.lines
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

Read the labels literally: **PROVEN** means a stated Lean theorem, not a
claim about the compiled host; **TESTED** means observed in tests or this
walkthrough, not proved for every input; **ASSUMED** names a trust-boundary
condition; **REFUTED** means this repository has a theorem or demonstration
that the stronger statement is false; and **UNKNOWN** means the page has no
evidence either way. A missing, skipped, unreadable, or unrun check is
UNKNOWN, never a passing result.

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

- [CONFIG.md](../CONFIG.md) — policy authoring after the v0.1.5 release install;
  it still does not claim a Windows route.
- [DEPLOY.md](DEPLOY.md) — development evidence and the production controls
  that remain unshipped.
- [`CLAIMS.md`](../CLAIMS.md) — the full claims map, row by row, with what
  may and may not be said publicly.

## Source build is a separate path

The source-build path is not the release install above. Its recorded cold cost
is **20m55s**, and its repair lives on a separate branch. This page does not
silently substitute that path for v0.1.5 or claim a fresh source-build run.

## Not built into the published v0.1.5 binary

The published v0.1.5 binary does not report its own version. The source-tree
version support landed after the release was built; a future release will
include it.
