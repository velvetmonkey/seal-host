# Operations: V1 core profile

This runbook covers the small operational surface shipped with the compatible
stdio host. It does not add metrics, tracing, SIEM export, an enterprise
database, HA, or an enforcement ladder.

## Authenticated health and readiness

The listener is opt-in. `--health` binds `127.0.0.1:9464` by default and
startup refuses unless a private token file is supplied. An explicit
`--health-listen` changes the address; wildcard binds still require the token
and should also be protected by a host firewall. There is no configuration
that starts an unauthenticated listener.

```sh
umask 077
openssl rand -hex 32 > /var/lib/seal-host/health.token

seal-host-rs \
  --health \
  --health-token-file /var/lib/seal-host/health.token \
  ...

TOKEN="$(tr -d '\r\n' < /var/lib/seal-host/health.token)"
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9464/healthz
curl -fsS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9464/readyz
```

`/healthz` means the health thread is serving. `/readyz` returns 200 only
after config, receipt/audit state, replay state, and the child transport have
started; it drops to 503 when the child/output transport is known dead or
during shutdown. Requests are capped at 8 KiB, connections have short I/O
timeouts, and only `GET /healthz` and `GET /readyz` are accepted.

## Authorization-decision retention and redaction

Authorization decisions contain full tool arguments, the signed policy, kernel
output, and approval metadata. Treat the authorization-decision directory as sensitive even
though it is mode `0700` and each artifact is mode `0600`.

Choose a retention period from legal, incident-response, and data-minimization
requirements; 30 days is an example, not a product default. Copy artifacts to
an access-controlled archive before deletion when audit retention requires it.
Delete only `receipt-<20 digits>-<64 hex>.json`; never delete
`.seal-audit-head.state` while the host is running. Stop the service before
bulk retention work so file selection is stable.

Do not redact an authorization decision in place: removing or replacing arguments destroys the
artifact the verifier re-derives. A disclosure-safe derivative must be labelled
`NON-VERIFIABLE REDACTED EXPORT`, retain the SHA-256 of the original artifact,
and live outside the authorization-decision directory. Keep or destroy the original according
to the retention policy; never present the derivative as a valid authorization decision.

## Key rotation and secret storage

Config-signing and approval-signing keys must remain separate.

1. Generate new keys in the secret manager or hardware-backed signer. Do not
   place private keys in the host arguments, config envelope, receipt tree, or
   token spool.
2. Re-sign the policy with the new config key. Stage the new trusted envelope
   mode `0600` and update the service's config public-key argument in one
   restart.
3. Update the approval public key and signer together. Drain or remove tokens
   signed by the old approval key; they will fail verification after restart.
4. Restart, check authenticated readiness, exercise one block and one signed
   approval, then revoke the old key in the secret manager.

The CLI demo's `.seal/*.key` files are device-local development secrets, not a
production secret-storage recommendation. Production service accounts should
receive only public verification keys; private signing operations belong in a
separate signer or secret manager with an audit trail.

## Replay-store backup and recovery

The SQLite replay database is live security state. Back it up with SQLite's
online backup operation so WAL state is included:

```sh
umask 077
sqlite3 /var/lib/seal-host/replay.sqlite \
  ".backup '/secure-backup/seal-replay-$(date +%Y%m%dT%H%M%S).sqlite'"
chmod 600 /secure-backup/seal-replay-*.sqlite
```

Recovery is fail-closed:

1. Stop the host.
2. Ensure the service state and authorization-decision directories are owner-only `0700`.
3. Restore the database to a temporary file in the state directory, set mode
   `0600`, fsync it, atomically rename it to `replay.sqlite`, and fsync the
   parent directory.
4. A stale backup may omit a recently consumed nonce. Before accepting new
   work, rotate the approval key and clear old token-spool entries (preferred),
   or keep the service stopped beyond the maximum configured approval TTL.
5. Start the host, require `/readyz` 200, and confirm a known consumed token is
   rejected before reopening traffic.

Back up the authorization-decision directory and `.seal-audit-head.state` as one generation if
cross-process audit continuity is required. Restoring only the head state or
only the authorization decisions creates an honest, detectable continuity gap; it does not
reconstruct missing evidence.
