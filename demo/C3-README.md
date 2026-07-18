# C3 — Linear + Consensus + Safety deploy

C3 demonstrates the shipped `deploy` recipe with exactly Safety, Consensus,
and Linear active in policy participation. A deterministic local `deploy` tool
is mediated three times under one signed policy and one kernel session:

1. `QUORUM-SHORT` presents a live Safety approval and the one-use Linear grant,
   but 1-of-3 votes is not a strict majority. Consensus denies, nothing reaches
   the adapter, and the combined deny does not commit Linear's candidate spend.
2. `DEPLOY-OK` runs after a second vote establishes 2-of-3. All three active
   kernels allow, the adapter executes exactly once, and the capability is
   committed from one remaining use to zero.
3. `REPLAY-DENY` repeats the identical deploy with Safety approval and quorum
   intact. Linear denies because the capability is exhausted; execution remains
   exactly once.

## Verification lane

Consensus is semantically fresh-state-decidable: `Kernels.consensusKernel` has
`State := Unit`, `Host.consensus_ingest_id` is identity, and
`Kernels.consensus_verdict_allow_iff` binds its allow verdict to the current
roster and votes. That is necessary but not sufficient for a standalone
receipt. The combined receipt schema carries Safety approval evidence but not
the Consensus votes or Linear grant events, and shipped `seal verify` replays
both as empty. Every C3 receipt is therefore honestly trace-scoped.

`trace-transcript.json` pins the signed config and vendored WASM, embeds the
three replay inputs and raw outputs, and is replayed by the shared
`demo/trace_replay.cjs` with one `seal_init`. Four controls are load-bearing:

- changing step 1 from 1-of-3 to 2-of-3 makes it re-derive ALLOW and mismatch;
- dropping `DEPLOY-OK` leaves the capability held, so the final deny re-derives
  ALLOW and mismatches;
- flipping one transcript byte fails; and
- byte-exact restoration recovers the original SHA-256 and a green replay.

The receipt attests only the mediation decision under the named signed policy.
Consensus here binds the deployed tool name, not the full argument bytes. C3
does not establish intent, full-system non-occurrence, that deployment cannot
occur by another route, or the H1 topology×config matrix.
