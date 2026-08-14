# C6 — trigger-driven Temporal freeze

C6 demonstrates one stateful Safety+Temporal session using the shipped
`init` + `add-kernel T` authoring machinery and its
`freeze-destructive-after-trigger` `no_after` policy.

The ordered runtime story is narrow:

1. `session.revoke` has a live matching Safety approval, is allowed by both
   active kernels, executes exactly once, and arms the trigger-driven freeze.
2. `audit.destroy` has its own live matching Safety approval but is denied by
   Temporal under that armed policy and never reaches the adapter.

## Honest verification labels

The pre-trigger `session.revoke` receipt is standalone: it is a fresh-state
decision and must pass the product's bundled `seal verify` self-check; that
result is not independent verification.

The post-trigger `audit.destroy` receipt is trace-scoped. Its unmodified receipt
schema is not extended; `requires_trace: <trace-transcript sha256>` lives only
in `events.ndjson`. The product's bundled `seal verify` self-check intentionally initializes a fresh
kernel, where no trigger has executed, so it re-derives ALLOW and rejects the
live-session BLOCK. That failure is the positive history-dependence exhibit,
not a defect and never an independently-verified label.

`trace-transcript.json` pins the signed config and vendored WASM SHA, embeds the
ordered canonical requests, raw per-step kernel outputs, and byte-exact runtime
receipts. `demo/trace_replay.cjs` performs one `seal_init`, feeds those requests
in order with no decision logic of its own, and byte-compares every output.
Dropping the trigger must fail with fresh-state ALLOW versus live-session BLOCK;
a one-byte transcript mutation must fail; byte-exact restoration must recover
the original SHA and a green full replay.

Fresh state is maximally permissive: freeze unarmed, Budget full, and no nonce
or Linear capability consumed. Therefore standalone stateful ALLOW receipts
attest only fresh state; session claims for Temporal, Budget, and Linear belong
on the trace lane.

We do not fake standalone verifiability by promoting state into config. That
would make the deny config-dependent, make the Temporal kernel do no work, and
leave the transition host-attested rather than kernel-attested.

The receipt claim remains mediation-only: this specific forbidden call was
denied under the armed signed policy. C6 makes no wall-clock, intent,
full-system non-occurrence, “no destructive action can ever occur,” or H1
topology×config-matrix claim.
