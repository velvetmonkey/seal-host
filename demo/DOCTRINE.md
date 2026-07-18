# Demo doctrine spine

`./demo/run c1`, `./demo/run c2`, `./demo/run c3`, `./demo/run c4`, `./demo/run c5`,
`./demo/run c6`, and `./demo/run c7` are the
deterministic, CI-load-bearing entrypoints. Each creates one artifact directory
containing:

- `events.ndjson` — the single narrative source of truth;
- `proof-manifest.json` — exact theorem names resolved from existing Lean
  `#print axioms` pins and the compiled modules that supplied them;
- `receipts/` — byte-identical copies from the runtime path;
- `receipt-strip.md` — regenerated from the NDJSON for job summaries; and
- `setup.log` — build and containment diagnostics, not persuasive narration.

Every step records the policy/config identity, participation sets, ordered
role, tool and argument digest, runtime kernel certificates, actual denying
kernel, pinned theorem references, receipt path, and a green in-run
verification result on its applicable lane. `BLOCK` is rendered as the
human-facing `DENY` while the trace retains the receipt vocabulary in
`receipt_verdict`.

## Two verification lanes

Lane A — **decision receipts (standalone)**: the frozen kernel maps
`(signed config, fresh state, request)` to the recorded verdict. Plain
`seal verify` independently replays every receipt assigned to this lane; any
non-green receipt fails CI.

Lane B — **trace transcripts (sequence)**: the frozen kernel is initialized
once with the pinned signed config and vendored WASM, then fed exactly the
recorded canonical requests in order. The demo-local replay harness contributes
only ordering and byte comparison: every raw `seal_decide` output must equal
the corresponding transcript bytes. It creates no receipt and supplies no
verdict semantics. A trace-scoped receipt carries `requires_trace` only in demo
metadata, never in the frozen receipt schema, and is never labelled
independently verified.

The Lane B finalizer requires full replay to pass, then drops the trigger and
requires a byte mismatch, flips one transcript byte and requires a mismatch,
restores the exact bytes and SHA-256, and requires full replay to pass again.

Soundness boundary: fresh state is maximally permissive—no Temporal freeze is
armed, Budget is full, and no Linear capability or approval nonce is consumed.
A standalone-verified stateful `ALLOW` therefore attests only the fresh-state
verdict and may read green even when the live session would have denied. For
Temporal, Budget, and Linear, session-context claims live exclusively on the
trace lane. A history-dependent `BLOCK` failing standalone replay is the benign
symptom; the permissive `ALLOW` direction is the real gap.

The finalizer verifies every Lane A receipt, flips one byte in an emitted
standalone receipt and requires verification to fail, restores the original
bytes and requires the SHA-256 to match, then verifies the standalone set
again. Lane B uses the transcript controls above. TTY and Markdown are
projections of `events.ndjson`; neither carries independent decision logic.

The fixed claim scope is deliberately narrow: the receipt attests the
mediation decision under the named policy. It does not establish intent,
full-system non-occurrence, or the H1 topology×config proof matrix.

C4 is the Budget+Safety token-governor sibling of C2. It uses the shipped
`token-governor` recipe and its real dotted `cost_arg` (`usage.tokens`) with a
reviewed cap of 10. Its first recorded call has a live Safety approval but is
denied by Budget at cost 11 without spending; the same prompt retries at cost
4, allows, executes exactly once, and moves the displayed remaining balance
from 10 to 6.

C3 is the Linear+Consensus+Safety deploy sibling. It uses the shipped `deploy`
recipe with a reviewed three-member roster, live votes file, real nested
`capability.id`, and a one-use grant. A 1-of-3 attempt is denied by Consensus
without committing Linear's candidate spend; 2-of-3 then allows one deployment
and consumes the capability; the identical retry is denied by Linear. Consensus
is semantically stateless (`State = Unit`, identity ingest), but artifact lanes
are assigned to whole receipts: because the receipt/verifier pair does not carry
and replay votes or Linear grant events, all three combined C3 receipts are
trace-scoped. The shared replay harness proves the Consensus veto with a
quorum-met input variant and the Linear history with a drop-DEPLOY-OK control.

C6 is the Temporal+Safety sibling of C4. It uses the shipped incremental
`init` + `add-kernel T` machinery, which emits the
`freeze-destructive-after-trigger` `no_after` policy. Its first recorded call
has a live Safety approval, allows, executes exactly once, and arms the
trigger-driven freeze. Its second recorded call has a separate live Safety
approval but is denied by Temporal and never executes. The receipt attests
only that this specific forbidden call was mediated to DENY under the armed
policy; C6 makes no wall-clock claim and does not claim that no destructive
action can ever occur. The trigger receipt is Lane A and independently verifies;
the frozen receipt is Lane B and requires the C6 transcript.

C5 is the Convergence+Safety mesh sibling. It uses the shipped `mesh` recipe
with the reviewed real `op` argument on `store.update`. Its first recorded call
has a live Safety approval, uses the kernel-fixed `orset.add` operation, allows,
and executes exactly once. Its second recorded call has a separate live Safety
approval but uses `assign`, is denied by Convergence, and never executes.
Convergence itself is stateless (`State = Unit`), so fresh replay still
re-derives BLOCK; however, the always-registered Temporal kernel's certificate
is trace-indexed, making the composite emitted bytes differ on fresh replay.
The first receipt is therefore Lane A while the second is honestly Lane B and
requires the C5 transcript. That transcript pins the exact two-call ordering
and approval-event sequence and exercises full replay, drop-trigger
byte-mismatch, byte-flip, and byte-exact restoration controls. The receipt
attests only that this specific `assign` call was mediated to DENY under the
mesh policy; C5 makes no universal replicated-store convergence claim.

C7 is the flagship six-kernel composition. It uses the shipped incremental
`init` + `add-kernel T/C/V/L/B` machinery and one signed policy with exactly
`ACTIVE {S,T,C,V,L,B}`; experimental Calibration (K) is deliberately absent.
Its headline call is mediated ALLOW with all six active kernel certificates
present and ALLOW, exhibiting `Host.registry_closed_algebra` for this one call.
Six following calls isolate one S, T, C, V, L, or B denial apiece while the
other five certificates remain ALLOW; every denial leaves candidate Linear
and Budget spend uncommitted and never reaches the adapter. All seven receipts
are Lane B because their composite bytes depend on omitted Consensus votes and
Linear grant events, with the later receipts also carrying session state. The
single transcript therefore performs full byte-exact replay, drop-trigger
mismatch, byte-flip mismatch, and exact SHA restoration plus replay. The claim
is only that each specific call was mediated under this signed policy, not
intent, full-system non-occurrence, universality, or the H1 topology×config
matrix.
