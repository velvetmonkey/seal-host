# C5 — replicated-store Convergence mesh

C5 demonstrates one Safety+Convergence session using the shipped `mesh`
recipe and its reviewed real `op` argument on `store.update`.

The ordered runtime story is narrow:

1. `store.update` with `op=orset.add` has a live matching Safety approval, is
   allowed by both active kernels, executes exactly once, and returns the
   deterministic adapter result.
2. `store.update` with `op=assign` has its own live matching Safety approval
   but is denied by Convergence and never reaches the adapter.

## Honest verification labels

The first `orset.add` receipt is standalone and must pass plain `seal verify`.

The second receipt is trace-scoped for a narrower reason than C6. Convergence
is stateless (`State = Unit`), and fresh replay still re-derives BLOCK from
`assign`. But Temporal is always registered even with no configured policies,
and its certificate includes the executed-trace count. Fresh replay emits a
step-1 Temporal certificate while the live call emitted step 2, so exact
decision bytes differ and plain `seal verify` correctly reports NOT VERIFIED.
The trace label records fresh BLOCK versus live BLOCK; it does not pretend the
Convergence decision itself is history-dependent.

`trace-transcript.json` nevertheless pins the signed config and vendored WASM
SHA, the ordered canonical requests, the actual approval-event sequence, raw
per-step kernel outputs, and byte-exact runtime receipts.
`demo/trace_replay.cjs` performs one `seal_init`, feeds those requests and
events in order with no verdict logic of its own, and byte-compares every
output. Dropping step 1 removes the two approval events it ingested, so step 2
still blocks but its Safety certificate changes from allow to deny and the raw
bytes must mismatch. A one-byte transcript mutation must fail; byte-exact
restoration must recover the original SHA and a green full replay.

The Convergence decision itself is not causal: `orset.add` does not arm
`assign`'s denial. Kernel V checks each configured operation independently
against its fixed proven-convergent set. The ordered trace is required for the
composite second receipt's exact bytes, not as evidence of Convergence state.

The receipt claim remains mediation-only: this specific non-convergent call
was denied under the signed mesh policy. C5 makes no intent, full-system
non-occurrence, universal replicated-store convergence, or H1
topology×config-matrix claim.
