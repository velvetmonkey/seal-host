# C7 — flagship six-kernel composition

C7 activates the complete non-experimental kernel stack in one signed policy:
Safety (S), Temporal (T), Consensus (C), Convergence (V), Linear (L), and
Budget (B). Calibration (K) is deliberately absent because it is experimental
and outside every recommended recipe.

The first call is the headline: `compose.allow` carries a live approval,
two-of-three votes, a proven-convergent operation, a one-use capability, an
in-budget charge, and a Temporal-safe request. The resulting composed ALLOW
contains six ALLOW certificates. This is the narrow runtime exhibit of
`Host.registry_closed_algebra`: this one mediated ALLOW carries every active
kernel's membership-guarded invariant.

The next six calls demonstrate the fail-closed AND-gate. In order, exactly one
of Safety, Temporal, Consensus, Convergence, Linear, or Budget denies while the
other five kernels allow. None reaches the deterministic adapter, and the
candidate Linear capability and Budget charge on each denied call remain
uncommitted. Only the headline executes downstream.

## Honest verification lane

All seven receipts are trace-scoped. The receipt schema does not carry the
Consensus votes or Linear grant events required to reproduce this combined
policy with plain `seal verify`; the later receipts also include the armed
Temporal trace and committed headline spend. No receipt is labelled
independently verified.

`trace-transcript.json` pins the signed config, vendored WASM SHA, exact ordered
requests and evidence events, raw kernel outputs, and byte-identical receipts.
The replay harness initializes once and byte-compares all seven decisions. It
must pass in full, fail when the headline trigger is dropped, fail after a
one-byte mutation, regain the exact original SHA after restoration, and pass
again.

The evidence scope is mediation only. It does not establish intent,
full-system non-occurrence outside the gate, universal system behavior, or the
H1 topology×config matrix.
