# Demo doctrine spine

`./demo/run c1` and `./demo/run c2` are the deterministic, CI-load-bearing
entrypoints. Each creates one artifact directory containing:

- `events.ndjson` — the single narrative source of truth;
- `proof-manifest.json` — exact theorem names resolved from existing Lean
  `#print axioms` pins and the compiled modules that supplied them;
- `receipts/` — byte-identical copies from the runtime path;
- `receipt-strip.md` — regenerated from the NDJSON for job summaries; and
- `setup.log` — build and containment diagnostics, not persuasive narration.

Every step records the policy/config identity, participation sets, ordered
role, tool and argument digest, runtime kernel certificates, actual denying
kernel, pinned theorem references, receipt path, and a green in-run
`seal verify`. `BLOCK` is rendered as the human-facing `DENY` while the trace
retains the receipt vocabulary in `receipt_verdict`.

The finalizer verifies every copied receipt, flips one byte in an emitted
receipt and requires verification to fail, restores the original bytes and
requires the SHA-256 to match, then verifies the full set again. TTY and
Markdown are projections of `events.ndjson`; neither carries independent
decision logic.

The fixed claim scope is deliberately narrow: the receipt attests the
mediation decision under the named policy. It does not establish intent,
full-system non-occurrence, or the H1 topology×config proof matrix.
