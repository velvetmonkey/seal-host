# Demo protocol eras

The golden-path demos deliberately retain both MCP eras because real child servers will sit on the 2025 and 2026 revisions for a long time, and a mediator that only speaks the newest revision is not a mediator. The machine-readable declarations live in `mcp_eras.py`: the filesystem flagship is the first dual-era pattern, while the other seven golden paths remain explicitly 2025 until they receive the same end-to-end conversion.

Run the converted pattern with an explicit era:

```console
python3 demo/golden_path.py filesystem --deterministic --era 2025
python3 demo/golden_path.py filesystem --deterministic --era 2026
```

There is intentionally no default. The 2025 path performs the
`initialize`/`2025-06-18` handshake. The 2026 path starts with
`server/discover`, never sends `initialize`, and attaches the `2026-07-28`
request metadata to every request.

## Remaining conversion inventory

| Demo | Still needed for a 2026 path |
|---|---|
| `golden_path.py` (C1 shell) | Make the contained child dual-era; convert manifest capture, raw-gate, and tamper-control sessions to explicit era requests; assert modern results and receipts. |
| `golden_path_postgres.py` (C2) | Make the Python adapter dual-era; convert manifest capture and every `PostgresSession` request; carry the selected era into its receipt assertions and trace metadata. |
| `golden_path_deploy.py` (C3) | Make the deploy adapter dual-era; convert capture and hero sessions; preserve the ordered Safety/Consensus/Linear trace while attributing its era. |
| `golden_path_token.py` (C4) | Make the token-governor adapter dual-era; convert capture and budget sessions; assert modern metadata on over-cap and retry receipts. |
| `golden_path_convergence.py` (C5) | Make the mesh adapter dual-era; convert capture and stateful calls; include `_meta` in modern trace replay inputs without changing ordering. |
| `golden_path_temporal.py` (C6) | Make the freeze adapter dual-era; convert capture, trigger, and forbidden calls; retain the modern metadata through stateful trace replay. |
| `golden_path_composition.py` (C7) | Make the six-kernel adapter dual-era; convert capture and all seven ordered calls; attribute and check every modern receipt without weakening the composed narrative. |
