# First-hour feel — seal developer-ingress approval loop (2026-07-11)

Ran `python3 demo/see_the_loop.py` (and twice more for verification).

Immediate impression:
- 15s to first "approval required: <target>" (synthetic, no setup).
- The one-command demo now prints the raw host BLOCK response containing "approval required: <64-hex>" (full wire message) before the summary, making the loop visible end-to-end in captured logs.
- CLI approver is a single invocation with --target --approve; it prints the exact TCB warning and appends a compact signed line.
- The "provider" simulation (real crypto verify) immediately accepts and prints "record accepted: allow".
- Side effect line appears: SYNTHETIC_LEDGER_ACTION...
- Second run with --deny: "signed deny", "record accepted: deny", then the refused block with the exact string "approval refused: ... (explicit signed decline)" and the audit note.
- No "timed out" anywhere on the deny path — explicit refused is visible in the captured transcript.

The separation is obvious even in the first run:
- You see the Lean-style block text.
- The signed token is target-bound with nonce+issuedAt.
- The deny produces a different, loud "refused" path.

The loud labels ("DEV-ONLY / UNAUTHENTICATED", "button is only an intent signal", "TCB = host + CLI + key", "co-resident attacker") are right there in the CLI output and in the quickstart banner. No one can miss them.

> The unsigned control-file / `approve_cli.py --plain` path exists only for keyless local smoke: it accepts approvals with no signature, so anyone who can write the token file can approve any call (the 64-hex target is not a secret). It is a disclosed dev convenience, never a production approval channel — production uses the signed ed25519-token channel. Full disclosure and the exact `--channel ed25519` swap: the "Control-file channel" section of [DEPLOY.md](../docs/DEPLOY.md).

Running twice produces structurally identical transcripts (different nonces and temps), exactly what the harness wants for captured logs.

Took < 3 minutes from "I wonder what this does" to having both paths and the audit evidence on disk. The docs section added to DEPLOY.md made the ORDERING (Lean) vs ORIGIN (key custody) split and the "does NOT prove" panel impossible to overlook.

Overall: the loop is now demoable in one command, the security boundaries are labeled at the point of use, and the signed decline is first-class rather than a missing-approval timeout. Exactly the developer experience the goal asked for.
