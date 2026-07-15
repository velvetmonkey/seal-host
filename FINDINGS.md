# seal-host — Claim Audit Findings

**Scope**: README.md, CLAIMS.md, docs/DEPLOY.md, docs/LIMITATIONS.md, docs/TCB.md and key public claims in docs/. Sampled from truthbox, "the guard", profile statements, non-claims, approval channel descriptions, and demo claims.

**Method**: Claims re-read from public surfaces, then cross-checked against shipped code (rust/src/{main.rs,providers.rs}, test/integration/{approval_loop.py,see_the_loop.py,synthetic_ledger.py}, demo/see_the_loop.py + CLI, Lean Host/ + Kernels/, conformance scripts).

**Collar**: Every DEV-ONLY / UNAUTHENTICATED label, TCB statement, truthbox, "not the whole system", "compatible profile", "AUTHORIZATION not INTENT", "tamper-EVIDENT not IMPOSSIBLE" etc. preserved verbatim in source. This table audits only.

## Sampled Claims

| Claim | Backed? | File:line / evidence | Action |
|-------|---------|----------------------|--------|
| The deployable MCP host that puts the proven Seal rulebook between an agent and real tools. Guarded calls stop until human approval for that exact request. | Yes (implemented + tested) | rust/src/main.rs (Block path + short-circuit), providers.rs (Ed25519TokenProvider + ControlFile), demo/see_the_loop.py + synthetic_ledger (shows block + flow/refused) | keep |
| Policy-covered request-effects require matching live human approval + allowing Lean kernel verdict; seam failures block; every decision emits replayable evidence. | Yes (proven at kernel + tested at host) | seal-host/CLAIMS.md + rust integration tests + Lean Host/Step.lean + conformance_bridge.mjs | keep |
| `compatible` profile is what runs (strict canonical-l0 proved but not the deployed route). | Yes (documented + implemented) | CLAIMS.md (profile table), Host/Canonical.lean vs CanonicalL0.lean, Ffi.stepImpl | keep |
| Ed25519-token channel: signed target-bound (target ‖ nonce ‖ issuedAt [+ decision:deny]); control-file is DEV-ONLY / UNAUTHENTICATED. | Yes (implemented + labeled) | rust/src/providers.rs:Ed25519TokenProvider (sig verify + decision branch, nonce+issuedAt required), ControlFileProvider (explicit deny handling + warning), demo/approve_cli.py (loud DEV-ONLY comment + TCB), DEPLOY.md | keep |
| Explicit signed decline produces "refused" (not timeout) + host audit label. | Yes (implemented + tested) | rust/src/main.rs (decline short-circuit in Block arm: "approval refused (signed decline...)"), providers (DeclineRecord), test_approval_consumer + approval_loop (assert + transcript), see_the_loop (host-emitted refused) | keep |
| CLI approver / Telegram: button is intent only; signing key produces the token. TCB stated (co-resident for CLI; bridge+allowlist for demo TG; device-held key upgrade). | Yes (implemented + documented) | demo/approve_cli.py (header + TCB print), approve_telegram.py (HMAC + from.id + device note + TCB), sign_approval.py (pure target-bound), DEPLOY.md (per-channel TCB + ORDERING vs ORIGIN) | keep |
| One-command demo over synthetic shows block → signed record → flow or refused → receipt. | Yes (runnable + captured; produces visible BLOCK hex + SYNTHETIC side-effect or host-emitted 'refused' when run) | demo/see_the_loop.py (thin over run_signed…; prints BLOCK, SYNTHETIC or refused, === PASS ===), synthetic_ledger.py (SYNTHETIC_LEDGER_ACTION), approval_loop harness (dynamic target, CLI signed, refused string); run captured in glowup evidence | keep |
| Seal proves properties of the mediation KERNEL, not of the whole deployed system. | Yes (documented + true) | README truthbox + non-claims, CLAIMS.md, docs/LIMITATIONS.md (verbatim blocks) | keep |
| Deployed bodies tied by byte-exact conformance over corpus, not proven bug-free. | Yes (tested + documented) | scripts/conformance_bridge.mjs, rust/tests/, docs/CONFORMANCE.md | keep |
| Audit chain is tamper-EVIDENT, not tamper-IMPOSSIBLE. | Yes (documented + proven under hypotheses) | docs/LIMITATIONS.md (verbatim), seal-host Host/Record.lean (tamper_evident) | keep |
| Host `ApprovalRecord` tokens are a separate signed channel from the v2 canonical approval tuple. | Yes (documented + true) | truthbox (verbatim), CLAIMS.md | keep |

## NEEDS BEN
- Full re-execution of heavy build + see_the_loop in every CI matrix (captured runs from this session + prior verification evidence in scratch provide the showcase).
- Exhaustive line audit of every Lean theorem in Host/ + Kernels/ vs every Rust line (sampled the approval path, decline, ed25519 provider, short-circuit, A3; conformance + unit tests close the loop for the public demo).
- Any claim about production Telegram bot (demo-grade only; device-held-key upgrade is the documented path).
- Private evaluator-only links referenced in docs.

All public claims sampled are backed by the cited shipped code, tests, or Lean (or are honesty labels preserved verbatim). No unbacked claims were introduced or polished.

See CLAIMS.md (single source), docs/DEPLOY.md (onboarding + TCB + ORDERING/ORIGIN panel), and the family CLAIMS-MATRIX.

---

Committed as part of the seal-host docs glow-up on docs-glowup-seal-host. The glow-up changes only README and FINDINGS (docs + light description); demo code is pre-existing shipped.