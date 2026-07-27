# Demo run state

Measured on **2026-07-27** at commit
`5f78736f37927a304d8fdf4e0d1bc0202d4f0941` in the
`docs/demo-run-state` worktree.

The prescribed environment was exported. The shared FFI directory
`/home/monkey/src/seal-host/.lake/build/lib` exists and contains
`libsealffi.so` and `lean/Ffi.olean`. The fresh worktree itself has no `.lake/`,
no worktree-local `.lake/build/lib/lean/Ffi.olean`, and no
`rust/target/debug/seal-host-rs` or `rust/target/release/seal-host-rs`. Other
known absences were `/home/monkey/wt/seal-assurance-kit`,
`/home/monkey/wt/canary`, `TELEGRAM_BOT_TOKEN`, `SEAL_TG_ALLOWED`, and any
completed C1-C7 artifact directory containing `events.ndjson`.

Commands that could run were timeboxed at 30 seconds. No command timed out. No
Lean or Cargo build was started, and `scripts/build_ffi_so.sh` was not run.
`MEASURED` below means an invocation or filesystem/environment observation.
`INFERRED` means a conclusion from the script's control flow because an absent
prerequisite prevented the claimed demo path from running.

## Inventory

| Script | Ran? | Exit | What it needed | What it showed or how it failed |
|---|---|---:|---|---|
| `approve_cli.py` | PASS | 0 | A token-file path, 64-hex target, exact line-framed `tools/call`, and approval decision; an ephemeral key was generated | MEASURED: displayed the exact request and appended a signed ApprovalRecord v2. It did not send the record to a host or verify host acceptance. |
| `approve_telegram.py` | SKIPPED-PREREQ | 2 | `TELEGRAM_BOT_TOKEN` and a real allowed Telegram user ID | MEASURED: `TELEGRAM_BOT_TOKEN required (get from @BotFather)` |
| `doctrine.py` | PASS | 0 | Nothing for direct invocation | MEASURED: exited 0 with no output. It is a library spine and explicitly says it is not an independent demo script. |
| `doctrine_check.py` | SKIPPED-PREREQ | 1 | A complete C1-C7 artifact directory containing `events.ndjson`, receipts, and proof metadata | MEASURED with the absent artifact path: `FileNotFoundError: [Errno 2] No such file or directory: '/tmp/demorun-measure.yzCg0a/absent-artifact/events.ndjson'` |
| `dogfood_cli.py` | SKIPPED-PREREQ | 1 | Worktree-local `rust/target/debug/seal-host-rs`, plus a human decision if it reaches the approval wait | MEASURED: `seal-host-rs not built at /home/monkey/wt/demorun/rust/target/debug/seal-host-rs.` |
| `dogfood_failclosed.py` | SKIPPED-PREREQ | 1 | Worktree-local `rust/target/debug/seal-host-rs` | MEASURED: `seal-host-rs not built at /home/monkey/wt/demorun/rust/target/debug/seal-host-rs. One-time build: bash scripts/build_all.sh` |
| `dogfood_telegram.py` | SKIPPED-PREREQ | 2 | `TELEGRAM_BOT_TOKEN`, `SEAL_TG_ALLOWED`, a real Telegram exchange, and then worktree-local `rust/target/debug/seal-host-rs` | MEASURED: `NOT RUN: this demo needs a real Telegram bot — nothing is mocked.` |
| `golden_path.py` | SKIPPED-PREREQ | — (not started) | A permitted FFI/Lean plus Cargo debug build, worktree-local build outputs, and the pinned local Docker image | INFERRED: the pinned image is present, so `shell --deterministic` would immediately call `build_named_targets()`, which runs the forbidden `scripts/build_ffi_so.sh` and Cargo build. |
| `golden_path_composition.py` | SKIPPED-PREREQ | 2 | `/home/monkey/wt/seal-assurance-kit` at `d5e14d173bd8b2170e244a91ad2ddc42ae168cff`, then the C1-style debug build outputs | MEASURED: `[SKIP] demo: assurance kit missing: /home/monkey/wt/seal-assurance-kit` |
| `golden_path_convergence.py` | SKIPPED-PREREQ | 2 | `/home/monkey/wt/seal-assurance-kit` at the pinned revision, then the C1-style debug build outputs | MEASURED: `[SKIP] demo: assurance kit missing: /home/monkey/wt/seal-assurance-kit` |
| `golden_path_deploy.py` | SKIPPED-PREREQ | 1 | `/home/monkey/wt/seal-assurance-kit` at the pinned revision, then the C1-style debug build outputs | MEASURED: the missing checkout is mislabeled by the script as `[FAIL] demo: [Errno 2] No such file or directory: PosixPath('/home/monkey/wt/seal-assurance-kit')`. This inventory classifies the absent checkout as a prerequisite, not a broken demo result. |
| `golden_path_filesystem.py` | SKIPPED-PREREQ | 2 | Branch `main` (or GitHub Actions), pinned assurance kit/image, and worktree-local `rust/target/release/seal-host-rs` from the release build path | MEASURED: `[SKIP] demo: seal-host must run from main, got docs/demo-run-state` |
| `golden_path_postgres.py` | SKIPPED-PREREQ | 2 | `/home/monkey/wt/seal-assurance-kit` at the pinned revision, pinned local Postgres image, and the C1-style debug build outputs | MEASURED: `[SKIP] demo: assurance kit missing: /home/monkey/wt/seal-assurance-kit`. The pinned Postgres image was separately confirmed local. |
| `golden_path_temporal.py` | SKIPPED-PREREQ | 2 | `/home/monkey/wt/seal-assurance-kit` at the pinned revision, then the C1-style debug build outputs | MEASURED: `[SKIP] demo: assurance kit missing: /home/monkey/wt/seal-assurance-kit` |
| `golden_path_token.py` | SKIPPED-PREREQ | 2 | `/home/monkey/wt/seal-assurance-kit` at the pinned revision, then the C1-style debug build outputs | MEASURED: `[SKIP] demo: assurance kit missing: /home/monkey/wt/seal-assurance-kit` |
| `proof_manifest.py` | SKIPPED-PREREQ | — (not started) | Existing worktree-local Lean `.olean` files and the axiom-check executables | INFERRED: `generate_proof_manifest()` runs `lake exe axiom_check` and can run `lake build axiom_check`; starting it would violate this lane's no-Lean-build rule. |
| `render_trace.py` | SKIPPED-PREREQ | 1 | A generated `events.ndjson` trace | MEASURED with the absent trace path: `FileNotFoundError: [Errno 2] No such file or directory: '/tmp/demorun-measure.yzCg0a/absent-artifact/events.ndjson'` |
| `run_g7.py` | SKIPPED-PREREQ | 1 | Worktree-local `rust/target/debug/seal-host-rs`; Part B additionally needs a Canary checkout or `CANARY_ROOT` | MEASURED: `AssertionError: build first: cargo build (missing /home/monkey/wt/demorun/rust/target/debug/seal-host-rs)` |
| `seal_host_shim.py` | SKIPPED-PREREQ | 1 | Worktree-local `rust/target/debug/seal-host-rs` (or an explicit valid `SEAL_HOST_RS`) | MEASURED with a policy and `/bin/true` child: `FileNotFoundError: [Errno 2] No such file or directory` at `os.execv(BIN, ...)`. |
| `see_the_loop.py` | SKIPPED-PREREQ | 1 | Worktree-local `rust/target/debug/seal-host-rs` | MEASURED: `FileNotFoundError: [Errno 2] No such file or directory: '/home/monkey/wt/demorun/rust/target/debug/seal-host-rs'` |
| `sqlite_mcp_server.py` | PASS | 0 | A disposable database path and line-framed MCP input | MEASURED: initialized, listed both tools, executed a real SQLite `DELETE` with rowcount 1, and searched schema objects. This is an unmediated tool server component; it does not demonstrate Seal verification. |

Counts: **3 PASS / 0 FAIL / 18 SKIPPED-PREREQ / 0 NOT-ATTEMPTED = 21**.

## Runner finding

`demo/run` is an executable Python doctrine runner, not a shell script. It maps
`c1` through `c7` to `shell`, `postgres`, `deploy`, `token`, `convergence`,
`temporal`, and `composition`; forces deterministic mode; writes a fresh
artifact directory; and then requires `doctrine_check.py` to succeed. It does
not include `golden_path_filesystem.py`.

`demo/run_g7.py` is a separate two-part program. Part A drives the debug Rust
host and mock MCP server through six denial/approval cases. Part B runs a
Canary LangGraph pipeline when a Canary checkout exists. Its report target is
`/tmp/seal-host-g7/G7-REPORT.md`; it is not called by `demo/run`.

## 1. Which demos need a build?

The following need worktree-local build artifacts and were not started past
their prerequisite boundaries:

- Debug host plus the Lean/FFI closure:
  `golden_path.py`, `golden_path_postgres.py`,
  `golden_path_deploy.py`, `golden_path_token.py`,
  `golden_path_convergence.py`, `golden_path_temporal.py`, and
  `golden_path_composition.py`. Each reaches `build_named_targets()`, which
  calls `scripts/build_ffi_so.sh` and Cargo.
- Release host plus the Lean/FFI closure:
  `golden_path_filesystem.py`, via `build_named_release_targets()`.
- Existing debug host:
  `dogfood_cli.py`, `dogfood_failclosed.py`, `dogfood_telegram.py`,
  `run_g7.py`, `seal_host_shim.py`, and `see_the_loop.py`.
- Existing Lean compiled theorem artifacts:
  `proof_manifest.py`. Its implementation can itself start Lean builds, so it
  was not invoked.

The prescribed shared `SEAL_FFI_LIB_DIR` is populated, but that does not satisfy
the scripts' hard-coded worktree-local host paths or their unconditional build
steps.

## 2. Which demos show a compulsory verify step?

No measured PASS in this environment showed receiver-side verification:
`approve_cli.py` stopped after signing, `doctrine.py` was a no-op module
invocation, and `sqlite_mcp_server.py` was an unmediated server.

From source (`INFERRED` because the demos were prerequisite-blocked):

- The actual human-runnable receiver gate among the 21 scripts is
  `doctrine_check.py <artifact_dir>`. The non-`.py` `demo/run` entry makes that
  gate compulsory after every C1-C7 run; a green demo process alone is not
  enough.
- C1 (`golden_path.py`), C2 (`golden_path_postgres.py`), and C4
  (`golden_path_token.py`) run plain `seal verify` on standalone receipts and
  require corruption controls to fail.
- C3 (`golden_path_deploy.py`) and C7 (`golden_path_composition.py`) require
  trace replay for every receipt and require plain standalone verification to
  refuse.
- C5 (`golden_path_convergence.py`) and C6 (`golden_path_temporal.py`) split
  the story: the first receipt must pass plain `seal verify`; the later
  stateful receipt must fail standalone verification and pass the ordered trace
  replay.
- `golden_path_filesystem.py` independently verifies its fresh-state read,
  Safety block, bad-signature block, and first approved write, but explicitly
  does not call its stateful Budget denial independently verified.
- `dogfood_cli.py`, `dogfood_failclosed.py`, `dogfood_telegram.py`,
  `see_the_loop.py`, and `run_g7.py` demonstrate or assert runtime
  block/refusal behavior, not a compulsory independent receiver receipt check.
  `dogfood_cli.py` merely tells the operator to re-check with `seal verify`.

Thus the settled compulsory-verify product moment is present in the doctrine
runner design, but it was not observable in a successful run on this fresh
worktree.

## 3. Is any demo silently green?

**YES — TWO SOURCE-LEVEL SILENT-GREEN PATHS WERE FOUND.**

1. `see_the_loop.py` prints `=== PASS ===` and returns 0 after the two helper
   calls without asserting `o1["flowed"]` or `o2["refused"]`. The helper can
   return those flags as false without raising, so the wrapper can claim PASS
   without establishing the approve or deny outcome it advertises.
2. `run_g7.py` describes Part B as putting the host in front of a real
   LangGraph agent, but `part_b()` returns after printing `SKIPPED` when Canary
   is absent; `main()` then still prints `G7 DEMO PASSED` and returns 0. That is
   a full-demo green label after omitting one of its two advertised parts.

These are `INFERRED` source findings, not measured green executions in this
lane, because both scripts were blocked first by the absent debug host. No
silent-green claim was seen in the three measured PASS scripts:
`approve_cli.py` accurately claimed only that it signed/appended a record,
`doctrine.py` made no success claim, and `sqlite_mcp_server.py` was driven
through real requests.

## Disagreements

- There are 21 top-level `demo/*.py` files, which is the inventory used here,
  but 22 Python files recursively because `demo/tests/test_doctrine.py` also
  exists. The brief should say “21 top-level Python scripts” if the test is
  intentionally excluded.
- The required measurement branch is `docs/demo-run-state`, while
  `golden_path_filesystem.py` refuses any local branch other than `main`.
  Following the work order therefore makes that demo un-runnable before its
  other prerequisites are considered.
- `golden_path_deploy.py` reports an absent assurance-kit checkout as a demo
  `FAIL`/exit 1; its siblings report the same environmental condition as
  `SKIP`/exit 2.
- `demo/run` covers C1-C7 but not the separate
  `golden_path_filesystem.py`, despite that script being part of the 21-file
  inventory.

Evidence: RUN `demorun`; raw timeboxed logs were captured under
`/tmp/demorun-measure.yzCg0a`.
