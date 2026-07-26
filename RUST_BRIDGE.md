# Rust Bridge: Trusted → Verified

How the Rust FFI host (`rust/`) moved from "trusted transport we worry about"
to "a seam whose fail-closed behavior is enforced by construction and pinned
by a conformance oracle". The Lean kernel's proofs were never in question;
this document is about everything BETWEEN the client's bytes and those
proofs.

## What seal does NOT claim (read this first)

**Seal mediates request-effects. It does not mediate responses.** Bytes the
guarded server writes back to the client are relayed verbatim (P6 below).
A compromised or chatty server can say anything to the client; seal's claim
is only that the server never *receives* a guarded call without a kernel
`Allow`. Do not restate seal's guarantee as "nothing leaks" — that claim is
false and stays false by design in V1.

**A-strict-child.** Routing follows the V1 wire protocol: a line is a
`tools/call` iff a strict JSON parse says so (byte-exact method). A line that
is NOT parseable as a tools/call (`"TOOLS/CALL"`, BOM-prefixed JSON, invalid
JSON) passes through unmediated — that is the protocol contract. A child
server with a LENIENT parser that "helpfully" interprets such a line as a
call executes outside the mediation contract. The guarded server must parse
its protocol strictly; this is a named assumption, not a theorem.

## Path inventory (source → sink → mediated?)

Effect sinks enumerated by review over `rust/src/`: one child-write helper,
one child spawn, one stdout-owner queue, private receipt/audit-state writes,
SQLite replay state, stderr telemetry, and one optional authenticated health
listener implemented in `health.rs`.

| # | Source | Sink | Mediated? |
|---|--------|------|-----------|
| P1 | stdin line (hostile) | `child_in.write_all` (classify fast path) | YES — `firstAgreementUnsafeNumber? == none`, then `seal_host_classify == 0`, literal-only mapping (`route_of_classify`); a Lean panic exits the process, never returns a routable default |
| P2 | stdin line | `child_in.write_all` (step path) | YES — `seal_host_step` route `forward`, exact parse (`route_of_step_output`) |
| P3 | stdin line | `child_in.write_all` (interactive retry) | YES — second `seal_host_step == forward` after a human-minted approval |
| P4 | operator argv | `Command::new(...).spawn()` | N/A — operator-trusted setup; the spawned child IS the guarded resource |
| P5 | kernel block response | client stdout | YES — kernel-authored bytes (`Seal.blockResponseLine`) |
| P6 | child stdout | client stdout (relay thread) | **NO — by design.** Requests are mediated; responses are not. See "What seal does NOT claim" |
| P7 | audit / A3 drops / errors | stderr | telemetry only, no effect |
| P8 | approval/token/tty evidence | (feeds Lean via A3 only) | parse failure drops the record ⇒ deny (fail-closed direction) |
| P9 | votes/grants/forecasts files | (raw text to Lean) | Lean parses; the grants cursor's line-split is drop-only |
| P10 | authenticated HTTP `GET /healthz` or `/readyz` | constant health response | N/A — operational status only; no MCP bytes, policy, approvals, receipts, child data, or mutation API |

Client stdout has one owner: child responses and host-authored refusals enter
the same bounded queue as complete newline-terminated frames. A frame is
written and flushed before the next begins. Write/flush failure is terminal;
child stdin write/flush and child stdout framing failures stop the session
fail-closed rather than being ignored.

Enforced invariant: **bytes reach the child ⇔ the Lean numeric-agreement scan
accepted and the kernel then returned classify == 0 or step route == forward
for the byte-identical line.** Every seam error, panic, or ambiguity refuses
the line and answers the client with the static `SEAM_ERROR_RESPONSE`.
Numeric disagreement returns a JSON-RPC invalid-request response naming the
exact literal the Lean scan rejected. (Step-level `"passthrough"` is
impossible in the deployed flow — step runs only on classify-mediated lines
— so `route_of_step_output` maps it to `SeamFailure`, not `Forward`.)

## Enforced by construction

1. **`Forward` is unconstructible without a kernel verdict.**
   `src/route.rs` holds the ONLY translation from kernel output to transport
   action: total functions where `Route::Forward` requires an exact
   `serde_json` parse of the kernel's output with route literally
   `"forward"`, and `ClassifyRoute::Passthrough` requires the
   literal `Ok(0)`. `main.rs` and the tests run the SAME functions — there is
   no test-mirror differential. The Rust translations are pinned by 4
   proptests (≈10k cases/run): garbage strings, mutated route fields, every
   `SeamError`, all `u32`s. The other half of the classify correspondence,
   Lean's `.passthrough` / `.act` / `.refuse` encoding as `0` / `1` / `2`,
   is pinned on real inputs by `Test/ClassifyEncoding.lean`. The guarantee
   holds because both the Lean encoding and the Rust translation are pinned.

2. **A Lean panic cannot fail open.** A compiled Lean `panic!` returns the
   type's `Inhabited` default; `seal_host_classify : UInt32` defaults to 0 =
   passthrough — a live fail-open (F1), demonstrated by
   `tests/panic_probe.rs::unguarded_lean_panic_returns_the_fail_open_default`.
   The host arms `lean_set_exit_on_panic(true)` AND `LEAN_ABORT_ON_PANIC=1`
   before the runtime initialises: a Lean panic now terminates the process
   (pipes close; nothing forwards). Verified empirically by
   `guarded_lean_panic_kills_the_process`, which drives the real binary's
   init path. If a future toolchain drops both hooks, that test goes red and
   the documented plan B applies (remove the classify fast-path; route every
   line through the `String`-returning `step`, whose panic default `""`
   already fails closed).

3. **Zero transformation of forwarded bytes.** The host reads raw bytes
   (`read_until`), hands Lean the terminator-stripped line, and on allow
   forwards the client's ORIGINAL bytes — no `format!` reconstruction, no
   CRLF rewriting. The only host transformation anywhere on the request path
   is the line-terminator strip that defines the seam's unit of judgment
   (named below as trusted framing).

4. **The FFI string seam is unambiguous.** Kernel strings are read by exact
   byte length (`seal_lean_string_size`; never `CStr`, which truncates at an
   interior NUL) and validated as strict UTF-8. NULL pointers, boxed
   scalars, non-string objects, invalid UTF-8, poisoned locks and Rust-side
   panics are all typed `SeamError`s — and `route.rs` maps every `SeamError`
   to a refusal.

5. **A refused line cannot hang the client.** Any seam failure answers with
   `SEAM_ERROR_RESPONSE` (JSON-RPC error, `id:null`). Numeric disagreement
   answers with the other host-authored refusal shape, also `id:null`, naming
   the exact literal returned by Lean. The id is null because recovering it
   would mean re-parsing raw input — the parser differential this host
   forbids. Non-UTF-8 input is refused per-line and the session survives
   (pinned by `tests/host_path.rs`).

6. **The whole path is ORACLE-tested, not spot-checked.**
   `tests/host_path.rs` drives the real binary (Lean FFI, providers, A3,
   child spawn) with `cat` as the guarded server: passthrough lines echo
   verbatim (LF and CRLF), every obfuscation disguise of a destructive call
   blocks with a DIFFERENT canonical target than the plain form, an approval
   unlocks exactly the canonical bytes (the disguise stays blocked with the
   approval in hand), and the approval is one-shot. This is
   `obfuscation_probe.mjs` promoted from demo script to conformance gate.

## Known, pinned differentials

- **Numbers beyond f64:** `serde_json` rejects `1e309` (whole parse fails);
  Lean's arbitrary-precision `JsonNumber` parses it — Lean MEDIATES a line
  the serde view can't read. Fail-closed direction (more mediation, never
  less); pinned by `known_lean_stricter_cases` so a silent flip to the
  bypass direction cannot pass CI.
- **Rust panics abort.** `libleanshared` bundles LLVM libunwind and its
  `_Unwind_*` exports shadow libgcc at load: a Rust `panic!` in any process
  linking Lean aborts instead of unwinding. Fail-closed (abort ⇒ nothing
  forwards) and pre-existing; it means `catch_unwind` in `lean.rs` is a
  belt, and process death is the actual backstop. Test code uses
  `Result`/`prop_assert!` so failures stay shrinkable.

## Residual TCB (named, not papered over)

Still trusted after this work:

- **Lean compiler, C codegen, Lean runtime** (compiles and hosts the proven
  `decide`); **emscripten** additionally in the wasm shape.
- **`scripts/ffi_shim.c`** and the `lean.h` static-inline helpers it
  re-exports (string size/cstr/is_string, panic hooks, module init).
- **`rust/src/` itself** — now minimized: routing totality is proptested,
  forwarding is verbatim, but the ~600 lines of transport are still trusted
  code, not proven code.
- **OS process model and file permissions** (A-origin): pipes, spawn, and
  write access to the trusted config, approval/token, votes/grants/forecast
  files. Whoever can write the approval file IS an approver.
- **Operator argv** (P4): the command line names the guarded server.
- **The wall clock and A3 state** (`a3.rs`): nonce set, TTL, future skew —
  exactly the host-side state the Lean proofs assume as given. Lean
  re-derives approval expiry as `min(issuedAt, now) + ttl`, so A3 is
  belt-and-braces, not the sole defense.
- **Evidence marshalling**: `serde_json`, `ed25519-dalek`, `hex` on the
  host approval path. Its NDJSON signed-token provider signs exact
  `ApprovalRecord` JSON payload bytes; the SealV2 canonical
  `(target, session, issuedAt, expiry, nonce)` token path lives in
  `mcp-seal-dev`. Failure direction is drop-the-record ⇒ deny.
- **Line framing**: the terminator strip that defines what "one line" means
  (the only byte-level transformation on the request path).
- **Host-authored refusals**: the static `SEAM_ERROR_RESPONSE` and the
  serde-framed numeric-agreement response containing only Lean's offending
  numeric token.
- **Response egress (P6)** and **A-strict-child** — see the top of this
  document; they are limitations of the claim, not bugs in the code.

## Verification snapshot (2026-07-02)

`cargo test` in `rust/`: 20 green, 0 warnings —
5 unit (a3, providers) · 11 differential (routing agreement incl. full
obfuscation disguise corpus + pathological shapes; Block-on-error and A3
proptests, ~18k generated cases) · 2 host-path oracle · 2 panic probes.
`cargo build --release` clean. `libsealffi.so` rebuilt from the updated shim
with `scripts/build_ffi_so.sh` (exports verified by `nm`).
