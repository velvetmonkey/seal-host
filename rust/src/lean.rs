// SPDX-License-Identifier: Apache-2.0
//! Minimal Lean 4 runtime FFI: just enough to initialise the runtime, load
//! the Ffi module's initializer and exchange lean strings.
//!
//! TCB note: everything in this file is trusted glue. A marshalling bug here
//! bypasses no Lean proof — Lean still decides — but a routing bug (e.g.
//! forwarding a line Lean said to block) would. Keep this file tiny and
//! boring.
//!
//! ROUTING PRESERVATION (the Lane C seam property, pinned by tests): the
//! route the Rust caller ACTS ON equals the verdict `seal_host_step` /
//! `seal_host_classify` RETURNED, with every `SeamError` mapped to
//! Block/Refuse and Forward constructible only from the exact
//! `"route":"forward"` literal. The proven-vs-trusted split:
//! * PINNED (pure Rust, property-tested — the binary and the tests run the
//!   SAME functions): the result→route mapping in `route.rs`
//!   (`route_of_step_output`, `route_of_classify`); tests
//!   `differential.rs::every_seam_error_variant_fails_closed` (exhaustive,
//!   compile-breaking on a new variant), `step_output_route_literal_only`,
//!   `classify_literal_only`, and the three-way harness's per-case invariant
//!   (`tests/three_way.rs`).
//! * TRUSTED GLUE (this file — not liftable to a tested pure function):
//!   `to_lean_string`/`from_lean_string`, the call mutex, `catch_unwind` and
//!   the process-wide panic policy. They cross a raw-pointer C ABI with no
//!   Lean-side counterpart to prove against, so they stay trusted, tiny and
//!   boring, and are enumerated in the Lane C boundary statement
//!   (docs/POLICY-ASSURANCE-BOUNDARY.md).
//!
//! Fail-closed seam contract:
//! * every call returns `Result`; the caller maps ANY `SeamError` to Block —
//!   there is no error value that can route bytes to the child;
//! * Lean panics terminate the process (`lean_set_exit_on_panic` +
//!   `LEAN_ABORT_ON_PANIC`) — without this, a compiled `panic!` returns the
//!   type's `default`, and `seal_host_classify`'s default is 0 = passthrough,
//!   a fail-OPEN (see `tests/panic_probe.rs` for the empirical check);
//! * kernel strings are read by exact byte length (never `CStr`, which stops
//!   at an interior NUL) and validated as strict UTF-8;
//! * a poisoned lock or a non-string result object is a `SeamError`, not a
//!   guess.

use std::ffi::c_void;
#[cfg(unix)]
use std::ffi::CStr;
use std::os::raw::{c_char, c_uint};
use std::panic::{catch_unwind, AssertUnwindSafe};
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Mutex;

type LeanObj = *mut c_void;

extern "C" {
    // libleanshared
    fn lean_initialize_runtime_module();
    fn lean_io_mark_end_initialization();
    fn lean_init_task_manager();
    // libsealffi shim (scripts/ffi_shim.c) — wraps the hidden module
    // initializer and the static-inline lean.h helpers.
    fn seal_ffi_initialize(builtin: u8, world: LeanObj) -> LeanObj;
    fn seal_lean_io_result_is_ok(r: LeanObj) -> u8;
    fn seal_lean_dec(o: LeanObj);
    fn seal_lean_mk_string(s: *const c_char, n: usize) -> LeanObj;
    fn seal_lean_string_cstr(o: LeanObj) -> *const c_char;
    fn seal_lean_string_size(o: LeanObj) -> usize;
    fn seal_lean_is_string(o: LeanObj) -> u8;
    fn seal_lean_set_exit_on_panic(flag: u8);
    fn seal_lean_force_panic() -> LeanObj;
    // libsealffi @[export] surface
    fn seal_host_init(envelope: LeanObj, pubkey: LeanObj) -> LeanObj;
    fn seal_host_step(input: LeanObj) -> LeanObj;
    fn seal_host_classify(line: LeanObj) -> c_uint;
    fn seal_host_mcp_version_gate(line: LeanObj, selected_revision: LeanObj) -> LeanObj;
    fn seal_host_mcp_revision_observe(line: LeanObj, selection: LeanObj) -> LeanObj;
    fn seal_host_first_agreement_unsafe_number(line: LeanObj) -> LeanObj;
    fn seal_host_canonical_effect(line: LeanObj) -> LeanObj;
    fn seal_policy_schema(unit: LeanObj) -> LeanObj;
    fn seal_policy_validate(payload: LeanObj) -> LeanObj;
}

/// Any failure of the FFI seam. Callers MUST treat every variant as Block;
/// none of them carries a verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeamError {
    /// A Rust-side panic during the call (caught; the Lean side exits the
    /// process on its own panics instead of returning defaults).
    Panic,
    /// The seam mutex was poisoned by an earlier panic.
    PoisonedLock,
    /// The kernel returned a NULL or non-string object where a string
    /// verdict was expected.
    NotAString,
    /// The kernel string was not valid UTF-8 (corrupted seam).
    InvalidUtf8,
}

impl std::fmt::Display for SeamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SeamError::Panic => "ffi seam panic",
            SeamError::PoisonedLock => "ffi seam lock poisoned",
            SeamError::NotAString => "ffi result not a string",
            SeamError::InvalidUtf8 => "ffi result not valid utf-8",
        };
        f.write_str(s)
    }
}

unsafe fn lean_dec(o: LeanObj) {
    if !o.is_null() && (o as usize) & 1 == 0 {
        seal_lean_dec(o);
    }
}

fn to_lean_string(s: &str) -> LeanObj {
    // Handles arbitrary byte content (including interior NULs) — no silent
    // downgrade of hostile lines.
    unsafe { seal_lean_mk_string(s.as_ptr() as *const c_char, s.len()) }
}

/// The Lean IO "world" token: `lean_box(0)`.
fn lean_world() -> LeanObj {
    1usize as LeanObj
}

/// Read a Lean string by its exact byte length (`m_size` includes the NUL
/// terminator; content is `size - 1` bytes). Rejects NULL, boxed scalars,
/// non-string objects and invalid UTF-8 — every rejection is a `SeamError`
/// the caller maps to Block.
fn from_lean_string(o: LeanObj) -> Result<String, SeamError> {
    if o.is_null() || (o as usize) & 1 == 1 {
        return Err(SeamError::NotAString);
    }
    unsafe {
        if seal_lean_is_string(o) == 0 {
            return Err(SeamError::NotAString);
        }
        let size = seal_lean_string_size(o);
        if size == 0 {
            return Err(SeamError::NotAString);
        }
        let p = seal_lean_string_cstr(o);
        if p.is_null() {
            return Err(SeamError::NotAString);
        }
        let bytes = std::slice::from_raw_parts(p as *const u8, size - 1);
        String::from_utf8(bytes.to_vec()).map_err(|_| SeamError::InvalidUtf8)
    }
}

/// Serialises all calls into the (non-thread-safe) Lean exports.
pub struct LeanHost {
    lock: Mutex<()>,
}

impl LeanHost {
    /// Initialise the Lean runtime exactly once per process, with the
    /// fail-closed panic policy armed (Lean panic ⇒ process exit, never a
    /// routable default).
    pub fn new() -> Self {
        Self::new_with_panic_guard(true)
    }

    /// Test seam for `tests/panic_probe.rs` ONLY: `guard = false` leaves the
    /// runtime's default return-a-default panic behavior in place so the
    /// probe can demonstrate the fail-open this host closes. Never call with
    /// `false` in production code.
    #[doc(hidden)]
    pub fn new_with_panic_guard(guard: bool) -> Self {
        unsafe {
            if guard {
                // Belt: runtime flag. Braces: env var read by the runtime's
                // own abort_on_panic() path. Either alone kills the process
                // on a Lean panic.
                seal_lean_set_exit_on_panic(1);
                std::env::set_var("LEAN_ABORT_ON_PANIC", "1");
            }
            lean_initialize_runtime_module();
            let res = seal_ffi_initialize(1, lean_world());
            if seal_lean_io_result_is_ok(res) == 0 {
                panic!("Lean Ffi module initialisation failed");
            }
            lean_dec(res);
            lean_io_mark_end_initialization();
            lean_init_task_manager();
        }
        LeanHost {
            lock: Mutex::new(()),
        }
    }

    fn call_string(&self, f: impl FnOnce() -> LeanObj) -> Result<String, SeamError> {
        let _g = self.lock.lock().map_err(|_| SeamError::PoisonedLock)?;
        catch_unwind(AssertUnwindSafe(|| {
            let r = f();
            let s = from_lean_string(r);
            unsafe { lean_dec(r) };
            s
        }))
        .map_err(|_| SeamError::Panic)?
    }

    pub fn init(&self, envelope: &str, pubkey: &str) -> Result<String, SeamError> {
        self.call_string(|| unsafe {
            seal_host_init(to_lean_string(envelope), to_lean_string(pubkey))
        })
    }

    pub fn step(&self, input: &str) -> Result<String, SeamError> {
        self.call_string(|| unsafe { seal_host_step(to_lean_string(input)) })
    }

    /// The policy-bundle JSON Schema — the schema projection of the SAME
    /// Lean codec whose parse projection the init path runs.
    pub fn policy_schema(&self) -> Result<String, SeamError> {
        self.call_string(|| unsafe { seal_policy_schema(lean_world()) })
    }

    /// Validate raw policy-bundle payload text through the Lean authority
    /// (number guard → JSON → parsePolicyBundle → ofBundle); returns the
    /// verdict JSON emitted by `seal_policy_validate`.
    pub fn policy_validate(&self, payload: &str) -> Result<String, SeamError> {
        self.call_string(|| unsafe { seal_policy_validate(to_lean_string(payload)) })
    }

    pub fn classify(&self, line: &str) -> Result<u32, SeamError> {
        let _g = self.lock.lock().map_err(|_| SeamError::PoisonedLock)?;
        catch_unwind(AssertUnwindSafe(|| unsafe {
            seal_host_classify(to_lean_string(line))
        }))
        .map_err(|_| SeamError::Panic)
    }

    /// Opaque call into the Lean-owned M.7 request gate.
    pub fn mcp_version_gate(
        &self,
        line: &str,
        selected_revision: &str,
    ) -> Result<String, SeamError> {
        self.call_string(|| unsafe {
            seal_host_mcp_version_gate(to_lean_string(line), to_lean_string(selected_revision))
        })
    }

    /// M.2 revision fold, kernel-owned: the selection after observing one
    /// gate-admitted line, from the selection before it. Both strings use
    /// the gate-input encoding (`""` / revision / the conflict sentinel) —
    /// the same vocabulary `mcp_version_gate` receives. The caller stores
    /// the result opaquely and maps any `SeamError` to a refused line with
    /// the selection left unchanged.
    pub fn mcp_revision_observe(&self, line: &str, selection: &str) -> Result<String, SeamError> {
        self.call_string(|| unsafe {
            seal_host_mcp_revision_observe(to_lean_string(line), to_lean_string(selection))
        })
    }

    /// Return the first raw numeric literal whose exact Lean value is not
    /// preserved by an IEEE-754 binary64 round trip. `None` means the
    /// independent agreement scan accepted every unquoted number.
    pub fn first_agreement_unsafe_number(&self, line: &str) -> Result<Option<String>, SeamError> {
        self.call_string(|| unsafe {
            seal_host_first_agreement_unsafe_number(to_lean_string(line))
        })
        .map(|literal| {
            if literal.is_empty() {
                None
            } else {
                Some(literal)
            }
        })
    }

    /// Observe the exact canonical effect fields derived by the pinned Lean
    /// kernel.  The caller must compare this opaque JSON result with Rust's
    /// independent derivation and reject every error or mismatch.
    pub fn canonical_effect(&self, line: &str) -> Result<String, SeamError> {
        self.call_string(|| unsafe { seal_host_canonical_effect(to_lean_string(line)) })
    }

    /// Test seam for `tests/panic_probe.rs` ONLY: trigger a Lean panic. With
    /// the guard armed the process must die here; if it returns, the value is
    /// the boxed default (0) — the exact fail-open classify would produce.
    #[doc(hidden)]
    pub fn force_panic_probe(&self) -> usize {
        let _g = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { seal_lean_force_panic() as usize }
    }
}

impl Default for LeanHost {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve the shared object that supplied the decision export actually
/// linked into this process. This is provenance only: hashing this artifact
/// identifies the native executor; it does not prove equivalence to the wasm
/// re-derivation body named by an authorization decision.
#[cfg(unix)]
pub fn loaded_ffi_path() -> Option<PathBuf> {
    unsafe {
        let mut info: libc::Dl_info = std::mem::zeroed();
        let symbol = seal_host_step as *const () as *const c_void;
        if libc::dladdr(symbol, &mut info) == 0 || info.dli_fname.is_null() {
            return None;
        }
        Some(PathBuf::from(
            CStr::from_ptr(info.dli_fname)
                .to_string_lossy()
                .into_owned(),
        ))
    }
}

#[cfg(not(unix))]
pub fn loaded_ffi_path() -> Option<std::path::PathBuf> {
    None
}
