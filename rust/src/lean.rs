// SPDX-License-Identifier: Apache-2.0
//! Minimal Lean 4 runtime FFI: just enough to initialise the runtime, load
//! the Ffi module's initializer and exchange lean strings.
//!
//! TCB note: everything in this file is trusted glue. A marshalling bug here
//! bypasses no Lean proof — Lean still decides — but a routing bug (e.g.
//! forwarding a line Lean said to block) would. Keep this file tiny and
//! boring.

use std::ffi::c_void;
use std::os::raw::{c_char, c_uint};
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
    // libsealffi @[export] surface
    fn seal_host_init(envelope: LeanObj, pubkey: LeanObj) -> LeanObj;
    fn seal_host_step(input: LeanObj) -> LeanObj;
    fn seal_host_classify(line: LeanObj) -> c_uint;
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

fn from_lean_string(o: LeanObj) -> String {
    unsafe {
        let p = seal_lean_string_cstr(o);
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// Serialises all calls into the (non-thread-safe) Lean exports.
pub struct LeanHost {
    lock: Mutex<()>,
}

impl LeanHost {
    /// Initialise the Lean runtime exactly once per process.
    pub fn new() -> Self {
        unsafe {
            lean_initialize_runtime_module();
            let res = seal_ffi_initialize(1, lean_world());
            if seal_lean_io_result_is_ok(res) == 0 {
                panic!("Lean Ffi module initialisation failed");
            }
            lean_dec(res);
            lean_io_mark_end_initialization();
            lean_init_task_manager();
        }
        LeanHost { lock: Mutex::new(()) }
    }

    pub fn init(&self, envelope: &str, pubkey: &str) -> String {
        let _g = self.lock.lock().unwrap();
        unsafe {
            let r = seal_host_init(to_lean_string(envelope), to_lean_string(pubkey));
            let s = from_lean_string(r);
            lean_dec(r);
            s
        }
    }

    pub fn step(&self, input: &str) -> String {
        let _g = self.lock.lock().unwrap();
        unsafe {
            let r = seal_host_step(to_lean_string(input));
            let s = from_lean_string(r);
            lean_dec(r);
            s
        }
    }

    pub fn classify(&self, line: &str) -> u32 {
        let _g = self.lock.lock().unwrap();
        unsafe { seal_host_classify(to_lean_string(line)) }
    }
}
