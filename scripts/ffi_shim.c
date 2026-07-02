/* SPDX-License-Identifier: Apache-2.0
 * Visibility shim linked into libsealffi.so: re-exports the module
 * initializer and the static-inline lean.h helpers the Rust host needs.
 */
#include <lean/lean.h>

/* Lean v4.28.0 module initializers take only (uint8_t builtin) and return the
 * IO result directly -- they do NOT consume a world token. The old 2-arg decl
 * happened to work on native x86-64 (the extra arg sits in an ignored register),
 * but wasm-ld's strict call typing redirects the signature-mismatched call to a
 * trap stub -> RuntimeError: unreachable at init. Call with the real 1-arg sig.
 * The public seal_ffi_initialize keeps its (builtin, w) shape for caller ABI
 * compatibility (Rust host + wasm wrapper); w is unused. */
extern lean_object* initialize_seal_x2dhost_Ffi(uint8_t builtin);

LEAN_EXPORT lean_object* seal_ffi_initialize(uint8_t builtin, lean_object* w) {
    (void)w;
    return initialize_seal_x2dhost_Ffi(builtin);
}

LEAN_EXPORT char const* seal_lean_string_cstr(b_lean_obj_arg o) {
    return lean_string_cstr(o);
}

LEAN_EXPORT uint8_t seal_lean_io_result_is_ok(b_lean_obj_arg r) {
    return lean_io_result_is_ok(r);
}

LEAN_EXPORT void seal_lean_dec(lean_obj_arg o) {
    lean_dec(o);
}

LEAN_EXPORT lean_object* seal_lean_mk_string(char const* s, size_t n) {
    return lean_mk_string_from_bytes(s, n);
}

/* Byte size of the string INCLUDING the NUL terminator (lean_string_object
 * m_size). Content bytes = size - 1. Lets the Rust host read kernel output
 * exactly instead of stopping at an interior NUL. */
LEAN_EXPORT size_t seal_lean_string_size(b_lean_obj_arg o) {
    return lean_string_size(o);
}

/* Object-shape guard: the host must never treat a non-string result as a
 * verdict. */
LEAN_EXPORT uint8_t seal_lean_is_string(b_lean_obj_arg o) {
    return lean_is_string(o);
}

/* Fail-closed panic policy: with exit-on-panic set, a Lean panic terminates
 * the process instead of returning the type's default value. Without it,
 * `seal_host_classify`'s default is 0 = passthrough — a fail-OPEN. The host
 * sets this before mediating any byte. */
LEAN_EXPORT void seal_lean_set_exit_on_panic(uint8_t flag) {
    lean_set_exit_on_panic(flag != 0);
}

/* Test-only: force a Lean panic so the harness can verify the process dies
 * (never returns a default that could route). Returns lean_box(0) — the
 * exact fail-open value classify would yield — if the panic does NOT kill
 * the process. */
LEAN_EXPORT lean_object* seal_lean_force_panic(void) {
    return lean_panic_fn(lean_box(0), lean_mk_string("seal-host panic-path probe"));
}
