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
