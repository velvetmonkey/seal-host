/* SPDX-License-Identifier: Apache-2.0
 * Visibility shim linked into libsealffi.so: re-exports the module
 * initializer and the static-inline lean.h helpers the Rust host needs.
 */
#include <lean/lean.h>

extern lean_object* initialize_seal_x2dhost_Ffi(uint8_t builtin, lean_object* w);

LEAN_EXPORT lean_object* seal_ffi_initialize(uint8_t builtin, lean_object* w) {
    return initialize_seal_x2dhost_Ffi(builtin, w);
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
