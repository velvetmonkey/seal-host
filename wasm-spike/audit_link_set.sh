#!/usr/bin/env bash
# Run link_set_audit.py over a real build tree's link set: exactly the objects
# build_wasm.sh links, in the same order, plus the toolchain archives that
# supply libc/libc++/compiler-rt, so no reference is left unresolved by
# accident.  Usage: ./audit_link_set.sh [BUILD_ROOT] (default: this directory).
#
# The link order matters (--allow-multiple-definition makes the first
# definition win), and glob order is LC_COLLATE-dependent, so the C locale is
# pinned here for the same reason build_wasm.sh pins it.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")"
AUDIT="$PWD/link_set_audit.py"
TOOLROOT="$PWD/emsdk/upstream/bin"
ROOT="${1:-$PWD}"
cd "$ROOT"

SYSLIB="emsdk/upstream/emscripten/cache/sysroot/lib/wasm32-emscripten"
[ -d "$SYSLIB" ] || SYSLIB="$OLDPWD/$SYSLIB"

# AUDIT_OBJECT_LIST substitutes a file of absolute object paths for the globs.
# It exists so a tamper control can swap individual objects for modified copies
# and audit the otherwise identical link set.
objects=()
if [ -n "${AUDIT_OBJECT_LIST:-}" ]; then
  objects=(--object-list "$AUDIT_OBJECT_LIST")
else
  for object in build-core/*.o build-seal/*.o build-pkg/*.o build-stdlib/*.o \
                build-stdlib-closure/*.o build-spec/*.o build-wasm-rt/*.o; do
    [ -e "$object" ] && objects+=(--object "$object")
  done
fi
archives=()
for archive in "$SYSLIB"/*.a; do
  [ -e "$archive" ] && archives+=(--archive "$archive")
done

# The JS/host boundary of the shipped link.  build_wasm.sh links with
# -sERROR_ON_UNDEFINED_SYMBOLS=0, so these really are unprovided in the final
# wasm and are satisfied (or trapped) by the JS runtime.  They are listed by
# exact name, never by wildcard, so a NEW unprovided symbol fails the audit
# instead of being absorbed by a pattern.  Every name is echoed in the output.
host_functions=(
  _abort_js __cxa_throw exit
  emscripten_asm_const_int emscripten_get_heap_max emscripten_get_now
  emscripten_resize_heap __syscall_openat
  __wasi_clock_time_get __wasi_fd_close __wasi_fd_fdstat_get
  __wasi_fd_read __wasi_fd_write
)
# Unprovided DATA is a weaker position than an unprovided call: the audit cannot
# see a segment for it, so admitting one is an operator assertion.  These are
# C++ RTTI/vtables, libc++ integer-formatting tables and the linker-defined heap
# base -- none of them a Lean module global.
host_data=(
  __heap_base
  _ZN20__em_asm_sig_builderI19__em_asm_type_tupleIJEEE6bufferE
  _ZNSt3__26__itoa10__pow10_32E
  _ZNSt3__26__itoa16__digits_base_10E
  _ZNSt3__27num_putIcNS_19ostreambuf_iteratorIcNS_11char_traitsIcEEEEE2idE
  _ZTIN4lean19unreachable_reachedE
  _ZTVN4lean19unreachable_reachedE
  _ZTVNSt3__210__function6__funcIZN4lean12task_manager12spawn_workerEvEUlvE_FvvEEE
  _ZTVNSt3__210__function6__funcIZN4lean12task_manager22spawn_dedicated_workerEP9lean_taskEUlvE_FvvEEE
)
allow=()
for symbol in "${host_functions[@]}"; do allow+=(--allow-undefined "$symbol"); done
for symbol in "${host_data[@]}"; do allow+=(--allow-undefined-data "$symbol"); done

focus=()
focus_target="${AUDIT_FOCUS:-build-core/Kernels_Temporal.o}"
[ "$focus_target" != none ] && [ -f "$focus_target" ] && focus=(--focus-object "$focus_target")

exec python3 "$AUDIT" \
  --llvm-nm "$TOOLROOT/llvm-nm" \
  --llvm-objdump "$TOOLROOT/llvm-objdump" \
  --llvm-readobj "$TOOLROOT/llvm-readobj" \
  --llvm-ar "$TOOLROOT/llvm-ar" \
  --root seal_init --root seal_decide --root seal_mcp_version_gate \
  ${AUDIT_EXTRA:-} \
  "${focus[@]}" "${objects[@]}" "${archives[@]}" "${allow[@]}"
