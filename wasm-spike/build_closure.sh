#!/usr/bin/env bash
# Compute + compile the transitive MODULE-INITIALIZER closure for the wasm decide
# path. The Lean-generated initialize_<Mod> chain calls an initializer for every
# transitively-imported module. We must provide a real (or stub) initializer for
# each, or the runtime aborts with "missing function: initialize_<Mod>".
#
#  - Lean stdlib modules (Init.*, Std.*, Lean.*): compile the real .c from
#    lean4-src/stage0/stdlib (their inits build runtime-read constants).
#  - External proof libs (mathlib/aesop/batteries/LeanSearchClient): STUB to no-op.
#    These set up elaboration-time tactic metadata only; nothing the decide path
#    reads at runtime. Compiling them is infeasible (whole of mathlib).
set -euo pipefail
cd "$(dirname "$0")"
source ./emsdk/emsdk_env.sh >/dev/null 2>&1

STDLIB=lean4-src/stage0/stdlib
OUTDIR=build-stdlib-closure
STUBS_C=build-core/stubs.c
CFLAGS="-O2 -I lean4-src/src/include -I gen/include -I gen -D LEAN_EMSCRIPTEN=1"
STUB_RE='^initialize_(mathlib_|aesop_|batteries_|LeanSearchClient_|Mathlib_|Aesop_|Batteries_)'
mkdir -p "$OUTDIR"

# accumulate stub module names here
STUBLIST=$(mktemp)
: > "$STUBLIST"

# Preserve already-discovered external proof-library stubs across reruns.
# Otherwise an existing stubs.o masks the gap in round 1, then an empty STUBLIST
# rewrites stubs.o to no symbols and the strict link fails.
if [ -f build-core/stubs.o ]; then
  emnm build-core/stubs.o 2>/dev/null \
    | awk '/ T initialize_/ {print $NF}' \
    | grep -E "$STUB_RE" \
    | sort -u > "$STUBLIST" || true
fi

emit_stubs() {
  { echo '#include <lean/lean.h>';
    sort -u "$STUBLIST" | while read -r m; do
      [ -n "$m" ] && echo "LEAN_EXPORT lean_object* $m(uint8_t b){(void)b;return lean_io_result_mk_ok(lean_box(0));}"
    done
  } > "$STUBS_C"
  emcc $CFLAGS -c "$STUBS_C" -o build-core/stubs.o
}

# The stage-0 Init.System.IO C checked out with Lean 4.28 still uses the old
# erased-world declaration for these two opaque IO primitives, while the
# runtime archive exports the current one-world-argument ABI. Native ABIs can
# accidentally tolerate this; wasm-ld correctly reports a type mismatch.
# Normalize the generated closure object and fail if upstream changes the
# source shape, so the compatibility patch cannot silently stop applying.
normalize_init_system_io_abi() {
  local src="$STDLIB/Init/System/IO.c"
  local patched="build-core/Init_System_IO.wasm.c"
  local out="$OUTDIR/Init_System_IO.o"
  [ -f "$out" ] || return 0
  grep -qF 'lean_object* lean_io_create_tempfile();' "$src"
  grep -qF 'lean_object* lean_io_create_tempdir();' "$src"
  grep -qF 'x_2 = lean_io_create_tempfile();' "$src"
  grep -qF 'x_2 = lean_io_create_tempdir();' "$src"
  sed \
    -e 's/lean_object\* lean_io_create_tempfile();/lean_object* lean_io_create_tempfile(lean_object*);/g' \
    -e 's/lean_object\* lean_io_create_tempdir();/lean_object* lean_io_create_tempdir(lean_object*);/g' \
    -e 's/lean_io_create_tempfile();/lean_io_create_tempfile(lean_box(0));/g' \
    -e 's/lean_io_create_tempdir();/lean_io_create_tempdir(lean_box(0));/g' \
    "$src" > "$patched"
  if grep -Eq 'lean_io_create_temp(file|dir)\(\)' "$patched"; then
    echo "[closure] failed to normalize Init.System.IO runtime ABI" >&2
    exit 1
  fi
  emcc $CFLAGS -c "$patched" -o "$out"
}

# One batched emnm pass over every object -> the global symbol table for the round.
scan_syms() {
  local objs=(build-core/*.o build-seal/*.o build-pkg/*.o build-stdlib/*.o)
  local closure_objs=("$OUTDIR"/*.o)
  [ -e "${closure_objs[0]}" ] && objs+=("${closure_objs[@]}")
  emnm "${objs[@]}" 2>/dev/null
}
defined_inits()    { grep -E ' T initialize_' /tmp/seal_syms.txt | awk '{print $NF}' | sort -u; }
referenced_inits() { grep -E ' U initialize_' /tmp/seal_syms.txt | awk '{print $NF}' | sort -u; }

round=0
while :; do
  round=$((round+1))
  scan_syms > /tmp/seal_syms.txt
  comm -23 <(referenced_inits) <(defined_inits) > /tmp/gap.txt
  n=$(grep -c . /tmp/gap.txt || true)
  echo "[closure] round $round: gap=$n"
  [ "$n" -eq 0 ] && break
  progress=0
  while read -r sym; do
    [ -z "$sym" ] && continue
    if echo "$sym" | grep -qE "$STUB_RE"; then
      grep -qx "$sym" "$STUBLIST" || { echo "$sym" >> "$STUBLIST"; progress=1; }
      continue
    fi
    mod=${sym#initialize_}
    rel=${mod//_//}.c
    src="$STDLIB/$rel"
    if [ ! -f "$src" ]; then
      # fallback: locate by basename tail
      cand=$(find "$STDLIB" -path "*/$rel" 2>/dev/null | head -1)
      [ -n "$cand" ] && src="$cand"
    fi
    if [ -f "$src" ]; then
      out="$OUTDIR/$mod.o"
      if [ ! -f "$out" ]; then
        if emcc $CFLAGS -c "$src" -o "$out" 2>"$OUTDIR/$mod.log"; then
          progress=1
        else
          echo "[closure] COMPILE FAIL $mod (see $OUTDIR/$mod.log)" >&2
          exit 1
        fi
      fi
    else
      echo "[closure] NO SOURCE for non-proof runtime initializer $sym ($rel)" >&2
      exit 1
    fi
  done < /tmp/gap.txt
  emit_stubs
  [ "$progress" -eq 0 ] && { echo "[closure] no progress, stopping"; break; }
done
emit_stubs
normalize_init_system_io_abi
echo "[closure] compiled objs: $(ls "$OUTDIR"/*.o 2>/dev/null | wc -l), stubbed: $(sort -u "$STUBLIST" | grep -c .)"
echo "[closure] stub list:"; sort -u "$STUBLIST" | sed 's/^/   /'
# The stubs are a recorded debt, not a warrant: build_wasm.sh's link-set audit
# must discharge every one of them against the real relocation graph before an
# artifact may be emitted. STUB_RE only chooses what to ATTEMPT stubbing.
sort -u "$STUBLIST" > build-core/stubbed_initializers.txt
rm -f "$STUBLIST"
