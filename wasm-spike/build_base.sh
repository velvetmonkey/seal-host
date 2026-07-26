#!/usr/bin/env bash
# Rebuild the non-project object sets required by build_closure/build_wasm.
# No object directory is assumed to exist from an earlier workstation run.
set -euo pipefail
cd "$(dirname "$0")"
source ./emsdk/emsdk_env.sh >/dev/null 2>&1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CFLAGS="-O2 -I lean4-src/src/include -I gen/include -I gen -D LEAN_EMSCRIPTEN=1"

mkdir -p build-pkg build-stdlib build-spec
rm -f build-pkg/*.o build-stdlib/*.o build-spec/*.o

compile() {
  local src="$1" out="$2"
  [ -f "$src" ] || { echo "[build_base] missing source: $src" >&2; exit 1; }
  emcc $CFLAGS -c "$src" -o "$out"
  echo "  ok  $src -> $out"
}

echo "[build_base] runtime package modules"
for src in "$ROOT"/.lake/packages/consensus-lean/.lake/build/ir/Consensus/Checker.c \
           "$ROOT"/.lake/packages/temporal-logic-lean/.lake/build/ir/Temporal/*.c \
           "$ROOT"/.lake/packages/UnicodeBasic/.lake/build/ir/UnicodeBasic.c \
           "$ROOT"/.lake/packages/UnicodeBasic/.lake/build/ir/UnicodeBasic/*.c; do
  rel="${src#*/.lake/build/ir/}"
  compile "$src" "build-pkg/${rel//\//_}.o"
done

echo "[build_base] stdlib value providers"
for rel in Init Lean/Data/Json Std/Data/HashMap Std/Data/HashMap/Lemmas; do
  compile "lean4-src/stage0/stdlib/$rel.c" "build-stdlib/${rel//\//_}.o"
done

echo "[build_base] compiler-shared specialization providers"
compile "$ROOT/.lake/packages/mathlib/.lake/build/ir/Mathlib/Tactic/Linter/TextBased.c" \
  build-spec/Mathlib_Tactic_Linter_TextBased.o
compile "$ROOT/.lake/packages/mathlib/.lake/build/ir/Mathlib/Util/GetAllModules.c" \
  build-spec/Mathlib_Util_GetAllModules.o
compile "$ROOT/.lake/packages/LeanSearchClient/.lake/build/ir/LeanSearchClient.c" \
  build-spec/LeanSearchClient.o
compile "$ROOT/.lake/packages/LeanSearchClient/.lake/build/ir/LeanSearchClient/LoogleSyntax.c" \
  build-spec/LeanSearchClient_LoogleSyntax.o
compile "lean4-src/stage0/stdlib/Init/Data/Format/Syntax.c" \
  build-spec/Init_Data_Format_Syntax.o
compile "lean4-src/stage0/stdlib/Lean/Elab/App.c" \
  build-spec/Lean_Elab_App.o
compile "lean4-src/stage0/stdlib/Lean/LibrarySuggestions/Basic.c" \
  build-spec/Lean_LibrarySuggestions_Basic.o

echo "[build_base] done: pkg=$(find build-pkg -name '*.o' | wc -l), stdlib=$(find build-stdlib -name '*.o' | wc -l), spec=$(find build-spec -name '*.o' | wc -l)"
