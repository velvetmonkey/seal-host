#!/usr/bin/env bash
# Physical controls for link_set_audit.py.  Every case is compiled with the real
# wasm toolchain and the audit is really executed against the real objects; a
# case that is not executed proves nothing.
set -euo pipefail
cd "$(dirname "$0")"
source ./emsdk/emsdk_env.sh >/dev/null 2>&1

readonly FIXTURES=link-set-audit-fixtures
readonly AUDIT=link_set_audit.py
readonly TOOLROOT="$PWD/emsdk/upstream/bin"
scratch=$(mktemp -d)
trap 'if [[ "${KEEP_TMP:-}" == "1" || "${KEEP_TMP:-}" == "true" ]]; then :; else rm -rf -- "$scratch"; fi' EXIT
cases_run=0

# build_case NAME TARGET INIT PROVIDER...   (INIT may be "-" for none)
# EXTRA_CFLAGS, if set, is appended to every compile in the case.
build_case() {
  local name=$1 target=$2 init=$3
  shift 3
  local init_flag=()
  [[ $init != - ]] && init_flag=(-DINIT="$init")
  emcc -O2 ${EXTRA_CFLAGS:-} -DTARGET="$target" "${init_flag[@]}" \
    -c "$FIXTURES/export_root.c" -o "$scratch/$name-0.o"
  local index=1
  for provider in "$@"; do
    emcc -O2 ${EXTRA_CFLAGS:-} -c "$FIXTURES/$provider" -o "$scratch/$name-$index.o"
    index=$((index + 1))
  done
}

# run_case NAME EXPECTED_RC [extra audit args...]; every entry of the EXPECT
# array must appear in the output.
run_case() {
  local name=$1 expected_rc=$2
  shift 2
  local objects=()
  for object in "$scratch/$name-"*.o; do objects+=(--object "$object"); done
  set +e
  out=$(python3 "$AUDIT" \
    --llvm-nm "$TOOLROOT/llvm-nm" \
    --llvm-objdump "$TOOLROOT/llvm-objdump" \
    --llvm-readobj "$TOOLROOT/llvm-readobj" \
    --root seal_init --root seal_decide --root seal_mcp_version_gate \
    "${objects[@]}" "$@" 2>&1)
  rc=$?
  set -e
  printf '%s\n' "$out"
  printf '[control] %s rc=%s expected=%s\n' "$name" "$rc" "$expected_rc"
  if [[ $rc -ne $expected_rc ]]; then
    printf '[control] %s FAILED: expected rc=%s\n' "$name" "$expected_rc" >&2
    exit 1
  fi
  local wanted
  for wanted in "${EXPECT[@]}"; do
    if [[ "$out" != *"$wanted"* ]]; then
      printf '[control] %s FAILED: output does not contain %s\n' "$name" "$wanted" >&2
      exit 1
    fi
  done
  cases_run=$((cases_run + 1))
}

# 1. Read-only data in an uninitialised module is admissible.
build_case benign checked_safe - benign_provider.c
EXPECT=('EXCEPT checked-global-free symbol=checked_safe' 'PASS')
run_case benign 0

# 2. Mutable state of an uninitialised module is not.
build_case offender proof_library_offender - offender_provider.c
EXPECT=('REJECT symbol=initializer_state' 'read_by=proof_library_offender')
run_case offender 1

# 3. Load-bearing control: the same defect wearing a name that looks like
#    ordinary business logic must still be rejected.  Nothing in the audit reads
#    a package name, so this must behave exactly like case 2.
build_case renamed ordinary_business_logic - renamed_provider.c
EXPECT=('REJECT symbol=initializer_state' 'read_by=ordinary_business_logic')
run_case renamed 1

# 4. The unsafe body is named by no direct call in the link.  Its only retention
#    edge is a function pointer inside another object's static data, and it is
#    entered by call_indirect.
build_case indirect dispatch_entry initialize_fixture_dispatch \
  indirect_dispatcher_provider.c indirect_provider.c
EXPECT=(
  'retained_indirect_callers=1'
  '--stored-function--> hidden_offender'
  'REJECT symbol=initializer_state'
  'read_by=hidden_offender'
)
run_case indirect 1

# 5. The reader's OWN module is initialised; the state it reads belongs to a
#    module that is not.  A per-object rule passes this by silence.
build_case cross cross_reader initialize_fixture_reader \
  cross_reader_provider.c cross_state_provider.c
EXPECT=('REJECT symbol=foreign_state' 'read_by=cross_reader')
run_case cross 1

# 6. The reader touches only read-only data, in an initialised module; the
#    unsafety is one stored pointer away inside that table's bytes.
build_case table table_reader initialize_fixture_reader2 \
  table_reader_provider.c table_provider.c
EXPECT=('--stored-data--> table_state' 'REJECT symbol=table_state')
run_case table 1

# 7. A reference the link set cannot resolve is not "fine": it fails closed,
#    and is admitted only by an explicit pattern that is echoed in the output.
build_case missing calls_missing - missing_provider.c
EXPECT=('unresolved function reference absent_host_helper')
run_case missing 1
EXPECT=('ALLOW-UNDEFINED kind=function pattern=absent_host_* count=1 symbols=absent_host_helper' 'PASS')
run_case missing 0 --allow-undefined 'absent_host_*'

# 8. A relocation kind the model does not cover must stop the audit, not be
#    skipped.  Compiled -fPIC, the same cross-module read becomes a GOT global
#    reference that llvm-objdump prints under the read symbol's own name; if the
#    audit ignored it, case 5's defect would vanish from a PIC build.
EXTRA_CFLAGS=-fPIC build_case pic cross_reader initialize_fixture_reader \
  cross_reader_provider.c cross_state_provider.c
EXPECT=('unmodelled CODE relocation R_WASM_GLOBAL_INDEX_LEB to foreign_state')
run_case pic 2

printf '[control] %s synthetic link-set controls passed\n' "$cases_run"
