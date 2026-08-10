#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build a public source tarball with an empty HOME and an allow-listed process
# environment, so host credentials and Git URL rewrites cannot affect the result.
set -euo pipefail

ARCHIVE=${1:?usage: verify_public_source_build.sh PUBLIC_SOURCE_TARBALL}
ARCHIVE=$(realpath "$ARCHIVE")
test -f "$ARCHIVE" || { echo "public source archive not found: $ARCHIVE" >&2; exit 1; }
test -r "$ARCHIVE" || { echo "public source archive is unreadable: $ARCHIVE" >&2; exit 1; }
test -s "$ARCHIVE" || { echo "public source archive is empty: $ARCHIVE" >&2; exit 1; }
for command in git lake cargo python3 tar; do
  command -v "$command" >/dev/null || { echo "missing clean-build prerequisite: $command" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
SOURCE="$WORK/source"
EMPTY_HOME="$WORK/home"
CARGO_HOME_CLEAN="$WORK/cargo-home"
mkdir -p "$SOURCE" "$EMPTY_HOME" "$CARGO_HOME_CLEAN"
tar -xzf "$ARCHIVE" -C "$SOURCE"
test ! -e "$SOURCE/.git" || { echo "public source archive unexpectedly contains .git" >&2; exit 1; }
test ! -e "$SOURCE/.lake" || { echo "public source archive unexpectedly contains .lake" >&2; exit 1; }

RUSTUP_HOME_READONLY=$(rustup show home)
ELAN_HOME_READONLY=${ELAN_HOME:-$HOME/.elan}
LEAN_PREFIX_READONLY=$(lean --print-prefix)
test -d "$RUSTUP_HOME_READONLY" || { echo "Rust toolchain home is unavailable" >&2; exit 1; }
test -n "$ELAN_HOME_READONLY" && test -d "$ELAN_HOME_READONLY" || {
  echo "ELAN_HOME must name the preinstalled Lean toolchain" >&2
  exit 1
}
test -x "$LEAN_PREFIX_READONLY/bin/lake" || { echo "direct Lake binary is unavailable" >&2; exit 1; }

env -i \
  HOME="$EMPTY_HOME" \
  PATH="$LEAN_PREFIX_READONLY/bin:$PATH" \
  LC_ALL=C.UTF-8 \
  RUSTUP_HOME="$RUSTUP_HOME_READONLY" \
  CARGO_HOME="$CARGO_HOME_CLEAN" \
  ELAN_HOME="$ELAN_HOME_READONLY" \
  LEANBUILD=lake \
  GIT_CONFIG_NOSYSTEM=1 \
  GIT_CONFIG_GLOBAL=/dev/null \
  GIT_CONFIG_COUNT=1 \
  GIT_CONFIG_KEY_0=credential.helper \
  GIT_CONFIG_VALUE_0= \
  GIT_TERMINAL_PROMPT=0 \
  GIT_ASKPASS=/bin/false \
  SSH_ASKPASS=/bin/false \
  GIT_SSH_COMMAND=/bin/false \
  bash -c '
    set -euo pipefail
    source=$1
    home=$2
    test -z "$(find "$home" -mindepth 1 -print -quit)"
    test -z "$(git config --get-regexp "^url\..*\.insteadof$" || true)"
    test -z "$(git config --get-all credential.helper)"
    test "$(command -v lake)" = "$(lean --print-prefix)/bin/lake"
    test -f "$source/vendor/mcp-seal/lakefile.toml"
    test "$(python3 -c '\''import json,sys; p=next(p for p in json.load(open(sys.argv[1]))["packages"] if p["name"] == "«mcp-seal»"); print(p.get("type"), p.get("dir"))'\'' "$source/lake-manifest.json")" = "path vendor/mcp-seal"
    echo "PASS isolation: env -i allow-list; empty HOME; no Git system/global config, URL rewrites, credential helper, askpass, SSH, or token variables"
    cd "$source"
    lake update
    bash vendor/mcp-seal/c/build.sh
    lake build +Ffi:c.o.export
    scripts/build_ffi_so.sh
    cargo test --manifest-path rust/Cargo.toml --locked --no-fail-fast
    cargo build --manifest-path rust/Cargo.toml --locked --release --bins
    python3 -m unittest discover -s demo/tests -v
    echo "PASS public source archive builds with no private access"
  ' bash "$SOURCE" "$EMPTY_HOME"
