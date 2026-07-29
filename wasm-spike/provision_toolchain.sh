#!/usr/bin/env bash
set -euo pipefail

# Recreate the ignored wasm toolchain trees. The Lean patch is part of the
# observed toolchain: the live v4.28.0 tree is not pristine (see PROVENANCE).
readonly EMSDK_VERSION="6.0.0"
readonly EMSDK_TAG="6.0.0"
readonly EMSDK_COMMIT="d223ae73c6998296e3ab27cf81dc2c2c9fd383de"
readonly EMSCRIPTEN_RELEASE="772bb4648be4a897ca062d6adc65bc70223d2703"
readonly EMSDK_REPOSITORY="https://github.com/emscripten-core/emsdk.git"
readonly EMSCRIPTEN_ARCHIVE_SHA256="b5ed0963521f1d35b8967f20b1776327980bcfd5133166b40e018f27f2380e89"
readonly EMSCRIPTEN_ARCHIVE_BYTES="269920796"
readonly NODE_VERSION="22.16.0"
readonly NODE_ARCHIVE_SHA256="f4cb75bb036f0d0eddf6b79d9596df1aaab9ddccd6a20bf489be5abe9467e84e"

readonly LEAN_TAG="v4.28.0"
readonly LEAN_COMMIT="7e01a1bf5c70fc6167d49c345d3bf80596e9a79b"
readonly LEAN_REPOSITORY="https://github.com/leanprover/lean4.git"
readonly LEAN_PATCHED_FILE="src/runtime/interrupt.cpp"
readonly LEAN_UPSTREAM_FILE_SHA256="c44d860e9d3392a1141b75333c9d083083afe6ab2047c5d515daf44006e89953"
readonly LEAN_PATCHED_FILE_SHA256="1f7acc450960a469c909d995f1f88affc5470d28080983c8706f143d4b078c64"

# The two installed trees currently occupy about 2.2 GiB. Leave room for both
# archives, extraction, Git objects, and a failed attempt that still needs
# cleanup before requiring an operator to free space.
readonly MIN_FREE_KIB=$((8 * 1024 * 1024))

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
ROOT="$SCRIPT_DIR"
STAGE=""

usage() {
  cat <<'EOF'
Usage: ./provision_toolchain.sh [--root DIRECTORY]

Provision DIRECTORY/emsdk and DIRECTORY/lean4-src. DIRECTORY defaults to the
directory containing this script. Existing correct trees are verified and
left alone; an existing wrong or incomplete tree is refused.
EOF
}

die() {
  printf '[provision_toolchain] REFUSING: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$STAGE" && -d "$STAGE" ]]; then
    rm -rf -- "$STAGE"
  fi
}
trap cleanup EXIT

while (($#)); do
  case "$1" in
    --root)
      (($# >= 2)) || die "--root requires a directory"
      ROOT=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

for command in awk curl df git mv python3 sha256sum stat; do
  command -v "$command" >/dev/null || die "required command is missing: $command"
done

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] ||
  die "the checked archive digests support Linux x86_64 only"

mkdir -p -- "$ROOT"
ROOT=$(cd "$ROOT" && pwd -P)
readonly ROOT
readonly EMSDK_DIR="$ROOT/emsdk"
readonly LEAN_DIR="$ROOT/lean4-src"
readonly LEAN_PATCH="$SCRIPT_DIR/lean4-v4.28.0-interrupt.patch"

[[ -f "$LEAN_PATCH" ]] || die "checked-in Lean patch is missing: $LEAN_PATCH"

file_sha256() {
  sha256sum "$1" | awk '{print $1}'
}

git_head() {
  git -C "$1" rev-parse HEAD 2>/dev/null || true
}

verify_tag() {
  local directory=$1
  local tag=$2
  local expected=$3
  local actual
  actual=$(git -C "$directory" rev-parse "refs/tags/$tag^{}" 2>/dev/null || true)
  [[ "$actual" == "$expected" ]] ||
    die "$directory tag $tag resolves to ${actual:-missing}, expected $expected"
}

verify_emsdk() {
  local directory=$1
  local actual status release version_line

  [[ -d "$directory/.git" ]] || die "$directory exists but is not an emsdk Git tree"
  actual=$(git_head "$directory")
  [[ "$actual" == "$EMSDK_COMMIT" ]] ||
    die "$directory is at ${actual:-unknown}, expected emsdk $EMSDK_VERSION ($EMSDK_COMMIT)"
  verify_tag "$directory" "$EMSDK_TAG" "$EMSDK_COMMIT"
  [[ $(git -C "$directory" remote get-url origin 2>/dev/null || true) == "$EMSDK_REPOSITORY" ]] ||
    die "$directory has an unexpected origin"
  status=$(git -C "$directory" status --porcelain --untracked-files=all)
  [[ -z "$status" ]] || die "$directory has unexpected tracked or untracked changes: $status"

  release=$(python3 - "$directory/emscripten-releases-tags.json" "$EMSDK_VERSION" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    print(json.load(stream)["releases"][sys.argv[2]])
PY
)
  [[ "$release" == "$EMSCRIPTEN_RELEASE" ]] ||
    die "$directory maps Emscripten $EMSDK_VERSION to $release, expected $EMSCRIPTEN_RELEASE"
  [[ $(<"$directory/upstream/.emsdk_version") == "releases-$EMSCRIPTEN_RELEASE-64bit" ]] ||
    die "$directory has the wrong installed Emscripten release"
  [[ $(<"$directory/upstream/emscripten/emscripten-version.txt") == "\"$EMSDK_VERSION\"" ]] ||
    die "$directory has the wrong emscripten-version.txt"
  [[ $(<"$directory/node/${NODE_VERSION}_64bit/.emsdk_version") == "node-${NODE_VERSION}-64bit" ]] ||
    die "$directory has the wrong installed Node dependency"

  version_line=$(
    export EMSDK_QUIET=1
    source "$directory/emsdk_env.sh" >/dev/null
    emcc --version | head -1
  )
  [[ "$version_line" == *") $EMSDK_VERSION ("* ]] ||
    die "$directory emcc reports an unexpected version: $version_line"
  printf '[provision_toolchain] verified emsdk %s at %s\n' "$EMSDK_VERSION" "$EMSDK_COMMIT"
  printf '[provision_toolchain] %s\n' "$version_line"
}

verify_lean() {
  local directory=$1
  local actual status upstream_sha patched_sha

  [[ -d "$directory/.git" ]] || die "$directory exists but is not a Lean Git tree"
  actual=$(git_head "$directory")
  [[ "$actual" == "$LEAN_COMMIT" ]] ||
    die "$directory is at ${actual:-unknown}, expected Lean $LEAN_TAG ($LEAN_COMMIT)"
  verify_tag "$directory" "$LEAN_TAG" "$LEAN_COMMIT"
  [[ $(git -C "$directory" remote get-url origin 2>/dev/null || true) == "$LEAN_REPOSITORY" ]] ||
    die "$directory has an unexpected origin"
  status=$(git -C "$directory" status --porcelain --untracked-files=all)
  [[ "$status" == " M $LEAN_PATCHED_FILE" ]] ||
    die "$directory does not have exactly the recorded Lean compatibility change: ${status:-clean}"
  upstream_sha=$(git -C "$directory" show "HEAD:$LEAN_PATCHED_FILE" | sha256sum | awk '{print $1}')
  [[ "$upstream_sha" == "$LEAN_UPSTREAM_FILE_SHA256" ]] ||
    die "$directory upstream $LEAN_PATCHED_FILE bytes do not match $LEAN_TAG"
  patched_sha=$(file_sha256 "$directory/$LEAN_PATCHED_FILE")
  [[ "$patched_sha" == "$LEAN_PATCHED_FILE_SHA256" ]] ||
    die "$directory patched $LEAN_PATCHED_FILE has digest $patched_sha, expected $LEAN_PATCHED_FILE_SHA256"
  git -C "$directory" diff --check
  printf '[provision_toolchain] verified Lean %s at %s plus recorded compatibility patch\n' \
    "$LEAN_TAG" "$LEAN_COMMIT"
}

fetch_verified() {
  local url=$1
  local destination=$2
  local expected_sha=$3
  local expected_bytes=${4:-}
  local actual_sha actual_bytes

  printf '[provision_toolchain] fetching %s\n' "$url"
  curl --fail --location --proto '=https' --tlsv1.2 --retry 3 \
    --output "$destination.part" "$url"
  actual_sha=$(file_sha256 "$destination.part")
  [[ "$actual_sha" == "$expected_sha" ]] ||
    die "downloaded $(basename "$destination") digest $actual_sha, expected $expected_sha"
  if [[ -n "$expected_bytes" ]]; then
    actual_bytes=$(stat -c %s "$destination.part")
    [[ "$actual_bytes" == "$expected_bytes" ]] ||
      die "downloaded $(basename "$destination") is $actual_bytes bytes, expected $expected_bytes"
  fi
  mv -- "$destination.part" "$destination"
  printf '[provision_toolchain] verified sha256 %s  %s\n' "$expected_sha" "$(basename "$destination")"
}

fetch_git_ref() {
  local directory=$1
  local repository=$2
  local tag=$3
  local commit=$4

  git init -q "$directory"
  git -C "$directory" remote add origin "$repository"
  git -C "$directory" fetch --quiet --no-tags --depth 1 origin "$commit"
  [[ $(git -C "$directory" rev-parse FETCH_HEAD) == "$commit" ]] ||
    die "$repository returned the wrong commit for $commit"
  git -C "$directory" checkout --quiet --detach "$commit"
  git -C "$directory" fetch --quiet --no-tags --depth 1 origin \
    "refs/tags/$tag:refs/tags/$tag"
  verify_tag "$directory" "$tag" "$commit"
  git -C "$directory" fsck --strict --no-dangling
}

emsdk_exists=0
lean_exists=0
if [[ -e "$EMSDK_DIR" ]]; then
  emsdk_exists=1
  verify_emsdk "$EMSDK_DIR"
fi
if [[ -e "$LEAN_DIR" ]]; then
  lean_exists=1
  verify_lean "$LEAN_DIR"
fi
if ((emsdk_exists && lean_exists)); then
  printf '[provision_toolchain] toolchain already provisioned; no changes made\n'
  exit 0
fi

available_kib=$(df -Pk "$ROOT" | awk 'NR == 2 {print $4}')
[[ "$available_kib" =~ ^[0-9]+$ ]] || die "could not determine free space for $ROOT"
printf '[provision_toolchain] free-space precondition: %s KiB available; %s KiB required\n' \
  "$available_kib" "$MIN_FREE_KIB"
((available_kib >= MIN_FREE_KIB)) ||
  die "only $available_kib KiB free at $ROOT; $MIN_FREE_KIB KiB required before fetching"

STAGE="$ROOT/.toolchain-provision.$$"
mkdir -- "$STAGE"

if ((!emsdk_exists)); then
  fetch_git_ref "$STAGE/emsdk" "$EMSDK_REPOSITORY" "$EMSDK_TAG" "$EMSDK_COMMIT"
  mkdir -p -- "$STAGE/emsdk/downloads"
  fetch_verified \
    "https://storage.googleapis.com/webassembly/emscripten-releases-builds/linux/$EMSCRIPTEN_RELEASE/wasm-binaries.tar.xz" \
    "$STAGE/emsdk/downloads/$EMSCRIPTEN_RELEASE-wasm-binaries.tar.xz" \
    "$EMSCRIPTEN_ARCHIVE_SHA256" "$EMSCRIPTEN_ARCHIVE_BYTES"
  fetch_verified \
    "https://storage.googleapis.com/webassembly/emscripten-releases-builds/deps/node-v$NODE_VERSION-linux-x64.tar.xz" \
    "$STAGE/emsdk/downloads/node-v$NODE_VERSION-linux-x64.tar.xz" \
    "$NODE_ARCHIVE_SHA256"
  EMSDK_KEEP_DOWNLOADS=1 "$STAGE/emsdk/emsdk" install "$EMSDK_VERSION"
  "$STAGE/emsdk/emsdk" activate "$EMSDK_VERSION"
  find "$STAGE/emsdk/downloads" -type f -delete
  verify_emsdk "$STAGE/emsdk"
fi

if ((!lean_exists)); then
  fetch_git_ref "$STAGE/lean4-src" "$LEAN_REPOSITORY" "$LEAN_TAG" "$LEAN_COMMIT"
  [[ $(file_sha256 "$STAGE/lean4-src/$LEAN_PATCHED_FILE") == "$LEAN_UPSTREAM_FILE_SHA256" ]] ||
    die "Lean $LEAN_TAG has unexpected pre-patch $LEAN_PATCHED_FILE bytes"
  git -C "$STAGE/lean4-src" apply --check "$LEAN_PATCH"
  git -C "$STAGE/lean4-src" apply "$LEAN_PATCH"
  verify_lean "$STAGE/lean4-src"
fi

if ((!emsdk_exists)); then
  mv -- "$STAGE/emsdk" "$EMSDK_DIR"
fi
if ((!lean_exists)); then
  mv -- "$STAGE/lean4-src" "$LEAN_DIR"
fi
rmdir "$STAGE"
STAGE=""

verify_emsdk "$EMSDK_DIR"
verify_lean "$LEAN_DIR"
printf '[provision_toolchain] provisioning complete under %s\n' "$ROOT"
