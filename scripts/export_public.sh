#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Deterministic private-to-public source exporter. Release output appears only
# after assemble -> scrub -> test -> rebuild -> pins -> SBOM -> sign -> drift.
set -euo pipefail

SCRIPT_DIR="${BASH_SOURCE[0]%/*}"
if [[ "$SCRIPT_DIR" == "${BASH_SOURCE[0]}" ]]; then
  SCRIPT_DIR=.
fi
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT=${1:?usage: export_public.sh EMPTY_OUTPUT_DIRECTORY}
OUTPUT=$(realpath -m "$OUTPUT")
WORKTREE_STATUS="$(git -C "$ROOT" status --porcelain)"
test -z "$WORKTREE_STATUS" || { echo "export requires a clean worktree" >&2; exit 1; }
mkdir -p "$OUTPUT"
OUTPUT_ENTRY="$(find "$OUTPUT" -mindepth 1 -maxdepth 1 -print -quit)"
test -z "$OUTPUT_ENTRY" || { echo "output directory must be empty" >&2; exit 1; }
for command in git lake cargo node python3 cosign tar gzip sha256sum; do
  command -v "$command" >/dev/null || { echo "missing exporter prerequisite: $command" >&2; exit 1; }
done
cargo cyclonedx --version >/dev/null

REVISION=$(git -C "$ROOT" rev-parse HEAD)
EPOCH=$(git -C "$ROOT" show -s --format=%ct "$REVISION")
WORK=$(mktemp -d)
trap 'rm -rf -- "$WORK"' EXIT
SOURCE="$WORK/source"
BUILD="$WORK/build"
SIGNED="$WORK/signed"
mkdir -p "$SOURCE" "$SIGNED"

echo "==> assemble $REVISION"
git -C "$ROOT" archive "$REVISION" | tar -xf - -C "$SOURCE"
test -d "$ROOT/.lake/packages/mcp-seal" || (cd "$ROOT" && lake update)
python3 "$SOURCE/scripts/prepare_public_source.py" \
  "$SOURCE" "$ROOT/.lake/packages/mcp-seal"
python3 "$SOURCE/scripts/retired_public_reference_gate.py" \
  --root "$SOURCE" --all-files
cp -a "$SOURCE" "$BUILD"

echo "==> scrub"
python3 "$SOURCE/scripts/public_scrub.py" "$SOURCE"
python3 "$BUILD/scripts/public_scrub.py" "$BUILD"

echo "==> test source-only gates"
(cd "$BUILD" && node scripts/claims-surface-drift.mjs)
cargo fmt --manifest-path "$BUILD/rust/Cargo.toml" --check
bash -n "$BUILD/scripts"/*.sh

echo "==> rebuild and test the exported tree"
(cd "$BUILD" && lake update)
(cd "$BUILD/vendor/mcp-seal" && bash c/build.sh)
(cd "$BUILD" && lake build +Ffi:c.o.export && scripts/build_ffi_so.sh)
(cd "$BUILD/rust" && cargo test --locked --no-fail-fast && cargo build --locked --release --bins)
(cd "$BUILD" && python3 -m unittest discover -s demo/tests -v)

echo "==> assert pins and public topology"
python3 "$SOURCE/scripts/public_scrub.py" "$SOURCE"

echo "==> generate CycloneDX SBOM"
(cd "$BUILD/rust" && cargo cyclonedx --format json --override-filename seal-host-rust.cdx)
install -m 0644 "$BUILD/rust/seal-host-rust.cdx.json" "$SIGNED/seal-host-${REVISION}.cdx.json"

archive() {
  local source=$1 destination=$2
  tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
    -C "$source" -cf - . | gzip -n > "$destination"
}
archive "$SOURCE" "$SIGNED/seal-host-${REVISION}-source.tar.gz"
(cd "$SIGNED" && sha256sum *.tar.gz *.cdx.json > SHA256SUMS)

echo "==> sign source, SBOM, and checksum manifest"
SIGN_ARGS=(--yes)
if [ -n "${SEAL_EXPORT_SIGNING_KEY:-}" ]; then SIGN_ARGS+=(--key "$SEAL_EXPORT_SIGNING_KEY"); fi
for artifact in "$SIGNED"/*.tar.gz "$SIGNED"/*.cdx.json "$SIGNED/SHA256SUMS"; do
  cosign sign-blob "${SIGN_ARGS[@]}" --bundle "$artifact.sigstore.json" "$artifact"
done

cp -a "$SIGNED"/. "$OUTPUT"/
echo "PASS signed deterministic public export: $OUTPUT"
