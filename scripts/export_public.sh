#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Deterministic private-to-public source exporter. Release output appears only
# after assemble -> scrub -> test -> rebuild -> pins -> SBOM -> sign -> drift.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
OUTPUT=${1:?usage: export_public.sh EMPTY_OUTPUT_DIRECTORY}
OUTPUT=$(realpath -m "$OUTPUT")
test -z "$(git -C "$ROOT" status --porcelain)" || { echo "export requires a clean worktree" >&2; exit 1; }
mkdir -p "$OUTPUT"
test -z "$(find "$OUTPUT" -mindepth 1 -maxdepth 1 -print -quit)" || { echo "output directory must be empty" >&2; exit 1; }
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
cp -a "$SOURCE" "$BUILD"

echo "==> scrub"
python3 "$SOURCE/scripts/public_scrub.py" "$SOURCE"
python3 "$BUILD/scripts/public_scrub.py" "$BUILD"

echo "==> test source-only gates"
(cd "$BUILD" && node scripts/claims-drift.mjs)
cargo fmt --manifest-path "$BUILD/rust/Cargo.toml" --check
bash -n "$BUILD/scripts"/*.sh

echo "==> rebuild and test the exported tree"
(cd "$BUILD" && { test -d .lake/packages/mcp-seal || lake update; })
(cd "$BUILD/.lake/packages/mcp-seal" && bash c/build.sh)
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
