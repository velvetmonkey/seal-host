#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${1:?usage: package_release.sh VERSION OUTPUT_DIR}
OUTPUT=${2:?usage: package_release.sh VERSION OUTPUT_DIR}
ARCH=$(uname -m)
case "$ARCH" in
  x86_64) TARGET=x86_64 ;;
  aarch64|arm64) TARGET=aarch64 ;;
  *) echo "unsupported release architecture: $ARCH" >&2; exit 1 ;;
esac
NAME="seal-host-${VERSION}-linux-${TARGET}"
STAGE="$OUTPUT/$NAME"
LEAN_PREFIX=$(lean --print-prefix)

test -x "$ROOT/rust/target/release/seal-host-rs"
test -f "$ROOT/.lake/build/lib/libsealffi.so"
command -v patchelf >/dev/null || { echo "patchelf is required" >&2; exit 1; }
mkdir -p "$STAGE/bin" "$STAGE/lib" "$STAGE/licenses"
install -m 0755 "$ROOT/rust/target/release/seal-host-rs" "$STAGE/bin/seal-host-rs"
install -m 0644 "$ROOT/.lake/build/lib/libsealffi.so" "$STAGE/lib/libsealffi.so"

# Bundle the Lean runtime closure named by the freshly linked FFI library.
ldd "$ROOT/.lake/build/lib/libsealffi.so" \
  | awk -v prefix="$LEAN_PREFIX/lib/lean/" '$3 ~ ("^" prefix) {print $3}' \
  | sort -u \
  | while IFS= read -r library; do
      cp -L "$library" "$STAGE/lib/$(basename "$library")"
      chmod 0644 "$STAGE/lib/$(basename "$library")"
    done

install -m 0644 "$ROOT/LICENSE" "$STAGE/licenses/LICENSE"
install -m 0644 "$ROOT/NOTICE" "$STAGE/licenses/NOTICE"
install -m 0644 "$LEAN_PREFIX/LICENSE" "$STAGE/licenses/LEAN-LICENSE"
cp -R "$LEAN_PREFIX/LICENSES" "$STAGE/licenses/LEAN-THIRD-PARTY-LICENSES"
patchelf --set-rpath '$ORIGIN/../lib' "$STAGE/bin/seal-host-rs"
for library in "$STAGE"/lib/*.so; do patchelf --set-rpath '$ORIGIN' "$library"; done
"$ROOT/scripts/runtime_dependency_gate.sh" "$STAGE"

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner \
  -C "$OUTPUT" -czf "$OUTPUT/$NAME.tar.gz" "$NAME"
sha256sum "$OUTPUT/$NAME.tar.gz" > "$OUTPUT/$NAME.tar.gz.sha256"
echo "$OUTPUT/$NAME.tar.gz"
