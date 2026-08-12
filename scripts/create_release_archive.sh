#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Create a tar.gz whose bytes do not depend on filesystem metadata or traversal.
set -euo pipefail

# Keep all filesystem traversal and archive metadata decisions under the
# release locale, even when this helper is invoked directly.
export LC_ALL=C

STAGE=${1:?usage: create_release_archive.sh STAGE ARCHIVE}
ARCHIVE=${2:?usage: create_release_archive.sh STAGE ARCHIVE}
test -d "$STAGE" || { echo "release stage is not a directory: $STAGE" >&2; exit 1; }
NAME=$(basename "$STAGE")
PARENT=$(cd "$(dirname "$STAGE")" && pwd)

# Normalize on disk as well as in the tar headers. This catches newly added
# content without requiring every copy site to remember its source mode.
find "$STAGE" -type d -exec chmod 0755 {} +
find "$STAGE" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE/bin/seal-host-rs"

tar --sort=name --format=gnu --mtime='UTC 1970-01-01' \
  --owner=0 --group=0 --numeric-owner \
  -C "$PARENT" -cf - "$NAME" | gzip -n > "$ARCHIVE"
