#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Compare deterministic payloads from two independent export_public.sh runs.
set -euo pipefail

LEFT=${1:?usage: compare_public_exports.sh FIRST_EXPORT SECOND_EXPORT}
RIGHT=${2:?usage: compare_public_exports.sh FIRST_EXPORT SECOND_EXPORT}
test -d "$LEFT" && test -d "$RIGHT"

shopt -s nullglob
LEFT_ARTIFACTS=("$LEFT"/*.tar.gz "$LEFT"/*.cdx.json "$LEFT"/SHA256SUMS)
RIGHT_ARTIFACTS=("$RIGHT"/*.tar.gz "$RIGHT"/*.cdx.json "$RIGHT"/SHA256SUMS)
test "${#LEFT_ARTIFACTS[@]}" -ge 3
test "${#LEFT_ARTIFACTS[@]}" -eq "${#RIGHT_ARTIFACTS[@]}"

for left in "${LEFT_ARTIFACTS[@]}"; do
  name=$(basename "$left")
  test -f "$RIGHT/$name" || { echo "second export missing $name" >&2; exit 1; }
  cmp "$left" "$RIGHT/$name"
done

echo "PASS separate public export runs are byte-identical"
