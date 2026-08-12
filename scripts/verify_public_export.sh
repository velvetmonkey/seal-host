#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Consume every Sigstore bundle emitted by export_public.sh, then prove that
# the same bundle does not verify a byte-modified payload.
set -euo pipefail

DIRECTORY=${1:?usage: verify_public_export.sh SIGNED_EXPORT_DIRECTORY}
test -d "$DIRECTORY" || { echo "signed export directory not found: $DIRECTORY" >&2; exit 1; }
COSIGN_BIN=${COSIGN_BIN:?COSIGN_BIN must name the installed cosign binary}
COSIGN_SHA256=${COSIGN_SHA256:?COSIGN_SHA256 must pin the installed cosign binary}
case "$COSIGN_BIN" in
  /*) ;;
  *) echo "COSIGN_BIN must be an absolute path" >&2; exit 1 ;;
esac
test -r "$COSIGN_BIN" && test -x "$COSIGN_BIN" || { echo "installed cosign binary is unavailable: $COSIGN_BIN" >&2; exit 1; }
path_cosign=$(PATH="$PATH" type -P cosign || true)
test -z "$path_cosign" || test "$path_cosign" = "$COSIGN_BIN" || {
  echo "cosign resolution failed: PATH selects $path_cosign before established verifier $COSIGN_BIN" >&2
  exit 1
}
actual_cosign_sha256=$(sha256sum "$COSIGN_BIN" | awk '{print $1}')
test "$actual_cosign_sha256" = "$COSIGN_SHA256" || {
  echo "cosign verifier digest mismatch: expected $COSIGN_SHA256, actual $actual_cosign_sha256" >&2
  exit 1
}

VERIFY_ARGS=()
if [ -n "${SEAL_EXPORT_SIGNING_KEY:-}" ]; then
  test -n "${SEAL_EXPORT_VERIFYING_KEY:-}" || {
    echo "SEAL_EXPORT_VERIFYING_KEY is required with SEAL_EXPORT_SIGNING_KEY" >&2
    exit 1
  }
  VERIFY_ARGS+=(--key "$SEAL_EXPORT_VERIFYING_KEY")
else
  test -n "${GITHUB_WORKFLOW_REF:-}" || {
    echo "GITHUB_WORKFLOW_REF is required for keyless export verification" >&2
    exit 1
  }
  VERIFY_ARGS+=(
    --certificate-identity "${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_WORKFLOW_REF}"
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
  )
fi

shopt -s nullglob
ARTIFACTS=("$DIRECTORY"/*.tar.gz "$DIRECTORY"/*.cdx.json "$DIRECTORY"/SHA256SUMS)
test "${#ARTIFACTS[@]}" -ge 3 || {
  echo "signed export is missing source, SBOM, or checksum artifacts" >&2
  exit 1
}

for artifact in "${ARTIFACTS[@]}"; do
  bundle="$artifact.sigstore.json"
  test -s "$bundle" || { echo "missing signature bundle: $bundle" >&2; exit 1; }
  "$COSIGN_BIN" verify-blob "${VERIFY_ARGS[@]}" --bundle "$bundle" "$artifact"
done

TAMPER_DIR=$(mktemp -d)
trap 'rm -rf -- "$TAMPER_DIR"' EXIT
TAMPERED="$TAMPER_DIR/$(basename "${ARTIFACTS[0]}")"
cp "${ARTIFACTS[0]}" "$TAMPERED"
printf '\0tampered' >> "$TAMPERED"
if "$COSIGN_BIN" verify-blob "${VERIFY_ARGS[@]}" \
    --bundle "${ARTIFACTS[0]}.sigstore.json" "$TAMPERED" \
    >"$TAMPER_DIR/verify.out" 2>&1; then
  echo "tampered blob unexpectedly verified" >&2
  exit 1
fi

echo "PASS verified ${#ARTIFACTS[@]} signed export artifacts"
echo "PASS tampered blob rejected"
