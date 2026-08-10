<!-- current-release: v0.1.6 -->
# Release provenance — v0.1.6 published

`seal-host` has **2** published releases. GitHub published current release
`v0.1.6` at `2026-08-10T15:21:07Z` with these **8** assets:

| Asset | Bytes |
|---|---:|
| `seal-host-v0.1.6-linux-x86_64.tar.gz` | 125272344 |
| `seal-host-v0.1.6-linux-aarch64.tar.gz` | 125898582 |
| `seal-host-v0.1.6-linux-x86_64.cdx.json` | 215433 |
| `seal-host-v0.1.6-linux-aarch64.cdx.json` | 214173 |
| `SEAL-RELEASE-PROVENANCE.json` | 2958 |
| `SEAL-RELEASE-PROVENANCE.sigstore.json` | 10399 |
| `SHA256SUMS` | 506 |
| `release_provenance.py` | 15297 |

The release page is
<https://github.com/velvetmonkey/seal-host/releases/tag/v0.1.6>.

## Download and verify

Prerequisites are Linux, GitHub CLI `gh` authenticated to GitHub, `sha256sum`,
Python 3, tar, and
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/). A
selective download must include `--pattern release_provenance.py` so the signed
standalone verifier is present. The following all-assets sequence was run from
a fresh directory on Linux x86_64:

```bash
mkdir seal-host-v0.1.6-download && cd seal-host-v0.1.6-download
gh release download v0.1.6 --repo velvetmonkey/seal-host
sha256sum -c SHA256SUMS
python3 release_provenance.py verify \
  --release-dir . \
  --release-version v0.1.6 \
  --statement SEAL-RELEASE-PROVENANCE.json \
  --bundle SEAL-RELEASE-PROVENANCE.sigstore.json \
  --certificate-identity 'https://github.com/velvetmonkey/seal-host/.github/workflows/release.yml@refs/tags/v0.1.6' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
ARCH=$(uname -m)
tar xzf "seal-host-v0.1.6-linux-${ARCH}.tar.gz"
SEAL_BIN="$PWD/seal-host-v0.1.6-linux-${ARCH}/bin/seal-host-rs"
test -x "$SEAL_BIN"
printf 'installed executable: %s\n' "seal-host-v0.1.6-linux-${ARCH}/bin/seal-host-rs"
```

Observed output:

```text
release_provenance.py: OK
seal-host-v0.1.6-linux-aarch64.cdx.json: OK
seal-host-v0.1.6-linux-aarch64.tar.gz: OK
seal-host-v0.1.6-linux-x86_64.cdx.json: OK
seal-host-v0.1.6-linux-x86_64.tar.gz: OK
PASS release provenance: valid signature and 6 exact subject digests
installed executable: seal-host-v0.1.6-linux-x86_64/bin/seal-host-rs
```

The x86_64 archive was extracted and its host was run outside every checkout.
The aarch64 archive was checksum- and provenance-verified and passed its hosted
build/container lane, but was not executed on a physical aarch64 host.

## What the statement attests

The published `SEAL-RELEASE-PROVENANCE.json` is an in-toto Statement v1 over
exactly six subjects: the x86_64 and aarch64 archives, their two CycloneDX
SBOMs, `release_provenance.py`, and `SHA256SUMS`. The published
`SEAL-RELEASE-PROVENANCE.sigstore.json` is its Sigstore verification bundle.
The statement and bundle are exempt from the subject set; an additional file
causes verification to refuse.

The keyless cosign certificate is scoped to:

```text
https://github.com/velvetmonkey/seal-host/.github/workflows/release.yml@refs/tags/v0.1.6
```

and the verifier requires issuer
`https://token.actions.githubusercontent.com`. This is a Seal-specific
provenance statement, not a GitHub artifact attestation.

The claim remains narrow: the named workflow identity signed a statement
binding the named payload bytes by SHA-256. It does not establish independently
controlled human signing, uncompromised infrastructure, source-to-binary
correspondence, reproducibility, hermeticity, compiler correctness, or the
applicability of Lean theorems to compiled bytes. Repository, workflow, tag,
GitHub Actions, and Sigstore control remain in the trust boundary.

## Verification status

**Current availability:** v0.1.6 was published at 2026-08-10T15:21:07Z with
eight assets: two Linux archives, two SBOMs, `SHA256SUMS`, the provenance
statement, its Sigstore bundle, and the standalone verifier. A failed future
release gate still produces no release; these commands name the release that
actually exists.

Install cosign, authenticate GitHub CLI to GitHub, then download the release's
verifier, both architectures' archives and SBOMs, checksum manifest, statement,
and bundle. The verifier is a release asset, so no private source checkout is
needed; it verifies its own published bytes as one of the signed subjects.

```bash
mkdir release && cd release
tag=v0.1.6
gh release download "$tag" --repo velvetmonkey/seal-host \
  --pattern "seal-host-${tag}-linux-*" \
  --pattern release_provenance.py \
  --pattern SHA256SUMS \
  --pattern SEAL-RELEASE-PROVENANCE.json \
  --pattern SEAL-RELEASE-PROVENANCE.sigstore.json
python3 release_provenance.py verify \
  --release-dir . \
  --release-version "$tag" \
  --statement SEAL-RELEASE-PROVENANCE.json \
  --bundle SEAL-RELEASE-PROVENANCE.sigstore.json \
  --certificate-identity "https://github.com/velvetmonkey/seal-host/.github/workflows/release.yml@refs/tags/${tag}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

The command succeeds only after cosign verifies the signed statement and the
gate independently confirms the exact six-subject set, every digest, the
canonical `SHA256SUMS` contents, signer description, and honest non-claims.
Missing files, an invalid signature, different bytes, an unavailable verifier,
an extra release file, a partial architecture matrix, or a verifier that returns
silent success all exit non-zero.

The first published binary, v0.1.5, does not self-report its version:
`--version` exits 2 with `error: unknown arg: --version`. That history remains
true. The current v0.1.6 x86_64 binary was physically run outside every checkout;
`--version` exited 0 and printed `0.1.6`, matching its tag.
