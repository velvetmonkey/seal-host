# Release provenance — not published

Repository package version: **v0.1.5**. Published `seal-host` releases: **0**.
The package version is not a published release. Published release archives,
SBOMs, checksum manifests, provenance statements, and verification bundles:
**0** in each category. There is consequently no release provenance to
download or verify.

## Checked-in publication contract

The release workflow and `scripts/release_provenance.py` define a fail-closed
publication contract. They are repository implementation, not evidence that a
publication occurred.

The proposed `SEAL-RELEASE-PROVENANCE.json` is an in-toto Statement v1 over
exactly six subjects: x86-64 and AArch64 archives, their two CycloneDX SBOMs,
the standalone verifier, and `SHA256SUMS`. The proposed
`SEAL-RELEASE-PROVENANCE.sigstore.json` is its Sigstore verification bundle.
The statement and bundle are exempt from the subject set; an additional file
causes verification to refuse.

The checked-in workflow uses a keyless cosign identity scoped to:

```text
https://github.com/velvetmonkey/seal-host/.github/workflows/release.yml@refs/tags/<tag>
```

and requires the certificate issuer
`https://token.actions.githubusercontent.com`. This is a Seal-specific
provenance statement, not a GitHub artifact attestation. GitHub artifact
attestations are unavailable for this user-owned private repository.

The proposed statement's scope is narrow: the named workflow identity signed
the named payload bytes by SHA-256. It does not establish independently
controlled human signing, uncompromised infrastructure, source-to-binary
correspondence, reproducibility, hermeticity, compiler correctness, or the
applicability of Lean theorems to compiled bytes. Repository, workflow, tag,
GitHub Actions, and Sigstore control remain in the trust boundary.

## Verification status

**Current availability:** v0.1.5 was published at 2026-08-10T00:38:06Z with
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
tag=v0.1.5
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

The published v0.1.5 binary does not self-report its version: `--version`
exits 2 with `error: unknown arg: --version`. Establish this release's identity
from the verified archive name and signed provenance, not from binary output.
