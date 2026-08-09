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

There is no reader verification procedure because there is no published
release. The checked-in verifier is configured to reject a missing file,
invalid signature, digest mismatch, non-canonical checksum manifest, extra
file, incomplete architecture matrix, or silent verifier success. Those are
implementation properties of the publication gate, not evidence of a release.
