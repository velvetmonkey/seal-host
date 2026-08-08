# Release provenance

GitHub artifact attestations are unavailable for this user-owned private
repository. The release workflow therefore does not call
`actions/attest-build-provenance` or `actions/attest`. It replaces that service
with a fail-closed Seal release-provenance statement signed by Sigstore cosign.
Publication remains gated: missing or invalid provenance is a hard failure.

## What the statement attests

`SEAL-RELEASE-PROVENANCE.json` is an in-toto Statement v1. Its subjects are the
exact published `*.tar.gz`, `*.cdx.json`, and consolidated `SHA256SUMS` file
bytes, named by release-asset basename and digested with SHA-256. Its companion
`SEAL-RELEASE-PROVENANCE.sigstore.json` is the Sigstore verification bundle.
The statement and bundle are not recursive subjects of the statement.

Cosign signs with a keyless ephemeral key certified for:

```text
https://github.com/velvetmonkey/seal-host/.github/workflows/release.yml@refs/tags/<tag>
```

The certificate must be issued by
`https://token.actions.githubusercontent.com`. No long-lived release private
key is committed to the repository or stored in an Actions secret. The claim is
narrow: the named GitHub Actions workflow identity signed a statement binding
the named exact payload bytes by SHA-256.

The statement carries its non-claims as signed data. In particular, it is not a
GitHub artifact attestation; it is not an independently controlled human or
organisation signing key; and it does not prove uncompromised infrastructure,
source-to-binary correspondence, reproducibility, hermeticity, compiler
correctness, or applicability of Lean theorems to compiled bytes. Repository,
workflow, and tag control and the GitHub Actions and Sigstore services remain in
the trust boundary.

## Verify a downloaded release

Install cosign, place all release payloads, the statement, and its bundle in one
directory, and run:

```bash
python3 scripts/release_provenance.py verify \
  --release-dir release \
  --statement release/SEAL-RELEASE-PROVENANCE.json \
  --bundle release/SEAL-RELEASE-PROVENANCE.sigstore.json \
  --certificate-identity "https://github.com/velvetmonkey/seal-host/.github/workflows/release.yml@refs/tags/v0.1.2" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

The command succeeds only after cosign verifies the signed statement and the
gate independently confirms the exact expected subject set, every digest, the
canonical `SHA256SUMS` contents, signer description, and honest non-claims.
Missing files, an invalid signature, different bytes, an unavailable verifier,
or a verifier that returns silent success all exit non-zero.
