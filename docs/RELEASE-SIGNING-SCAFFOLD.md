# Release Signing Scaffold (superseded)

The former unsigned release-signing scaffold is superseded. The active
`.github/workflows/release.yml` now creates, keyless-signs, and fail-closed
verifies a concrete in-toto release-provenance statement before publication.
See [`RELEASE-PROVENANCE.md`](RELEASE-PROVENANCE.md) for its exact claim,
non-claims, key custody, and consumer command.

The old GitHub artifact-attestation call is not silently tolerated: that service
is unavailable for this user-owned public repository and has been explicitly
replaced by the signed statement. The release job has `id-token: write`, binds
the exact workflow identity, signs the complete payload digest list, and refuses
publication unless cosign and the independent digest gate both answer PASS.
