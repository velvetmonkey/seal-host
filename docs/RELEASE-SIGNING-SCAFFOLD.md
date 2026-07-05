# Release Signing Scaffold

`.github/workflows/release-signing-scaffold.yml` is a manual-dispatch scaffold
for the future signed-release path. It does not sign artifacts today and does
not request an OIDC token. Its only output is an unsigned manifest, source-input
hashes, and the future cosign keyless command shape.

Run condition:

```text
workflow_dispatch only; acknowledge_unsigned_scaffold must be UNSIGNED-SCAFFOLD
```

Current guarantees:

- no private keys, signing keys, or secret material are committed;
- no artifact is represented as signed by this workflow;
- the uploaded `release-signing-scaffold` artifact is unsigned metadata only.

Future keyless signing must be reviewed before enabling:

- add `permissions: id-token: write` only to the real signing workflow;
- bind the expected GitHub Actions workflow identity in verification policy;
- sign a concrete artifact list produced by the release build;
- verify bundles before any release is promoted.
