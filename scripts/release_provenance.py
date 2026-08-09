#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Create and fail-closed verify Seal release provenance.

Cosign verifies who signed the statement bytes. This gate additionally verifies
that the signed in-toto subjects are exactly the payload bytes about to be
published. Neither half is optional.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import NoReturn


STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = (
    "https://github.com/velvetmonkey/seal-host/release-provenance/v1"
)
CLAIM = (
    "The named GitHub Actions release workflow identity signed a statement "
    "binding these exact release payload bytes, at these names, by SHA-256."
)
DIGEST_SCOPE = (
    "Complete file bytes of both published architecture archives, both "
    "CycloneDX JSON SBOMs, the standalone verifier, and the consolidated "
    "SHA256SUMS; extracted binaries are not separate subjects."
)
KEY_CUSTODY = (
    "Sigstore keyless ephemeral key certified for the GitHub Actions OIDC "
    "workflow identity; no long-lived release private key is stored in this "
    "repository or an Actions secret."
)
NON_CLAIMS = [
    (
        "This is not a GitHub artifact attestation and does not use GitHub's "
        "artifact attestation service."
    ),
    (
        "It does not prove that the signer workflow, tag, repository "
        "administrators, GitHub Actions, Sigstore services, build runner, "
        "compiler, dependencies, or source were uncompromised."
    ),
    (
        "It does not prove a reproducible or hermetic build, source-to-binary "
        "correspondence, or that any Lean theorem applies to compiled bytes."
    ),
    (
        "It does not establish an independently controlled human or "
        "organisational release key; repository, workflow, and tag control or "
        "the relevant hosted services can exercise this workflow identity."
    ),
    (
        "It does not separately attest an extracted binary; verification is "
        "of the exact published archive, SBOM, verifier, and checksum-manifest "
        "bytes."
    ),
    (
        "It does not make provenance or signature verification optional; "
        "absence, invalidity, digest disagreement, or an unavailable verifier "
        "is refusal, not a pass."
    ),
]
CHECKSUMS_NAME = "SHA256SUMS"
STATEMENT_NAME = "SEAL-RELEASE-PROVENANCE.json"
BUNDLE_NAME = "SEAL-RELEASE-PROVENANCE.sigstore.json"
VERIFIER_NAME = "release_provenance.py"
PROVENANCE_METADATA = {STATEMENT_NAME, BUNDLE_NAME}


def refuse(message: str) -> NoReturn:
    print(f"REFUSE release provenance: {message}", file=sys.stderr)
    raise SystemExit(1)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        refuse(f"cannot read payload {path.name}: {error}")
    return digest.hexdigest()


def require_cosign_digest(command: Path, expected: str | None) -> None:
    if expected is None:
        return
    normalized = expected.removeprefix("sha256:")
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        refuse("--cosign-sha256 must be a lowercase SHA-256 hex digest")
    actual = sha256(command)
    if actual != normalized:
        refuse(f"cosign verifier digest mismatch: expected {normalized}, actual {actual}")


def refuse_path_shadow(command: Path) -> None:
    if command.name != "cosign":
        return
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory or ".") / command.name
        if candidate.is_file() and candidate.stat().st_mode & 0o111:
            if candidate.resolve() != command.resolve():
                refuse(
                    "cosign resolution failed: PATH selects "
                    f"{candidate} before established verifier {command}"
                )
            return


def expected_payload_names(release_version: str) -> set[str]:
    if not release_version or Path(release_version).name != release_version:
        refuse("release version must be a non-empty basename")
    return {
        f"seal-host-{release_version}-linux-{arch}{suffix}"
        for arch in ("x86_64", "aarch64")
        for suffix in (".tar.gz", ".cdx.json")
    } | {VERIFIER_NAME}


def payload_paths(release_dir: Path, release_version: str) -> list[Path]:
    if not release_dir.is_dir():
        refuse(f"release directory is unavailable: {release_dir}")

    expected_payloads = expected_payload_names(release_version)
    allowed_names = expected_payloads | {CHECKSUMS_NAME} | PROVENANCE_METADATA
    entries = {path.name: path for path in release_dir.iterdir()}
    unexpected = sorted(set(entries) - allowed_names)
    if unexpected:
        refuse(
            "release directory contains files that are neither signed subjects "
            f"nor provenance metadata: {', '.join(unexpected)}"
        )

    missing = sorted(expected_payloads - set(entries))
    if missing:
        refuse(
            "release payload set is incomplete; missing expected signed subjects: "
            + ", ".join(missing)
        )

    by_name: dict[str, Path] = {}
    for name in sorted(expected_payloads):
        path = entries[name]
        if path.is_symlink() or not path.is_file():
            refuse(f"release payload is not a regular file: {name}")
        by_name[name] = path

    checksums = release_dir / CHECKSUMS_NAME
    if checksums.is_symlink() or not checksums.is_file():
        refuse(f"missing checksum manifest: {checksums}")
    by_name[CHECKSUMS_NAME] = checksums
    return [by_name[name] for name in sorted(by_name)]


def expected_checksum_bytes(paths: list[Path]) -> bytes:
    payloads = [path for path in paths if path.name != CHECKSUMS_NAME]
    return "".join(
        f"{sha256(path)}  {path.name}\n" for path in sorted(payloads, key=lambda p: p.name)
    ).encode("utf-8")


def require_checksum_manifest(paths: list[Path]) -> None:
    checksums = next(path for path in paths if path.name == CHECKSUMS_NAME)
    try:
        actual = checksums.read_bytes()
    except OSError as error:
        refuse(f"cannot read checksum manifest: {error}")
    expected = expected_checksum_bytes(paths)
    if actual != expected:
        refuse(
            "SHA256SUMS does not exactly name and hash every tarball and SBOM "
            "payload"
        )


def subjects(paths: list[Path]) -> list[dict[str, object]]:
    return [
        {"name": path.name, "digest": {"sha256": sha256(path)}}
        for path in sorted(paths, key=lambda p: p.name)
    ]


def create(args: argparse.Namespace) -> int:
    release_dir = Path(args.release_dir)
    output = Path(args.output)
    if output.parent.resolve() != release_dir.resolve() or output.name != STATEMENT_NAME:
        refuse(
            f"provenance statement output must be {STATEMENT_NAME} directly inside "
            "the release directory"
        )
    paths = payload_paths(release_dir, args.release_version)
    require_checksum_manifest(paths)

    statement = {
        "_type": STATEMENT_TYPE,
        "subject": subjects(paths),
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "claim": CLAIM,
            "digestScope": DIGEST_SCOPE,
            "signer": {
                "identity": args.signer_identity,
                "issuer": args.oidc_issuer,
                "keyCustody": KEY_CUSTODY,
            },
            "nonClaims": NON_CLAIMS,
        },
    }
    try:
        output.write_text(
            json.dumps(statement, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as error:
        refuse(f"cannot write provenance statement: {error}")
    print(f"PASS created release provenance statement with {len(paths)} exact subjects")
    return 0


def load_statement(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        refuse(f"missing provenance statement: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        refuse(f"provenance statement is unreadable or invalid JSON: {error}")
    if not isinstance(value, dict):
        refuse("provenance statement root is not an object")
    return value


def require_signature(args: argparse.Namespace, statement: Path, bundle: Path) -> None:
    if bundle.is_symlink() or not bundle.is_file():
        refuse(f"missing provenance signature bundle: {bundle}")

    cosign = args.cosign
    if "/" not in cosign:
        refuse("cosign verifier resolution requires an explicit absolute path")
    command_path = Path(cosign)
    if not command_path.is_absolute():
        refuse(f"cosign verifier path is not absolute: {cosign}")
    if not command_path.is_file() or not command_path.stat().st_mode & 0o111:
        refuse(f"cosign verifier unavailable: {cosign}")
    refuse_path_shadow(command_path)
    require_cosign_digest(command_path, args.cosign_sha256)

    verify = [str(command_path), "verify-blob", "--bundle", str(bundle)]
    if args.key:
        verify.extend(["--key", args.key])
    else:
        verify.extend(
            [
                "--certificate-identity",
                args.certificate_identity,
                "--certificate-oidc-issuer",
                args.certificate_oidc_issuer,
            ]
        )
    verify.append(str(statement))
    try:
        result = subprocess.run(verify, text=True, capture_output=True, check=False)
    except OSError as error:
        refuse(f"cosign verifier could not execute: {error}")
    evidence = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part.strip())
    if result.returncode != 0:
        detail = evidence.splitlines()[-1] if evidence else "no diagnostic output"
        refuse(f"cosign signature verification failed: {detail}")
    if not evidence:
        refuse("cosign verifier returned success without verification evidence")


def require_statement(
    statement: dict[str, object], paths: list[Path], expected_identity: str, expected_issuer: str
) -> None:
    if statement.get("_type") != STATEMENT_TYPE:
        refuse("statement _type is not in-toto Statement v1")
    if statement.get("predicateType") != PREDICATE_TYPE:
        refuse("statement predicateType is not Seal release provenance v1")

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict):
        refuse("statement predicate is missing or not an object")
    if predicate.get("claim") != CLAIM:
        refuse("statement claim is missing or changed")
    if predicate.get("digestScope") != DIGEST_SCOPE:
        refuse("statement digest scope is missing or changed")
    if predicate.get("nonClaims") != NON_CLAIMS:
        refuse("statement honest non-claims are missing or changed")
    signer = predicate.get("signer")
    if not isinstance(signer, dict):
        refuse("statement signer is missing or not an object")
    if signer.get("identity") != expected_identity:
        refuse("statement signer identity does not match the required signer")
    if signer.get("issuer") != expected_issuer:
        refuse("statement signer issuer does not match the required issuer")
    if signer.get("keyCustody") != KEY_CUSTODY:
        refuse("statement key-custody disclosure is missing or changed")

    raw_subjects = statement.get("subject")
    if not isinstance(raw_subjects, list) or not raw_subjects:
        refuse("statement has no subjects")
    actual_by_name: dict[str, str] = {}
    for subject in raw_subjects:
        if not isinstance(subject, dict):
            refuse("statement contains a non-object subject")
        name = subject.get("name")
        digest = subject.get("digest")
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not isinstance(digest, dict)
            or set(digest) != {"sha256"}
            or not isinstance(digest.get("sha256"), str)
        ):
            refuse("statement subject must have a basename and only a sha256 digest")
        if name in actual_by_name:
            refuse(f"statement contains duplicate subject: {name}")
        actual_by_name[name] = digest["sha256"]

    expected_names = {path.name for path in paths}
    actual_names = set(actual_by_name)
    if actual_names != expected_names:
        missing = ", ".join(sorted(expected_names - actual_names)) or "none"
        extra = ", ".join(sorted(actual_names - expected_names)) or "none"
        refuse(f"statement subject set mismatch (missing: {missing}; extra: {extra})")
    for path in paths:
        actual_digest = sha256(path)
        stated_digest = actual_by_name[path.name]
        if stated_digest != actual_digest:
            refuse(
                f"subject digest mismatch for {path.name}: statement "
                f"{stated_digest}, actual {actual_digest}"
            )


def verify(args: argparse.Namespace) -> int:
    release_dir = Path(args.release_dir)
    statement_path = Path(args.statement)
    bundle_path = Path(args.bundle)
    if (
        statement_path.parent.resolve() != release_dir.resolve()
        or statement_path.name != STATEMENT_NAME
    ):
        refuse(f"statement must be {STATEMENT_NAME} inside the release directory")
    if (
        bundle_path.parent.resolve() != release_dir.resolve()
        or bundle_path.name != BUNDLE_NAME
    ):
        refuse(f"bundle must be {BUNDLE_NAME} inside the release directory")
    statement = load_statement(statement_path)
    require_signature(args, statement_path, bundle_path)
    paths = payload_paths(release_dir, args.release_version)
    require_checksum_manifest(paths)
    expected_identity = args.expected_signer_identity or args.certificate_identity
    if not expected_identity:
        refuse("--expected-signer-identity is required with --key")
    expected_issuer = args.expected_oidc_issuer or args.certificate_oidc_issuer
    if not expected_issuer:
        refuse("--expected-oidc-issuer is required with --key")
    require_statement(statement, paths, expected_identity, expected_issuer)
    print(
        f"PASS release provenance: valid signature and {len(paths)} exact subject digests"
    )
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    subparsers = result.add_subparsers(dest="command", required=True)

    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--release-dir", required=True)
    create_parser.add_argument("--release-version", required=True)
    create_parser.add_argument("--output", required=True)
    create_parser.add_argument("--signer-identity", required=True)
    create_parser.add_argument("--oidc-issuer", required=True)
    create_parser.set_defaults(handler=create)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--release-dir", required=True)
    verify_parser.add_argument("--release-version", required=True)
    verify_parser.add_argument("--statement", required=True)
    verify_parser.add_argument("--bundle", required=True)
    verify_parser.add_argument("--cosign", required=True)
    verify_parser.add_argument("--cosign-sha256")
    trust = verify_parser.add_mutually_exclusive_group(required=True)
    trust.add_argument("--key")
    trust.add_argument("--certificate-identity")
    verify_parser.add_argument("--certificate-oidc-issuer")
    verify_parser.add_argument("--expected-signer-identity")
    verify_parser.add_argument("--expected-oidc-issuer")
    verify_parser.set_defaults(handler=verify)
    return result


def main() -> int:
    args = parser().parse_args()
    if args.command == "verify":
        if args.certificate_identity and not args.certificate_oidc_issuer:
            refuse("--certificate-oidc-issuer is required with --certificate-identity")
        if args.key and not args.expected_signer_identity:
            refuse("--expected-signer-identity is required with --key")
        if args.key and not args.expected_oidc_issuer:
            refuse("--expected-oidc-issuer is required with --key")
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
