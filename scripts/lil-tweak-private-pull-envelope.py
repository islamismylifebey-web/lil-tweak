#!/usr/bin/env python3
"""Create a release-bound, encrypted GHCR pull-auth envelope."""

from __future__ import annotations

import argparse
import base64
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


class EnvelopeError(Exception):
    """A request that must fail without reflecting credential material."""


class CryptoUnavailable(Exception):
    """The fixed OpenSSL executable is unavailable."""


LOWER_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
LOWER_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
NONZERO_INTEGER = re.compile(r"[1-9][0-9]*\Z")
SAFE_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9])?\Z"
)
IMAGE_COMPONENT = re.compile(r"[a-z0-9]+(?:[._-]+[a-z0-9]+)*\Z")
UTC_SECOND = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
PUBLIC_KEY_PEM = re.compile(
    rb"-----BEGIN PUBLIC KEY-----\r?\n"
    rb"(?:[A-Za-z0-9+/]{1,76}={0,2}\r?\n)+"
    rb"-----END PUBLIC KEY-----\r?\n?\Z"
)
MAX_PUBLIC_KEY_BYTES = 4096
RSA_4096_CIPHERTEXT_BYTES = 512
RSA_OAEP_SHA256_MAX_PLAINTEXT_BYTES = 446


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def build_context_and_payload(
    *,
    recipient_public_key: bytes,
    nonce: str,
    recipient_expires_at: str,
    repository: str,
    run_id: str,
    run_attempt: str,
    workflow_ref: str,
    workflow_sha: str,
    source_commit: str,
    core_image: str,
    postgres_image: str,
    runner_image: str,
    actor: str,
    token: str,
    now: datetime,
) -> tuple[bytes, bytes]:
    arguments = argparse.Namespace(
        nonce=nonce,
        recipient_expires_at=recipient_expires_at,
        repository=repository,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_ref=workflow_ref,
        workflow_sha=workflow_sha,
        source_commit=source_commit,
        core_image=core_image,
        postgres_image=postgres_image,
        runner_image=runner_image,
    )
    _validate_public_request(arguments, now=now)
    if not actor or not token:
        raise EnvelopeError
    try:
        encoded_auth = base64.b64encode(f"{actor}:{token}".encode("ascii")).decode(
            "ascii"
        )
    except UnicodeEncodeError as error:
        raise EnvelopeError from error
    context = {
        "deadline": recipient_expires_at,
        "images": {
            "core": core_image,
            "postgres": postgres_image,
            "runner": runner_image,
        },
        "nonce": nonce,
        "recipient_public_key_sha256": hashlib.sha256(
            recipient_public_key
        ).hexdigest(),
        "repository": repository,
        "run_attempt": run_attempt,
        "run_id": run_id,
        "schema": "lil-tweak-private-pull-context/v1",
        "source_commit": source_commit,
    }
    context_bytes = _canonical_json(context)
    payload = _canonical_json(
        {
            "auths": {"ghcr.io": {"auth": encoded_auth}},
            "binding_sha256": hashlib.sha256(context_bytes).hexdigest(),
            "nonce": nonce,
        }
    )
    # RSA-4096 with OAEP/SHA-256 accepts at most 512 - 2*32 - 2 bytes.
    if len(payload) > RSA_OAEP_SHA256_MAX_PLAINTEXT_BYTES:
        raise EnvelopeError
    return context_bytes, payload


def _decode_public_key(encoded: str) -> bytes:
    if not encoded or len(encoded) > 8192:
        raise EnvelopeError
    try:
        encoded_bytes = encoded.encode("ascii")
        public_key = base64.b64decode(encoded_bytes, validate=True)
    except (UnicodeEncodeError, ValueError) as error:
        raise EnvelopeError from error
    if (
        not public_key
        or len(public_key) > MAX_PUBLIC_KEY_BYTES
        or not PUBLIC_KEY_PEM.fullmatch(public_key)
    ):
        raise EnvelopeError
    return public_key


def _openssl_environment() -> dict[str, str]:
    # The credential-bearing parent environment must not reach the crypto child.
    return {"LANG": "C", "LC_ALL": "C"}


def _run_openssl(
    command: list[str], *, input_bytes: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            command,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_openssl_environment(),
            check=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise CryptoUnavailable from error


def _encrypt_payload(
    *, openssl: str, recipient_public_key: bytes, payload: bytes
) -> bytes:
    openssl_path = Path(openssl)
    if not openssl_path.is_file() or not os.access(openssl_path, os.X_OK):
        raise CryptoUnavailable

    with tempfile.TemporaryDirectory(prefix="lil-tweak-public-key-") as directory:
        public_key_path = Path(directory) / "recipient-public.pem"
        public_key_path.write_bytes(recipient_public_key)
        public_key_path.chmod(0o600)

        inspection = _run_openssl(
            [
                str(openssl_path),
                "rsa",
                "-pubin",
                "-in",
                str(public_key_path),
                "-text",
                "-noout",
            ]
        )
        if inspection.returncode != 0 or not re.search(
            rb"^Public-Key: \(4096 bit\)$", inspection.stdout, re.MULTILINE
        ):
            raise EnvelopeError

        encrypted = _run_openssl(
            [
                str(openssl_path),
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-pkeyopt",
                "rsa_padding_mode:oaep",
                "-pkeyopt",
                "rsa_oaep_md:sha256",
                "-pkeyopt",
                "rsa_mgf1_md:sha256",
            ],
            input_bytes=payload,
        )
        if (
            encrypted.returncode != 0
            or len(encrypted.stdout) != RSA_4096_CIPHERTEXT_BYTES
        ):
            raise CryptoUnavailable
        return encrypted.stdout


def _valid_ghcr_digest(reference: str) -> bool:
    if not isinstance(reference, str) or not reference.startswith("ghcr.io/"):
        return False
    name, marker, digest = reference.partition("@sha256:")
    if marker != "@sha256:" or not LOWER_SHA256.fullmatch(digest):
        return False
    components = name.removeprefix("ghcr.io/").split("/")
    return len(components) >= 2 and all(
        IMAGE_COMPONENT.fullmatch(component) for component in components
    )


def _parse_deadline(value: str, now: datetime) -> datetime:
    if not UTC_SECOND.fullmatch(value):
        raise EnvelopeError
    try:
        deadline = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise EnvelopeError from error
    remaining = (deadline - now).total_seconds()
    if remaining <= 0 or remaining > 20 * 60:
        raise EnvelopeError
    return deadline


def _validate_public_request(
    arguments: argparse.Namespace, *, now: datetime | None = None
) -> None:
    if arguments.workflow_ref != "refs/heads/main":
        raise EnvelopeError
    if (
        not LOWER_COMMIT.fullmatch(arguments.workflow_sha)
        or arguments.source_commit != arguments.workflow_sha
    ):
        raise EnvelopeError
    if not LOWER_COMMIT.fullmatch(arguments.source_commit):
        raise EnvelopeError
    if not SAFE_REPOSITORY.fullmatch(arguments.repository):
        raise EnvelopeError
    if not NONZERO_INTEGER.fullmatch(arguments.run_id) or not NONZERO_INTEGER.fullmatch(
        arguments.run_attempt
    ):
        raise EnvelopeError
    if not LOWER_SHA256.fullmatch(arguments.nonce):
        raise EnvelopeError
    _parse_deadline(arguments.recipient_expires_at, now or datetime.now(UTC))
    if not all(
        _valid_ghcr_digest(reference)
        for reference in (
            arguments.core_image,
            arguments.postgres_image,
            arguments.runner_image,
        )
    ):
        raise EnvelopeError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue", add_help=False)
    for name in (
        "openssl",
        "recipient-public-key-base64",
        "nonce",
        "recipient-expires-at",
        "repository",
        "run-id",
        "run-attempt",
        "workflow-ref",
        "workflow-sha",
        "source-commit",
        "core-image",
        "postgres-image",
        "runner-image",
    ):
        issue.add_argument(f"--{name}", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        _validate_public_request(arguments)
        recipient_public_key = _decode_public_key(
            arguments.recipient_public_key_base64
        )
        actor = os.environ.get("LIL_TWEAK_GHCR_ACTOR", "")
        token = os.environ.pop("LIL_TWEAK_GHCR_TOKEN", "")
        context, payload = build_context_and_payload(
            recipient_public_key=recipient_public_key,
            nonce=arguments.nonce,
            recipient_expires_at=arguments.recipient_expires_at,
            repository=arguments.repository,
            run_id=arguments.run_id,
            run_attempt=arguments.run_attempt,
            workflow_ref=arguments.workflow_ref,
            workflow_sha=arguments.workflow_sha,
            source_commit=arguments.source_commit,
            core_image=arguments.core_image,
            postgres_image=arguments.postgres_image,
            runner_image=arguments.runner_image,
            actor=actor,
            token=token,
            now=datetime.now(UTC),
        )
        ciphertext = _encrypt_payload(
            openssl=arguments.openssl,
            recipient_public_key=recipient_public_key,
            payload=payload,
        )
        print(
            "PRIVATE_PULL_CONTEXT_BASE64="
            + base64.b64encode(context).decode("ascii")
        )
        print(
            "PRIVATE_PULL_CIPHERTEXT_BASE64="
            + base64.b64encode(ciphertext).decode("ascii")
        )
        return 0
    except CryptoUnavailable:
        print("private-pull-envelope: cryptography unavailable", file=sys.stderr)
        return 3
    except (EnvelopeError, SystemExit):
        print("private-pull-envelope: invalid request", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

