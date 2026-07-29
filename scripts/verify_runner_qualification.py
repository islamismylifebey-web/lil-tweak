from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import NoReturn

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from liltweak.runner_qualification import (
    MAX_QUALIFICATION_BYTES,
    RunnerQualificationChallenge,
    RunnerQualificationExpectations,
    RunnerQualificationVerifier,
    SignedRunnerQualificationAttestation,
    build_runner_qualification_challenge,
    runner_key_id,
)

_GENERIC_REJECTION = "runner qualification rejected"


class DuplicateJsonKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError("duplicate JSON key")
        result[key] = value
    return result


def _read_bounded_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("qualification input must be a singly linked regular file")
        if metadata.st_size < 2 or metadata.st_size > MAX_QUALIFICATION_BYTES:
            raise ValueError("qualification input size is invalid")
        data = bytearray()
        while len(data) <= MAX_QUALIFICATION_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MAX_QUALIFICATION_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        final_metadata = os.fstat(descriptor)
        if (
            len(data) != metadata.st_size
            or len(data) > MAX_QUALIFICATION_BYTES
            or final_metadata.st_dev != metadata.st_dev
            or final_metadata.st_ino != metadata.st_ino
            or final_metadata.st_size != metadata.st_size
            or final_metadata.st_nlink != 1
        ):
            raise ValueError("qualification input changed or exceeded its limit")
        return bytes(data)
    finally:
        os.close(descriptor)


def read_bounded_json(path: Path) -> object:
    text = _read_bounded_bytes(path).decode("utf-8", errors="strict")
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)


def write_private_json(path: Path, payload: object) -> None:
    encoded = (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True).encode("utf-8") + b"\n"
    )
    if len(encoded) > MAX_QUALIFICATION_BYTES:
        raise ValueError("qualification output exceeded its limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("qualification output permissions are invalid")
        written = 0
        while written < len(encoded):
            count = os.write(descriptor, encoded[written:])
            if count <= 0:
                raise OSError("qualification output write made no progress")
            written += count
        os.fsync(descriptor)
        final_metadata = os.fstat(descriptor)
        if (
            final_metadata.st_dev != metadata.st_dev
            or final_metadata.st_ino != metadata.st_ino
            or final_metadata.st_nlink != 1
            or final_metadata.st_size != len(encoded)
            or stat.S_IMODE(final_metadata.st_mode) != 0o600
        ):
            raise ValueError("qualification output changed during write")
    finally:
        os.close(descriptor)


def decode_public_key(value: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("public key must be URL-safe base64") from exc
    if len(decoded) != 32:
        raise ValueError("public key must contain exactly 32 bytes")
    return decoded


def encode_public_key(value: bytes) -> str:
    if len(value) != 32:
        raise ValueError("public key must contain exactly 32 bytes")
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _load_issuer_public_key(path: Path) -> bytes:
    payload = read_bounded_json(path)
    if (
        not isinstance(payload, dict)
        or set(payload) != {"public_key_b64"}
        or not isinstance(payload["public_key_b64"], str)
    ):
        raise ValueError("issuer public key artifact is invalid")
    return decode_public_key(payload["public_key_b64"])


def issue(arguments: argparse.Namespace) -> int:
    issuer_private_key = Ed25519PrivateKey.generate()
    issuer_public_key = issuer_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    challenge = build_runner_qualification_challenge(
        runner_id=arguments.runner_id,
        key_id=arguments.key_id,
        repository_id=arguments.repository_id,
        repository_commit=arguments.repository_commit,
        repository_tree=arguments.repository_tree,
        image_ref=arguments.image_ref,
        sandbox_profile_digest=arguments.sandbox_profile_digest,
        runtime_sha256=arguments.runtime_sha256,
        limiter_sha256=arguments.limiter_sha256,
        qualifier_sha256=arguments.qualifier_sha256,
        destroyer_sha256=arguments.destroyer_sha256,
        issuer_private_key=issuer_private_key,
        lifetime_seconds=arguments.lifetime_seconds,
    )
    write_private_json(arguments.output, challenge.model_dump(mode="json"))
    write_private_json(
        arguments.issuer_public_key_output,
        {"public_key_b64": encode_public_key(issuer_public_key)},
    )
    print(challenge.challenge_digest)
    return 0


def verify(arguments: argparse.Namespace) -> int:
    issuer_public_key = _load_issuer_public_key(arguments.issuer_public_key_file)
    runner_public_key = decode_public_key(arguments.runner_public_key_b64)
    challenge = RunnerQualificationChallenge.model_validate(read_bounded_json(arguments.challenge))
    attestation = SignedRunnerQualificationAttestation.model_validate(
        read_bounded_json(arguments.attestation)
    )
    expectations = RunnerQualificationExpectations(
        runner_id=arguments.runner_id,
        repository_id=arguments.repository_id,
        repository_commit=arguments.repository_commit,
        repository_tree=arguments.repository_tree,
        image_ref=arguments.image_ref,
        sandbox_profile_digest=arguments.sandbox_profile_digest,
        runtime_sha256=arguments.runtime_sha256,
        limiter_sha256=arguments.limiter_sha256,
        qualifier_sha256=arguments.qualifier_sha256,
        destroyer_sha256=arguments.destroyer_sha256,
    )
    verifier = RunnerQualificationVerifier(
        expectations=expectations,
        trusted_issuer_public_keys={runner_key_id(issuer_public_key): issuer_public_key},
        trusted_runner_public_keys={arguments.runner_id: runner_public_key},
    )
    decision = verifier.verify(
        challenge=challenge,
        attestation=attestation,
        now=datetime.now(UTC),
    )
    write_private_json(arguments.output, decision.model_dump(mode="json"))
    print(json.dumps(decision.model_dump(mode="json"), sort_keys=True))
    return 0 if decision.qualified and decision.connection_authorized is False else 1


def _add_source_bindings(target: argparse.ArgumentParser) -> None:
    target.add_argument("--runner-id", required=True)
    target.add_argument("--repository-id", required=True)
    target.add_argument("--repository-commit", required=True)
    target.add_argument("--repository-tree", required=True)
    target.add_argument("--image-ref", required=True)
    target.add_argument("--sandbox-profile-digest", required=True)
    target.add_argument("--runtime-sha256", required=True)
    target.add_argument("--limiter-sha256", required=True)
    target.add_argument("--qualifier-sha256", required=True)
    target.add_argument("--destroyer-sha256", required=True)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        description="Issue or verify dormant Lil Tweak runner qualification evidence."
    )
    commands = root.add_subparsers(dest="command", required=True)
    issue_parser = commands.add_parser("issue")
    _add_source_bindings(issue_parser)
    issue_parser.add_argument("--key-id", required=True)
    issue_parser.add_argument("--lifetime-seconds", type=int, default=600)
    issue_parser.add_argument("--output", required=True, type=Path)
    issue_parser.add_argument("--issuer-public-key-output", required=True, type=Path)
    issue_parser.set_defaults(handler=issue)

    verify_parser = commands.add_parser("verify")
    _add_source_bindings(verify_parser)
    verify_parser.add_argument("--challenge", required=True, type=Path)
    verify_parser.add_argument("--attestation", required=True, type=Path)
    verify_parser.add_argument("--issuer-public-key-file", required=True, type=Path)
    verify_parser.add_argument("--runner-public-key-b64", required=True)
    verify_parser.add_argument("--output", required=True, type=Path)
    verify_parser.set_defaults(handler=verify)
    return root


def _reject() -> NoReturn:
    print(_GENERIC_REJECTION, file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    arguments = parser().parse_args()
    try:
        return int(arguments.handler(arguments))
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
    ):
        _reject()


if __name__ == "__main__":
    raise SystemExit(main())
