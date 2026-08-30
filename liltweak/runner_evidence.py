from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from pydantic import ValidationError

from .creator_contract import content_digest
from .runner_qualification import (
    RunnerQualificationChallenge,
    RunnerQualificationDecision,
    RunnerQualificationExpectations,
    RunnerQualificationVerifier,
    SignedRunnerQualificationAttestation,
    runner_key_id,
)
from .workbench_executor import ExecutorUnavailableError

_BUNDLE_SCHEMA_VERSION = "runner-qualification-bundle-v1"
_BUNDLE_FIELDS = frozenset(
    {
        "schema_version",
        "challenge",
        "attestation",
        "decision",
        "issuer_public_key",
        "runner_public_key",
        "bundle_digest",
    }
)
_HEX = frozenset("0123456789abcdef")
_CLOCK_SKEW = timedelta(seconds=5)


@dataclass(frozen=True)
class VerifiedRunnerQualificationBundle:
    runner_id: str
    repository_id: str
    repository_commit: str
    repository_tree: str
    qualification_id: str
    evidence_digest: str
    bundle_digest: str
    issuer_key_id: str
    runner_key_id: str
    verified_at: datetime
    challenge_expires_at: datetime


class RunnerQualificationBundleVerifier:
    """Verify signed qualification evidence against server-pinned trust anchors."""

    def __init__(
        self,
        *,
        expected_runner_id: str,
        expected_repository_id: str,
        expected_repository_commit: str,
        expected_evidence_digest: str,
        trusted_issuer_public_keys: Mapping[str, str],
        trusted_runner_public_keys: Mapping[str, str],
        maximum_age: timedelta,
    ) -> None:
        if not _safe_identifier(expected_runner_id):
            raise ValueError("runner qualification expected runner identity is invalid")
        if not _repository_identifier(expected_repository_id):
            raise ValueError("runner qualification expected repository identity is invalid")
        if not _object_id(expected_repository_commit):
            raise ValueError("runner qualification expected repository commit is invalid")
        if not _digest(expected_evidence_digest):
            raise ValueError("runner qualification expected evidence digest is invalid")
        if not isinstance(maximum_age, timedelta) or not (
            timedelta(seconds=1) <= maximum_age <= timedelta(days=30)
        ):
            raise ValueError("runner qualification maximum age is invalid")

        issuers = _trusted_issuer_keys(trusted_issuer_public_keys)
        runners = _trusted_runner_keys(trusted_runner_public_keys)
        if expected_runner_id not in runners:
            raise ValueError("expected runner does not have a pinned public key")

        self._expected_runner_id = expected_runner_id
        self._expected_repository_id = expected_repository_id
        self._expected_repository_commit = expected_repository_commit
        self._expected_evidence_digest = expected_evidence_digest
        self._trusted_issuer_public_keys = issuers
        self._trusted_runner_public_keys = runners
        self._maximum_age = maximum_age

    def verify(
        self,
        payload: Mapping[str, object],
        *,
        now: datetime | None = None,
    ) -> VerifiedRunnerQualificationBundle:
        observed_at = now or datetime.now(UTC)
        if observed_at.tzinfo is None or observed_at.utcoffset() is None:
            raise ValueError("runner qualification verification time must be timezone-aware")
        observed_at = observed_at.astimezone(UTC)

        try:
            bundle = _mapping(payload, "runner qualification bundle is invalid")
            if set(bundle) != _BUNDLE_FIELDS:
                raise ExecutorUnavailableError(
                    "runner qualification bundle fields or schema are invalid"
                )
            if bundle.get("schema_version") != _BUNDLE_SCHEMA_VERSION:
                raise ExecutorUnavailableError("runner qualification bundle schema is invalid")

            bundle_digest = bundle.get("bundle_digest")
            if not _digest(bundle_digest):
                raise ExecutorUnavailableError("runner qualification bundle digest is invalid")
            unsigned_bundle = {
                key: value for key, value in bundle.items() if key != "bundle_digest"
            }
            if not _same_digest(bundle_digest, content_digest(unsigned_bundle)):
                raise ExecutorUnavailableError("runner qualification bundle digest mismatch")

            challenge = RunnerQualificationChallenge.model_validate(
                _mapping(
                    bundle.get("challenge"),
                    "runner qualification challenge is invalid",
                )
            )
            attestation = SignedRunnerQualificationAttestation.model_validate(
                _mapping(
                    bundle.get("attestation"),
                    "runner qualification attestation is invalid",
                )
            )
            decision = RunnerQualificationDecision.model_validate(
                _mapping(
                    bundle.get("decision"),
                    "runner qualification decision is invalid",
                )
            )

            if challenge.runner_id != self._expected_runner_id:
                raise ExecutorUnavailableError(
                    "runner qualification runner identity binding is invalid"
                )
            if challenge.repository_id != self._expected_repository_id:
                raise ExecutorUnavailableError(
                    "runner qualification repository identity binding is invalid"
                )
            if challenge.repository_commit != self._expected_repository_commit:
                raise ExecutorUnavailableError(
                    "runner qualification repository commit binding is invalid"
                )
            if not _same_digest(
                attestation.evidence_digest,
                self._expected_evidence_digest,
            ):
                raise ExecutorUnavailableError(
                    "runner qualification evidence digest does not match the pinned digest"
                )

            issuer_public_key = self._trusted_issuer_public_keys.get(
                challenge.issuer_key_id
            )
            if issuer_public_key is None:
                raise ExecutorUnavailableError(
                    "runner qualification issuer key is untrusted or not pinned"
                )
            runner_public_key = self._trusted_runner_public_keys.get(
                challenge.runner_id
            )
            if runner_public_key is None:
                raise ExecutorUnavailableError(
                    "runner qualification runner key is untrusted or not pinned"
                )

            bundled_issuer_key = _public_key(
                bundle.get("issuer_public_key"),
                "issuer",
            )
            bundled_runner_key = _public_key(
                bundle.get("runner_public_key"),
                "runner",
            )
            if not hmac.compare_digest(bundled_issuer_key, issuer_public_key):
                raise ExecutorUnavailableError(
                    "runner qualification issuer key does not match the pinned key"
                )
            if not hmac.compare_digest(bundled_runner_key, runner_public_key):
                raise ExecutorUnavailableError(
                    "runner qualification runner key does not match the pinned key"
                )
            if runner_key_id(issuer_public_key) != challenge.issuer_key_id:
                raise ExecutorUnavailableError(
                    "runner qualification issuer key fingerprint is invalid"
                )
            if runner_key_id(runner_public_key) != challenge.key_id:
                raise ExecutorUnavailableError(
                    "runner qualification runner key fingerprint is invalid"
                )

            expectations = RunnerQualificationExpectations(
                runner_id=challenge.runner_id,
                repository_id=challenge.repository_id,
                repository_commit=challenge.repository_commit,
                repository_tree=challenge.repository_tree,
                image_ref=challenge.image_ref,
                sandbox_profile_digest=challenge.sandbox_profile_digest,
                runtime_sha256=challenge.runtime_sha256,
                limiter_sha256=challenge.limiter_sha256,
                qualifier_sha256=challenge.qualifier_sha256,
                destroyer_sha256=challenge.destroyer_sha256,
                suite_digest=challenge.suite_digest,
            )
            recomputed = RunnerQualificationVerifier(
                expectations=expectations,
                trusted_issuer_public_keys={
                    challenge.issuer_key_id: issuer_public_key,
                },
                trusted_runner_public_keys={
                    challenge.runner_id: runner_public_key,
                },
            ).verify(
                challenge=challenge,
                attestation=attestation,
                now=decision.verified_at,
            )
            if recomputed.model_dump(mode="json") != decision.model_dump(mode="json"):
                raise ExecutorUnavailableError(
                    "runner qualification decision does not match verified evidence"
                )
            if (
                not decision.qualified
                or decision.connection_authorized
                or decision.failure_codes
                or decision.qualification_id != challenge.qualification_id
                or decision.evidence_digest != attestation.evidence_digest
            ):
                raise ExecutorUnavailableError(
                    "runner qualification decision is not an accepted qualification"
                )

            verified_at = decision.verified_at.astimezone(UTC)
            if verified_at > observed_at + _CLOCK_SKEW:
                raise ExecutorUnavailableError("runner qualification evidence is from the future")
            if observed_at - verified_at > self._maximum_age:
                raise ExecutorUnavailableError("runner qualification evidence is stale or expired")

            return VerifiedRunnerQualificationBundle(
                runner_id=challenge.runner_id,
                repository_id=challenge.repository_id,
                repository_commit=challenge.repository_commit,
                repository_tree=challenge.repository_tree,
                qualification_id=challenge.qualification_id,
                evidence_digest=attestation.evidence_digest,
                bundle_digest=cast(str, bundle_digest),
                issuer_key_id=challenge.issuer_key_id,
                runner_key_id=challenge.key_id,
                verified_at=verified_at,
                challenge_expires_at=challenge.expires_at.astimezone(UTC),
            )
        except ExecutorUnavailableError:
            raise
        except ValidationError as exc:
            first_error = exc.errors()[0]
            raise ExecutorUnavailableError(
                f"runner qualification attestation evidence is invalid: {first_error['msg']}"
            ) from exc
        except (ValueError, TypeError, binascii.Error) as exc:
            raise ExecutorUnavailableError(
                "runner qualification cryptographic evidence is invalid"
            ) from exc


def parse_qualification_public_keys(
    payload: str | None,
    *,
    key_by_runner: bool,
) -> dict[str, str]:
    """Parse a JSON string map without accepting embedded or malformed key data."""
    if payload is None or not payload.strip():
        raise ValueError("runner qualification pinned public keys are missing")
    import json

    try:
        parsed = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("runner qualification pinned public keys are invalid JSON") from exc
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in parsed.items()
    ):
        raise ValueError("runner qualification pinned public keys must be a string map")
    result = cast(dict[str, str], parsed)
    if key_by_runner:
        _trusted_runner_keys(result)
    else:
        _trusted_issuer_keys(result)
    return dict(result)


def _trusted_issuer_keys(keys: Mapping[str, str]) -> dict[str, bytes]:
    if not keys or len(keys) > 16:
        raise ValueError("runner qualification requires one to sixteen pinned issuer keys")
    trusted: dict[str, bytes] = {}
    for key_id, encoded in keys.items():
        if not _digest(key_id):
            raise ValueError("runner qualification issuer key id is invalid")
        public_key = _public_key_value(encoded, "issuer")
        if runner_key_id(public_key) != key_id:
            raise ValueError("runner qualification issuer key fingerprint is invalid")
        trusted[key_id] = public_key
    return trusted


def _trusted_runner_keys(keys: Mapping[str, str]) -> dict[str, bytes]:
    if not keys or len(keys) > 16:
        raise ValueError("runner qualification requires one to sixteen pinned runner keys")
    trusted: dict[str, bytes] = {}
    for runner_id, encoded in keys.items():
        if not _safe_identifier(runner_id):
            raise ValueError("runner qualification runner key identity is invalid")
        trusted[runner_id] = _public_key_value(encoded, "runner")
    return trusted


def _mapping(value: object, message: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise ExecutorUnavailableError(message)
    return cast(Mapping[str, object], value)


def _public_key(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise ExecutorUnavailableError(
            f"runner qualification {label} public key is invalid"
        )
    try:
        return _public_key_value(value, label)
    except ValueError as exc:
        raise ExecutorUnavailableError(str(exc)) from exc


def _public_key_value(value: str, label: str) -> bytes:
    if not value or "=" in value or len(value) > 64:
        raise ValueError(f"runner qualification {label} public key is invalid")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(
            f"runner qualification {label} public key is invalid"
        ) from exc
    if (
        len(decoded) != 32
        or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value
    ):
        raise ValueError(f"runner qualification {label} public key is invalid")
    return decoded


def _safe_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "._:-" for character in value)
    )


def _repository_identifier(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("github:"):
        return False
    owner_repo = value.removeprefix("github:").split("/")
    return len(owner_repo) == 2 and all(_safe_identifier(part) for part in owner_repo)


def _object_id(value: object) -> bool:
    return isinstance(value, str) and len(value) in {40, 64} and all(
        character in _HEX for character in value
    )


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in _HEX for character in value
    )


def _same_digest(left: object, right: object) -> bool:
    return _digest(left) and _digest(right) and hmac.compare_digest(
        cast(str, left),
        cast(str, right),
    )
