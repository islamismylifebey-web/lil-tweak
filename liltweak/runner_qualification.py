from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from .creator_contract import CreatorSchema, canonical_json, content_digest

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_OBJECT_ID_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_IMAGE_PATTERN = r"^[a-z0-9][a-z0-9._/-]{0,255}@sha256:[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^[A-Za-z0-9_-]{86}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_REPOSITORY_ID_PATTERN = r"^github:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
_CHALLENGE_SIGNATURE_DOMAIN = b"liltweak:runner-qualification-challenge:v1\0"
_ATTESTATION_SIGNATURE_DOMAIN = b"liltweak:runner-qualification:v1\0"
MAX_QUALIFICATION_BYTES = 128_000
MAX_QUALIFICATION_LIFETIME_SECONDS = 600

REQUIRED_QUALIFICATION_CHECKS: tuple[str, ...] = (
    "network.ipv4_egress_denied",
    "network.ipv6_egress_denied",
    "network.dns_denied",
    "network.loopback_host_denied",
    "network.metadata_denied",
    "network.proxy_environment_absent",
    "network.host_unix_sockets_absent",
    "identity.non_root",
    "isolation.no_new_privileges",
    "isolation.capabilities_dropped",
    "isolation.mac_policy_enforced",
    "isolation.seccomp_enforced",
    "isolation.host_pid_namespace_absent",
    "resource.cpu_hard_limit",
    "resource.memory_hard_limit",
    "resource.pid_hard_limit",
    "resource.disk_bytes_hard_limit",
    "resource.inode_hard_limit",
    "resource.wall_clock_hard_limit",
    "resource.output_hard_limit",
    "filesystem.source_read_only",
    "filesystem.root_read_only",
    "filesystem.git_metadata_absent",
    "filesystem.credentials_absent",
    "filesystem.other_repositories_absent",
    "filesystem.host_devices_absent",
    "filesystem.container_socket_absent",
    "filesystem.ssh_agent_absent",
    "filesystem.host_proc_environ_absent",
    "filesystem.control_plane_state_absent",
    "adversarial.timeout_terminated",
    "adversarial.oom_terminated",
    "adversarial.fork_bomb_terminated",
    "adversarial.output_flood_terminated",
    "adversarial.disk_flood_terminated",
    "adversarial.inode_flood_terminated",
    "adversarial.sleeping_child_terminated",
    "control.live_cancel_kills_cgroup",
    "control.emergency_stop_kills_cgroup",
    "control.crash_recovery_reaps_orphans",
    "integrity.source_digest_unchanged",
    "cleanup.cgroup_empty",
    "cleanup.cgroup_removed",
    "cleanup.mounts_detached",
    "cleanup.network_namespace_removed",
    "cleanup.workspace_destroyed",
    "cleanup.process_tree_dead",
)

QUALIFICATION_SUITE_DIGEST = content_digest(
    {
        "schema_version": "runner-qualification-suite-v1",
        "checks": REQUIRED_QUALIFICATION_CHECKS,
    }
)


def runner_key_id(public_key: bytes) -> str:
    if not isinstance(public_key, bytes) or len(public_key) != 32:
        raise ValueError("runner qualification public key must contain exactly 32 bytes")
    return hashlib.sha256(public_key).hexdigest()


def _public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


class RunnerQualificationChallenge(CreatorSchema):
    schema_version: Literal["runner-qualification-challenge-v1"] = (
        "runner-qualification-challenge-v1"
    )
    qualification_id: StrictStr = Field(pattern=r"^rq_[0-9a-f]{32}$")
    runner_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    key_id: StrictStr = Field(pattern=_SHA256_PATTERN)
    issuer_key_id: StrictStr = Field(pattern=_SHA256_PATTERN)
    nonce: StrictStr = Field(pattern=_SHA256_PATTERN)
    suite_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    repository_id: StrictStr = Field(pattern=_REPOSITORY_ID_PATTERN)
    repository_commit: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    repository_tree: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    image_ref: StrictStr = Field(pattern=_IMAGE_PATTERN)
    sandbox_profile_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    runtime_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    limiter_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    qualifier_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    destroyer_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    issued_at: datetime
    expires_at: datetime
    challenge_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    issuer_signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def validate_challenge(self) -> RunnerQualificationChallenge:
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("runner qualification timestamps must be timezone-aware")
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if lifetime <= 0 or lifetime > MAX_QUALIFICATION_LIFETIME_SECONDS:
            raise ValueError("runner qualification challenge lifetime is invalid")
        if self.suite_digest != QUALIFICATION_SUITE_DIGEST:
            raise ValueError("runner qualification suite is not the required suite")
        expected = content_digest(
            self.model_dump(
                mode="json",
                exclude={"challenge_digest", "issuer_signature"},
            )
        )
        if self.challenge_digest != expected:
            raise ValueError("runner qualification challenge digest mismatch")
        return self


class QualificationObservation(CreatorSchema):
    check_id: StrictStr = Field(min_length=1, max_length=128)
    passed: StrictBool
    evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    duration_ms: StrictInt = Field(ge=0, le=600_000)
    source: Literal["external_host_supervisor"] = "external_host_supervisor"
    failure_code: StrictStr | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def validate_result(self) -> QualificationObservation:
        if self.passed and self.failure_code is not None:
            raise ValueError("passing qualification observations cannot include a failure")
        if not self.passed and self.failure_code is None:
            raise ValueError("failed qualification observations require a failure code")
        return self


class SignedRunnerQualificationAttestation(CreatorSchema):
    schema_version: Literal["runner-qualification-v1"] = "runner-qualification-v1"
    qualification_id: StrictStr = Field(pattern=r"^rq_[0-9a-f]{32}$")
    challenge_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    runner_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    key_id: StrictStr = Field(pattern=_SHA256_PATTERN)
    nonce: StrictStr = Field(pattern=_SHA256_PATTERN)
    suite_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    repository_id: StrictStr = Field(pattern=_REPOSITORY_ID_PATTERN)
    repository_commit: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    repository_tree: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    image_ref: StrictStr = Field(pattern=_IMAGE_PATTERN)
    sandbox_profile_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    runtime_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    limiter_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    qualifier_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    destroyer_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    boot_id_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    session_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    started_at: datetime
    finished_at: datetime
    observations: tuple[QualificationObservation, ...] = Field(
        min_length=len(REQUIRED_QUALIFICATION_CHECKS),
        max_length=len(REQUIRED_QUALIFICATION_CHECKS),
    )
    cleanup_verified: StrictBool
    raw_output_retained: Literal[False] = False
    evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def validate_attestation(self) -> SignedRunnerQualificationAttestation:
        if not _aware(self.started_at) or not _aware(self.finished_at):
            raise ValueError("runner qualification timestamps must be timezone-aware")
        duration = (self.finished_at - self.started_at).total_seconds()
        if duration < 0 or duration > MAX_QUALIFICATION_LIFETIME_SECONDS:
            raise ValueError("runner qualification duration is invalid")
        check_ids = tuple(item.check_id for item in self.observations)
        if check_ids != REQUIRED_QUALIFICATION_CHECKS:
            raise ValueError("runner qualification observations are not exact and ordered")
        expected = content_digest(
            self.model_dump(
                mode="json",
                exclude={"evidence_digest", "signature"},
            )
        )
        if self.evidence_digest != expected:
            raise ValueError("runner qualification evidence digest mismatch")
        return self


class RunnerQualificationExpectations(CreatorSchema):
    runner_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    repository_id: StrictStr = Field(pattern=_REPOSITORY_ID_PATTERN)
    repository_commit: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    repository_tree: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    image_ref: StrictStr = Field(pattern=_IMAGE_PATTERN)
    sandbox_profile_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    runtime_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    limiter_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    qualifier_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    destroyer_sha256: StrictStr = Field(pattern=_SHA256_PATTERN)
    suite_digest: StrictStr = Field(default=QUALIFICATION_SUITE_DIGEST, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_suite(self) -> RunnerQualificationExpectations:
        if self.suite_digest != QUALIFICATION_SUITE_DIGEST:
            raise ValueError("runner qualification expectation suite mismatch")
        return self


class RunnerQualificationDecision(CreatorSchema):
    schema_version: Literal["runner-qualification-decision-v1"] = "runner-qualification-decision-v1"
    qualification_id: StrictStr = Field(pattern=r"^rq_[0-9a-f]{32}$")
    evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    qualified: StrictBool
    connection_authorized: Literal[False] = False
    failure_codes: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=64)
    verified_at: datetime

    @model_validator(mode="after")
    def validate_decision(self) -> RunnerQualificationDecision:
        if not _aware(self.verified_at):
            raise ValueError("runner qualification decision time must be timezone-aware")
        if self.qualified == bool(self.failure_codes):
            raise ValueError("runner qualification decision contradicts its failures")
        return self


def build_runner_qualification_challenge(
    *,
    runner_id: str,
    key_id: str,
    repository_id: str,
    repository_commit: str,
    repository_tree: str,
    image_ref: str,
    sandbox_profile_digest: str,
    runtime_sha256: str,
    limiter_sha256: str,
    qualifier_sha256: str,
    destroyer_sha256: str,
    issuer_private_key: Ed25519PrivateKey,
    issued_at: datetime | None = None,
    lifetime_seconds: int = MAX_QUALIFICATION_LIFETIME_SECONDS,
    qualification_id: str | None = None,
    nonce: str | None = None,
) -> RunnerQualificationChallenge:
    if (
        isinstance(lifetime_seconds, bool)
        or lifetime_seconds < 1
        or lifetime_seconds > MAX_QUALIFICATION_LIFETIME_SECONDS
    ):
        raise ValueError("runner qualification lifetime is invalid")
    created = issued_at or datetime.now(UTC)
    issuer_public_key = _public_bytes(issuer_private_key)
    values = {
        "qualification_id": qualification_id or f"rq_{uuid.uuid4().hex}",
        "runner_id": runner_id,
        "key_id": key_id,
        "issuer_key_id": runner_key_id(issuer_public_key),
        "nonce": nonce or hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
        "suite_digest": QUALIFICATION_SUITE_DIGEST,
        "repository_id": repository_id,
        "repository_commit": repository_commit,
        "repository_tree": repository_tree,
        "image_ref": image_ref,
        "sandbox_profile_digest": sandbox_profile_digest,
        "runtime_sha256": runtime_sha256,
        "limiter_sha256": limiter_sha256,
        "qualifier_sha256": qualifier_sha256,
        "destroyer_sha256": destroyer_sha256,
        "issued_at": created,
        "expires_at": created + timedelta(seconds=lifetime_seconds),
    }
    draft = RunnerQualificationChallenge.model_construct(
        **values,
        challenge_digest="0" * 64,
        issuer_signature="A" * 86,
    )
    challenge_digest = content_digest(
        draft.model_dump(
            mode="json",
            exclude={"challenge_digest", "issuer_signature"},
        )
    )
    unsigned = RunnerQualificationChallenge.model_construct(
        **values,
        challenge_digest=challenge_digest,
        issuer_signature="A" * 86,
    )
    return RunnerQualificationChallenge(
        **values,
        challenge_digest=challenge_digest,
        issuer_signature=encode_runner_signature(
            issuer_private_key.sign(runner_qualification_challenge_signature_message(unsigned))
        ),
    )


def runner_qualification_challenge_signature_message(
    challenge: RunnerQualificationChallenge,
) -> bytes:
    payload = canonical_json(
        challenge.model_dump(mode="json", exclude={"issuer_signature"})
    ).encode("utf-8")
    return _CHALLENGE_SIGNATURE_DOMAIN + payload


def runner_qualification_signature_message(
    attestation: SignedRunnerQualificationAttestation,
) -> bytes:
    payload = canonical_json(attestation.model_dump(mode="json", exclude={"signature"})).encode(
        "utf-8"
    )
    return _ATTESTATION_SIGNATURE_DOMAIN + payload


def encode_runner_signature(signature: bytes) -> str:
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("runner qualification signature must contain exactly 64 bytes")
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _decode_runner_signature(signature: str) -> bytes:
    try:
        decoded = base64.b64decode(
            signature + ("=" * (-len(signature) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError("runner qualification signature is invalid") from exc
    if len(decoded) != 64:
        raise ValueError("runner qualification signature is invalid")
    return decoded


class RunnerQualificationVerifier:
    """Verify dormant runner evidence without authorizing an execution connection."""

    def __init__(
        self,
        *,
        expectations: RunnerQualificationExpectations,
        trusted_issuer_public_keys: Mapping[str, bytes],
        trusted_runner_public_keys: Mapping[str, bytes],
    ) -> None:
        issuers = dict(trusted_issuer_public_keys)
        runners = dict(trusted_runner_public_keys)
        if not issuers or not runners:
            raise ValueError("runner qualification issuer and runner keys are required")
        for key_id, public_key in issuers.items():
            if key_id != runner_key_id(public_key):
                raise ValueError("runner qualification issuer key id is invalid")
        for runner_id, public_key in runners.items():
            if (
                not isinstance(runner_id, str)
                or not runner_id
                or len(runner_id) > 128
                or not isinstance(public_key, bytes)
                or len(public_key) != 32
            ):
                raise ValueError("runner qualification runner key mapping is invalid")
        if expectations.runner_id not in runners:
            raise ValueError("expected runner does not have a trusted public key")
        self.expectations = expectations
        self._issuer_keys = issuers
        self._runner_keys = runners

    def verify(
        self,
        *,
        challenge: RunnerQualificationChallenge,
        attestation: SignedRunnerQualificationAttestation,
        now: datetime | None = None,
    ) -> RunnerQualificationDecision:
        challenge = RunnerQualificationChallenge.model_validate(challenge.model_dump(mode="json"))
        attestation = SignedRunnerQualificationAttestation.model_validate(
            attestation.model_dump(mode="json")
        )
        observed_at = now or datetime.now(UTC)
        if not _aware(observed_at):
            raise ValueError("runner qualification verification time must be timezone-aware")
        failures: list[str] = []

        def require(condition: bool, failure_code: str) -> None:
            if condition or failure_code in failures:
                return
            if len(failures) < 63:
                failures.append(failure_code)
            elif len(failures) == 63:
                failures.append("additional_failures_omitted")

        require(observed_at >= challenge.issued_at, "challenge_not_yet_valid")
        require(observed_at <= challenge.expires_at, "challenge_expired")
        require(attestation.started_at >= challenge.issued_at, "attestation_started_early")
        require(attestation.finished_at <= challenge.expires_at, "attestation_finished_late")
        require(attestation.finished_at <= observed_at, "attestation_from_future")

        for field in (
            "runner_id",
            "repository_id",
            "repository_commit",
            "repository_tree",
            "image_ref",
            "sandbox_profile_digest",
            "runtime_sha256",
            "limiter_sha256",
            "qualifier_sha256",
            "destroyer_sha256",
            "suite_digest",
        ):
            require(
                getattr(challenge, field) == getattr(self.expectations, field),
                f"unexpected_{field}",
            )

        issuer_public_key = self._issuer_keys.get(challenge.issuer_key_id)
        if issuer_public_key is None:
            require(False, "untrusted_challenge_issuer")
        else:
            try:
                Ed25519PublicKey.from_public_bytes(issuer_public_key).verify(
                    _decode_runner_signature(challenge.issuer_signature),
                    runner_qualification_challenge_signature_message(challenge),
                )
            except (InvalidSignature, ValueError):
                require(False, "challenge_signature_invalid")

        for field in (
            "qualification_id",
            "runner_id",
            "key_id",
            "nonce",
            "suite_digest",
            "repository_id",
            "repository_commit",
            "repository_tree",
            "image_ref",
            "sandbox_profile_digest",
            "runtime_sha256",
            "limiter_sha256",
            "qualifier_sha256",
            "destroyer_sha256",
        ):
            require(
                getattr(attestation, field) == getattr(challenge, field),
                f"{field}_mismatch",
            )
        require(
            attestation.challenge_digest == challenge.challenge_digest,
            "challenge_digest_mismatch",
        )
        require(attestation.cleanup_verified, "cleanup_unverified")
        for observation in attestation.observations:
            require(observation.passed, f"check_failed:{observation.check_id}")

        public_key = self._runner_keys.get(challenge.runner_id)
        if public_key is None or runner_key_id(public_key) != challenge.key_id:
            require(False, "untrusted_runner_key")
        else:
            try:
                Ed25519PublicKey.from_public_bytes(public_key).verify(
                    _decode_runner_signature(attestation.signature),
                    runner_qualification_signature_message(attestation),
                )
            except (InvalidSignature, ValueError):
                require(False, "runner_signature_invalid")

        return RunnerQualificationDecision(
            qualification_id=challenge.qualification_id,
            evidence_digest=attestation.evidence_digest,
            qualified=not failures,
            connection_authorized=False,
            failure_codes=tuple(failures),
            verified_at=observed_at,
        )
