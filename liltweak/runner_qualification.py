from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import os
import re
import secrets
import signal
import stat
import subprocess
import uuid
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
_LOCAL_CONNECTION_SIGNATURE_DOMAIN = b"liltweak:local-runner-connection:v1\0"
MAX_QUALIFICATION_BYTES = 128_000
MAX_QUALIFICATION_LIFETIME_SECONDS = 600
MAX_LOCAL_CONNECTION_LIFETIME_SECONDS = 300

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


LOCAL_RUNNER_PROBE_GATES: tuple[str, ...] = (
    "platform.linux",
    "runtime.executable_trusted",
    "runtime.sha256_pinned",
    "runtime.version_observed",
    "limiter.executable_trusted",
    "limiter.sha256_pinned",
    "limiter.version_observed",
    "qualifier.executable_trusted",
    "qualifier.sha256_pinned",
    "destroyer.executable_trusted",
    "destroyer.sha256_pinned",
    "runtime_root.directory_trusted",
    "runtime_root.manifest_pinned",
    "kernel.no_new_privileges",
    "kernel.cap_sys_admin_absent",
    "kernel.seccomp_active",
    "resource.cgroup_v2_delegated",
    "isolation.synthetic_namespace_probe",
)


class LocalRunnerProbeExpectations(CreatorSchema):
    """Server-owned pins used by the non-authorizing local capability probe."""

    schema_version: Literal["local-runner-probe-expectations-v1"] = (
        "local-runner-probe-expectations-v1"
    )
    provider_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    runtime_path: StrictStr = "/usr/bin/bwrap"
    limiter_path: StrictStr = "/usr/bin/prlimit"
    qualifier_path: StrictStr = "/opt/liltweak-qualification/bin/collect"
    destroyer_path: StrictStr = "/opt/liltweak-qualification/bin/destroy"
    runtime_root: StrictStr = "/opt/liltweak-runtime/rootfs"
    runtime_manifest_name: StrictStr = Field(
        default=".liltweak-rootfs-manifest.json",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    )
    runtime_sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    limiter_sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    qualifier_sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    destroyer_sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    runtime_manifest_sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    target_uid: StrictInt = Field(default=65_532, ge=1, le=4_294_967_294)
    target_gid: StrictInt = Field(default=65_532, ge=1, le=4_294_967_294)
    command_timeout_seconds: StrictInt = Field(default=3, ge=1, le=10)

    @model_validator(mode="after")
    def validate_paths(self) -> LocalRunnerProbeExpectations:
        paths = (
            self.runtime_path,
            self.limiter_path,
            self.qualifier_path,
            self.destroyer_path,
            self.runtime_root,
        )
        if any(not Path(value).is_absolute() or "\x00" in value for value in paths):
            raise ValueError("local runner probe paths must be absolute and NUL-free")
        if len(set(paths)) != len(paths):
            raise ValueError("local runner probe paths must be distinct")
        if Path(self.runtime_root) == Path("/"):
            raise ValueError("local runner runtime root must be dedicated")
        return self


class LocalExecutableObservation(CreatorSchema):
    role: Literal["runtime", "limiter", "qualifier", "destroyer"]
    path: StrictStr
    present: StrictBool
    trusted: StrictBool
    sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    expected_sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    version: StrictStr | None = Field(default=None, max_length=256)
    version_probe: Literal["passed", "failed", "timed_out", "not_run"] = "not_run"
    version_output_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)


class LocalCommandProbeObservation(CreatorSchema):
    command_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    exit_code: StrictInt | None = Field(default=None, ge=-255, le=255)
    timed_out: StrictBool
    stdout_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    stderr_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    stdout_bytes: StrictInt = Field(ge=0, le=1_000_000)
    stderr_bytes: StrictInt = Field(ge=0, le=1_000_000)
    result_code: Literal[
        "passed",
        "failed",
        "timed_out",
        "not_run_untrusted",
        "not_run_unpinned",
    ]


class LocalKernelObservation(CreatorSchema):
    system: StrictStr = Field(max_length=64)
    no_new_privileges: StrictBool
    seccomp_mode: StrictInt = Field(ge=0, le=2)
    cap_sys_admin_effective: StrictBool
    cgroup_v2_present: StrictBool
    cgroup_v2_delegated: StrictBool


class LocalRuntimeRootObservation(CreatorSchema):
    path: StrictStr
    present: StrictBool
    trusted: StrictBool
    manifest_path: StrictStr
    manifest_sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    expected_manifest_sha256: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)


class LocalRunnerProbeGate(CreatorSchema):
    gate_id: StrictStr = Field(min_length=1, max_length=128)
    passed: StrictBool
    failure_code: StrictStr | None = Field(default=None, min_length=1, max_length=128)
    evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_gate(self) -> LocalRunnerProbeGate:
        if self.passed == (self.failure_code is not None):
            raise ValueError("local runner probe gate contradicts its failure code")
        expected = content_digest(self.model_dump(mode="json", exclude={"evidence_digest"}))
        if self.evidence_digest != expected:
            raise ValueError("local runner probe gate evidence digest mismatch")
        return self


class LocalRunnerCapabilityReport(CreatorSchema):
    schema_version: Literal["local-runner-capability-report-v1"] = (
        "local-runner-capability-report-v1"
    )
    provider_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    expectations_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    executables: tuple[LocalExecutableObservation, ...] = Field(min_length=4, max_length=4)
    runtime_root: LocalRuntimeRootObservation
    kernel: LocalKernelObservation
    namespace_probe: LocalCommandProbeObservation
    gates: tuple[LocalRunnerProbeGate, ...] = Field(
        min_length=len(LOCAL_RUNNER_PROBE_GATES),
        max_length=len(LOCAL_RUNNER_PROBE_GATES),
    )
    blockers: tuple[StrictStr, ...] = Field(max_length=len(LOCAL_RUNNER_PROBE_GATES))
    host_qualified: StrictBool
    report_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_report(self) -> LocalRunnerCapabilityReport:
        roles = tuple(item.role for item in self.executables)
        if roles != ("runtime", "limiter", "qualifier", "destroyer"):
            raise ValueError("local runner executable observations are not exact and ordered")
        gate_ids = tuple(item.gate_id for item in self.gates)
        if gate_ids != LOCAL_RUNNER_PROBE_GATES:
            raise ValueError("local runner probe gates are not exact and ordered")
        expected_blockers = tuple(
            gate.failure_code for gate in self.gates if gate.failure_code is not None
        )
        if self.blockers != expected_blockers:
            raise ValueError("local runner probe blockers do not match failed gates")
        if self.host_qualified != (not self.blockers):
            raise ValueError("local runner host qualification contradicts its blockers")
        expected = content_digest(self.model_dump(mode="json", exclude={"report_digest"}))
        if self.report_digest != expected:
            raise ValueError("local runner capability report digest mismatch")
        return self


class LocalRunnerExecutionBindings(CreatorSchema):
    repository_id: StrictStr = Field(min_length=1, max_length=512)
    repository_commit: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    repository_tree: StrictStr = Field(pattern=_OBJECT_ID_PATTERN)
    source_snapshot_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    task_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    plan_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    execution_attempt: StrictInt = Field(ge=1, le=100)
    sandbox_profile_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    resource_profile_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    network_mode: Literal["denied"] = "denied"

    @property
    def bindings_digest(self) -> str:
        return content_digest(self.model_dump(mode="json"))


class LocalRunnerConnectionAuthorization(CreatorSchema):
    """Externally signed authorization; this module intentionally has no issuing function."""

    schema_version: Literal["local-runner-connection-authorization-v1"] = (
        "local-runner-connection-authorization-v1"
    )
    authorization_id: StrictStr = Field(pattern=r"^lra_[0-9a-f]{32}$")
    owner_key_id: StrictStr = Field(pattern=_SHA256_PATTERN)
    provider_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    report_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    qualification_id: StrictStr = Field(pattern=r"^rq_[0-9a-f]{32}$")
    qualification_evidence_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    bindings: LocalRunnerExecutionBindings
    bindings_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    nonce: StrictStr = Field(pattern=_SHA256_PATTERN)
    generation: StrictInt = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    authorization_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def validate_authorization(self) -> LocalRunnerConnectionAuthorization:
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("local runner authorization timestamps must be timezone-aware")
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if lifetime <= 0 or lifetime > MAX_LOCAL_CONNECTION_LIFETIME_SECONDS:
            raise ValueError("local runner authorization lifetime is invalid")
        if self.bindings_digest != self.bindings.bindings_digest:
            raise ValueError("local runner authorization bindings digest mismatch")
        expected = content_digest(
            self.model_dump(
                mode="json",
                exclude={"authorization_digest", "signature"},
            )
        )
        if self.authorization_digest != expected:
            raise ValueError("local runner authorization digest mismatch")
        return self


class LocalRunnerConnectionDecision(CreatorSchema):
    schema_version: Literal["local-runner-connection-decision-v1"] = (
        "local-runner-connection-decision-v1"
    )
    provider_id: StrictStr = Field(pattern=_SAFE_ID_PATTERN)
    report_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    host_qualified: StrictBool
    qualification_verified: StrictBool
    authorization_verified: StrictBool
    connection_authorized: StrictBool
    authorization_id: StrictStr | None = Field(default=None, pattern=r"^lra_[0-9a-f]{32}$")
    authorization_digest: StrictStr | None = Field(default=None, pattern=_SHA256_PATTERN)
    failure_codes: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=64)
    verified_at: datetime
    decision_digest: StrictStr = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_decision(self) -> LocalRunnerConnectionDecision:
        if not _aware(self.verified_at):
            raise ValueError("local runner connection decision time must be timezone-aware")
        authorized = (
            self.host_qualified
            and self.qualification_verified
            and self.authorization_verified
            and not self.failure_codes
        )
        if self.connection_authorized != authorized:
            raise ValueError("local runner connection decision contradicts its gates")
        if self.authorization_verified != (
            self.authorization_id is not None and self.authorization_digest is not None
        ):
            raise ValueError("local runner authorization identity is inconsistent")
        expected = content_digest(self.model_dump(mode="json", exclude={"decision_digest"}))
        if self.decision_digest != expected:
            raise ValueError("local runner connection decision digest mismatch")
        return self


def local_runner_authorization_signature_message(
    authorization: LocalRunnerConnectionAuthorization,
) -> bytes:
    payload = canonical_json(authorization.model_dump(mode="json", exclude={"signature"})).encode(
        "utf-8"
    )
    return _LOCAL_CONNECTION_SIGNATURE_DOMAIN + payload


class LocalRunnerQualificationProbe:
    """Measure local prerequisites without creating an execution transport."""

    _EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()

    def __init__(self, expectations: LocalRunnerProbeExpectations) -> None:
        self.expectations = expectations

    def collect(self) -> LocalRunnerCapabilityReport:
        executable_specs = (
            ("runtime", self.expectations.runtime_path, self.expectations.runtime_sha256, True),
            ("limiter", self.expectations.limiter_path, self.expectations.limiter_sha256, True),
            (
                "qualifier",
                self.expectations.qualifier_path,
                self.expectations.qualifier_sha256,
                False,
            ),
            (
                "destroyer",
                self.expectations.destroyer_path,
                self.expectations.destroyer_sha256,
                False,
            ),
        )
        observations = tuple(
            self._observe_executable(role, path, expected, observe_version=observe_version)
            for role, path, expected, observe_version in executable_specs
        )
        observed = {item.role: item for item in observations}
        runtime_root = self._observe_runtime_root()
        kernel = self._observe_kernel()
        namespace_probe = self._namespace_probe(observed)
        gate_inputs: tuple[tuple[str, bool, str], ...] = (
            ("platform.linux", kernel.system == "Linux", "platform_not_linux"),
            (
                "runtime.executable_trusted",
                observed["runtime"].trusted,
                self._executable_failure(observed["runtime"]),
            ),
            (
                "runtime.sha256_pinned",
                self._hash_matches(observed["runtime"]),
                self._pin_failure(observed["runtime"]),
            ),
            (
                "runtime.version_observed",
                observed["runtime"].version_probe == "passed",
                f"runtime_version_probe_{observed['runtime'].version_probe}",
            ),
            (
                "limiter.executable_trusted",
                observed["limiter"].trusted,
                self._executable_failure(observed["limiter"]),
            ),
            (
                "limiter.sha256_pinned",
                self._hash_matches(observed["limiter"]),
                self._pin_failure(observed["limiter"]),
            ),
            (
                "limiter.version_observed",
                observed["limiter"].version_probe == "passed",
                f"limiter_version_probe_{observed['limiter'].version_probe}",
            ),
            (
                "qualifier.executable_trusted",
                observed["qualifier"].trusted,
                self._executable_failure(observed["qualifier"]),
            ),
            (
                "qualifier.sha256_pinned",
                self._hash_matches(observed["qualifier"]),
                self._pin_failure(observed["qualifier"]),
            ),
            (
                "destroyer.executable_trusted",
                observed["destroyer"].trusted,
                self._executable_failure(observed["destroyer"]),
            ),
            (
                "destroyer.sha256_pinned",
                self._hash_matches(observed["destroyer"]),
                self._pin_failure(observed["destroyer"]),
            ),
            (
                "runtime_root.directory_trusted",
                runtime_root.trusted,
                ("runtime_root_missing" if not runtime_root.present else "runtime_root_untrusted"),
            ),
            (
                "runtime_root.manifest_pinned",
                (
                    runtime_root.manifest_sha256 is not None
                    and runtime_root.expected_manifest_sha256 is not None
                    and secrets.compare_digest(
                        runtime_root.manifest_sha256,
                        runtime_root.expected_manifest_sha256,
                    )
                ),
                self._runtime_manifest_failure(runtime_root),
            ),
            (
                "kernel.no_new_privileges",
                kernel.no_new_privileges,
                "kernel_no_new_privileges_absent",
            ),
            (
                "kernel.cap_sys_admin_absent",
                not kernel.cap_sys_admin_effective,
                "kernel_cap_sys_admin_effective",
            ),
            (
                "kernel.seccomp_active",
                kernel.seccomp_mode == 2,
                "kernel_seccomp_filter_not_active",
            ),
            (
                "resource.cgroup_v2_delegated",
                kernel.cgroup_v2_delegated,
                ("cgroup_v2_not_delegated" if kernel.cgroup_v2_present else "cgroup_v2_missing"),
            ),
            (
                "isolation.synthetic_namespace_probe",
                namespace_probe.result_code == "passed",
                f"bubblewrap_namespace_probe_{namespace_probe.result_code}",
            ),
        )
        gates = tuple(
            self._gate(gate_id, passed, failure) for gate_id, passed, failure in gate_inputs
        )
        blockers = tuple(gate.failure_code for gate in gates if gate.failure_code is not None)
        values = {
            "provider_id": self.expectations.provider_id,
            "expectations_digest": content_digest(self.expectations.model_dump(mode="json")),
            "executables": observations,
            "runtime_root": runtime_root,
            "kernel": kernel,
            "namespace_probe": namespace_probe,
            "gates": gates,
            "blockers": blockers,
            "host_qualified": not blockers,
        }
        unsigned = LocalRunnerCapabilityReport.model_construct(
            **values,
            report_digest="0" * 64,
        )
        return LocalRunnerCapabilityReport(
            **values,
            report_digest=content_digest(
                unsigned.model_dump(mode="json", exclude={"report_digest"})
            ),
        )

    def decide(
        self,
        *,
        report: LocalRunnerCapabilityReport,
        qualification: RunnerQualificationDecision | None,
        authorization: LocalRunnerConnectionAuthorization | None,
        expected_bindings: LocalRunnerExecutionBindings,
        trusted_owner_public_keys: Mapping[str, bytes],
        now: datetime | None = None,
        forbidden_owner_key_ids: Collection[str] = (),
        used_authorization_ids: Collection[str] = (),
        revoked_authorization_ids: Collection[str] = (),
        minimum_generation: int = 0,
    ) -> LocalRunnerConnectionDecision:
        report = LocalRunnerCapabilityReport.model_validate(report.model_dump(mode="json"))
        observed_at = now or datetime.now(UTC)
        if not _aware(observed_at):
            raise ValueError("local runner decision time must be timezone-aware")
        failures = list(report.blockers)

        def fail(code: str) -> None:
            if code not in failures and len(failures) < 64:
                failures.append(code)

        qualification_verified = False
        if qualification is None:
            fail("independent_qualification_missing")
        else:
            qualification = RunnerQualificationDecision.model_validate(
                qualification.model_dump(mode="json")
            )
            qualification_verified = qualification.qualified and not qualification.failure_codes
            if not qualification_verified:
                fail("independent_qualification_failed")

        authorization_verified = False
        authorization_id: str | None = None
        authorization_digest: str | None = None
        if authorization is None:
            fail("signed_connection_authorization_missing")
        else:
            authorization = LocalRunnerConnectionAuthorization.model_validate(
                authorization.model_dump(mode="json")
            )
            authorization_failures: list[str] = []

            def require(condition: bool, code: str) -> None:
                if not condition and code not in authorization_failures:
                    authorization_failures.append(code)

            require(observed_at >= authorization.issued_at, "authorization_not_yet_valid")
            require(observed_at < authorization.expires_at, "authorization_expired")
            require(
                authorization.provider_id == report.provider_id,
                "authorization_provider_mismatch",
            )
            require(
                authorization.report_digest == report.report_digest,
                "authorization_report_mismatch",
            )
            require(
                authorization.bindings_digest == expected_bindings.bindings_digest,
                "authorization_bindings_mismatch",
            )
            require(
                authorization.bindings == expected_bindings,
                "authorization_binding_fields_mismatch",
            )
            if qualification is not None:
                require(
                    authorization.qualification_id == qualification.qualification_id,
                    "authorization_qualification_mismatch",
                )
                require(
                    authorization.qualification_evidence_digest == qualification.evidence_digest,
                    "authorization_evidence_mismatch",
                )
            require(
                authorization.owner_key_id not in set(forbidden_owner_key_ids),
                "candidate_or_runner_self_authorization",
            )
            require(
                authorization.authorization_id not in set(used_authorization_ids),
                "authorization_replayed",
            )
            require(
                authorization.authorization_id not in set(revoked_authorization_ids),
                "authorization_revoked",
            )
            require(
                authorization.generation > minimum_generation,
                "authorization_anti_rollback_failed",
            )
            public_key = trusted_owner_public_keys.get(authorization.owner_key_id)
            require(public_key is not None, "authorization_owner_untrusted")
            if public_key is not None:
                require(
                    runner_key_id(public_key) == authorization.owner_key_id,
                    "authorization_owner_key_id_invalid",
                )
                try:
                    Ed25519PublicKey.from_public_bytes(public_key).verify(
                        _decode_runner_signature(authorization.signature),
                        local_runner_authorization_signature_message(authorization),
                    )
                except (InvalidSignature, ValueError):
                    require(False, "authorization_signature_invalid")
            for code in authorization_failures:
                fail(code)
            authorization_verified = not authorization_failures
            if authorization_verified:
                authorization_id = authorization.authorization_id
                authorization_digest = authorization.authorization_digest

        values = {
            "provider_id": report.provider_id,
            "report_digest": report.report_digest,
            "host_qualified": report.host_qualified,
            "qualification_verified": qualification_verified,
            "authorization_verified": authorization_verified,
            "connection_authorized": not failures,
            "authorization_id": authorization_id,
            "authorization_digest": authorization_digest,
            "failure_codes": tuple(failures),
            "verified_at": observed_at,
        }
        unsigned = LocalRunnerConnectionDecision.model_construct(
            **values,
            decision_digest="0" * 64,
        )
        return LocalRunnerConnectionDecision(
            **values,
            decision_digest=content_digest(
                unsigned.model_dump(mode="json", exclude={"decision_digest"})
            ),
        )

    def _observe_executable(
        self,
        role: Literal["runtime", "limiter", "qualifier", "destroyer"],
        path_text: str,
        expected_sha256: str | None,
        *,
        observe_version: bool,
    ) -> LocalExecutableObservation:
        path = Path(path_text)
        present, trusted = self._trusted_executable(path)
        digest = self._file_digest(path) if trusted else None
        version: str | None = None
        version_probe: Literal["passed", "failed", "timed_out", "not_run"] = "not_run"
        version_output_digest: str | None = None
        if observe_version and trusted:
            result = self._run_bounded((path_text, "--version"))
            version_probe = (
                "timed_out" if result.timed_out else "passed" if result.exit_code == 0 else "failed"
            )
            version_output_digest = content_digest(
                {
                    "stdout": result.stdout_digest,
                    "stderr": result.stderr_digest,
                    "exit_code": result.exit_code,
                    "timed_out": result.timed_out,
                }
            )
            if version_probe == "passed":
                version = self._version_line(result.stdout or result.stderr)
        return LocalExecutableObservation(
            role=role,
            path=path_text,
            present=present,
            trusted=trusted,
            sha256=digest,
            expected_sha256=expected_sha256,
            version=version,
            version_probe=version_probe,
            version_output_digest=version_output_digest,
        )

    def _observe_runtime_root(self) -> LocalRuntimeRootObservation:
        root = Path(self.expectations.runtime_root)
        manifest = root / self.expectations.runtime_manifest_name
        present = root.exists()
        trusted = False
        if present:
            try:
                absolute = Path(os.path.abspath(os.fspath(root)))
                resolved = absolute.resolve(strict=True)
                metadata = absolute.lstat()
                trusted = (
                    absolute == resolved
                    and not absolute.is_symlink()
                    and absolute != Path("/")
                    and stat.S_ISDIR(metadata.st_mode)
                    and metadata.st_uid == 0
                    and not metadata.st_mode & 0o022
                )
            except OSError:
                trusted = False
        manifest_sha256 = None
        manifest_present, manifest_trusted = self._trusted_regular_file(manifest, executable=False)
        if trusted and manifest_present and manifest_trusted:
            manifest_sha256 = self._file_digest(manifest)
        return LocalRuntimeRootObservation(
            path=str(root),
            present=present,
            trusted=trusted,
            manifest_path=str(manifest),
            manifest_sha256=manifest_sha256,
            expected_manifest_sha256=self.expectations.runtime_manifest_sha256,
        )

    @staticmethod
    def _observe_kernel() -> LocalKernelObservation:
        system = os.uname().sysname if hasattr(os, "uname") else "unknown"
        status: dict[str, str] = {}
        try:
            for line in Path("/proc/self/status").read_text(encoding="utf-8").splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    status[key] = value.strip()
        except OSError:
            pass
        try:
            effective_capabilities = int(status.get("CapEff", "0"), 16)
        except ValueError:
            effective_capabilities = 0
        try:
            seccomp_mode = int(status.get("Seccomp", "0"))
        except ValueError:
            seccomp_mode = 0
        cgroup_root = Path("/sys/fs/cgroup")
        cgroup_v2_present = (cgroup_root / "cgroup.controllers").is_file()
        cgroup_v2_delegated = cgroup_v2_present and all(
            os.access(cgroup_root / name, os.W_OK)
            for name in ("cgroup.procs", "cgroup.subtree_control", "cgroup.kill")
        )
        return LocalKernelObservation(
            system=system,
            no_new_privileges=status.get("NoNewPrivs") == "1",
            seccomp_mode=seccomp_mode if seccomp_mode in {0, 1, 2} else 0,
            cap_sys_admin_effective=bool(effective_capabilities & (1 << 21)),
            cgroup_v2_present=cgroup_v2_present,
            cgroup_v2_delegated=cgroup_v2_delegated,
        )

    def _namespace_probe(
        self,
        observed: Mapping[str, LocalExecutableObservation],
    ) -> LocalCommandProbeObservation:
        runtime = observed["runtime"]
        limiter = observed["limiter"]
        command_digest = content_digest(
            {
                "schema_version": "local-runner-synthetic-namespace-probe-v1",
                "runtime_sha256": runtime.sha256,
                "limiter_sha256": limiter.sha256,
                "target_uid": self.expectations.target_uid,
                "target_gid": self.expectations.target_gid,
            }
        )
        if not runtime.trusted or not limiter.trusted:
            return self._not_run_probe(command_digest, "not_run_untrusted")
        if not self._hash_matches(runtime) or not self._hash_matches(limiter):
            return self._not_run_probe(command_digest, "not_run_unpinned")
        command = (
            self.expectations.limiter_path,
            "--as=268435456:268435456",
            "--cpu=2:2",
            "--nproc=32:32",
            "--fsize=1048576:1048576",
            "--nofile=64:64",
            "--",
            self.expectations.runtime_path,
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-cgroup-try",
            "--disable-userns",
            "--assert-userns-disabled",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--cap-drop",
            "ALL",
            "--uid",
            str(self.expectations.target_uid),
            "--gid",
            str(self.expectations.target_gid),
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--",
            "/usr/bin/id",
            "-u",
        )
        result = self._run_bounded(command)
        passed = (
            not result.timed_out
            and result.exit_code == 0
            and result.stdout.decode("utf-8", errors="replace").strip()
            == str(self.expectations.target_uid)
        )
        return LocalCommandProbeObservation(
            command_digest=command_digest,
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stdout_digest=result.stdout_digest,
            stderr_digest=result.stderr_digest,
            stdout_bytes=len(result.stdout),
            stderr_bytes=len(result.stderr),
            result_code=("passed" if passed else "timed_out" if result.timed_out else "failed"),
        )

    @staticmethod
    def _not_run_probe(
        command_digest: str,
        result_code: Literal["not_run_untrusted", "not_run_unpinned"],
    ) -> LocalCommandProbeObservation:
        empty = hashlib.sha256(b"").hexdigest()
        return LocalCommandProbeObservation(
            command_digest=command_digest,
            exit_code=None,
            timed_out=False,
            stdout_digest=empty,
            stderr_digest=empty,
            stdout_bytes=0,
            stderr_bytes=0,
            result_code=result_code,
        )

    @dataclass(frozen=True)
    class _BoundedResult:
        exit_code: int | None
        timed_out: bool
        stdout: bytes
        stderr: bytes
        stdout_digest: str
        stderr_digest: str

    def _run_bounded(self, command: tuple[str, ...]) -> _BoundedResult:
        try:
            process = subprocess.Popen(
                command,
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                },
                start_new_session=True,
            )
        except OSError as exc:
            normalized = self._normalize_output(str(exc).encode("utf-8"))
            return self._BoundedResult(
                exit_code=None,
                timed_out=False,
                stdout=b"",
                stderr=normalized,
                stdout_digest=self._EMPTY_DIGEST,
                stderr_digest=hashlib.sha256(normalized).hexdigest(),
            )
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=self.expectations.command_timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        stdout = self._normalize_output(stdout)
        stderr = self._normalize_output(stderr)
        return self._BoundedResult(
            exit_code=process.returncode,
            timed_out=timed_out,
            stdout=stdout[:1_000_000],
            stderr=stderr[:1_000_000],
            stdout_digest=hashlib.sha256(stdout).hexdigest(),
            stderr_digest=hashlib.sha256(stderr).hexdigest(),
        )

    @staticmethod
    def _normalize_output(value: bytes) -> bytes:
        text = value.decode("utf-8", errors="replace")
        text = re.sub(r"/proc/[0-9]+/", "/proc/<pid>/", text)
        text = text.replace("\r\n", "\n")
        return text.encode("utf-8")

    @staticmethod
    def _version_line(value: bytes) -> str | None:
        lines = value.decode("utf-8", errors="replace").splitlines()
        return lines[0][:256] if lines else None

    @classmethod
    def _trusted_executable(cls, path: Path) -> tuple[bool, bool]:
        return cls._trusted_regular_file(path, executable=True)

    @staticmethod
    def _trusted_regular_file(path: Path, *, executable: bool) -> tuple[bool, bool]:
        if not path.exists():
            return False, False
        try:
            absolute = Path(os.path.abspath(os.fspath(path)))
            resolved = absolute.resolve(strict=True)
            metadata = absolute.lstat()
        except OSError:
            return True, False
        trusted = (
            absolute == resolved
            and not absolute.is_symlink()
            and stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
            and metadata.st_uid == 0
            and not metadata.st_mode & 0o022
            and (not executable or os.access(absolute, os.X_OK))
        )
        return True, trusted

    @staticmethod
    def _file_digest(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _hash_matches(observation: LocalExecutableObservation) -> bool:
        return (
            observation.sha256 is not None
            and observation.expected_sha256 is not None
            and secrets.compare_digest(observation.sha256, observation.expected_sha256)
        )

    @staticmethod
    def _executable_failure(observation: LocalExecutableObservation) -> str:
        return (
            f"{observation.role}_executable_missing"
            if not observation.present
            else f"{observation.role}_executable_untrusted"
        )

    @staticmethod
    def _pin_failure(observation: LocalExecutableObservation) -> str:
        if observation.expected_sha256 is None:
            return f"{observation.role}_sha256_not_pinned"
        if observation.sha256 is None:
            return f"{observation.role}_sha256_unavailable"
        return f"{observation.role}_sha256_mismatch"

    @staticmethod
    def _runtime_manifest_failure(observation: LocalRuntimeRootObservation) -> str:
        if observation.expected_manifest_sha256 is None:
            return "runtime_manifest_sha256_not_pinned"
        if observation.manifest_sha256 is None:
            return "runtime_manifest_missing_or_untrusted"
        return "runtime_manifest_sha256_mismatch"

    @staticmethod
    def _gate(gate_id: str, passed: bool, failure_code: str) -> LocalRunnerProbeGate:
        values = {
            "gate_id": gate_id,
            "passed": passed,
            "failure_code": None if passed else failure_code,
        }
        draft = LocalRunnerProbeGate.model_construct(**values, evidence_digest="0" * 64)
        return LocalRunnerProbeGate(
            **values,
            evidence_digest=content_digest(
                draft.model_dump(mode="json", exclude={"evidence_digest"})
            ),
        )
