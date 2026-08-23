from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .reasoning_policy import (
    PROFILE_REGISTRY,
    REASONING_POLICY,
    ReasoningProfileName,
    ReasoningProfileUnavailable,
    require_primary_engineering_model,
)

_ORDINARY_PROFILE = PROFILE_REGISTRY[ReasoningProfileName.ORDINARY]


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    return default if raw is None else float(raw)


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    return default if raw is None else int(raw)


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    lowered = raw.casefold()
    if lowered not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false")
    return lowered == "true"


def _repository_mappings_env() -> dict[str, str]:
    raw = os.getenv("LILTWEAK_REPOSITORIES_JSON", "{}")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("LILTWEAK_REPOSITORIES_JSON must be valid JSON") from exc
    if not isinstance(payload, dict) or len(payload) > 1_000:
        raise ValueError("LILTWEAK_REPOSITORIES_JSON must be an object with at most 1000 entries")
    mappings: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError("repository mapping keys and values must be strings")
        if re.fullmatch(r"(?:local|github):[A-Za-z0-9][A-Za-z0-9._:-]{0,120}", key) is None:
            raise ValueError(
                "repository mapping keys must be URL-safe opaque local: or github: identifiers"
            )
        mappings[key] = value
    return mappings


def _json_text_env(name: str) -> str | None:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return None
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} must be valid JSON") from exc
    return raw


def _key_env(name: str) -> bytes | None:
    raw = os.getenv(name)
    if not raw:
        return None
    if re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", raw) is None:
        raise ValueError(f"{name} must be URL-safe base64")
    try:
        padded = raw + ("=" * (-len(raw) % 4))
        key = base64.b64decode(
            padded.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{name} must be URL-safe base64") from exc
    if len(key) != 32:
        raise ValueError(f"{name} must decode to exactly 32 bytes")
    return key


def _artifact_key_env() -> bytes | None:
    return _key_env("LILTWEAK_ARTIFACT_ENCRYPTION_KEY")


def _evidence_key_env() -> bytes | None:
    return _key_env("LILTWEAK_EVIDENCE_SIGNING_KEY")


def _creator_key_env() -> bytes | None:
    return _key_env("LILTWEAK_CREATOR_SIGNING_KEY")


def _owner_id_env() -> str:
    value = os.getenv("LILTWEAK_OWNER_ID", "maurice-pennington-bey")
    if (
        not value
        or len(value) > 128
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("LILTWEAK_OWNER_ID must be a non-empty safe identifier")
    return value


def _engineering_model_env() -> str:
    try:
        return require_primary_engineering_model(
            os.getenv("LILTWEAK_MODEL", REASONING_POLICY.primary_model.value)
        ).value
    except ReasoningProfileUnavailable as exc:
        raise ValueError("LILTWEAK_MODEL must name the canonical primary model") from exc


@dataclass(frozen=True)
class Settings:
    environment: str
    database_path: Path
    dev_api_key: str | None
    auth_disabled: bool
    model: str
    monthly_budget_usd: float
    job_hard_limit_usd: float
    planning_reservation_usd: float = 1.0
    workspace_root: Path = Path("./repositories")
    repository_mappings: dict[str, str] = field(default_factory=dict)
    owner_id: str = "maurice-pennington-bey"
    artifact_root: Path = Path("./artifacts")
    artifact_encryption_key: bytes | None = None
    evidence_signing_key: bytes | None = None
    creator_signing_key: bytes | None = None
    live_model_enabled: bool = False
    live_monthly_limit_usd: float = 5.0
    live_call_limit_usd: float = 0.10
    live_input_token_limit: int = 12_000
    live_output_token_limit: int = 1_024
    repository_execution_enabled: bool = False
    execution_runtime_root: Path = Path("./runtime-root")
    execution_image_ref: str | None = None
    server_host: str = "127.0.0.1"
    workbench_enabled: bool = False
    workbench_model_enabled: bool = False
    workbench_model: str = _ORDINARY_PROFILE.model.value
    workbench_reasoning_tier: str = _ORDINARY_PROFILE.variant.effort.value
    workbench_reasoning_mode: str = _ORDINARY_PROFILE.variant.request_mode.value
    workbench_reasoning_profile: str = _ORDINARY_PROFILE.name.value
    workbench_workspace_root: Path = Path("./workbench-tasks")
    workbench_session_ttl_seconds: int = 3_600
    workbench_rate_limit_per_minute: int = 120
    workbench_input_token_limit: int = 12_000
    workbench_output_token_limit: int = 4_096
    workbench_cost_ceiling_usd: float = 0.20
    workbench_monthly_limit_usd: float = 5.0
    workbench_runner_enabled: bool = False
    workbench_runner_gateway_url: str | None = None
    workbench_runner_contract_json: str | None = None
    workbench_runner_expected_contract_digest: str | None = None
    workbench_runner_qualification_digest: str | None = None
    workbench_runner_authorization_digest: str | None = None
    workbench_runner_auth_token: str | None = field(default=None, repr=False)
    workbench_runner_signing_keys_json: str | None = None

    def __post_init__(self) -> None:
        supported_environments = {
            "development",
            "test",
            "preview",
            "staging",
            "production",
        }
        if self.environment not in supported_environments:
            raise ValueError("LILTWEAK_ENVIRONMENT is not supported")
        if self.auth_disabled and self.environment != "test":
            raise ValueError("authentication can be disabled only in the test environment")
        numeric_settings = {
            "LILTWEAK_MONTHLY_BUDGET_USD": (self.monthly_budget_usd, True),
            "LILTWEAK_JOB_HARD_LIMIT_USD": (self.job_hard_limit_usd, False),
            "LILTWEAK_PLANNING_RESERVATION_USD": (
                self.planning_reservation_usd,
                False,
            ),
        }
        for name, (value, zero_allowed) in numeric_settings.items():
            if (
                isinstance(value, bool)
                or not math.isfinite(value)
                or value < 0
                or (value == 0 and not zero_allowed)
            ):
                qualifier = "non-negative" if zero_allowed else "positive"
                raise ValueError(f"{name} must be a finite {qualifier} number")
        for name, value in {
            "LILTWEAK_LIVE_MONTHLY_LIMIT_USD": self.live_monthly_limit_usd,
            "LILTWEAK_LIVE_CALL_LIMIT_USD": self.live_call_limit_usd,
        }.items():
            if isinstance(value, bool) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} must be a finite positive number")
        if self.live_input_token_limit < 256 or self.live_input_token_limit > 200_000:
            raise ValueError("LILTWEAK_LIVE_INPUT_TOKEN_LIMIT is invalid")
        if self.live_output_token_limit < 1_024 or self.live_output_token_limit > 32_000:
            raise ValueError("LILTWEAK_LIVE_OUTPUT_TOKEN_LIMIT is invalid")
        if self.workbench_reasoning_tier not in {"low", "medium", "high", "xhigh", "max"}:
            raise ValueError("LILTWEAK_WORKBENCH_REASONING_TIER is invalid")
        if self.workbench_reasoning_mode not in {"standard", "pro"}:
            raise ValueError("LILTWEAK_WORKBENCH_REASONING_MODE is invalid")
        try:
            profile = PROFILE_REGISTRY[ReasoningProfileName(self.workbench_reasoning_profile)]
        except (KeyError, ValueError) as exc:
            raise ValueError("LILTWEAK_WORKBENCH_REASONING_PROFILE is invalid") from exc
        if (
            self.workbench_model != profile.model.value
            or self.workbench_reasoning_tier != profile.variant.effort.value
            or self.workbench_reasoning_mode != profile.variant.request_mode.value
        ):
            raise ValueError(
                "Workbench model, mode, and effort must match the named reasoning profile"
            )
        if self.workbench_session_ttl_seconds < 300 or self.workbench_session_ttl_seconds > 86_400:
            raise ValueError("LILTWEAK_WORKBENCH_SESSION_TTL_SECONDS is invalid")
        if (
            self.workbench_rate_limit_per_minute < 10
            or self.workbench_rate_limit_per_minute > 10_000
        ):
            raise ValueError("LILTWEAK_WORKBENCH_RATE_LIMIT_PER_MINUTE is invalid")
        if self.workbench_input_token_limit < 256 or self.workbench_input_token_limit > 200_000:
            raise ValueError("LILTWEAK_WORKBENCH_INPUT_TOKEN_LIMIT is invalid")
        if self.workbench_output_token_limit < 1_024 or self.workbench_output_token_limit > 32_000:
            raise ValueError("LILTWEAK_WORKBENCH_OUTPUT_TOKEN_LIMIT is invalid")
        if (
            not math.isfinite(self.workbench_cost_ceiling_usd)
            or self.workbench_cost_ceiling_usd <= 0
        ):
            raise ValueError("LILTWEAK_WORKBENCH_COST_CEILING_USD must be positive")
        if (
            not math.isfinite(self.workbench_monthly_limit_usd)
            or self.workbench_monthly_limit_usd < self.workbench_cost_ceiling_usd
        ):
            raise ValueError("LILTWEAK_WORKBENCH_MONTHLY_LIMIT_USD must cover one call ceiling")
        if (
            not isinstance(self.server_host, str)
            or not self.server_host
            or len(self.server_host) > 253
            or any(ord(character) < 33 or ord(character) == 127 for character in self.server_host)
        ):
            raise ValueError("LILTWEAK_SERVER_HOST is invalid")
        if self.workbench_enabled:
            try:
                bind_address = ipaddress.ip_address(self.server_host)
            except ValueError as exc:
                raise ValueError(
                    "private Workbench requires LILTWEAK_SERVER_HOST to be a loopback IP literal"
                ) from exc
            if not bind_address.is_loopback:
                raise ValueError(
                    "private Workbench requires LILTWEAK_SERVER_HOST to be a loopback IP literal"
                )
        if self.workbench_enabled and not self.dev_api_key:
            raise ValueError("private Workbench requires LILTWEAK_DEV_API_KEY")
        if self.workbench_runner_enabled:
            for name, value in {
                "LILTWEAK_WORKBENCH_RUNNER_GATEWAY_URL": self.workbench_runner_gateway_url,
                "LILTWEAK_WORKBENCH_RUNNER_CONTRACT_JSON": self.workbench_runner_contract_json,
                "LILTWEAK_WORKBENCH_RUNNER_EXPECTED_CONTRACT_DIGEST": (
                    self.workbench_runner_expected_contract_digest
                ),
                "LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_DIGEST": (
                    self.workbench_runner_qualification_digest
                ),
                "LILTWEAK_WORKBENCH_RUNNER_AUTHORIZATION_DIGEST": (
                    self.workbench_runner_authorization_digest
                ),
                "LILTWEAK_WORKBENCH_RUNNER_AUTH_TOKEN": self.workbench_runner_auth_token,
                "LILTWEAK_WORKBENCH_RUNNER_SIGNING_KEYS_JSON": (
                    self.workbench_runner_signing_keys_json
                ),
            }.items():
                if value in {None, ""}:
                    raise ValueError(f"{name} is required when the GALOR Runner V2 is enabled")
            if self.workbench_runner_gateway_url is not None:
                parsed = re.fullmatch(r"https?://[^/\s?#]+(?:/[^?#\s]*)?", self.workbench_runner_gateway_url)
                if parsed is None:
                    raise ValueError("LILTWEAK_WORKBENCH_RUNNER_GATEWAY_URL is invalid")
            for name, value in {
                "LILTWEAK_WORKBENCH_RUNNER_EXPECTED_CONTRACT_DIGEST": (
                    self.workbench_runner_expected_contract_digest
                ),
                "LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_DIGEST": (
                    self.workbench_runner_qualification_digest
                ),
                "LILTWEAK_WORKBENCH_RUNNER_AUTHORIZATION_DIGEST": (
                    self.workbench_runner_authorization_digest
                ),
            }.items():
                if value is None or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                    raise ValueError(f"{name} must be a lowercase SHA-256 digest")
            if (
                self.workbench_runner_auth_token is not None
                and (
                    len(self.workbench_runner_auth_token) < 16
                    or any(
                        ord(character) < 33 or ord(character) == 127
                        for character in self.workbench_runner_auth_token
                    )
                )
            ):
                raise ValueError("LILTWEAK_WORKBENCH_RUNNER_AUTH_TOKEN is invalid")
        if (
            self.live_model_enabled
            and self.creator_signing_key is None
            and self.evidence_signing_key is None
        ):
            raise ValueError(
                "live model calls require LILTWEAK_CREATOR_SIGNING_KEY "
                "or LILTWEAK_EVIDENCE_SIGNING_KEY"
            )
        if self.repository_execution_enabled:
            if self.creator_signing_key is None and self.evidence_signing_key is None:
                raise ValueError(
                    "repository execution requires a durable Creator or evidence signing key"
                )
            if (
                self.execution_image_ref is None
                or re.fullmatch(
                    r"[a-z0-9][a-z0-9._/-]{0,255}@sha256:[0-9a-f]{64}",
                    self.execution_image_ref,
                )
                is None
            ):
                raise ValueError("repository execution requires an immutable runtime image digest")
            resolved_roots = {
                "workspace": self.workspace_root.resolve(),
                "artifact": self.artifact_root.resolve(),
                "runtime": self.execution_runtime_root.resolve(),
            }
            if Path("/") in resolved_roots.values() or len(set(resolved_roots.values())) != 3:
                raise ValueError("workspace, artifact, and runtime roots must be distinct")
            roots = list(resolved_roots.values())
            if any(
                first.is_relative_to(second) or second.is_relative_to(first)
                for index, first in enumerate(roots)
                for second in roots[index + 1 :]
            ):
                raise ValueError("workspace, artifact, and runtime roots must be disjoint")
        for name, key in {
            "LILTWEAK_ARTIFACT_ENCRYPTION_KEY": self.artifact_encryption_key,
            "LILTWEAK_EVIDENCE_SIGNING_KEY": self.evidence_signing_key,
            "LILTWEAK_CREATOR_SIGNING_KEY": self.creator_signing_key,
        }.items():
            if key is not None and (not isinstance(key, bytes) or len(key) != 32):
                raise ValueError(f"{name} must contain exactly 32 bytes")
        if self.environment == "production" and self.evidence_signing_key is None:
            raise ValueError("production requires LILTWEAK_EVIDENCE_SIGNING_KEY")

    @classmethod
    def from_env(cls) -> Settings:
        environment = os.getenv("LILTWEAK_ENVIRONMENT", "development")
        auth_disabled = _bool_env("LILTWEAK_AUTH_DISABLED")
        if auth_disabled and environment != "test":
            raise ValueError("authentication can be disabled only in the test environment")
        evidence_signing_key = _evidence_key_env()
        if environment == "production" and evidence_signing_key is None:
            raise ValueError("production requires LILTWEAK_EVIDENCE_SIGNING_KEY")
        return cls(
            environment=environment,
            database_path=Path(os.getenv("LILTWEAK_DB_PATH", "./data/liltweak.db")),
            dev_api_key=os.getenv("LILTWEAK_DEV_API_KEY"),
            auth_disabled=auth_disabled,
            model=_engineering_model_env(),
            monthly_budget_usd=_float_env("LILTWEAK_MONTHLY_BUDGET_USD", 250.0),
            job_hard_limit_usd=_float_env("LILTWEAK_JOB_HARD_LIMIT_USD", 5.0),
            planning_reservation_usd=_float_env(
                "LILTWEAK_PLANNING_RESERVATION_USD",
                1.0,
            ),
            workspace_root=Path(os.getenv("LILTWEAK_WORKSPACE_ROOT", "./repositories")),
            repository_mappings=_repository_mappings_env(),
            owner_id=_owner_id_env(),
            artifact_root=Path(os.getenv("LILTWEAK_ARTIFACT_ROOT", "./artifacts")),
            artifact_encryption_key=_artifact_key_env(),
            evidence_signing_key=evidence_signing_key,
            creator_signing_key=_creator_key_env(),
            live_model_enabled=_bool_env("LILTWEAK_LIVE_MODEL_ENABLED"),
            live_monthly_limit_usd=_float_env(
                "LILTWEAK_LIVE_MONTHLY_LIMIT_USD",
                5.0,
            ),
            live_call_limit_usd=_float_env(
                "LILTWEAK_LIVE_CALL_LIMIT_USD",
                0.10,
            ),
            live_input_token_limit=_int_env(
                "LILTWEAK_LIVE_INPUT_TOKEN_LIMIT",
                12_000,
            ),
            live_output_token_limit=_int_env(
                "LILTWEAK_LIVE_OUTPUT_TOKEN_LIMIT",
                1_024,
            ),
            repository_execution_enabled=_bool_env("LILTWEAK_REPOSITORY_EXECUTION_ENABLED"),
            execution_runtime_root=Path(
                os.getenv("LILTWEAK_EXECUTION_RUNTIME_ROOT", "./runtime-root")
            ),
            execution_image_ref=os.getenv("LILTWEAK_EXECUTION_IMAGE_REF"),
            server_host=os.getenv("LILTWEAK_SERVER_HOST", "127.0.0.1"),
            workbench_enabled=_bool_env("LILTWEAK_WORKBENCH_ENABLED", False),
            workbench_model_enabled=_bool_env("LILTWEAK_WORKBENCH_MODEL_ENABLED"),
            workbench_model=os.getenv("LILTWEAK_WORKBENCH_MODEL", _ORDINARY_PROFILE.model.value),
            workbench_reasoning_tier=os.getenv(
                "LILTWEAK_WORKBENCH_REASONING_TIER",
                _ORDINARY_PROFILE.variant.effort.value,
            ),
            workbench_reasoning_mode=os.getenv(
                "LILTWEAK_WORKBENCH_REASONING_MODE",
                _ORDINARY_PROFILE.variant.request_mode.value,
            ),
            workbench_reasoning_profile=os.getenv(
                "LILTWEAK_WORKBENCH_REASONING_PROFILE", _ORDINARY_PROFILE.name.value
            ),
            workbench_workspace_root=Path(
                os.getenv("LILTWEAK_WORKBENCH_WORKSPACE_ROOT", "./workbench-tasks")
            ),
            workbench_session_ttl_seconds=_int_env("LILTWEAK_WORKBENCH_SESSION_TTL_SECONDS", 3_600),
            workbench_rate_limit_per_minute=_int_env(
                "LILTWEAK_WORKBENCH_RATE_LIMIT_PER_MINUTE", 120
            ),
            workbench_input_token_limit=_int_env("LILTWEAK_WORKBENCH_INPUT_TOKEN_LIMIT", 12_000),
            workbench_output_token_limit=_int_env("LILTWEAK_WORKBENCH_OUTPUT_TOKEN_LIMIT", 4_096),
            workbench_cost_ceiling_usd=_float_env("LILTWEAK_WORKBENCH_COST_CEILING_USD", 0.20),
            workbench_monthly_limit_usd=_float_env("LILTWEAK_WORKBENCH_MONTHLY_LIMIT_USD", 5.0),
            workbench_runner_enabled=_bool_env("LILTWEAK_WORKBENCH_RUNNER_ENABLED", False),
            workbench_runner_gateway_url=os.getenv("LILTWEAK_WORKBENCH_RUNNER_GATEWAY_URL"),
            workbench_runner_contract_json=_json_text_env("LILTWEAK_WORKBENCH_RUNNER_CONTRACT_JSON"),
            workbench_runner_expected_contract_digest=os.getenv(
                "LILTWEAK_WORKBENCH_RUNNER_EXPECTED_CONTRACT_DIGEST"
            ),
            workbench_runner_qualification_digest=os.getenv(
                "LILTWEAK_WORKBENCH_RUNNER_QUALIFICATION_DIGEST"
            ),
            workbench_runner_authorization_digest=os.getenv(
                "LILTWEAK_WORKBENCH_RUNNER_AUTHORIZATION_DIGEST"
            ),
            workbench_runner_auth_token=os.getenv("LILTWEAK_WORKBENCH_RUNNER_AUTH_TOKEN"),
            workbench_runner_signing_keys_json=_json_text_env(
                "LILTWEAK_WORKBENCH_RUNNER_SIGNING_KEYS_JSON"
            ),
        )
