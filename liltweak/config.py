from __future__ import annotations

import base64
import binascii
import json
import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path


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
        if not key.startswith(("local:", "github:")):
            raise ValueError("repository mapping keys must start with local: or github:")
        mappings[key] = value
    return mappings


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
        if (
            self.live_model_enabled
            and self.creator_signing_key is None
            and self.evidence_signing_key is None
        ):
            raise ValueError(
                "live model calls require LILTWEAK_CREATOR_SIGNING_KEY "
                "or LILTWEAK_EVIDENCE_SIGNING_KEY"
            )
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
            model=os.getenv("LILTWEAK_MODEL", "gpt-5.6-luna"),
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
        )
