"""Validated environment contract. This module never loads dotenv files."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .limits import TRUSTED_WORK_ROOT_INODES


_SIGNING_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CANONICAL_OWNER_SCOPE = "ab43c7488fb38a90c7bb9c4bcc0e23e5"


@dataclass(frozen=True, slots=True)
class Config:
    database_url: str
    signing_keys: dict[str, bytes]
    canonical_owner_id: str
    openai_api_key: str
    openai_model: str
    runner_image: str
    work_root: Path
    work_root_inodes: int
    evidence_bucket: str
    evidence_endpoint: str
    aws_access_key_id: str
    aws_secret_access_key: str
    git_allowed_hosts: tuple[str, ...] = ()
    galor_readonly_url: str | None = None
    max_admitted_jobs: int = 1
    job_timeout_seconds: int = 20 * 60

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "Config":
        values = os.environ if environ is None else environ

        def required(name: str) -> str:
            value = values.get(name, "").strip()
            if not value:
                raise ValueError(f"missing configuration: {name}")
            return value

        try:
            raw_keys = json.loads(required("LIL_TWEAK_SIGNING_KEYS_JSON"))
        except json.JSONDecodeError:
            raise ValueError("invalid signing key configuration") from None
        if (
            not isinstance(raw_keys, dict)
            or not raw_keys
            or any(
                not isinstance(key, str)
                or not _SIGNING_KEY_ID.fullmatch(key)
                or not isinstance(value, str)
                or len(value.encode("utf-8")) < 32
                for key, value in raw_keys.items()
            )
        ):
            raise ValueError("invalid signing key configuration")
        runner_image = required("LIL_TWEAK_RUNNER_IMAGE")
        if "@sha256:" not in runner_image:
            raise ValueError("runner image must be digest-pinned")
        evidence_endpoint = required("LIL_TWEAK_EVIDENCE_ENDPOINT")
        if urlsplit(evidence_endpoint).scheme != "https":
            raise ValueError("evidence endpoint must use HTTPS")
        galor = values.get("LIL_TWEAK_GALOR_READONLY_URL", "").strip() or None
        if galor:
            galor_url = urlsplit(galor)
            if (
                galor_url.scheme != "https"
                or not galor_url.hostname
                or galor_url.username is not None
                or galor_url.password is not None
                or galor_url.query
                or galor_url.fragment
            ):
                raise ValueError("invalid GALOR read-only URL")
        git_allowed_hosts = tuple(
            item.strip().lower()
            for item in values.get("LIL_TWEAK_GIT_ALLOWED_HOSTS", "").split(",")
            if item.strip()
        )
        if any(
            not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host)
            or host.startswith(".")
            or host.endswith(".")
            for host in git_allowed_hosts
        ):
            raise ValueError("invalid Git host allowlist")
        try:
            max_admitted_jobs = int(
                values.get("LIL_TWEAK_MAX_ADMITTED_JOBS", "1")
            )
            job_timeout_seconds = int(
                values.get("LIL_TWEAK_JOB_TIMEOUT_SECONDS", "1200")
            )
        except ValueError:
            raise ValueError("invalid execution limits") from None
        if max_admitted_jobs != 1 or not 60 <= job_timeout_seconds <= 3600:
            raise ValueError("invalid execution limits")
        try:
            work_root_inodes = int(values.get("LIL_TWEAK_WORK_ROOT_INODES", ""))
        except ValueError:
            raise ValueError("invalid work root inode capacity") from None
        if work_root_inodes != TRUSTED_WORK_ROOT_INODES:
            raise ValueError("invalid work root inode capacity")
        canonical_owner_id = required("LIL_TWEAK_CANONICAL_OWNER_ID")
        if canonical_owner_id != CANONICAL_OWNER_SCOPE:
            raise ValueError("invalid canonical owner scope")
        return cls(
            database_url=required("LIL_TWEAK_DATABASE_URL"),
            signing_keys={key: value.encode("utf-8") for key, value in raw_keys.items()},
            canonical_owner_id=canonical_owner_id,
            openai_api_key=required("OPENAI_API_KEY"),
            openai_model=required("LIL_TWEAK_OPENAI_MODEL"),
            runner_image=runner_image,
            work_root=Path(required("LIL_TWEAK_WORK_ROOT")),
            work_root_inodes=work_root_inodes,
            evidence_bucket=required("LIL_TWEAK_EVIDENCE_BUCKET"),
            evidence_endpoint=evidence_endpoint,
            aws_access_key_id=required("LIL_TWEAK_R2_ACCESS_KEY_ID"),
            aws_secret_access_key=required("LIL_TWEAK_R2_SECRET_ACCESS_KEY"),
            git_allowed_hosts=git_allowed_hosts,
            galor_readonly_url=galor,
            max_admitted_jobs=max_admitted_jobs,
            job_timeout_seconds=job_timeout_seconds,
        )
