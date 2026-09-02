from __future__ import annotations

import base64
import binascii
import json
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CREDENTIALS_PATH = Path("/etc/liltweak-runner/credentials.json")
SIGNING_KEY_PATH = Path("/etc/liltweak-runner/runner_signing_key.pem")
CONTROL_PLANE_URL = "https://runner-control.liltweak.galorweb.works"
MAX_CREDENTIAL_BYTES = 16_384
_KEY_ID = re.compile(r"^[a-f0-9]{64}$")
_BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")


class ConfigError(ValueError):
    """Reject unsafe host runner configuration."""


@dataclass(frozen=True)
class RunnerCredentials:
    control_plane_url: str
    cf_access_client_id: str
    cf_access_client_secret: str
    runner_bearer_token: str
    controller_key_id: str
    controller_public_key: bytes
    runner_private_key: Ed25519PrivateKey


def _secret(value: object, label: str) -> str:
    if not isinstance(value, str) or not 8 <= len(value) <= 4096:
        raise ConfigError(f"{label} is invalid")
    if "\r" in value or "\n" in value or "\0" in value:
        raise ConfigError(f"{label} is invalid")
    return value


def _raw_key(value: object, label: str) -> bytes:
    if not isinstance(value, str) or not _BASE64URL.fullmatch(value):
        raise ConfigError(f"{label} is invalid")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise ConfigError(f"{label} is invalid") from exc
    if len(decoded) != 32:
        raise ConfigError(f"{label} has an invalid length")
    return decoded


def parse_credentials(
    value: object,
    *,
    runner_private_key: Ed25519PrivateKey,
) -> RunnerCredentials:
    expected = {
        "schema_version",
        "endpoint",
        "runner_id",
        "bearer_token",
        "access_client_id",
        "access_client_secret",
        "dispatch_key_id",
        "dispatch_public_key",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise ConfigError("runner credentials have an invalid shape")
    payload = cast(Mapping[str, object], value)
    if payload["schema_version"] != "lil-tweak.runner-credentials/v1":
        raise ConfigError("runner credentials schema is invalid")
    if payload["endpoint"] != CONTROL_PLANE_URL:
        raise ConfigError("control plane URL is not authorized")
    if payload["runner_id"] != "galor-tweak-runner-01":
        raise ConfigError("runner identity is not authorized")
    key_id = payload["dispatch_key_id"]
    if not isinstance(key_id, str) or not _KEY_ID.fullmatch(key_id):
        raise ConfigError("controller key id is invalid")
    return RunnerCredentials(
        control_plane_url=CONTROL_PLANE_URL,
        cf_access_client_id=_secret(payload["access_client_id"], "Access client id"),
        cf_access_client_secret=_secret(payload["access_client_secret"], "Access client secret"),
        runner_bearer_token=_secret(payload["bearer_token"], "runner bearer token"),
        controller_key_id=key_id,
        controller_public_key=_raw_key(payload["dispatch_public_key"], "controller public key"),
        runner_private_key=runner_private_key,
    )


def validate_secret_metadata(metadata: object, *, process_uid: int) -> None:
    if process_uid != 0:
        raise ConfigError("runner supervisor must execute as root")
    mode = int(getattr(metadata, "st_mode", 0))
    if not stat.S_ISREG(mode):
        raise ConfigError("credentials must be a regular file")
    if int(getattr(metadata, "st_uid", -1)) != 0:
        raise ConfigError("credentials must be root owned")
    if int(getattr(metadata, "st_nlink", 0)) != 1:
        raise ConfigError("credentials must have a single link")
    if stat.S_IMODE(mode) not in {0o400, 0o600}:
        raise ConfigError("credentials permissions must be 0400 or 0600")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("credentials contain a duplicate JSON key")
        result[key] = value
    return result


def _read_secret_file(path: Path, *, max_bytes: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        get_effective_uid = getattr(os, "geteuid", lambda: -1)
        validate_secret_metadata(metadata, process_uid=get_effective_uid())
        if metadata.st_size < 2 or metadata.st_size > max_bytes:
            raise ConfigError("protected file size is invalid")
        raw = os.read(descriptor, max_bytes + 1)
        final = os.fstat(descriptor)
        if (
            len(raw) != metadata.st_size
            or final.st_dev != metadata.st_dev
            or final.st_ino != metadata.st_ino
            or final.st_size != metadata.st_size
            or final.st_nlink != 1
        ):
            raise ConfigError("protected file changed while being read")
    finally:
        os.close(descriptor)
    return raw


def load_credentials(
    path: Path = CREDENTIALS_PATH,
    signing_key_path: Path = SIGNING_KEY_PATH,
) -> RunnerCredentials:
    if path != CREDENTIALS_PATH or signing_key_path != SIGNING_KEY_PATH:
        raise ConfigError("protected runner path is not authorized")
    raw = _read_secret_file(path, max_bytes=MAX_CREDENTIAL_BYTES)
    private_key_bytes = _read_secret_file(signing_key_path, max_bytes=4096)
    try:
        loaded_key = serialization.load_pem_private_key(private_key_bytes, password=None)
    except (TypeError, ValueError) as exc:
        raise ConfigError("runner signing key is invalid") from exc
    if not isinstance(loaded_key, Ed25519PrivateKey):
        raise ConfigError("runner signing key is not Ed25519")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError("credentials JSON is invalid") from exc
    return parse_credentials(payload, runner_private_key=loaded_key)
