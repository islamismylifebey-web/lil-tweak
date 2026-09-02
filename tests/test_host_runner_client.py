from __future__ import annotations

import base64
import json
from types import SimpleNamespace

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from runner.client import ControlPlaneClient, ControlPlaneError
from runner.config import ConfigError, parse_credentials, validate_secret_metadata
from runner.protocol import canonical_json


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _credentials_payload() -> dict[str, object]:
    return {
        "schema_version": "lil-tweak.runner-credentials/v1",
        "endpoint": "https://runner-control.liltweak.galorweb.works",
        "runner_id": "galor-tweak-runner-01",
        "bearer_token": "runner-bearer",
        "access_client_id": "runner.access",
        "access_client_secret": "access-secret",
        "dispatch_key_id": "a" * 64,
        "dispatch_public_key": _b64url(b"c" * 32),
    }


def _parse_credentials() -> object:
    return parse_credentials(
        _credentials_payload(),
        runner_private_key=Ed25519PrivateKey.from_private_bytes(b"r" * 32),
    )


def test_credentials_reject_any_control_plane_url_substitution() -> None:
    payload = _credentials_payload()
    payload["endpoint"] = "https://attacker.invalid"

    with pytest.raises(ConfigError, match="control plane"):
        parse_credentials(
            payload,
            runner_private_key=Ed25519PrivateKey.from_private_bytes(b"r" * 32),
        )


def test_credentials_file_must_be_root_owned_single_link_and_private() -> None:
    with pytest.raises(ConfigError, match="permissions"):
        validate_secret_metadata(
            SimpleNamespace(st_mode=0o100640, st_uid=0, st_nlink=1),
            process_uid=0,
        )
    with pytest.raises(ConfigError, match="root owned"):
        validate_secret_metadata(
            SimpleNamespace(st_mode=0o100600, st_uid=1000, st_nlink=1),
            process_uid=0,
        )
    with pytest.raises(ConfigError, match="single link"):
        validate_secret_metadata(
            SimpleNamespace(st_mode=0o100600, st_uid=0, st_nlink=2),
            process_uid=0,
        )


def test_poll_is_access_authenticated_and_operation_domain_signed() -> None:
    credentials = _parse_credentials()
    runner_public_key = credentials.runner_private_key.public_key()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == (
            "https://runner-control.liltweak.galorweb.works/v1/runners/galor-tweak-runner-01/next"
        )
        assert request.headers["Authorization"] == "Bearer runner-bearer"
        assert request.headers["CF-Access-Client-Id"] == "runner.access"
        assert request.headers["CF-Access-Client-Secret"] == "access-secret"
        envelope = json.loads(request.content)
        assert envelope["request"]["operation"] == "poll"
        runner_public_key.verify(
            base64.urlsafe_b64decode(envelope["signature"] + "=="),
            ("lil-tweak.runner-request/poll/v1\n" + canonical_json(envelope["request"])).encode(),
        )
        return httpx.Response(404, json={"error": "no_offer"})

    client = ControlPlaneClient(
        credentials,
        transport=httpx.MockTransport(handler),
        clock_ms=lambda: 1_000_000,
        nonce=lambda: b"n" * 32,
    )

    assert client.poll() is None


def test_claim_rejects_any_non_success_response_without_executing() -> None:
    credentials = _parse_credentials()

    client = ControlPlaneClient(
        credentials,
        transport=httpx.MockTransport(
            lambda request: httpx.Response(409, json={"error": "replayed"})
        ),
        clock_ms=lambda: 1_000_000,
        nonce=lambda: b"n" * 32,
    )

    with pytest.raises(ControlPlaneError, match="claim rejected"):
        client.claim(execution_id="exec-001", attempt_nonce=_b64url(b"a" * 32))
