from __future__ import annotations

from pathlib import Path

import pytest

import main as entrypoint
from liltweak.config import Settings, _repository_mappings_env


def _settings(*, server_host: str = "127.0.0.1", workbench_enabled: bool = False) -> Settings:
    return Settings(
        environment="test",
        database_path=Path(":memory:"),
        dev_api_key="owner-key" if workbench_enabled else None,
        auth_disabled=False,
        model="test-model",
        monthly_budget_usd=250,
        job_hard_limit_usd=5,
        server_host=server_host,
        workbench_enabled=workbench_enabled,
    )


def test_server_bind_defaults_to_explicit_ipv4_loopback() -> None:
    assert _settings().server_host == "127.0.0.1"


@pytest.mark.parametrize("server_host", ["127.0.0.1", "127.42.0.7", "::1"])
def test_private_workbench_accepts_only_literal_loopback_addresses(server_host: str) -> None:
    assert _settings(server_host=server_host, workbench_enabled=True).server_host == server_host


@pytest.mark.parametrize(
    "server_host",
    ["0.0.0.0", "::", "192.168.1.10", "203.0.113.10", "localhost", "*", ""],
)
def test_private_workbench_rejects_wildcard_or_non_loopback_bind(server_host: str) -> None:
    with pytest.raises(ValueError, match=r"loopback IP literal|SERVER_HOST is invalid"):
        _settings(server_host=server_host, workbench_enabled=True)


def test_non_workbench_service_retains_explicit_deployment_bind() -> None:
    assert _settings(server_host="0.0.0.0").server_host == "0.0.0.0"


def test_repository_ids_use_one_url_safe_opaque_grammar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "LILTWEAK_REPOSITORIES_JSON",
        '{"github:owner.project":"snapshots/project","local:repo_one":"repository"}',
    )
    assert _repository_mappings_env() == {
        "github:owner.project": "snapshots/project",
        "local:repo_one": "repository",
    }
    monkeypatch.setenv(
        "LILTWEAK_REPOSITORIES_JSON",
        '{"github:owner/project":"snapshots/project"}',
    )
    with pytest.raises(ValueError, match="URL-safe opaque"):
        _repository_mappings_env()


def test_builtin_server_uses_validated_settings_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    application = object()

    monkeypatch.setenv("PORT", "8765")
    monkeypatch.setenv("LILTWEAK_WORKBENCH_ENABLED", "true")
    monkeypatch.setenv("LILTWEAK_DEV_API_KEY", "owner-key")
    monkeypatch.setenv("LILTWEAK_SERVER_HOST", "127.0.0.1")
    monkeypatch.setattr(
        entrypoint,
        "create_app",
        lambda *, settings: observed.setdefault("settings", settings) and application,
    )

    def fake_run(app: object, **kwargs: object) -> None:
        observed["app"] = app
        observed.update(kwargs)

    monkeypatch.setattr(entrypoint.uvicorn, "run", fake_run)

    entrypoint.main()

    settings = observed["settings"]
    assert isinstance(settings, Settings)
    assert settings.server_host == "127.0.0.1"
    assert observed == {
        "settings": settings,
        "app": application,
        "host": "127.0.0.1",
        "port": 8765,
        "log_level": "info",
    }
