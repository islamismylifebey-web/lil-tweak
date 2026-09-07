from __future__ import annotations

from fastapi.testclient import TestClient

from liltweak.vercel_boundary import trusted_vercel_deployment_host
from liltweak.vercel_runtime import create_vercel_app


def test_only_vercel_owned_deployment_hosts_are_trusted() -> None:
    deployed = "lil-tweak-abc123-galor-web-works.vercel.app"
    branch = "lil-tweak-git-feat-restore-real-tweak-vercel-galor-web-works.vercel.app"
    assert trusted_vercel_deployment_host(deployed, deployed, branch)
    assert trusted_vercel_deployment_host(branch, deployed, branch)
    assert not trusted_vercel_deployment_host("lil-tweak.vercel.app", deployed, branch)
    assert not trusted_vercel_deployment_host("evil.example", deployed, branch)


def test_protected_vercel_host_auto_establishes_owner_session(monkeypatch, tmp_path) -> None:
    deployed = "lil-tweak-abc123-galor-web-works.vercel.app"
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "preview")
    monkeypatch.setenv("VERCEL_URL", deployed)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-placeholder-not-used")
    monkeypatch.setenv("LILTWEAK_VERCEL_STATE_ROOT", str(tmp_path))
    app = create_vercel_app(enable_model=False)
    client = TestClient(app, base_url=f"https://{deployed}")
    response = client.get("/v1/workbench/session")
    assert response.status_code == 200
    body = response.json()
    assert body["authenticated"] is True
    assert body["actor_id"] == "maurice-pennington-bey"
    assert response.cookies.get("liltweak_owner_session")


def test_protected_branch_alias_auto_establishes_owner_session(monkeypatch, tmp_path) -> None:
    deployed = "lil-tweak-abc123-galor-web-works.vercel.app"
    branch = "lil-tweak-git-feat-restore-real-tweak-vercel-galor-web-works.vercel.app"
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "preview")
    monkeypatch.setenv("VERCEL_URL", deployed)
    monkeypatch.setenv("VERCEL_BRANCH_URL", branch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-placeholder-not-used")
    monkeypatch.setenv("LILTWEAK_VERCEL_STATE_ROOT", str(tmp_path))
    app = create_vercel_app(enable_model=False)
    client = TestClient(app, base_url=f"https://{branch}")
    response = client.get("/v1/workbench/session")
    assert response.status_code == 200
    assert response.json()["authenticated"] is True


def test_public_alias_does_not_auto_establish_owner_session(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "preview")
    monkeypatch.setenv("VERCEL_URL", "lil-tweak-abc123-galor-web-works.vercel.app")
    monkeypatch.setenv("VERCEL_BRANCH_URL", "lil-tweak-git-feat-restore-real-tweak-vercel-galor-web-works.vercel.app")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-placeholder-not-used")
    monkeypatch.setenv("LILTWEAK_VERCEL_STATE_ROOT", str(tmp_path))
    app = create_vercel_app(enable_model=False)
    client = TestClient(app, base_url="https://lil-tweak.vercel.app")
    response = client.get("/v1/workbench/session")
    assert response.status_code in {400, 401}
