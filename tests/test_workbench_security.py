from __future__ import annotations

import os
from pathlib import Path

import pytest

from liltweak.workbench_security import (
    SecurityBoundaryError,
    SessionManager,
    WorkspacePathGuard,
    redact,
)


def test_path_traversal_and_absolute_paths_are_denied(tmp_path: Path) -> None:
    guard = WorkspacePathGuard(tmp_path)
    for value in (
        "../secret",
        "/etc/passwd",
        "a/../../b",
        r"a\b",
        "a//b",
        "a/./b",
        "a/b/",
    ):
        with pytest.raises(SecurityBoundaryError):
            guard.resolve(value, allow_missing=True)


def test_symlink_and_hardlink_escape_are_denied(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-workbench-test"
    outside.write_text("secret", encoding="utf-8")
    (tmp_path / "link").symlink_to(outside)
    with pytest.raises(SecurityBoundaryError, match="symlink"):
        WorkspacePathGuard(tmp_path).resolve("link")
    (tmp_path / "link").unlink()
    os.link(outside, tmp_path / "hard")
    with pytest.raises(SecurityBoundaryError, match="hardlink"):
        WorkspacePathGuard(tmp_path).resolve("hard")


def test_secret_redaction() -> None:
    output = "Authorization: Bearer abc123 password=secret ya29.token"
    redacted = redact(output)
    assert "abc123" not in redacted
    assert "secret" not in redacted
    assert "ya29.token" not in redacted


def test_session_expiry_signature_and_csrf(monkeypatch: pytest.MonkeyPatch) -> None:
    manager = SessionManager(b"s" * 32)
    session, cookie = manager.create("owner")
    csrf = manager.csrf_for_cookie(cookie)
    assert manager.verify(cookie).actor_id == session.actor_id
    assert manager.verify_csrf(cookie, csrf).actor_id == "owner"
    with pytest.raises(SecurityBoundaryError, match="CSRF"):
        manager.verify_csrf(cookie, "wrong")
    with pytest.raises(SecurityBoundaryError):
        manager.verify(cookie + "tampered")
    monkeypatch.setattr("liltweak.workbench_security.time.time", lambda: session.expires_at)
    with pytest.raises(SecurityBoundaryError, match="expired"):
        manager.verify(cookie)


def test_session_codec_is_unambiguous_for_binary_signatures_and_actor_punctuation() -> None:
    manager = SessionManager(b"s" * 32)
    for _ in range(256):
        session, cookie = manager.create("owner.name:local")
        verified = manager.verify(cookie)
        assert verified.session_id == session.session_id
        assert verified.actor_id == "owner.name:local"
        assert cookie.count(".") == 1
