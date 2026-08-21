from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from liltweak import context_manifest as context_module
from liltweak.context_manifest import (
    TOKEN_BOUND_METHOD,
    ContextManifest,
    ContextPolicy,
    FileCategory,
    PolicyDecision,
    build_context_manifest,
)


def _write_repository(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "node_modules" / "dependency").mkdir(parents=True)
    (root / "AGENTS.md").write_text("Root instruction.\n", encoding="utf-8")
    (root / "src" / "AGENTS.md").write_text("Nested instruction.\n", encoding="utf-8")
    (root / "src" / "app.py").write_text(
        "import json\nfrom pathlib import Path\n\n"
        "class Worker:\n"
        "    async def run(self) -> None:\n"
        "        return None\n",
        encoding="utf-8",
    )
    (root / "tests" / "test_app.py").write_text(
        "from src.app import Worker\n\ndef test_worker():\n    assert Worker\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    (root / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "name: CI\n",
        encoding="utf-8",
    )
    (root / ".env").write_text("TOKEN=not-for-context\n", encoding="utf-8")
    (root / "credential.txt").write_text(
        "sk-proj-abcdefghijklmnopqrstuvwxyz012345\n",
        encoding="utf-8",
    )
    (root / "image.bin").write_bytes(b"image\x00payload")
    (root / "node_modules" / "dependency" / "index.js").write_text(
        "ignored dependency\n",
        encoding="utf-8",
    )


def test_context_manifest_has_exact_provenance_policy_and_indexes(tmp_path: Path) -> None:
    _write_repository(tmp_path)
    diagnostic = (
        f"{tmp_path / 'src' / 'app.py'}:5:9: warning W100 await is unnecessary\n"
        "/outside/private.py:2: error leaked sk-proj-abcdefghijklmnopqrstuvwxyz012345\n"
    )
    manifest = build_context_manifest(
        tmp_path,
        repository_id="repo:demo",
        source_revision="a" * 40,
        objective="Inspect the worker safely.",
        diagnostics=diagnostic,
    )
    repeated = build_context_manifest(
        tmp_path,
        repository_id="repo:demo",
        source_revision="a" * 40,
        objective="Inspect the worker safely.",
        diagnostics=diagnostic,
    )

    assert manifest.manifest_digest == repeated.manifest_digest
    assert [item.path for item in manifest.instructions] == ["AGENTS.md", "src/AGENTS.md"]
    assert [item.scope for item in manifest.instructions] == [".", "src"]
    assert [item.precedence for item in manifest.instructions] == [0, 1]

    python = {item.path: item for item in manifest.python_indexes}
    app_index = python["src/app.py"]
    assert {item.qualified_name for item in app_index.symbols} == {
        "Worker",
        "Worker.run",
    }
    assert {item.module for item in app_index.imports} == {"json", "pathlib"}
    assert {(item.category, item.path) for item in manifest.project_signals} >= {
        ("manifest", "pyproject.toml"),
        ("lock", "uv.lock"),
        ("ci", ".github/workflows/ci.yml"),
        ("test", "tests/test_app.py"),
    }

    files = {item.path: item for item in manifest.files}
    assert files[".env"].policy_reasons == ("sensitive_path",)
    assert files["credential.txt"].policy_reasons == ("credential_shaped_content",)
    assert files["credential.txt"].secret_rule_ids == ("openai-api-key",)
    assert files["image.bin"].policy_reasons == ("binary_content",)
    assert files["node_modules"].category == FileCategory.VENDOR
    assert files["node_modules"].policy_decision == PolicyDecision.EXCLUDED
    assert "node_modules/dependency/index.js" not in files

    assert len(manifest.diagnostics) == 2
    local, external = manifest.diagnostics
    assert local.path == "src/app.py"
    assert local.external_path_sha256 is None
    assert external.path is None
    assert external.external_path_sha256 is not None
    assert external.message.startswith("[REDACTED:")
    assert str(tmp_path) not in manifest.model_dump_json()

    assert manifest.token_budget.method == TOKEN_BOUND_METHOD
    assert manifest.token_budget.within_budget is True
    assert manifest.token_budget.conservative_context_token_upper_bound == sum(
        item.utf8_bytes for item in manifest.excerpts
    )
    assert manifest.token_budget.remaining_context_tokens >= 0


def test_context_selection_fails_closed_at_conservative_token_bound(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text("A" * 100, encoding="utf-8")
    (tmp_path / "one.py").write_text("x = '" + "x" * 100 + "'\n", encoding="utf-8")
    (tmp_path / "two.py").write_text("y = '" + "y" * 100 + "'\n", encoding="utf-8")
    policy = ContextPolicy(
        input_token_ceiling=256,
        reserved_output_tokens=128,
        max_excerpt_characters=100,
    )
    manifest = build_context_manifest(
        tmp_path,
        repository_id="repo:budget",
        source_revision="b" * 40,
        objective="bounded",
        policy=policy,
    )

    assert manifest.token_budget.available_context_tokens == 128
    assert manifest.token_budget.conservative_context_token_upper_bound <= 128
    assert any(item.selection_blocker == "context_token_budget" for item in manifest.files)
    assert all(
        item.conservative_token_upper_bound == len(item.text.encode("utf-8"))
        for item in manifest.excerpts
    )

    tampered = manifest.model_dump(mode="json")
    tampered["manifest_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="manifest digest mismatch"):
        ContextManifest.model_validate(tampered)


def test_regular_file_is_hashed_and_read_from_pinned_repository_snapshot(tmp_path: Path) -> None:
    content = b"regular repository content\n"
    (tmp_path / "regular.txt").write_bytes(content)

    manifest = build_context_manifest(
        tmp_path,
        repository_id="repo:regular",
        source_revision="c" * 40,
        objective="read regular file",
    )

    record = next(item for item in manifest.files if item.path == "regular.txt")
    excerpt = next(item for item in manifest.excerpts if item.path == "regular.txt")
    assert record.policy_decision == PolicyDecision.ALLOWED
    assert record.sha256 == hashlib.sha256(content).hexdigest()
    assert record.byte_count == len(content)
    assert excerpt.text.encode() == content


def test_hardlink_to_outside_file_is_rejected_without_content_ingestion(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    outside = tmp_path / "outside-control-plane.txt"
    outside.write_text("outside control-plane content must not enter context\n", encoding="utf-8")
    os.link(outside, repository / "linked.txt")

    manifest = build_context_manifest(
        repository,
        repository_id="repo:hardlink",
        source_revision="d" * 40,
        objective="reject outside hardlink",
    )

    record = next(item for item in manifest.files if item.path == "linked.txt")
    assert record.policy_decision == PolicyDecision.EXCLUDED
    assert record.policy_reasons == ("hardlink",)
    assert record.sha256 is None
    assert all(item.path != "linked.txt" for item in manifest.excerpts)
    assert "outside control-plane content" not in manifest.model_dump_json()


def test_every_name_for_a_multilink_repository_inode_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "first.txt").write_text("shared inode\n", encoding="utf-8")
    os.link(tmp_path / "first.txt", tmp_path / "second.txt")

    manifest = build_context_manifest(
        tmp_path,
        repository_id="repo:multilink",
        source_revision="e" * 40,
        objective="reject multi-link files",
    )

    records = {item.path: item for item in manifest.files}
    assert records["first.txt"].policy_reasons == ("hardlink",)
    assert records["second.txt"].policy_reasons == ("hardlink",)
    assert manifest.excerpts == ()


def test_symlink_swap_during_fd_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    victim = repository / "victim.txt"
    victim.write_text("pinned original content\n", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside replacement content\n", encoding="utf-8")
    victim_inode = victim.stat().st_ino
    original_read = context_module.os.read
    swapped = False

    def swap_then_read(descriptor: int, size: int) -> bytes:
        nonlocal swapped
        if not swapped and os.fstat(descriptor).st_ino == victim_inode:
            victim.unlink()
            victim.symlink_to(outside)
            swapped = True
        return original_read(descriptor, size)

    monkeypatch.setattr(context_module.os, "read", swap_then_read)

    with pytest.raises(ValueError, match="source changed during context scan"):
        build_context_manifest(
            repository,
            repository_id="repo:symlink-swap",
            source_revision="f" * 40,
            objective="reject a symlink swap",
        )
    assert swapped is True


def test_file_identity_drift_during_read_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("stable until identity check\n", encoding="utf-8")
    victim_inode = victim.stat().st_ino
    original_identity = context_module._stat_identity
    matching_calls = 0

    def drift_once(metadata: os.stat_result) -> tuple[int, ...]:
        nonlocal matching_calls
        identity = original_identity(metadata)
        if metadata.st_ino == victim_inode:
            matching_calls += 1
            if matching_calls == 3:
                return (*identity[:-1], identity[-1] + 1)
        return identity

    monkeypatch.setattr(context_module, "_stat_identity", drift_once)

    with pytest.raises(ValueError, match="source changed during context scan"):
        build_context_manifest(
            tmp_path,
            repository_id="repo:identity-drift",
            source_revision="1" * 40,
            objective="reject identity drift",
        )
