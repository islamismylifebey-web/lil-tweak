from __future__ import annotations

import os
import stat
import subprocess
import sys
import time
from pathlib import Path

import pytest

from liltweak.creator import outcome_digest_for_fixture
from liltweak.creator_contract import CommandKind, SandboxCommand
from liltweak.execution_contract import ExecutionRecipe
from liltweak.models import RepositoryRef
from liltweak.repository import RepositoryInspector, is_sensitive_path
from liltweak.source_snapshot import (
    RepositorySnapshotBuilder,
    SourceSnapshotError,
    _GitBatchReader,
)
from tests.repository_helpers import initialize_repository, run_git

IMAGE = "registry.invalid/liltweak-python@sha256:" + ("a" * 64)


def recipe(**changes: object) -> ExecutionRecipe:
    values: dict[str, object] = {
        "recipe_id": "python-verify",
        "image_ref": IMAGE,
        "commands": (
            SandboxCommand(
                command_id="tests",
                kind=CommandKind.TEST,
                argv=("pytest", "-q"),
                timeout_seconds=60,
            ),
        ),
    }
    values.update(changes)
    return ExecutionRecipe.model_validate(values)


def builder_for(workspace: Path, commit: str) -> tuple[RepositorySnapshotBuilder, RepositoryRef]:
    inspector = RepositoryInspector(
        workspace,
        repository_mappings={"local:fixture": "repository"},
    )
    reference = RepositoryRef(
        provider="local",
        repository_id="fixture",
        revision=commit,
    )
    return RepositorySnapshotBuilder(inspector), reference


def make_tree_writable(root: Path) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_dir() and not path.is_symlink():
            os.chmod(path, 0o700)
        elif not path.is_symlink():
            os.chmod(path, 0o600)
    os.chmod(root, 0o700)


def test_execution_recipe_rejects_shell_and_interpreter_evaluation() -> None:
    with pytest.raises(ValueError, match="safe bare executable"):
        recipe(
            commands=(
                SandboxCommand(
                    command_id="shell",
                    kind=CommandKind.TEST,
                    argv=("sh", "-c", "pytest"),
                    timeout_seconds=10,
                ),
            )
        )
    with pytest.raises(ValueError, match="interpreter evaluation"):
        recipe(
            commands=(
                SandboxCommand(
                    command_id="python-eval",
                    kind=CommandKind.TEST,
                    argv=("python", "-c", "print('unsafe')"),
                    timeout_seconds=10,
                ),
            )
        )
    with pytest.raises(ValueError, match="safe bare executable"):
        recipe(
            commands=(
                SandboxCommand(
                    command_id="package-install",
                    kind=CommandKind.TEST,
                    argv=("pip", "install", "anything"),
                    timeout_seconds=10,
                ),
            )
        )
    with pytest.raises(ValueError, match="cannot modify source"):
        recipe(
            commands=(
                SandboxCommand(
                    command_id="ruff-fix",
                    kind=CommandKind.LINT,
                    argv=("ruff", "check", "--fix", "."),
                    timeout_seconds=10,
                ),
            )
        )


def test_execution_recipe_digest_is_deterministic_and_bounded() -> None:
    first = recipe()
    second = recipe()
    assert first.recipe_digest == second.recipe_digest
    assert first.network_allowed is False
    assert first.source_write_allowed is False
    assert first.deployment_allowed is False
    assert outcome_digest_for_fixture("not-the-recipe") != first.recipe_digest


def test_process_observation_rejects_contradictory_success_and_signal() -> None:
    from liltweak.execution_contract import ProcessObservation

    with pytest.raises(ValueError, match="exactly one"):
        ProcessObservation(
            command_id="contradictory",
            exit_code=0,
            signal=9,
            stdout_digest="0" * 64,
            stderr_digest="0" * 64,
            stdout_bytes=0,
            stderr_bytes=0,
            duration_ms=1,
        )


def test_committed_tree_snapshot_is_deterministic_and_git_free(tmp_path: Path) -> None:
    _repository, commit = initialize_repository(tmp_path)
    builder, reference = builder_for(tmp_path, commit)
    first = builder.prepare_manifest(reference)
    second = builder.prepare_manifest(reference)
    assert first == second
    assert first.resolved_revision == commit
    assert first.file_count == 4
    assert first.credential_finding_count == 0

    destination = tmp_path / "materialized"
    observed = builder.materialize(reference, first, destination)
    assert observed == first
    assert not (destination / ".git").exists()
    assert (destination / "src" / "app.py").is_file()
    assert stat.S_IMODE((destination / "src" / "app.py").stat().st_mode) == 0o444
    make_tree_writable(destination)


def test_batch_ingestion_preserves_golden_manifest_and_uses_six_processes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repository, commit = initialize_repository(tmp_path)
    builder, reference = builder_for(tmp_path, commit)
    direct_calls: list[tuple[str, ...]] = []
    batch_modes: list[str] = []
    original_git = builder._git
    original_batch = builder._git_batch

    def tracked_git(repository: Path, *arguments: str, **kwargs):
        direct_calls.append(arguments)
        return original_git(repository, *arguments, **kwargs)

    def tracked_batch(repository: Path, batch_mode: str, **kwargs):
        batch_modes.append(batch_mode)
        return original_batch(repository, batch_mode, **kwargs)

    monkeypatch.setattr(builder, "_git", tracked_git)
    monkeypatch.setattr(builder, "_git_batch", tracked_batch)
    manifest = builder.prepare_manifest(reference)

    assert manifest.tree_digest == (
        "22eb6f462bbce85d0dc67d705863126ac0331e0a6b40cd0d93c9faafba14ab06"
    )
    assert manifest.archive_digest == (
        "f8f8bd50c0f0b6fcc2fbcd7bbf1ba30b249e07046dc77c3cde8d11febb4e05d9"
    )
    assert manifest.file_count == 4
    assert manifest.total_bytes == 226
    assert len(direct_calls) == 2
    assert all(arguments[0] == "ls-tree" for arguments in direct_calls)
    assert batch_modes == ["--batch-check", "--batch", "--batch-check", "--batch"]


def test_batch_ingestion_preserves_binary_newlines_duplicates_and_mode(tmp_path: Path) -> None:
    repository, _commit = initialize_repository(tmp_path)
    fixtures = {
        "binary.dat": b"\x00\xffbinary\nbody\x00",
        "header-looking.txt": b"0" * 40 + b" blob 999\nactual\nbody\n",
        "duplicate-a.txt": b"same-object\n",
        "duplicate-b.txt": b"same-object\n",
        "empty.txt": b"",
        "executable": b"#!/no/interpreter\nfixture\n",
    }
    for name, data in fixtures.items():
        (repository / name).write_bytes(data)
    (repository / "executable").chmod(0o755)
    run_git(repository, "add", *fixtures)
    run_git(repository, "commit", "-q", "-m", "batch protocol fixtures")
    commit = run_git(repository, "rev-parse", "HEAD")
    builder, reference = builder_for(tmp_path, commit)

    manifest = builder.prepare_manifest(reference)
    destination = tmp_path / "materialized-batch-fixtures"
    builder.materialize(reference, manifest, destination)

    assert manifest.file_count == 10
    for name, expected in fixtures.items():
        assert (destination / name).read_bytes() == expected
    assert stat.S_IMODE((destination / "executable").stat().st_mode) == 0o555
    make_tree_writable(destination)


@pytest.mark.parametrize(
    ("limits", "message", "expected_modes"),
    [
        (
            {"max_files": 1},
            "file limit",
            [],
        ),
        (
            {"max_total_bytes": 1_000, "max_file_bytes": 10},
            "oversized file",
            ["--batch-check"],
        ),
        (
            {"max_total_bytes": 225, "max_file_bytes": 200},
            "snapshot byte limit",
            ["--batch-check"],
        ),
    ],
)
def test_size_admission_rejects_before_content_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limits: dict[str, int],
    message: str,
    expected_modes: list[str],
) -> None:
    _repository, commit = initialize_repository(tmp_path)
    inspector = RepositoryInspector(
        tmp_path,
        repository_mappings={"local:fixture": "repository"},
    )
    builder = RepositorySnapshotBuilder(inspector, **limits)
    reference = RepositoryRef(
        provider="local",
        repository_id="fixture",
        revision=commit,
    )
    batch_modes: list[str] = []
    original_batch = builder._git_batch

    def tracked_batch(repository: Path, batch_mode: str, **kwargs):
        batch_modes.append(batch_mode)
        return original_batch(repository, batch_mode, **kwargs)

    monkeypatch.setattr(builder, "_git_batch", tracked_batch)
    with pytest.raises(SourceSnapshotError, match=message):
        builder.prepare_manifest(reference)
    assert batch_modes == expected_modes


def _scripted_batch_reader(script: str, *, timeout: float = 2) -> _GitBatchReader:
    return _GitBatchReader(
        command=[sys.executable, "-c", script],
        environment={},
        deadline=time.monotonic() + timeout,
    )


def test_batch_protocol_reads_exact_binary_body_and_delimiter() -> None:
    object_id = "a" * 40
    body = b"\x00line one\nline two\xff"
    script = (
        "import sys\n"
        "sys.stdin.buffer.readline()\n"
        f"body = {body!r}\n"
        f"sys.stdout.buffer.write(b'{object_id} blob ' + str(len(body)).encode() + b'\\n')\n"
        "sys.stdout.buffer.write(body + b'\\n')\n"
        "sys.stdout.buffer.flush()\n"
    )
    with _scripted_batch_reader(script) as reader:
        assert reader.read_blob(object_id, expected_size=len(body)) == body


@pytest.mark.parametrize(
    ("script", "message"),
    [
        (
            "import sys\n"
            "oid = sys.stdin.buffer.readline().strip()\n"
            "sys.stdout.buffer.write(b'b' * 40 + b' blob 0\\n\\n')\n"
            "sys.stdout.buffer.flush()\n",
            "metadata",
        ),
        (
            "import sys\n"
            "oid = sys.stdin.buffer.readline().strip()\n"
            "sys.stdout.buffer.write(oid + b' blob 3\\nabcX')\n"
            "sys.stdout.buffer.flush()\n",
            "delimiter",
        ),
        (
            "import sys\n"
            "sys.stdin.buffer.readline()\n"
            "sys.stdout.buffer.write(b'x' * 300)\n"
            "sys.stdout.buffer.flush()\n",
            "header exceeded",
        ),
    ],
)
def test_batch_protocol_rejects_malformed_responses(script: str, message: str) -> None:
    object_id = "a" * 40
    with (
        pytest.raises(SourceSnapshotError, match=message),
        _scripted_batch_reader(script) as reader,
    ):
        reader.read_blob(object_id, expected_size=0 if "metadata" in message else 3)


@pytest.mark.parametrize("raw_size", [b"+0", b"-0", b"00", b"1_0"])
def test_batch_protocol_rejects_noncanonical_sizes(raw_size: bytes) -> None:
    object_id = "a" * 40
    script = (
        "import sys\n"
        "oid = sys.stdin.buffer.readline().strip()\n"
        f"sys.stdout.buffer.write(oid + b' blob ' + {raw_size!r} + b'\\n')\n"
        "sys.stdout.buffer.flush()\n"
    )
    with (
        pytest.raises(SourceSnapshotError, match="header is invalid"),
        _scripted_batch_reader(script) as reader,
    ):
        reader.check(object_id)


def test_batch_protocol_enforces_one_deadline_and_kills_stalled_process() -> None:
    object_id = "a" * 40
    script = "import sys, time\nsys.stdin.buffer.readline()\ntime.sleep(5)\n"
    with (
        pytest.raises(SourceSnapshotError, match="batch operation failed"),
        _scripted_batch_reader(script, timeout=0.05) as reader,
    ):
        reader.check(object_id)
    assert reader.process is not None
    assert reader.process.poll() is not None


def test_batch_protocol_deadline_covers_stdin_backpressure() -> None:
    object_id = "a" * 40
    script = (
        "import os, threading, time\n"
        "def stop():\n"
        "    time.sleep(0.5)\n"
        "    os._exit(0)\n"
        "threading.Thread(target=stop, daemon=True).start()\n"
        f"response = b'{object_id} blob 0\\n'\n"
        "while True:\n"
        "    os.write(1, response)\n"
    )
    started = time.monotonic()
    with (
        pytest.raises(SourceSnapshotError, match="batch operation failed"),
        _scripted_batch_reader(script, timeout=0.05) as reader,
    ):
        while True:
            reader.check(object_id)
    assert time.monotonic() - started < 0.4
    assert reader.process is not None
    assert reader.process.poll() is not None


def test_batch_protocol_normalizes_broken_pipe_during_cleanup() -> None:
    object_id = "a" * 40
    reader = _scripted_batch_reader("raise SystemExit(3)\n")
    assert reader.process is not None
    reader.process.wait(timeout=1)
    with pytest.raises(SourceSnapshotError, match="batch operation failed"), reader:
        reader.check(object_id)


def test_batch_protocol_rejects_nonzero_exit_after_valid_response() -> None:
    object_id = "a" * 40
    script = (
        "import sys\n"
        "oid = sys.stdin.buffer.readline().strip()\n"
        "sys.stdout.buffer.write(oid + b' blob 0\\n')\n"
        "sys.stdout.buffer.flush()\n"
        "raise SystemExit(3)\n"
    )
    with (
        pytest.raises(SourceSnapshotError, match="batch operation failed"),
        _scripted_batch_reader(script) as reader,
    ):
        assert reader.check(object_id) == 0


def test_batch_protocol_rejects_size_drift_between_admission_and_content() -> None:
    object_id = "a" * 40
    script = (
        "import sys\n"
        "oid = sys.stdin.buffer.readline().strip()\n"
        "sys.stdout.buffer.write(oid + b' blob 4\\nbody\\n')\n"
        "sys.stdout.buffer.flush()\n"
    )
    with (
        pytest.raises(SourceSnapshotError, match="size changed"),
        _scripted_batch_reader(script) as reader,
    ):
        reader.read_blob(object_id, expected_size=3)


def test_batch_protocol_rejects_premature_eof() -> None:
    object_id = "a" * 40
    script = (
        "import sys\n"
        "oid = sys.stdin.buffer.readline().strip()\n"
        "sys.stdout.buffer.write(oid + b' blob 3\\nab')\n"
        "sys.stdout.buffer.flush()\n"
    )
    with (
        pytest.raises(SourceSnapshotError, match="response was complete"),
        _scripted_batch_reader(script) as reader,
    ):
        reader.read_blob(object_id, expected_size=3)


def test_batch_protocol_rejects_trailing_output() -> None:
    object_id = "a" * 40
    script = (
        "import sys\n"
        "oid = sys.stdin.buffer.readline().strip()\n"
        "sys.stdout.buffer.write(oid + b' blob 0\\nunexpected')\n"
        "sys.stdout.buffer.flush()\n"
    )
    with (
        pytest.raises(SourceSnapshotError, match="trailing output"),
        _scripted_batch_reader(script) as reader,
    ):
        assert reader.check(object_id) == 0


def test_batch_ingestion_rejects_content_that_does_not_match_object_id(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _repository, commit = initialize_repository(tmp_path)
    builder, reference = builder_for(tmp_path, commit)
    original_batch = builder._git_batch

    class CorruptingReader:
        def __init__(self, delegate: _GitBatchReader) -> None:
            self.delegate = delegate
            self.corrupted = False

        def __enter__(self):
            self.delegate.__enter__()
            return self

        def __exit__(self, exception_type, exception, traceback) -> None:
            self.delegate.__exit__(exception_type, exception, traceback)

        def read_blob(self, object_id: str, *, expected_size: int) -> bytes:
            data = self.delegate.read_blob(object_id, expected_size=expected_size)
            if data and not self.corrupted:
                self.corrupted = True
                return bytes([data[0] ^ 1]) + data[1:]
            return data

    def corrupt_content(repository: Path, batch_mode: str, **kwargs):
        delegate = original_batch(repository, batch_mode, **kwargs)
        return CorruptingReader(delegate) if batch_mode == "--batch" else delegate

    monkeypatch.setattr(builder, "_git_batch", corrupt_content)
    with pytest.raises(SourceSnapshotError, match="object id"):
        builder.prepare_manifest(reference)


def test_batch_ingestion_supports_sha256_git_repositories(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    initialized = subprocess.run(
        ["git", "-C", str(repository), "init", "-q", "--object-format=sha256"],
        capture_output=True,
        check=False,
    )
    if initialized.returncode != 0:
        pytest.skip("installed Git does not support SHA-256 repositories")
    (repository / "fixture.txt").write_bytes(b"sha256 fixture\n")
    run_git(repository, "config", "user.name", "Test User")
    run_git(repository, "config", "user.email", "test@example.invalid")
    run_git(repository, "add", "fixture.txt")
    run_git(repository, "commit", "-q", "-m", "SHA-256 fixture")
    commit = run_git(repository, "rev-parse", "HEAD")
    assert len(commit) == 64
    builder, reference = builder_for(tmp_path, commit)

    manifest = builder.prepare_manifest(reference)
    destination = tmp_path / "materialized-sha256"
    observed = builder.materialize(reference, manifest, destination)

    assert observed == manifest
    assert manifest.resolved_revision == commit
    assert manifest.file_count == 1
    assert (destination / "fixture.txt").read_bytes() == b"sha256 fixture\n"
    make_tree_writable(destination)


def test_snapshot_rejects_dirty_ignored_and_secret_state(tmp_path: Path) -> None:
    repository, commit = initialize_repository(tmp_path)
    builder, reference = builder_for(tmp_path, commit)
    (repository / "untracked.txt").write_text("untracked", encoding="utf-8")
    with pytest.raises(SourceSnapshotError, match="clean, exact"):
        builder.prepare_manifest(reference)
    (repository / "untracked.txt").unlink()

    fake_key = "sk-" + "proj-" + ("R" * 32)
    (repository / "src" / "secret.py").write_text(fake_key, encoding="utf-8")
    run_git(repository, "add", "src/secret.py")
    run_git(repository, "commit", "-q", "-m", "credential fixture")
    secret_commit = run_git(repository, "rev-parse", "HEAD")
    _builder, secret_reference = builder_for(tmp_path, secret_commit)
    with pytest.raises(SourceSnapshotError, match="credential-shaped"):
        _builder.prepare_manifest(secret_reference)


@pytest.mark.parametrize(
    "filename",
    [".ENV", ".Env.production", "CREDENTIALS.JSON"],
)
def test_snapshot_rejects_mixed_case_sensitive_filenames(
    tmp_path: Path,
    filename: str,
) -> None:
    repository, _commit = initialize_repository(tmp_path)
    (repository / filename).write_text("not-a-credential\n", encoding="utf-8")
    run_git(repository, "add", filename)
    run_git(repository, "commit", "-q", "-m", "mixed-case sensitive filename")
    commit = run_git(repository, "rev-parse", "HEAD")
    builder, reference = builder_for(tmp_path, commit)

    assert is_sensitive_path(filename)
    with pytest.raises(SourceSnapshotError, match=r"sensitive|credential"):
        builder.prepare_manifest(reference)


def test_snapshot_allows_mixed_case_env_example_policy(tmp_path: Path) -> None:
    repository, _commit = initialize_repository(tmp_path)
    filename = ".ENV.EXAMPLE"
    (repository / filename).write_text("EXAMPLE_VALUE=\n", encoding="utf-8")
    run_git(repository, "add", filename)
    run_git(repository, "commit", "-q", "-m", "mixed-case environment example")
    commit = run_git(repository, "rev-parse", "HEAD")
    builder, reference = builder_for(tmp_path, commit)

    assert not is_sensitive_path(filename)
    assert builder.prepare_manifest(reference).file_count == 5


def test_snapshot_rejects_symlinks_and_source_drift(tmp_path: Path) -> None:
    repository, commit = initialize_repository(tmp_path)
    builder, reference = builder_for(tmp_path, commit)
    approved = builder.prepare_manifest(reference)
    (repository / "src" / "app.py").write_text("changed = True\n", encoding="utf-8")
    with pytest.raises(SourceSnapshotError, match="no longer matches"):
        builder.materialize(reference, approved, tmp_path / "stale")

    run_git(repository, "reset", "--hard", commit)
    (repository / "linked.py").symlink_to("src/app.py")
    run_git(repository, "add", "linked.py")
    run_git(repository, "commit", "-q", "-m", "symlink fixture")
    symlink_commit = run_git(repository, "rev-parse", "HEAD")
    _builder, symlink_reference = builder_for(tmp_path, symlink_commit)
    with pytest.raises(SourceSnapshotError, match="clean, exact"):
        _builder.prepare_manifest(symlink_reference)


def test_snapshot_path_validation_rejects_git_and_casefolded_ancestors() -> None:
    with pytest.raises(SourceSnapshotError, match="unsafe"):
        RepositorySnapshotBuilder._validate_path(
            ".GIT/config",
            set(),
            set(),
            set(),
        )

    collisions: set[str] = set()
    file_keys: set[str] = set()
    ancestor_keys: set[str] = set()
    RepositorySnapshotBuilder._validate_path(
        "Foo",
        collisions,
        file_keys,
        ancestor_keys,
    )
    with pytest.raises(SourceSnapshotError, match="ancestor"):
        RepositorySnapshotBuilder._validate_path(
            "foo/bar.py",
            collisions,
            file_keys,
            ancestor_keys,
        )


def test_git_snapshot_reader_stops_at_the_output_limit(tmp_path: Path) -> None:
    _repository, commit = initialize_repository(tmp_path)
    builder, _reference = builder_for(tmp_path, commit)
    noisy_git = tmp_path / "noisy-git"
    noisy_git.write_text(
        f"#!{sys.executable}\nimport os\nos.write(1, b'x' * 1_000_000)\n",
        encoding="utf-8",
    )
    noisy_git.chmod(0o700)
    builder.git_binary = str(noisy_git)
    with pytest.raises(SourceSnapshotError, match="output exceeded"):
        builder._git(
            tmp_path,
            "ls-tree",
            output_limit=1_024,
        )
