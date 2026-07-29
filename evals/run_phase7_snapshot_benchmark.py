from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

APP_ROOT = Path(__file__).parents[1]
SOURCE_ROOT = Path(os.environ.get("LILTWEAK_BENCHMARK_SOURCE_ROOT", str(APP_ROOT))).resolve()
sys.path.insert(0, str(SOURCE_ROOT))

from liltweak.models import RepositoryRef  # noqa: E402
from liltweak.repository import RepositoryInspector  # noqa: E402
from liltweak.source_snapshot import RepositorySnapshotBuilder  # noqa: E402

GIT_ENVIRONMENT = {
    "HOME": "/nonexistent",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}


def run_git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        env=GIT_ENVIRONMENT,
        text=True,
    )
    return completed.stdout.strip()


def make_repository(root: Path, *, file_count: int, file_bytes: int) -> str:
    repository = root / "repository"
    repository.mkdir()
    run_git(repository, "init", "-q")
    run_git(repository, "config", "user.name", "Lil Tweak Benchmark")
    run_git(repository, "config", "user.email", "benchmark@example.invalid")
    fixtures = repository / "fixtures"
    fixtures.mkdir()
    for index in range(file_count):
        prefix = f"{index:08d}:".encode("ascii")
        body = (prefix + (b"x" * file_bytes))[:file_bytes]
        (fixtures / f"{index:08d}.txt").write_bytes(body)
    run_git(repository, "add", "fixtures")
    run_git(repository, "commit", "-q", "-m", "deterministic snapshot benchmark")
    return run_git(repository, "rev-parse", "HEAD")


def sample(
    *,
    file_count: int,
    file_bytes: int,
    repetitions: int,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="liltweak-snapshot-benchmark-") as raw_root:
        root = Path(raw_root)
        commit = make_repository(root, file_count=file_count, file_bytes=file_bytes)
        inspector = RepositoryInspector(
            root,
            repository_mappings={"local:benchmark": "repository"},
        )
        builder = RepositorySnapshotBuilder(inspector)
        reference = RepositoryRef(
            provider="local",
            repository_id="benchmark",
            revision=commit,
        )
        process_counts: list[int] = []
        elapsed_samples: list[float] = []
        for _index in range(repetitions):
            process_count = 0
            original_git = builder._git

            def wrap_git(delegate):
                def tracked_git(repository: Path, *arguments: str, **kwargs):
                    nonlocal process_count
                    process_count += 1
                    return delegate(repository, *arguments, **kwargs)

                return tracked_git

            builder._git = wrap_git(original_git)  # type: ignore[method-assign]
            original_batch = getattr(builder, "_git_batch", None)
            if original_batch is not None:

                def wrap_batch(delegate):
                    def tracked_batch(repository: Path, batch_mode: str, **kwargs):
                        nonlocal process_count
                        process_count += 1
                        return delegate(repository, batch_mode, **kwargs)

                    return tracked_batch

                builder._git_batch = wrap_batch(original_batch)  # type: ignore[attr-defined]
            started = time.perf_counter()
            manifest = builder.prepare_manifest(reference)
            elapsed_samples.append(time.perf_counter() - started)
            process_counts.append(process_count)
            builder._git = original_git  # type: ignore[method-assign]
            if original_batch is not None:
                builder._git_batch = original_batch  # type: ignore[attr-defined,method-assign]
        return {
            "file_count": manifest.file_count,
            "file_bytes": file_bytes,
            "total_bytes": manifest.total_bytes,
            "repetitions": repetitions,
            "elapsed_seconds": [round(item, 6) for item in elapsed_samples],
            "median_seconds": round(statistics.median(elapsed_samples), 6),
            "snapshot_git_processes": process_counts,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", nargs="+", type=int, default=[254, 1_004])
    parser.add_argument("--file-bytes", type=int, default=128)
    parser.add_argument("--repetitions", type=int, default=5)
    arguments = parser.parse_args()
    if (
        arguments.file_bytes < 9
        or arguments.repetitions < 1
        or any(count < 1 for count in arguments.files)
    ):
        parser.error("files, file bytes, and repetitions must be positive and bounded")
    source_file = SOURCE_ROOT / "liltweak" / "source_snapshot.py"
    result = {
        "source_root": str(SOURCE_ROOT),
        "source_snapshot_sha256": hashlib.sha256(source_file.read_bytes()).hexdigest(),
        "cases": [
            sample(
                file_count=file_count,
                file_bytes=arguments.file_bytes,
                repetitions=arguments.repetitions,
            )
            for file_count in arguments.files
        ],
        "provider_calls": 0,
        "paid_calls": 0,
        "executions": 0,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
