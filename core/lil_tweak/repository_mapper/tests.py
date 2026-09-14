"""Conservative test-to-component relationship inference."""

from __future__ import annotations

from pathlib import PurePosixPath


def predictable_test_targets(test_path: str, module_paths: tuple[str, ...]) -> tuple[str, ...]:
    name = PurePosixPath(test_path).name
    stem = PurePosixPath(name).stem
    for prefix in ("test_",):
        if stem.startswith(prefix):
            stem = stem[len(prefix) :]
    for suffix in ("_test", ".test", ".spec"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
    if not stem:
        return ()
    candidates = [
        path
        for path in module_paths
        if PurePosixPath(path).stem == stem and path != test_path
    ]
    return tuple(sorted(candidates))
