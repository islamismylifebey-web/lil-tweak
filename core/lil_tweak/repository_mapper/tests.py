"""Test coverage inference helpers."""

from __future__ import annotations

from pathlib import PurePosixPath

from .languages import module_name_for_path


def production_candidates_for_test(test_path: str) -> list[str]:
    pure = PurePosixPath(test_path)
    name = pure.name
    candidates: list[str] = []
    if name.startswith("test_") and pure.suffix == ".py":
        stem = name.removeprefix("test_").removesuffix(".py")
        candidates.extend(
            [
                f"core/lil_tweak/{stem}.py",
                f"lil_tweak/{stem}.py",
                f"{stem}.py",
            ]
        )
    if ".test." in name or ".spec." in name:
        stem = name.replace(".test.", ".").replace(".spec.", ".")
        parent = pure.parent.parent if pure.parent.name == "tests" else pure.parent
        candidates.append(parent.joinpath(stem).as_posix())
        candidates.append(PurePosixPath("lib").joinpath(stem).as_posix())
        candidates.append(PurePosixPath("app").joinpath(stem).as_posix())
    return candidates


def imported_modules_in_test(imports: list[str]) -> list[str]:
    modules: list[str] = []
    for item in imports:
        if item.startswith("core.lil_tweak."):
            modules.append(item.removeprefix("core."))
        elif item.startswith("lil_tweak."):
            modules.append(item)
    return sorted(set(modules))


def module_tested_by_name(test_path: str, source_path: str) -> bool:
    return source_path in production_candidates_for_test(test_path) or (
        module_name_for_path(source_path) in imported_modules_in_test([])
    )
