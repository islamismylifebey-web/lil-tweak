from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import platform
import re
import stat
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.repository import secret_rule_ids  # noqa: E402

BASELINE_COMMIT = "373400cb2b459dbf8a37dacceb0d3d1186eef949"
BRANCH = "codex/lil-tweak-live-workbench-build"
REPOSITORY = "github:islamismylifebey-web/lil-tweak"
OUTPUT_NAMES = (
    "SUPPLY_CHAIN_SBOM.json",
    "LICENSE_INVENTORY.json",
    "BUILD_PROVENANCE.json",
    "DEPENDENCY_SECURITY_SCAN_REPORT.json",
)
MAX_SECRET_SCAN_FILE_BYTES = 5_000_000
REQUIRED_SOURCE_DATE_EPOCH = "1735689600"
REQUIRED_WHEEL_PAYLOAD = frozenset(
    {
        "migrations/0009_canonical_control_plane.sql",
        "migrations/0010_workbench_canonical_authority.sql",
        "migrations/0011_canonical_active_cancellation.sql",
        "docs/prompt.md",
        "docs/engineering-prompt.md",
        "docs/creator-live-prompt.md",
        "docs/workbench-agent-prompt.md",
        "web/workbench/index.html",
        "web/workbench/app.js",
        "web/workbench/styles.css",
    }
)
REQUIRED_SDIST_PAYLOAD = REQUIRED_WHEEL_PAYLOAD | frozenset(
    {"README.md", "pyproject.toml", "liltweak/__init__.py"}
)
FORBIDDEN_WHEEL_DIRECTORIES = frozenset({"evals", "scripts", "tests"})
SYNTHETIC_SECRET_FIXTURE_ALLOWLIST: dict[str, dict[str, object]] = {
    "tests/test_context_manifest.py": {
        "content_sha256": "13b6139b1e9a29c07bdd7e4290b4d6d165476ebc9642e0b26ede04839b5a20cd",
        "rule_ids": ("openai-api-key",),
    },
    "tests/test_reasoning_provider.py": {
        "content_sha256": "ea86c8e9009a9ed8651d5f59cd337840a06c803728e81189a0eef45212bcbaa4",
        "rule_ids": ("credential-assignment", "openai-api-key"),
    },
    "tests/test_runner_qualification_cli.py": {
        "content_sha256": "e749657e1aa21d3503b6264a00e437236e9da16e8ef222bdeffb31b1a8fd8eab",
        "rule_ids": ("credential-assignment",),
    },
    "tests/test_training_readiness.py": {
        "content_sha256": "f9471490bf48d6a3f026de6a2c81589b8cd9a4711ab070a2dba83effd6e64ea6",
        "rule_ids": ("openai-api-key",),
    },
}


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


class ArtifactValidationError(ValueError):
    """Raised when a package artifact cannot safely support provenance."""


def _read_regular_artifact(path: Path, *, expected_suffix: str, kind: str) -> bytes:
    if not path.name.endswith(expected_suffix):
        raise ArtifactValidationError(
            f"{kind} artifact must have the {expected_suffix!r} suffix: {path}"
        )
    try:
        path_status = path.lstat()
    except OSError as exc:
        raise ArtifactValidationError(f"{kind} artifact cannot be inspected: {path}") from exc
    if not stat.S_ISREG(path_status.st_mode):
        raise ArtifactValidationError(f"{kind} artifact is not a regular file: {path}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ArtifactValidationError(
            f"{kind} artifact cannot be opened without following links: {path}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ArtifactValidationError(f"{kind} artifact is not a regular file: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read()
        after = os.fstat(descriptor)
        try:
            final_path_status = path.lstat()
        except OSError as exc:
            raise ArtifactValidationError(
                f"{kind} artifact path changed while being read: {path}"
            ) from exc
        if (
            path_status.st_dev != before.st_dev
            or path_status.st_ino != before.st_ino
            or path_status.st_size != before.st_size
            or path_status.st_mtime_ns != before.st_mtime_ns
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or after.st_dev != final_path_status.st_dev
            or after.st_ino != final_path_status.st_ino
            or after.st_size != final_path_status.st_size
            or after.st_mtime_ns != final_path_status.st_mtime_ns
            or len(data) != after.st_size
        ):
            raise ArtifactValidationError(f"{kind} artifact changed while being read: {path}")
        return data
    finally:
        os.close(descriptor)


def _logical_wheel_member(name: str) -> str:
    """Return the installed path for a wheel member stored under `.data/data`."""

    parts = PurePosixPath(name).parts
    if len(parts) >= 3 and parts[0].endswith(".data") and parts[1] == "data":
        return "/".join(parts[2:])
    return name


def _inspect_wheel(data: bytes, *, path: Path) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise ArtifactValidationError(f"wheel contains duplicate archive members: {path}")

            logical_files: set[str] = set()
            forbidden: set[str] = set()
            for info in infos:
                name = info.filename
                pure = PurePosixPath(name)
                if (
                    not name
                    or "\\" in name
                    or pure.is_absolute()
                    or any(part in {"", ".", ".."} for part in pure.parts)
                ):
                    raise ArtifactValidationError(
                        f"wheel contains an unsafe archive member {name!r}: {path}"
                    )
                mode = info.external_attr >> 16
                if stat.S_IFMT(mode) == stat.S_IFLNK:
                    raise ArtifactValidationError(
                        f"wheel contains a symbolic-link member {name!r}: {path}"
                    )
                if info.is_dir():
                    continue
                logical_name = _logical_wheel_member(name)
                logical_files.add(logical_name)
                logical_parts = PurePosixPath(logical_name).parts
                if any(part in FORBIDDEN_WHEEL_DIRECTORIES for part in logical_parts[:-1]):
                    forbidden.add(logical_name)

            corrupt_member = archive.testzip()
            if corrupt_member is not None:
                raise ArtifactValidationError(
                    f"wheel member failed its CRC check {corrupt_member!r}: {path}"
                )
            metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
            if len(metadata_names) != 1:
                raise ArtifactValidationError(
                    f"wheel must contain exactly one METADATA record: {path}"
                )
            metadata = archive.read(metadata_names[0]).decode("utf-8", errors="strict")
            if any(
                line.casefold().startswith("license-file:")
                and line.split(":", 1)[1].strip() == "LICENSE_INVENTORY.json"
                for line in metadata.splitlines()
            ):
                raise ArtifactValidationError(
                    "wheel falsely classifies LICENSE_INVENTORY.json as the project license: "
                    f"{path}"
                )
    except zipfile.BadZipFile as exc:
        raise ArtifactValidationError(f"wheel is not a valid ZIP archive: {path}") from exc

    missing = sorted(REQUIRED_WHEEL_PAYLOAD - logical_files)
    if missing:
        raise ArtifactValidationError(
            "wheel is missing required runtime payload: " + ", ".join(missing)
        )
    if forbidden:
        raise ArtifactValidationError(
            "wheel contains forbidden development payload: " + ", ".join(sorted(forbidden))
        )


def _inspect_sdist(data: bytes, *, path: Path) -> None:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise ArtifactValidationError(f"sdist contains duplicate archive members: {path}")
            roots: set[str] = set()
            logical_files: set[str] = set()
            for member in members:
                name = member.name
                pure = PurePosixPath(name)
                if (
                    not name
                    or "\\" in name
                    or pure.is_absolute()
                    or any(part in {"", ".", ".."} for part in pure.parts)
                ):
                    raise ArtifactValidationError(
                        f"sdist contains an unsafe archive member {name!r}: {path}"
                    )
                roots.add(pure.parts[0])
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise ArtifactValidationError(
                        f"sdist contains a non-regular archive member {name!r}: {path}"
                    )
                if member.isfile() and len(pure.parts) > 1:
                    logical_files.add("/".join(pure.parts[1:]))
            if len(roots) != 1:
                raise ArtifactValidationError(
                    f"sdist must contain exactly one top-level directory: {path}"
                )
            missing = sorted(REQUIRED_SDIST_PAYLOAD - logical_files)
            if missing:
                raise ArtifactValidationError(
                    "sdist is missing required source payload: " + ", ".join(missing)
                )
            if "LICENSE_INVENTORY.json" in logical_files:
                raise ArtifactValidationError(
                    f"sdist falsely packages LICENSE_INVENTORY.json as a license file: {path}"
                )
    except (tarfile.TarError, UnicodeDecodeError) as exc:
        raise ArtifactValidationError(f"sdist is not a valid gzip tar archive: {path}") from exc


def package_artifact_subjects(
    wheel_artifact: Path,
    sdist_artifact: Path,
) -> list[dict[str, object]]:
    wheel_data = _read_regular_artifact(
        wheel_artifact,
        expected_suffix=".whl",
        kind="wheel",
    )
    _inspect_wheel(wheel_data, path=wheel_artifact)
    sdist_data = _read_regular_artifact(
        sdist_artifact,
        expected_suffix=".tar.gz",
        kind="sdist",
    )
    _inspect_sdist(sdist_data, path=sdist_artifact)
    return [
        {
            "artifact_type": "wheel",
            "path": wheel_artifact.name,
            "sha256": digest_bytes(wheel_data),
            "byte_count": len(wheel_data),
        },
        {
            "artifact_type": "sdist",
            "path": sdist_artifact.name,
            "sha256": digest_bytes(sdist_data),
            "byte_count": len(sdist_data),
        },
    ]


def _build_system(root: Path = APP_ROOT) -> dict[str, object]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    build_system = project.get("build-system")
    if not isinstance(build_system, dict):
        raise ArtifactValidationError("pyproject.toml has no [build-system] table")
    requirements = build_system.get("requires")
    backend = build_system.get("build-backend")
    if (
        not isinstance(requirements, list)
        or not requirements
        or not all(isinstance(requirement, str) and requirement for requirement in requirements)
        or not isinstance(backend, str)
        or not backend
    ):
        raise ArtifactValidationError("pyproject.toml has an incomplete build-system definition")
    return {"requires": requirements, "build_backend": backend}


def _source_date_epoch() -> int:
    observed = os.environ.get("SOURCE_DATE_EPOCH")
    if observed != REQUIRED_SOURCE_DATE_EPOCH:
        raise ArtifactValidationError(
            "provenance generation requires SOURCE_DATE_EPOCH=" + REQUIRED_SOURCE_DATE_EPOCH
        )
    return int(observed)


def git_output(*arguments: str) -> str:
    result = subprocess.run(
        ("git", *arguments),
        cwd=APP_ROOT,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
        env={
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        },
    )
    return result.stdout.strip()


def locked_packages() -> list[dict[str, object]]:
    lock = tomllib.loads((APP_ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages: list[dict[str, object]] = []
    for item in lock["package"]:
        name = item["name"]
        version = item["version"]
        hashes = sorted(
            {
                artifact["hash"].removeprefix("sha256:")
                for key in ("wheels",)
                for artifact in item.get(key, ())
                if artifact.get("hash", "").startswith("sha256:")
            }
            | (
                {item["sdist"]["hash"].removeprefix("sha256:")}
                if item.get("sdist", {}).get("hash", "").startswith("sha256:")
                else set()
            )
        )
        packages.append(
            {
                "name": name,
                "version": version,
                "purl": (
                    f"pkg:generic/{name}@{version}"
                    if "editable" in item.get("source", {})
                    else f"pkg:pypi/{name}@{version}"
                ),
                "hashes": hashes,
                "source": item.get("source", {}),
            }
        )
    return sorted(packages, key=lambda package: (str(package["name"]), str(package["version"])))


def sbom(packages: list[dict[str, object]]) -> dict[str, object]:
    components = []
    for package in packages:
        if "editable" in package["source"]:
            continue
        component: dict[str, object] = {
            "type": "library",
            "bom-ref": package["purl"],
            "name": package["name"],
            "version": package["version"],
            "purl": package["purl"],
            "properties": [
                {
                    "name": "liltweak:lock-source",
                    "value": json.dumps(package["source"], sort_keys=True),
                }
            ],
        }
        if package["hashes"]:
            component["hashes"] = [
                {"alg": "SHA-256", "content": value} for value in package["hashes"]
            ]
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000071",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": REPOSITORY,
                "name": "lil-tweak-engine",
                "version": "0.7.1",
            },
            "properties": [
                {"name": "liltweak:repository", "value": REPOSITORY},
                {"name": "liltweak:branch", "value": BRANCH},
                {"name": "liltweak:baseline-commit", "value": BASELINE_COMMIT},
                {"name": "liltweak:candidate-commit", "value": "recorded-externally-after-freeze"},
            ],
        },
        "components": components,
    }


def license_inventory(packages: list[dict[str, object]]) -> dict[str, object]:
    records: list[dict[str, object]] = []
    for package in packages:
        name = str(package["name"])
        try:
            metadata = importlib.metadata.metadata(name)
        except importlib.metadata.PackageNotFoundError:
            records.append(
                {
                    "package": name,
                    "version": package["version"],
                    "status": "NOT_INSTALLED_FOR_METADATA_REVIEW",
                    "license_expression": None,
                    "license_classifiers": [],
                }
            )
            continue
        expression = metadata.get("License-Expression") or metadata.get("License") or None
        classifiers = sorted(
            value for value in metadata.get_all("Classifier", ()) if value.startswith("License ::")
        )
        records.append(
            {
                "package": name,
                "version": package["version"],
                "status": "OBSERVED" if expression or classifiers else "UNKNOWN_REVIEW_REQUIRED",
                "license_expression": expression,
                "license_classifiers": classifiers,
            }
        )
    unknown = sum(record["status"] != "OBSERVED" for record in records)
    return {
        "schema_version": "license-inventory-v1",
        "repository": REPOSITORY,
        "branch": BRANCH,
        "baseline_commit": BASELINE_COMMIT,
        "candidate_commit": "recorded_externally_after_freeze",
        "package_count": len(records),
        "review_required_count": unknown,
        "operational_release_gate": "BLOCKED" if unknown else "PASSED",
        "packages": records,
    }


def tracked_files() -> tuple[str, ...]:
    output = git_output("ls-files", "-co", "--exclude-standard", "-z")
    return tuple(sorted(value for value in output.split("\0") if value))


def _safe_relative_path(value: str) -> bool:
    pure = PurePosixPath(value)
    return (
        bool(value)
        and not pure.is_absolute()
        and not any(part in {"", ".", ".."} for part in pure.parts)
    )


def _read_scan_candidate(
    root: Path,
    relative: str,
) -> tuple[bytes | None, dict[str, object] | None]:
    if not _safe_relative_path(relative):
        return None, {"path": relative, "reason": "unsafe_repository_relative_path"}
    path = root / relative
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None, {"path": relative, "reason": "file_missing_during_scan"}
    except OSError as exc:
        return None, {
            "path": relative,
            "reason": "file_could_not_be_opened_without_following_links",
            "error_type": type(exc).__name__,
        }
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            return None, {"path": relative, "reason": "non_regular_file"}
        if before.st_size > MAX_SECRET_SCAN_FILE_BYTES:
            return None, {
                "path": relative,
                "reason": "file_exceeds_scan_limit",
                "byte_count": before.st_size,
                "limit_bytes": MAX_SECRET_SCAN_FILE_BYTES,
            }
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            data = handle.read(MAX_SECRET_SCAN_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        if len(data) > MAX_SECRET_SCAN_FILE_BYTES:
            return None, {
                "path": relative,
                "reason": "file_exceeds_scan_limit",
                "byte_count_at_least": len(data),
                "limit_bytes": MAX_SECRET_SCAN_FILE_BYTES,
            }
        if (
            before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or len(data) != after.st_size
        ):
            return None, {"path": relative, "reason": "file_changed_during_scan"}
        return data, None
    finally:
        os.close(descriptor)


def _is_exact_synthetic_fixture(relative: str, finding: dict[str, object]) -> bool:
    expected = SYNTHETIC_SECRET_FIXTURE_ALLOWLIST.get(relative)
    return expected is not None and (
        finding["content_sha256"] == expected["content_sha256"]
        and tuple(finding["rule_ids"]) == expected["rule_ids"]
    )


def _workflow_paths(root: Path) -> tuple[Path, ...]:
    workflow_root = root / ".github" / "workflows"
    return tuple(sorted({*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")}))


def _workflow_action_is_immutably_referenced(reference: str) -> bool:
    normalized = reference.strip().strip("\"'")
    if normalized.startswith("./"):
        return True
    if normalized.startswith("docker://"):
        return re.fullmatch(r"docker://[^\s@]+@sha256:[0-9a-f]{64}", normalized) is not None
    return re.fullmatch(r"[^\s@]+@[0-9a-f]{40}", normalized) is not None


def security_report(
    packages: list[dict[str, object]],
    *,
    root: Path = APP_ROOT,
    files: tuple[str, ...] | None = None,
) -> dict[str, object]:
    findings: list[dict[str, object]] = []
    fixture_findings: list[dict[str, object]] = []
    scan_blockers: list[dict[str, object]] = []
    scanned = 0
    considered_files = tracked_files() if files is None else files
    for relative in considered_files:
        data, blocker = _read_scan_candidate(root, relative)
        if blocker is not None:
            scan_blockers.append(blocker)
            continue
        assert data is not None
        scanned += 1
        rules = secret_rule_ids(data)
        if rules:
            finding = {
                "path": relative,
                "rule_ids": list(rules),
                "content_sha256": digest_bytes(data),
            }
            if _is_exact_synthetic_fixture(relative, finding):
                fixture_findings.append(finding)
            else:
                findings.append(finding)
    workflow_findings: list[str] = []
    action_pattern = re.compile(r"\buses\s*:\s*(?P<reference>[^\s#}]+)")
    for workflow in _workflow_paths(root):
        for line_number, line in enumerate(workflow.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            action = action_pattern.search(line)
            if action is not None and not _workflow_action_is_immutably_referenced(
                action.group("reference")
            ):
                workflow_findings.append(f"{workflow.relative_to(root)}:{line_number}")
    secret_status = "BLOCKED" if scan_blockers else "FAILED" if findings else "PASSED"
    return {
        "schema_version": "dependency-security-scan-v1",
        "repository": REPOSITORY,
        "branch": BRANCH,
        "baseline_commit": BASELINE_COMMIT,
        "candidate_commit": "recorded_externally_after_freeze",
        "locked_package_count": len(packages),
        "secret_scan": {
            "status": secret_status,
            "files_considered": len(considered_files),
            "files_scanned": scanned,
            "release_findings": findings,
            "scan_blockers": scan_blockers,
            "synthetic_test_fixture_findings": fixture_findings,
            "fixture_policy": (
                "A synthetic credential-rejection fixture is allowlisted only when its path, "
                "complete-file SHA-256 digest, and exact rule-id tuple all match this generator's "
                "reviewed fixture registry. Any content change becomes a release finding."
            ),
        },
        "workflow_action_pin_scan": {
            "status": "PASSED" if not workflow_findings else "FAILED",
            "findings": workflow_findings,
        },
        "lock_integrity": {
            "status": "PASSED",
            "lock_sha256": digest_bytes((root / "uv.lock").read_bytes()),
        },
        "known_vulnerability_database_scan": {
            "status": "BLOCKED",
            "reason": (
                "No pinned offline vulnerability database/scanner is present in the "
                "locked environment."
            ),
        },
        "runner_image_scan": {
            "status": "BLOCKED",
            "reason": "No qualified immutable runner image is configured.",
        },
        "operational_release_gate": "BLOCKED",
    }


def provenance(
    outputs: dict[str, bytes],
    package_subjects: list[dict[str, object]],
) -> dict[str, object]:
    source_date_epoch = _source_date_epoch()
    return {
        "schema_version": "build-provenance-v1",
        "repository": REPOSITORY,
        "branch": BRANCH,
        "baseline_commit": BASELINE_COMMIT,
        "candidate_commit": "recorded_externally_after_freeze",
        "reproducible_build_epoch": datetime.fromtimestamp(source_date_epoch, UTC).isoformat(),
        "observation_time": "recorded externally with exact-commit verification",
        "builder": "Lil Tweak Master Builder local private workspace",
        "build_system": _build_system(),
        "environment": {
            "python": platform.python_version(),
            "platform": f"{platform.system().lower()}-{platform.machine().lower()}",
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "uv": subprocess.run(
                ("uv", "--version"),
                cwd=APP_ROOT,
                check=True,
                capture_output=True,
                text=True,
                shell=False,
            ).stdout.strip(),
        },
        "materials": [
            {"path": "uv.lock", "sha256": digest_bytes((APP_ROOT / "uv.lock").read_bytes())},
            {
                "path": "pyproject.toml",
                "sha256": digest_bytes((APP_ROOT / "pyproject.toml").read_bytes()),
            },
        ],
        "subjects": package_subjects,
        "evidence_artifacts": [
            {"path": name, "sha256": digest_bytes(data), "byte_count": len(data)}
            for name, data in sorted(outputs.items())
        ],
        "public_deployment_performed": False,
        "gcp_access_performed": False,
        "runner_image_built": False,
        "candidate_commit_recorded_externally": False,
    }


def generate(
    *,
    wheel_artifact: Path,
    sdist_artifact: Path,
) -> dict[str, bytes]:
    package_subjects = package_artifact_subjects(wheel_artifact, sdist_artifact)
    packages = locked_packages()
    outputs = {
        "SUPPLY_CHAIN_SBOM.json": canonical(sbom(packages)),
        "LICENSE_INVENTORY.json": canonical(license_inventory(packages)),
        "DEPENDENCY_SECURITY_SCAN_REPORT.json": canonical(security_report(packages)),
    }
    outputs["BUILD_PROVENANCE.json"] = canonical(provenance(outputs, package_subjects))
    return outputs


def main() -> int:
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("--output-directory", type=Path, default=APP_ROOT)
    argument_parser.add_argument("--wheel-artifact", type=Path, required=True)
    argument_parser.add_argument("--sdist-artifact", type=Path, required=True)
    arguments = argument_parser.parse_args()
    try:
        outputs = generate(
            wheel_artifact=arguments.wheel_artifact,
            sdist_artifact=arguments.sdist_artifact,
        )
    except ArtifactValidationError as exc:
        argument_parser.error(str(exc))
    arguments.output_directory.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        (arguments.output_directory / name).write_bytes(data)
    package_subjects = json.loads(outputs["BUILD_PROVENANCE.json"])["subjects"]
    print(
        json.dumps(
            {
                "schema_version": "supply-chain-generation-v1",
                "outputs": [
                    {"path": name, "sha256": digest_bytes(data)}
                    for name, data in sorted(outputs.items())
                ],
                "package_artifact_subjects": package_subjects,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
