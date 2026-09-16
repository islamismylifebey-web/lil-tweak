#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any


EXPECTED_REPOSITORY = "islamismylifebey-web/lil-tweak"
REGISTRY_ROOT = "ghcr.io/islamismylifebey-web"
PACKAGES = {"lil-tweak-core", "lil-tweak-runner", "lil-tweak-postgres"}

PYTHON_BASE_IMAGE = (
    "docker.io/library/python@sha256:"
    "2fe5997d249a808b8eeea52c58a1dbffbba28754dc11699ef5c029f2d818ce79"
)
RUNNER_BASE_IMAGE = (
    "docker.io/library/node@sha256:"
    "a05717adfe7289e2a0fa36a694dc430a510adab6467c7036e51551198935abef"
)
POSTGRES_PARENT_IMAGE = (
    "docker.io/library/postgres@sha256:"
    "d13db94ae661d517c5ed57c509a578d5ea64aae639871ba25294f4f42d83de28"
)
SYFT_IMAGE = (
    "ghcr.io/anchore/syft@sha256:"
    "600896ff278677fb13b16dc35999452f4e79636fc098c9fee6ce3cffef9858e2"
)
GRYPE_IMAGE = (
    "ghcr.io/anchore/grype@sha256:"
    "461c87fefcd20d133f4d99db4623608637eecb439045f9fc8d6eebbb4149e766"
)

COMMIT = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAX_JSON_BYTES = 16 * 1024 * 1024
SCAN_NAMES = (
    "core.sbom.json",
    "runner.sbom.json",`n    "postgres.sbom.json",`n    "core.grype.json",
    "runner.grype.json",`n    "postgres.grype.json",`n)


class ReleaseError(Exception):
    pass


def _fail(code: str) -> None:
    raise ReleaseError(code)


def _read_bytes(path: Path, error: str, maximum: int = MAX_JSON_BYTES) -> bytes:
    try:
        if path.is_symlink() or not path.is_file():
            _fail(error)
        size = path.stat().st_size
        if not 0 < size <= maximum:
            _fail(error)
        data = path.read_bytes()
    except OSError as exception:
        raise ReleaseError(error) from exception
    if len(data) != size:
        _fail(error)
    return data


def _read_json(path: Path, error: str) -> Any:
    data = _read_bytes(path, error)
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exception:
        raise ReleaseError(error) from exception


def _package_repository(package: str, error: str) -> str:
    if package not in PACKAGES:
        _fail(error)
    return f"{REGISTRY_ROOT}/{package}"


def _image_reference(reference: str, package: str, error: str) -> None:
    repository = _package_repository(package, error)
    prefix = repository + "@"
    if not reference.startswith(prefix) or DIGEST.fullmatch(reference[len(prefix) :]) is None:
        _fail(error)


def validate_context(
    event_name: str,
    repository: str,
    ref: str,
    source_commit: str,
    github_sha: str,
) -> None:
    if (
        event_name != "workflow_dispatch"
        or repository != EXPECTED_REPOSITORY
        or ref != "refs/heads/main"
        or COMMIT.fullmatch(source_commit) is None
        or COMMIT.fullmatch(github_sha) is None
        or source_commit != github_sha
    ):
        _fail("release_context_invalid")


def _validate_package_payload(payload: Any, package: str, error: str) -> None:
    _package_repository(package, error)
    repository = payload.get("repository") if isinstance(payload, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("name") != package
        or payload.get("package_type") != "container"
        or payload.get("visibility") != "private"
        or not isinstance(repository, dict)
        or repository.get("full_name") != EXPECTED_REPOSITORY
    ):
        _fail(error)


def validate_package_metadata(package: str, path: Path) -> None:
    payload = _read_json(path, "package_metadata_invalid")
    _validate_package_payload(payload, package, "package_metadata_invalid")


def validate_package_inventory(path: Path) -> None:
    error = "package_inventory_invalid"
    payload = _read_json(path, error)
    if not isinstance(payload, list) or len(payload) > 100:
        _fail(error)
    observed: set[str] = set()
    for package in payload:
        name = package.get("name") if isinstance(package, dict) else None
        if (
            not isinstance(name, str)
            or name in observed
            or package.get("package_type") != "container"
        ):
            _fail(error)
        observed.add(name)
        if name in PACKAGES:
            _validate_package_payload(package, name, error)


def create_image_reference(
    package: str,
    metadata_path: Path | None,
    manifest_path: Path,
    expected_digest: str | None,
) -> str:
    repository = _package_repository(package, "published_image_invalid")
    manifest_bytes = _read_bytes(manifest_path, "published_image_invalid")
    manifest = _read_json(manifest_path, "published_image_invalid")
    metadata = (
        _read_json(metadata_path, "published_image_invalid") if metadata_path is not None else None
    )
    digest = (
        metadata.get("containerimage.digest")
        if isinstance(metadata, dict)
        else expected_digest
    )
    config = manifest.get("config") if isinstance(manifest, dict) else None
    layers = manifest.get("layers") if isinstance(manifest, dict) else None
    manifest_types = {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
    config_types = {
        "application/vnd.oci.image.config.v1+json",
        "application/vnd.docker.container.image.v1+json",
    }
    manifest_hashes = {"sha256:" + hashlib.sha256(manifest_bytes).hexdigest()}
    if manifest_bytes.endswith(b"\n"):
        manifest_hashes.add("sha256:" + hashlib.sha256(manifest_bytes[:-1]).hexdigest())
    if (
        (metadata_path is not None and not isinstance(metadata, dict))
        or (metadata_path is None and expected_digest is None)
        or not isinstance(digest, str)
        or DIGEST.fullmatch(digest) is None
        or digest not in manifest_hashes
        or (
            expected_digest is not None
            and (DIGEST.fullmatch(expected_digest) is None or digest != expected_digest)
        )
        or not isinstance(manifest, dict)
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") not in manifest_types
        or "manifests" in manifest
        or not isinstance(config, dict)
        or config.get("mediaType") not in config_types
        or not isinstance(config.get("digest"), str)
        or DIGEST.fullmatch(config["digest"]) is None
        or not isinstance(config.get("size"), int)
        or isinstance(config.get("size"), bool)
        or config["size"] < 0
        or not isinstance(layers, list)
    ):
        _fail("published_image_invalid")
    for layer in layers:
        media_type = layer.get("mediaType") if isinstance(layer, dict) else None
        if (
            not isinstance(layer, dict)
            or not isinstance(media_type, str)
            or not (
                media_type.startswith("application/vnd.oci.image.layer.")
                or media_type.startswith("application/vnd.docker.image.rootfs.")
            )
            or not isinstance(layer.get("digest"), str)
            or DIGEST.fullmatch(layer["digest"]) is None
            or not isinstance(layer.get("size"), int)
            or isinstance(layer.get("size"), bool)
            or layer["size"] < 0
        ):
            _fail("published_image_invalid")
    return f"{repository}@{digest}"


def validate_pull_evidence(reference: str, path: Path) -> None:
    package = reference.split("@", 1)[0].rsplit("/", 1)[-1]
    _image_reference(reference, package, "pull_evidence_invalid")
    payload = _read_json(path, "pull_evidence_invalid")
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], dict):
        _fail("pull_evidence_invalid")
    image = payload[0]
    repo_digests = image.get("RepoDigests")
    if (
        image.get("Architecture") != "amd64"
        or image.get("Os") != "linux"
        or not isinstance(repo_digests, list)
        or reference not in repo_digests
        or any(not isinstance(item, str) for item in repo_digests)
    ):
        _fail("pull_evidence_invalid")


def validate_anonymous_denial(exit_code: int, path: Path) -> None:
    message = _read_bytes(path, "anonymous_pull_check_invalid", maximum=64 * 1024)
    try:
        normalized = message.decode("utf-8").lower()
    except UnicodeDecodeError as exception:
        raise ReleaseError("anonymous_pull_check_invalid") from exception
    denial_markers = (
        "unauthorized",
        "authentication required",
        "requested access to the resource is denied",
        "denied: denied",
    )
    if not 0 < exit_code <= 255 or not any(marker in normalized for marker in denial_markers):
        _fail("anonymous_pull_check_invalid")


def _write_new(path: Path, data: bytes, error: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(path, 0o600)
    except OSError as exception:
        raise ReleaseError(error) from exception


def write_receipts(
    directory: Path,
    source_commit: str,
    core_image: str,
    runner_image: str,
    postgres_image: str,
) -> None:
    error = "release_receipts_invalid"
    if COMMIT.fullmatch(source_commit) is None:
        _fail(error)
    _image_reference(core_image, "lil-tweak-core", error)
    _image_reference(runner_image, "lil-tweak-runner", error)
    _image_reference(postgres_image, "lil-tweak-postgres", error)
    if postgres_image.rsplit("@", 1)[1] == POSTGRES_PARENT_IMAGE.rsplit("@", 1)[1]:
        _fail(error)
    try:
        if directory.is_symlink() or not directory.is_dir():
            _fail(error)
        directory = directory.resolve(strict=True)
    except OSError as exception:
        raise ReleaseError(error) from exception

    scan_data: dict[str, bytes] = {}
    for name in SCAN_NAMES:
        path = directory / name
        data = _read_bytes(path, error, maximum=64 * 1024 * 1024)
        try:
            json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exception:
            raise ReleaseError(error) from exception
        scan_data[name] = data

    outputs = {
        "base-image-receipt.txt": "".join(
            f"{reference} {reference.rsplit('@', 1)[1]}\n"
            for reference in (PYTHON_BASE_IMAGE, RUNNER_BASE_IMAGE, POSTGRES_PARENT_IMAGE)
        ).encode("ascii"),
        "image-scan-hashes.txt": "".join(
            f"{hashlib.sha256(scan_data[name]).hexdigest()}  {name}\n" for name in SCAN_NAMES
        ).encode("ascii"),
        "release-image-inputs.json": (
            json.dumps(
                {
                    "schema": "lil-tweak-release-image-inputs-v1",
                    "source_commit": source_commit,
                    "images": {
                        "core": core_image,
                        "runner": runner_image,
                        "postgres": postgres_image,
                        "python_base": PYTHON_BASE_IMAGE,
                        "runner_base": RUNNER_BASE_IMAGE,
                    },
                    "parent_images": {"postgres": POSTGRES_PARENT_IMAGE},
                    "tools": {"syft": SYFT_IMAGE, "grype": GRYPE_IMAGE},
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8"),
    }
    if any((directory / name).exists() or (directory / name).is_symlink() for name in outputs):
        _fail(error)
    for name in SCAN_NAMES:
        try:
            os.chmod(directory / name, 0o600)
        except OSError as exception:
            raise ReleaseError(error) from exception
    for name, data in outputs.items():
        _write_new(directory / name, data, error)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lil-tweak-private-release.py")
    commands = parser.add_subparsers(dest="command", required=True)

    context = commands.add_parser("validate-context")
    context.add_argument("--event-name", required=True)
    context.add_argument("--repository", required=True)
    context.add_argument("--ref", required=True)
    context.add_argument("--source-commit", required=True)
    context.add_argument("--github-sha", required=True)

    package = commands.add_parser("package-metadata")
    package.add_argument("--package", required=True)
    package.add_argument("--metadata", type=Path, required=True)

    inventory = commands.add_parser("package-inventory")
    inventory.add_argument("--metadata", type=Path, required=True)

    image = commands.add_parser("image-reference")
    image.add_argument("--package", required=True)
    image.add_argument("--metadata", type=Path)
    image.add_argument("--manifest", type=Path, required=True)
    image.add_argument("--expected-digest")

    pull = commands.add_parser("pull-evidence")
    pull.add_argument("--reference", required=True)
    pull.add_argument("--inspect", type=Path, required=True)

    anonymous = commands.add_parser("anonymous-denial")
    anonymous.add_argument("--exit-code", type=int, required=True)
    anonymous.add_argument("--stderr", type=Path, required=True)

    receipts = commands.add_parser("write-receipts")
    receipts.add_argument("--directory", type=Path, required=True)
    receipts.add_argument("--source-commit", required=True)
    receipts.add_argument("--core-image", required=True)
    receipts.add_argument("--runner-image", required=True)
    receipts.add_argument("--postgres-image", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "validate-context":
            validate_context(
                arguments.event_name,
                arguments.repository,
                arguments.ref,
                arguments.source_commit,
                arguments.github_sha,
            )
            print(arguments.source_commit)
        elif arguments.command == "package-metadata":
            validate_package_metadata(arguments.package, arguments.metadata)
            print("package_metadata_valid")
        elif arguments.command == "package-inventory":
            validate_package_inventory(arguments.metadata)
            print("package_inventory_valid")
        elif arguments.command == "image-reference":
            print(
                create_image_reference(
                    arguments.package,
                    arguments.metadata,
                    arguments.manifest,
                    arguments.expected_digest,
                )
            )
        elif arguments.command == "pull-evidence":
            validate_pull_evidence(arguments.reference, arguments.inspect)
            print("pull_evidence_valid")
        elif arguments.command == "anonymous-denial":
            validate_anonymous_denial(arguments.exit_code, arguments.stderr)
            print("anonymous_pull_denied")
        elif arguments.command == "write-receipts":
            write_receipts(
                arguments.directory,
                arguments.source_commit,
                arguments.core_image,
                arguments.runner_image,
                arguments.postgres_image,
            )
            print("release_receipts_written")
    except ReleaseError as error:
        print(str(error), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

