#!/usr/bin/env python3
"""Preflight a source tree for truthful network-none dependency support.

This script never downloads or installs dependencies. It recognizes only a
small set of repository-local, lockfile-bound layouts that can be consumed by
tools inside a network-disabled sandbox.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path, PurePosixPath


MAX_LOCK_BYTES = 8 * 1024 * 1024
MAX_VENDOR_FILE_BYTES = 25 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AuditError(ValueError):
    pass


def bounded_text(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise AuditError(f"unsafe dependency metadata: {path.name}")
    if path.stat().st_size > MAX_LOCK_BYTES:
        raise AuditError(f"dependency metadata is too large: {path.name}")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeError:
        raise AuditError(f"dependency metadata is not UTF-8: {path.name}") from None


def local_vendor(root: Path, value: str, *, suffix: str | None = None) -> Path:
    if not value.startswith("file:"):
        raise AuditError("network-resolved npm dependency; vendor tarballs and use file: paths")
    raw = value.removeprefix("file:")
    posix = PurePosixPath(raw)
    if not raw or posix.is_absolute() or any(part in ("", ".", "..") for part in posix.parts):
        raise AuditError("unsafe vendored npm path")
    candidate = root.joinpath(*posix.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        raise AuditError(f"missing vendored npm tarball: {raw}") from None
    if root != resolved.parent and root not in resolved.parents:
        raise AuditError("vendored npm path escapes source root")
    if candidate.is_symlink() or not resolved.is_file():
        raise AuditError("vendored npm dependency must be a regular file")
    if suffix and resolved.suffix != suffix:
        raise AuditError(f"vendored npm dependency must use {suffix}")
    if resolved.stat().st_size > MAX_VENDOR_FILE_BYTES:
        raise AuditError("vendored npm tarball exceeds source file limit")
    return resolved


def sha512_integrity(value: object) -> bytes | None:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        return None
    try:
        digest = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError):
        return None
    return digest if len(digest) == 64 else None


def file_sha512(path: Path) -> bytes:
    digest = hashlib.sha512()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.digest()


def audit_npm(root: Path, reports: list[str]) -> None:
    lock = root / "package-lock.json"
    if not lock.exists():
        if (root / "yarn.lock").exists() or (root / "pnpm-lock.yaml").exists():
            raise AuditError("only a package-lock.json with vendored file: tarballs is supported offline")
        return
    try:
        payload = json.loads(bounded_text(lock))
    except json.JSONDecodeError:
        raise AuditError("invalid package-lock.json") from None
    if not isinstance(payload, dict) or payload.get("lockfileVersion") not in (2, 3):
        raise AuditError("npm offline support requires package-lock.json version 2 or 3")
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise AuditError("package-lock.json packages map is required")
    vendored = 0
    for location, descriptor in packages.items():
        if not isinstance(descriptor, dict):
            raise AuditError("invalid package-lock.json package entry")
        resolved = descriptor.get("resolved")
        if location == "" and resolved is None:
            continue
        if resolved is None and (descriptor.get("link") or not descriptor):
            continue
        if not isinstance(resolved, str):
            raise AuditError("npm dependency is not frozen to a vendored tarball")
        package = local_vendor(root, resolved, suffix=".tgz")
        expected_digest = sha512_integrity(descriptor.get("integrity"))
        if expected_digest is None:
            raise AuditError("vendored npm dependency needs a valid sha512 integrity")
        if file_sha512(package) != expected_digest:
            raise AuditError("vendored npm dependency integrity mismatch")
        vendored += 1
    reports.append(f"npm: vendored {vendored} integrity-bound tarball(s)")


def logical_requirement_lines(value: str) -> list[str]:
    lines: list[str] = []
    pending = ""
    for raw in value.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        pending += (" " if pending else "") + stripped.removesuffix("\\").strip()
        if not stripped.endswith("\\"):
            lines.append(pending)
            pending = ""
    if pending:
        raise AuditError("unterminated requirements.txt continuation")
    return lines


def audit_python(root: Path, reports: list[str]) -> None:
    requirements = root / "requirements.txt"
    pyproject = root / "pyproject.toml"
    if not requirements.exists():
        if pyproject.exists():
            try:
                parsed = tomllib.loads(bounded_text(pyproject))
            except tomllib.TOMLDecodeError:
                raise AuditError("invalid pyproject.toml") from None
            dependencies = parsed.get("project", {}).get("dependencies", [])
            if dependencies:
                raise AuditError("Python dependencies require a hashed requirements.txt and vendor/wheels")
        return
    lines = logical_requirement_lines(bounded_text(requirements))
    if "--no-index" not in lines:
        raise AuditError("requirements.txt must contain --no-index")
    find_links = [line for line in lines if line.startswith("--find-links")]
    if not any("vendor/wheels" in line for line in find_links):
        raise AuditError("requirements.txt must use --find-links vendor/wheels")
    wheelhouse = root / "vendor" / "wheels"
    if wheelhouse.is_symlink() or not wheelhouse.is_dir() or not any(wheelhouse.glob("*.whl")):
        raise AuditError("vendor/wheels must contain reviewed wheel files")
    requirements_count = 0
    for line in lines:
        if line.startswith("-"):
            continue
        if "http://" in line or "https://" in line or "git+" in line or " @ " in line:
            raise AuditError("network-resolved Python dependency")
        if "==" not in line:
            raise AuditError("Python dependency must be exactly pinned")
        hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})(?:\s|$)", line)
        if not hashes or any(not SHA256.fullmatch(value) for value in hashes):
            raise AuditError("Python dependency must include a sha256 hash")
        requirements_count += 1
    reports.append(f"python: {requirements_count} hashed requirement(s) with local wheelhouse")


def audit_go(root: Path, reports: list[str]) -> None:
    if not (root / "go.mod").exists():
        return
    for relative in ("go.sum", "vendor/modules.txt"):
        path = root / relative
        if path.is_symlink() or not path.is_file():
            raise AuditError(f"Go offline support requires {relative}")
        bounded_text(path)
    reports.append("go: go.sum plus vendor/modules.txt")


def audit_rust(root: Path, reports: list[str]) -> None:
    if not (root / "Cargo.lock").exists():
        return
    bounded_text(root / "Cargo.lock")
    config = root / ".cargo" / "config.toml"
    if config.is_symlink() or not config.is_file():
        raise AuditError("Rust offline support requires .cargo/config.toml")
    try:
        parsed = tomllib.loads(bounded_text(config))
    except tomllib.TOMLDecodeError:
        raise AuditError("invalid .cargo/config.toml") from None
    source = parsed.get("source", {})
    crates = source.get("crates-io", {}) if isinstance(source, dict) else {}
    replacement = crates.get("replace-with") if isinstance(crates, dict) else None
    replacement_config = source.get(replacement, {}) if isinstance(replacement, str) else {}
    directory = replacement_config.get("directory") if isinstance(replacement_config, dict) else None
    if not isinstance(directory, str):
        raise AuditError("Rust crates.io must be replaced with a vendored directory")
    vendor = root / directory
    if vendor.is_symlink() or not vendor.is_dir() or root not in vendor.resolve().parents:
        raise AuditError("Rust vendored source directory is missing or unsafe")
    reports.append("rust: Cargo.lock plus local source replacement")


def audit(root: Path) -> list[str]:
    if root.is_symlink() or not root.is_dir():
        raise AuditError("source root must be a regular directory")
    resolved = root.resolve()
    unsupported = [name for name in ("composer.lock", "Gemfile.lock", "packages.lock.json") if (resolved / name).exists()]
    if unsupported:
        raise AuditError(f"unsupported offline dependency lock: {unsupported[0]}")
    reports: list[str] = []
    audit_npm(resolved, reports)
    audit_python(resolved, reports)
    audit_go(resolved, reports)
    audit_rust(resolved, reports)
    return reports


def main(argv: list[str]) -> int:
    if argv == ["--check"]:
        print("offline dependency verifier check: ok")
        return 0
    if len(argv) != 1:
        print("usage: verify-offline-dependencies.py SOURCE_DIRECTORY", file=sys.stderr)
        return 2
    try:
        reports = audit(Path(argv[0]))
    except (AuditError, OSError) as error:
        print(f"offline dependency audit failed: {error}", file=sys.stderr)
        return 1
    if not reports:
        print("offline dependency audit: runner-preinstalled toolchains only; no third-party lock detected")
    else:
        for report in reports:
            print(report)
        print("offline dependency audit: ok; sandbox network remains disabled")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
