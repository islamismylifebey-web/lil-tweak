"""Setuptools PEP 517 backend with byte-reproducible source archives."""

from __future__ import annotations

import gzip
import io
import os
import stat
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from setuptools import build_meta as _setuptools

DEFAULT_SOURCE_DATE_EPOCH = 1_735_689_600
_REGULAR_MODES = {tarfile.REGTYPE, tarfile.AREGTYPE}


def _source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH", str(DEFAULT_SOURCE_DATE_EPOCH))
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise RuntimeError("SOURCE_DATE_EPOCH must be a non-negative integer") from exc
    if epoch < 0:
        raise RuntimeError("SOURCE_DATE_EPOCH must be a non-negative integer")
    return epoch


def _normalized_mode(member: tarfile.TarInfo) -> int:
    if member.isdir():
        return 0o755
    return 0o755 if member.mode & stat.S_IXUSR else 0o644


def _validate_member_name(name: str) -> None:
    pure = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in name.split("/"))
    ):
        raise RuntimeError(f"sdist contains an unsafe archive member: {name!r}")


def _normalized_sdist_bytes(source: bytes, *, epoch: int) -> bytes:
    """Return a safe, deterministically ordered gzip tar stream."""

    if epoch < 0:
        raise ValueError("epoch must be non-negative")

    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(source), mode="r:gz") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise RuntimeError("sdist contains duplicate archive members")
            for member in members:
                _validate_member_name(member.name)
                if member.type not in _REGULAR_MODES and not member.isdir():
                    raise RuntimeError(
                        f"sdist contains unsupported archive member type: {member.name}"
                    )
                payload: bytes | None = None
                if member.isfile():
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise RuntimeError(f"sdist member cannot be read: {member.name}")
                    payload = extracted.read()
                entries.append((member, payload))
    except tarfile.TarError as exc:
        raise RuntimeError("setuptools produced an invalid sdist archive") from exc

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, payload in sorted(entries, key=lambda item: item[0].name):
            normalized = tarfile.TarInfo(member.name)
            normalized.type = tarfile.DIRTYPE if member.isdir() else tarfile.REGTYPE
            normalized.mode = _normalized_mode(member)
            normalized.uid = 0
            normalized.gid = 0
            normalized.uname = ""
            normalized.gname = ""
            normalized.mtime = epoch
            normalized.size = len(payload) if payload is not None else 0
            archive.addfile(
                normalized,
                io.BytesIO(payload) if payload is not None else None,
            )

    output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        fileobj=output,
        compresslevel=9,
        mtime=epoch,
    ) as compressed:
        compressed.write(tar_buffer.getvalue())
    return output.getvalue()


def build_sdist(
    sdist_directory: str,
    config_settings: dict[str, Any] | None = None,
) -> str:
    """Build with setuptools, then normalize all archive metadata and ordering."""

    filename = _setuptools.build_sdist(sdist_directory, config_settings)
    artifact = Path(sdist_directory) / filename
    epoch = _source_date_epoch()
    normalized = _normalized_sdist_bytes(
        artifact.read_bytes(),
        epoch=epoch,
    )
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{artifact.name}.",
            suffix=".normalized",
            dir=artifact.parent,
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(normalized)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o644)
        os.replace(temporary, artifact)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    os.utime(artifact, (epoch, epoch), follow_symlinks=False)
    return filename


build_wheel = _setuptools.build_wheel
get_requires_for_build_wheel = _setuptools.get_requires_for_build_wheel
get_requires_for_build_sdist = _setuptools.get_requires_for_build_sdist
prepare_metadata_for_build_wheel = _setuptools.prepare_metadata_for_build_wheel
build_editable = _setuptools.build_editable
get_requires_for_build_editable = _setuptools.get_requires_for_build_editable
prepare_metadata_for_build_editable = _setuptools.prepare_metadata_for_build_editable
