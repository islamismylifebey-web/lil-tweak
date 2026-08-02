from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

import build_backend
from build_backend import _normalized_sdist_bytes


def synthetic_sdist(*, mtime: float, reverse: bool = False) -> bytes:
    entries = [
        ("lil_tweak_engine-0.7.1", None),
        ("lil_tweak_engine-0.7.1/pyproject.toml", b"[build-system]\n"),
        ("lil_tweak_engine-0.7.1/liltweak/__init__.py", b'VERSION = "0.7.1"\n'),
    ]
    if reverse:
        entries.reverse()
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in entries:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE if payload is None else tarfile.REGTYPE
            member.mode = 0o775 if payload is None else 0o664
            member.uid = 123
            member.gid = 456
            member.uname = "builder"
            member.gname = "builder"
            member.mtime = mtime
            member.size = len(payload) if payload is not None else 0
            archive.addfile(member, io.BytesIO(payload) if payload is not None else None)
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=int(mtime)) as compressed:
        compressed.write(tar_buffer.getvalue())
    return output.getvalue()


def test_normalization_removes_wall_clock_owner_mode_and_order_variation() -> None:
    epoch = 1_735_689_600
    first = _normalized_sdist_bytes(synthetic_sdist(mtime=1_800_000_000.1), epoch=epoch)
    second = _normalized_sdist_bytes(
        synthetic_sdist(mtime=1_900_000_000.9, reverse=True),
        epoch=epoch,
    )

    assert first == second
    with gzip.GzipFile(fileobj=io.BytesIO(first)) as compressed:
        tar_payload = compressed.read()
        assert compressed.mtime == epoch
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as archive:
            members = archive.getmembers()
    assert [member.name for member in members] == sorted(member.name for member in members)
    assert all(member.mtime == epoch for member in members)
    assert all(member.uid == 0 and member.gid == 0 for member in members)
    assert all(member.uname == "" and member.gname == "" for member in members)
    assert all(member.mode == (0o755 if member.isdir() else 0o644) for member in members)


def test_normalization_rejects_links_and_negative_epoch() -> None:
    source = synthetic_sdist(mtime=1_800_000_000)
    with pytest.raises(ValueError, match="non-negative"):
        _normalized_sdist_bytes(source, epoch=-1)

    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
        link = tarfile.TarInfo("lil_tweak_engine-0.7.1/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        archive.addfile(link)
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=1) as compressed:
        compressed.write(tar_buffer.getvalue())
    with pytest.raises(RuntimeError, match="unsupported archive member type"):
        _normalized_sdist_bytes(output.getvalue(), epoch=1)


def test_normalization_rejects_unsafe_and_duplicate_member_names() -> None:
    def archive_with_names(names: tuple[str, ...]) -> bytes:
        tar_buffer = io.BytesIO()
        with tarfile.open(fileobj=tar_buffer, mode="w") as archive:
            for name in names:
                payload = b"content\n"
                member = tarfile.TarInfo(name)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        output = io.BytesIO()
        with gzip.GzipFile(fileobj=output, mode="wb", mtime=1) as compressed:
            compressed.write(tar_buffer.getvalue())
        return output.getvalue()

    with pytest.raises(RuntimeError, match="unsafe archive member"):
        _normalized_sdist_bytes(archive_with_names(("package/../../escape",)), epoch=1)
    with pytest.raises(RuntimeError, match="duplicate archive members"):
        _normalized_sdist_bytes(archive_with_names(("package/file", "package/file")), epoch=1)


def test_build_sdist_hook_replaces_setuptools_output_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    filename = "lil_tweak_engine-0.7.1.tar.gz"
    artifact = tmp_path / filename
    artifact.write_bytes(synthetic_sdist(mtime=1_900_000_000.9, reverse=True))
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1735689600")
    monkeypatch.setattr(
        build_backend._setuptools,
        "build_sdist",
        lambda directory, settings: filename,
    )

    assert build_backend.build_sdist(str(tmp_path)) == filename
    assert artifact.read_bytes() == _normalized_sdist_bytes(
        synthetic_sdist(mtime=1_800_000_000.1),
        epoch=1_735_689_600,
    )
    assert int(artifact.stat().st_mtime) == 1_735_689_600
