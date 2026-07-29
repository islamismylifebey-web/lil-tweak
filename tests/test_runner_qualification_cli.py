from __future__ import annotations

import argparse
import os
import stat
from pathlib import Path

import pytest

from liltweak.runner_qualification import MAX_QUALIFICATION_BYTES
from scripts import verify_runner_qualification as cli


def test_read_bounded_json_uses_strict_utf8(tmp_path: Path) -> None:
    evidence = tmp_path / "invalid-utf8.json"
    evidence.write_bytes(b'{"evidence":"\xff"}')

    with pytest.raises(UnicodeDecodeError):
        cli.read_bounded_json(evidence)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"duplicate":1,"duplicate":2}',
        b'{"nested":{"duplicate":1,"duplicate":2}}',
    ],
)
def test_read_bounded_json_rejects_duplicate_keys(
    tmp_path: Path,
    payload: bytes,
) -> None:
    evidence = tmp_path / "duplicate.json"
    evidence.write_bytes(payload)

    with pytest.raises(cli.DuplicateJsonKeyError, match="duplicate JSON key"):
        cli.read_bounded_json(evidence)


def test_read_bounded_json_rejects_symlink_input(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    symlink = tmp_path / "evidence.json"
    symlink.symlink_to(target)

    with pytest.raises(OSError):
        cli.read_bounded_json(symlink)


def test_read_bounded_json_rejects_hardlinked_input(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    hardlink = tmp_path / "evidence.json"
    os.link(target, hardlink)

    with pytest.raises(ValueError, match="singly linked regular file"):
        cli.read_bounded_json(hardlink)


def test_read_bounded_json_rejects_oversize_input(tmp_path: Path) -> None:
    evidence = tmp_path / "oversize.json"
    evidence.write_bytes(b"{" + (b" " * MAX_QUALIFICATION_BYTES) + b"}")

    with pytest.raises(ValueError, match="input size is invalid"):
        cli.read_bounded_json(evidence)


def test_write_private_json_uses_o_excl_and_preserves_existing_file(
    tmp_path: Path,
) -> None:
    output = tmp_path / "decision.json"
    output.write_text("do-not-overwrite", encoding="utf-8")

    with pytest.raises(FileExistsError):
        cli.write_private_json(output, {"qualified": True})

    assert output.read_text(encoding="utf-8") == "do-not-overwrite"


def test_write_private_json_creates_owner_only_regular_file(tmp_path: Path) -> None:
    output = tmp_path / "decision.json"

    cli.write_private_json(output, {"qualified": False})

    metadata = output.stat()
    assert stat.S_ISREG(metadata.st_mode)
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1


def test_main_redacts_operational_error_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    secret = "forbidden-secret-value"

    def reject_with_secret(_: argparse.Namespace) -> int:
        raise ValueError(f"internal detail: {secret}")

    class FakeParser:
        def parse_args(self) -> argparse.Namespace:
            return argparse.Namespace(handler=reject_with_secret)

    monkeypatch.setattr(cli, "parser", FakeParser)

    with pytest.raises(SystemExit) as error:
        cli.main()

    captured = capsys.readouterr()
    assert error.value.code == 2
    assert captured.out == ""
    assert captured.err == "runner qualification rejected\n"
    assert secret not in captured.err
