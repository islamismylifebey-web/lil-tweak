from __future__ import annotations

import argparse
import json
import os
import signal
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from liltweak.creator_contract import canonical_json
from liltweak.providers.github.runner_v3_contracts import RunnerV3JobManifest
from liltweak.providers.github.runner_v3_executor import (
    RunnerV3ExecutionError,
    RunnerV3Executor,
)

_MAX_MANIFEST_BYTES = 1_000_000


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RunnerV3ExecutionError(
                "Runner V3 manifest contains a duplicate JSON key"
            )
        result[key] = value
    return result


def _read_manifest(path: Path) -> RunnerV3JobManifest:
    if path.is_symlink():
        raise RunnerV3ExecutionError(
            "Runner V3 manifest path cannot be a symlink"
        )
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise RunnerV3ExecutionError(
            "Runner V3 manifest file could not be opened"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 2
            or before.st_size > _MAX_MANIFEST_BYTES
            or before.st_nlink != 1
        ):
            raise RunnerV3ExecutionError(
                "Runner V3 manifest file metadata is invalid"
            )
        raw = os.read(descriptor, _MAX_MANIFEST_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            len(raw) != before.st_size
            or after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_size != before.st_size
            or after.st_nlink != 1
        ):
            raise RunnerV3ExecutionError(
                "Runner V3 manifest changed while being read"
            )
    finally:
        os.close(descriptor)
    try:
        value: Any = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
        return RunnerV3JobManifest.model_validate(value)
    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
        raise RunnerV3ExecutionError(
            "Runner V3 manifest JSON or digest is invalid"
        ) from exc


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Execute one bounded GitHub-first Runner V3 job",
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    cancellation = {"requested": False}

    def request_cancellation(
        _signum: int,
        _frame: object,
    ) -> None:
        cancellation["requested"] = True

    previous = {
        signum: signal.getsignal(signum)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    for signum in previous:
        signal.signal(signum, request_cancellation)
    try:
        manifest = _read_manifest(arguments.manifest)
        receipt = RunnerV3Executor().execute(
            manifest,
            workspace=arguments.workspace,
            output_directory=arguments.output_directory,
            cancellation_requested=lambda: cancellation["requested"],
        )
    except RunnerV3ExecutionError as exc:
        print(
            canonical_json(
                {
                    "outcome": "failed",
                    "error": str(exc),
                }
            )
        )
        return 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)

    print(
        canonical_json(
            {
                "execution_id": receipt.execution_id,
                "outcome": receipt.outcome.value,
                "receipt_digest": receipt.receipt_digest,
                "workspace_changed": receipt.workspace_changed,
            }
        )
    )
    if receipt.outcome.value == "succeeded":
        return 0
    if receipt.outcome.value == "cancelled":
        return 130
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
