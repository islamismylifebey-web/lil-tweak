"""Read JSON from stdin; validate or preview only. No approval/export/write commands."""
from __future__ import annotations

import argparse
import sys
from typing import TextIO

from .authoring import AUTHOR_SCHEMA
from .package import ForgeError, canonical, compile_draft, parse_json

MAX_INPUT_CHARACTERS = 2 * 1024 * 1024


def main(argv: list[str] | None = None, *, stdin: TextIO | None = None,
         stdout: TextIO | None = None, stderr: TextIO | None = None) -> int:
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    parser = argparse.ArgumentParser(description="Skill Forge unverified compiler preview")
    parser.add_argument("command", choices=("schema", "validate", "preview"))
    args = parser.parse_args(argv)
    try:
        if args.command == "schema":
            stdout.write(canonical(AUTHOR_SCHEMA).decode())
            return 0
        raw = stdin.read(MAX_INPUT_CHARACTERS + 1)
        if len(raw) > MAX_INPUT_CHARACTERS or len(raw.encode("utf-8")) > MAX_INPUT_CHARACTERS:
            raise ForgeError("input_size_limit")
        package = compile_draft(parse_json(raw))
        if args.command == "preview":
            stderr.write("UNVERIFIED PREVIEW: not approved for export or activation.\n")
            stdout.write(package.as_dict()["SKILL.md"].decode())
        else:
            stdout.write(canonical({"state": "COMPILED", "digest": package.digest,
                                    "files": [p for p, _ in package.files]}).decode())
        return 0
    except (ForgeError, OSError, UnicodeError) as exc:
        stderr.write((exc.code if isinstance(exc, ForgeError) else "input_output_error") + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
