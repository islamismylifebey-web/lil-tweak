#!/usr/bin/env python3
"""Generate the self-excluding final Lil Tweak source-tree manifest."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "FINAL_FILE_MANIFEST.json"
PRESERVED_AUDITED_BASELINE_FILES = (
    {
        "relative_path": "docs/agent-interactions.png",
        "sha256": "b629e2f4536cc723704f9e32efb0d8d460144dc1442000be590f1785c02f2112",
        "bytes": 107725,
    },
    {
        "relative_path": "docs/agent-sequence.png",
        "sha256": "d4a83ac5bd703618570e87be91fcba888e61371e1b0fbb4b04dcd8ffb1de728e",
        "bytes": 59921,
    },
)


def generate() -> dict[str, object]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=10,
        shell=False,
    )
    paths = sorted(
        value.decode("utf-8")
        for value in result.stdout.split(b"\0")
        if value and value.decode("utf-8") != OUTPUT.name
    )
    files: list[dict[str, object]] = []
    for relative in paths:
        path = ROOT / relative
        if path.is_symlink() or not path.is_file():
            raise RuntimeError(f"manifest path is not a regular file: {relative}")
        content = path.read_bytes()
        files.append(
            {
                "relative_path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
                "bytes": len(content),
            }
        )
    local_paths = {str(item["relative_path"]) for item in files}
    files.extend(
        dict(item)
        for item in PRESERVED_AUDITED_BASELINE_FILES
        if str(item["relative_path"]) not in local_paths
    )
    files.sort(key=lambda item: str(item["relative_path"]))
    return {
        "schema_version": "1.0",
        "package": "lil-tweak-sol-high-direct-build",
        "built_at_utc": datetime.now(UTC).isoformat(),
        "repository": "islamismylifebey-web/lil-tweak",
        "branch": "codex/lil-tweak-live-workbench-build",
        "audited_baseline": "c8227ce5c2a0718671d95c34529088ee38efe238",
        "corrective_package_sha256": (
            "e519a00ab0035690963772c16843a264f2a2ceefc0c8a8ecfc87a1e5dad5c60c"
        ),
        "scope": (
            "final Git tree: local Git/untracked build files plus unchanged audited-baseline "
            "binary assets preserved by the remote base tree"
        ),
        "preserved_audited_baseline_files": [
            str(item["relative_path"]) for item in PRESERVED_AUDITED_BASELINE_FILES
        ],
        "self_excluded_from_hash_list": True,
        "file_count_excluding_manifest": len(files),
        "files": files,
    }


if __name__ == "__main__":
    OUTPUT.write_text(
        json.dumps(generate(), indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )
