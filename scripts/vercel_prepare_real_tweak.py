from __future__ import annotations

import asyncio
import os
from pathlib import Path

from qualify_operational_provider import run

LIL_TWEAK_VERCEL_PROJECT_ID = "prj_b2irbcWTB8UwPwMhk6d47wh5w8TN"
OUTPUT = Path(__file__).parents[1] / "operational-provider-qualification.json"


def _is_lil_tweak_project() -> bool:
    project_id = os.getenv("VERCEL_PROJECT_ID", "")
    deployment_url = os.getenv("VERCEL_URL", "")
    return project_id == LIL_TWEAK_VERCEL_PROJECT_ID or deployment_url.startswith("lil-tweak-")


def main() -> int:
    if not _is_lil_tweak_project():
        print("Skipping Lil Tweak provider qualification for another Vercel project.")
        return 0
    if not os.getenv("OPENAI_API_KEY"):
        raise SystemExit("OPENAI_API_KEY is required for Lil Tweak provider qualification")
    if OUTPUT.exists():
        OUTPUT.unlink()
    return asyncio.run(run(OUTPUT))


if __name__ == "__main__":
    raise SystemExit(main())
