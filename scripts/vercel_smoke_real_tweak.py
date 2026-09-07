from __future__ import annotations

import json
import os
import stat

from liltweak.vercel_runtime import _state_root

LIL_TWEAK_VERCEL_PROJECT_ID = "prj_b2irbcWTB8UwPwMhk6d47wh5w8TN"


def _is_lil_tweak_project() -> bool:
    project_id = os.getenv("VERCEL_PROJECT_ID", "")
    deployment_url = os.getenv("VERCEL_URL", "")
    return project_id == LIL_TWEAK_VERCEL_PROJECT_ID or deployment_url.startswith("lil-tweak-")


def main() -> int:
    if not _is_lil_tweak_project():
        print("Skipping real Tweak smoke for another Vercel project.")
        return 0
    root = _state_root()
    mode = stat.S_IMODE(root.stat().st_mode)
    if mode != 0o700:
        raise RuntimeError(f"Vercel state root mode is {oct(mode)}, expected 0o700")
    print(json.dumps({"status": "PASSED", "stage": "private-state-root"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
