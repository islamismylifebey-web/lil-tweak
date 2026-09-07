from __future__ import annotations

import json
import os

from liltweak.api import build_default_service
from liltweak.vercel_runtime import _owner_key, _settings, _state_root

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
    owner_key = _owner_key()
    settings = _settings(root, owner_key, model_enabled=False)
    service = build_default_service(settings)
    if service.store is None:
        raise RuntimeError("default Tweak service has no store")
    print(json.dumps({"status": "PASSED", "stage": "default-service"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
