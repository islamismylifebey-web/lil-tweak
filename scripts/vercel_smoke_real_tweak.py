from __future__ import annotations

import json
import os

from fastapi.testclient import TestClient

from liltweak.vercel_runtime import create_vercel_app

LIL_TWEAK_VERCEL_PROJECT_ID = "prj_b2irbcWTB8UwPwMhk6d47wh5w8TN"


def _is_lil_tweak_project() -> bool:
    project_id = os.getenv("VERCEL_PROJECT_ID", "")
    deployment_url = os.getenv("VERCEL_URL", "")
    return project_id == LIL_TWEAK_VERCEL_PROJECT_ID or deployment_url.startswith("lil-tweak-")


def main() -> int:
    if not _is_lil_tweak_project():
        print("Skipping real Tweak smoke for another Vercel project.")
        return 0
    host = os.getenv("VERCEL_URL", "")
    if not host:
        raise SystemExit("VERCEL_URL is required for real Tweak smoke")
    client = TestClient(create_vercel_app(enable_model=False), base_url=f"https://{host}")
    response = client.get("/v1/workbench/session")
    if response.status_code != 200:
        raise RuntimeError(f"owner session failed with HTTP {response.status_code}")
    payload = response.json()
    if payload.get("authenticated") is not True:
        raise RuntimeError("owner session is not authenticated")
    if payload.get("actor_id") != "maurice-pennington-bey":
        raise RuntimeError("owner session actor is incorrect")
    if not response.cookies.get("liltweak_owner_session"):
        raise RuntimeError("owner session cookie was not issued")
    print(json.dumps({"status": "PASSED", "stage": "owner-session"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
