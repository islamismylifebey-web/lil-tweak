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


def _require_ok(response: object, label: str) -> None:
    status_code = getattr(response, "status_code", 0)
    if not 200 <= status_code < 300:
        raise RuntimeError(f"{label} failed with HTTP {status_code}")


def main() -> int:
    if not _is_lil_tweak_project():
        print("Skipping real Tweak smoke for another Vercel project.")
        return 0
    host = os.getenv("VERCEL_URL", "")
    client = TestClient(create_vercel_app(), base_url=f"https://{host}")
    session = client.get("/v1/workbench/session")
    _require_ok(session, "owner session")
    csrf = session.json()["csrf_token"]
    conversation = client.post(
        "/v1/workbench/planning/conversations",
        headers={"X-CSRF-Token": csrf},
        json={"title": "Real Tweak Vercel recovery"},
    )
    _require_ok(conversation, "planning conversation creation")
    if not str(conversation.json().get("id", "")).startswith("planning:"):
        raise RuntimeError("Planning Chat conversation id is invalid")
    print(json.dumps({"status": "PASSED", "stage": "planning-conversation"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
