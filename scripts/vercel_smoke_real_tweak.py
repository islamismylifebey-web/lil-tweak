from __future__ import annotations

import json
import os

from fastapi.testclient import TestClient

from liltweak.planning_chat import PlanningConversationCreate, PlanningConversationStore
from liltweak.vercel_runtime import _owner_key, _settings, _state_root, create_vercel_app

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
    app = create_vercel_app()
    client = TestClient(app, base_url=f"https://{host}")
    session = client.get("/v1/workbench/session")
    if session.status_code != 200:
        raise RuntimeError(f"qualified owner session failed with HTTP {session.status_code}")

    root = _state_root()
    settings = _settings(root, _owner_key(), model_enabled=True)
    conversation = PlanningConversationStore(settings.database_path).create(
        PlanningConversationCreate(title="Qualified app DB interaction")
    )
    if not conversation.id.startswith("planning:"):
        raise RuntimeError("qualified app Planning Chat store write failed")
    print(json.dumps({"status": "PASSED", "stage": "qualified-session-plus-store"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
