from __future__ import annotations

import json
import os

from fastapi.testclient import TestClient

from liltweak.api import build_default_service, create_app
from liltweak.planning_chat import PlanningChatService, PlanningConversationStore
from liltweak.vercel_boundary import VercelOwnerBoundary
from liltweak.vercel_runtime import _owner_key, _settings, _state_root

LIL_TWEAK_VERCEL_PROJECT_ID = "prj_b2irbcWTB8UwPwMhk6d47wh5w8TN"


class NoCallPlanningProvider:
    def profile_is_qualified(self, _profile_name: object) -> bool:
        return False


def _is_lil_tweak_project() -> bool:
    project_id = os.getenv("VERCEL_PROJECT_ID", "")
    deployment_url = os.getenv("VERCEL_URL", "")
    return project_id == LIL_TWEAK_VERCEL_PROJECT_ID or deployment_url.startswith("lil-tweak-")


def main() -> int:
    if not _is_lil_tweak_project():
        print("Skipping real Tweak smoke for another Vercel project.")
        return 0
    host = os.getenv("VERCEL_URL", "")
    root = _state_root()
    owner_key = _owner_key()
    settings = _settings(root, owner_key, model_enabled=False)
    service = build_default_service(settings)
    planning = PlanningChatService(
        provider=NoCallPlanningProvider(),
        store=PlanningConversationStore(settings.database_path),
    )
    app = create_app(service=service, settings=settings, planning_chat_service=planning)
    app.add_middleware(
        VercelOwnerBoundary,
        owner_key=owner_key,
        deployment_host=host,
        branch_host=os.getenv("VERCEL_BRANCH_URL"),
    )
    client = TestClient(app, base_url=f"https://{host}")
    session = client.get("/v1/workbench/session")
    if session.status_code != 200:
        raise RuntimeError(f"owner session failed with HTTP {session.status_code}")
    conversation = client.post(
        "/v1/workbench/planning/conversations",
        headers={"X-CSRF-Token": session.json()["csrf_token"]},
        json={"title": "Real Tweak Vercel recovery"},
    )
    if conversation.status_code != 201:
        raise RuntimeError(f"planning conversation creation failed with HTTP {conversation.status_code}")
    print(json.dumps({"status": "PASSED", "stage": "planning-http-create"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
