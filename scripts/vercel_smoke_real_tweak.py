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
    if status_code < 200 or status_code >= 300:
        raise RuntimeError(f"{label} failed with HTTP {status_code}")


def main() -> int:
    if not _is_lil_tweak_project():
        print("Skipping real Tweak smoke for another Vercel project.")
        return 0
    host = os.getenv("VERCEL_URL", "")
    if not host:
        raise SystemExit("VERCEL_URL is required for real Tweak smoke")

    client = TestClient(create_vercel_app(), base_url=f"https://{host}")
    session = client.get("/v1/workbench/session")
    _require_ok(session, "owner session")
    csrf = session.json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf}

    conversation = client.post(
        "/v1/workbench/planning/conversations",
        headers=headers,
        json={"title": "Vercel recovery smoke"},
    )
    _require_ok(conversation, "planning conversation creation")
    conversation_id = conversation.json()["id"]

    turn = client.post(
        f"/v1/workbench/planning/conversations/{conversation_id}/turn",
        headers=headers,
        json={
            "message": (
                "Identify yourself by name and software-engineering role in one short sentence."
            )
        },
    )
    _require_ok(turn, "Planning Chat turn")
    payload = turn.json()
    answer = str(payload.get("answer", ""))
    normalized = answer.casefold()
    if "tweak" not in normalized or not ("engineer" in normalized or "engineering" in normalized):
        raise RuntimeError("Planning Chat identity smoke did not identify real Tweak")
    if payload.get("current_model") != "gpt-5.6-sol":
        raise RuntimeError("Planning Chat did not use the qualified Sol model")
    if payload.get("reasoning_effort") != "high":
        raise RuntimeError("Planning Chat reasoning effort is not high")

    print(
        json.dumps(
            {
                "status": "PASSED",
                "owner_session": True,
                "planning_chat": True,
                "identity": "Lil Tweak",
                "current_model": payload.get("current_model"),
                "reasoning_effort": payload.get("reasoning_effort"),
                "answer_length": len(answer),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
