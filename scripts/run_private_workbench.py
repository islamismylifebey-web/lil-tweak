from __future__ import annotations

import argparse
import sys
from pathlib import Path

import uvicorn

APP_ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(APP_ROOT))

from liltweak.api import build_default_service, create_app  # noqa: E402
from liltweak.config import Settings  # noqa: E402
from liltweak.operational_qualification import load_operational_qualifications  # noqa: E402
from liltweak.planning_chat import PlanningChatService, PlanningConversationStore  # noqa: E402
from liltweak.reasoning_provider import OpenAIResponsesReasoningProvider  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the private localhost Lil Tweak Workbench.")
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--port", type=int, default=8787)
    arguments = parser.parse_args()
    if arguments.port < 1024 or arguments.port > 65_535:
        raise ValueError("private Workbench port is invalid")
    settings = Settings.from_env()
    if not settings.workbench_enabled or not settings.workbench_model_enabled:
        raise RuntimeError("private Workbench and its qualified model must be explicitly enabled")
    qualifications = load_operational_qualifications(arguments.qualification)
    provider = OpenAIResponsesReasoningProvider(
        qualifications=qualifications,
        maximum_concurrency=2,
    )
    service = build_default_service(settings)
    planning = PlanningChatService(
        provider=provider,
        store=PlanningConversationStore(settings.database_path),
    )
    app = create_app(
        service=service,
        settings=settings,
        workbench_reasoning_provider=provider,
        planning_chat_service=planning,
    )
    uvicorn.run(
        app,
        host=settings.server_host,
        port=arguments.port,
        access_log=False,
        server_header=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
