from __future__ import annotations

import hashlib
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from .api import build_default_service, create_app
from .config import Settings
from .operational_qualification import load_operational_qualifications
from .planning_chat import PlanningChatService, PlanningConversationStore
from .reasoning_policy import REASONING_POLICY
from .reasoning_provider import OpenAIResponsesReasoningProvider
from .vercel_boundary import VercelOwnerBoundary


def _private_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _state_root() -> Path:
    root = Path(os.getenv("LILTWEAK_VERCEL_STATE_ROOT", "/tmp/liltweak"))
    _private_directory(root)
    for child in ("repositories", "artifacts", "workbench-tasks"):
        _private_directory(root / child)
    return root


def _owner_key() -> str:
    secret = os.getenv("LILTWEAK_VERCEL_SESSION_SECRET") or os.getenv("OPENAI_API_KEY")
    if not secret:
        raise RuntimeError("Vercel owner session secret is not configured")
    return hashlib.sha256(
        secret.encode("utf-8") + b"LilTweakVercelOwnerSessionV1"
    ).hexdigest()


def _qualification_path() -> Path | None:
    configured = os.getenv("LILTWEAK_OPERATIONAL_QUALIFICATION_PATH")
    candidates = [
        Path(configured) if configured else None,
        Path(__file__).parents[1] / "operational-provider-qualification.json",
    ]
    return next((path for path in candidates if path is not None and path.is_file()), None)


def _settings(root: Path, owner_key: str, *, model_enabled: bool) -> Settings:
    environment = "production" if os.getenv("VERCEL_ENV") == "production" else "preview"
    return Settings(
        environment=environment,
        database_path=root / "liltweak.db",
        dev_api_key=owner_key,
        auth_disabled=False,
        model=REASONING_POLICY.primary_model.value,
        monthly_budget_usd=250.0,
        job_hard_limit_usd=5.0,
        workspace_root=root / "repositories",
        artifact_root=root / "artifacts",
        workbench_enabled=True,
        workbench_model_enabled=model_enabled,
        workbench_workspace_root=root / "workbench-tasks",
        evidence_signing_key=(
            hashlib.sha256(
                owner_key.encode("ascii") + b"LilTweakVercelEvidenceV1"
            ).digest()
            if environment == "production"
            else None
        ),
        repository_execution_enabled=False,
        workbench_runner_enabled=False,
    )


def create_vercel_app(*, enable_model: bool | None = None) -> FastAPI:
    root = _state_root()
    owner_key = _owner_key()
    qualification_path = _qualification_path()
    model_enabled = (
        enable_model
        if enable_model is not None
        else bool(os.getenv("OPENAI_API_KEY") and qualification_path is not None)
    )
    if model_enabled and qualification_path is None:
        raise RuntimeError("live model qualification evidence is not available")

    settings = _settings(root, owner_key, model_enabled=model_enabled)
    service = build_default_service(settings)
    provider: OpenAIResponsesReasoningProvider | None = None
    planning_chat: PlanningChatService | None = None
    if model_enabled:
        qualifications = load_operational_qualifications(qualification_path)
        provider = OpenAIResponsesReasoningProvider(
            qualifications=qualifications,
            maximum_concurrency=2,
        )
        planning_chat = PlanningChatService(
            provider=provider,
            store=PlanningConversationStore(settings.database_path),
            input_token_ceiling=settings.workbench_input_token_limit,
            output_token_ceiling=settings.workbench_output_token_limit,
        )

    app = create_app(
        service=service,
        settings=settings,
        workbench_reasoning_provider=provider,
        planning_chat_service=planning_chat,
    )

    @app.get("/", include_in_schema=False)
    async def vercel_root() -> RedirectResponse:
        return RedirectResponse("/workbench", status_code=307)

    app.add_middleware(
        VercelOwnerBoundary,
        owner_key=owner_key,
        deployment_host=os.getenv("VERCEL_URL"),
        branch_host=os.getenv("VERCEL_BRANCH_URL"),
    )
    return app
