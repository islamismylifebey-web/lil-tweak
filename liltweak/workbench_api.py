import asyncio
import hashlib
import secrets
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .config import Settings
from .workbench import WorkbenchController, WorkbenchError
from .workbench_agent import WorkbenchModelError
from .workbench_contract import (
    ApprovalDecision,
    CandidateSubmission,
    TaskImport,
    WorkbenchApproval,
    WorkbenchEvidence,
    WorkbenchHealth,
    WorkbenchTask,
)
from .workbench_executor import ExecutorUnavailableError, ToolExecutionError
from .workbench_policy import ToolPolicyError
from .workbench_security import (
    SecurityBoundaryError,
    Session,
    SessionManager,
    SlidingWindowRateLimiter,
)
from .workbench_store import (
    WorkbenchConflict,
    WorkbenchNotFound,
)


class ApiSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(ApiSchema):
    owner_key: str = Field(min_length=1, max_length=8_192)


class SessionResponse(ApiSchema):
    authenticated: bool
    actor_id: str
    csrf_token: str
    expires_at: float


class ApprovalAction(ApiSchema):
    approval_id: str = Field(min_length=1, max_length=128)
    decision: ApprovalDecision


class ExecuteRequest(ApiSchema):
    approval_id: str = Field(min_length=1, max_length=128)


class EmergencyResponse(ApiSchema):
    emergency_stopped: bool
    canceled_tasks: list[str]


def mount_workbench(
    app: FastAPI,
    *,
    controller: WorkbenchController,
    settings: Settings,
    session_signing_key: bytes,
) -> None:
    sessions = SessionManager(
        session_signing_key,
        ttl_seconds=settings.workbench_session_ttl_seconds,
    )
    limiter = SlidingWindowRateLimiter(
        limit=settings.workbench_rate_limit_per_minute,
        window_seconds=60,
    )
    router = APIRouter(prefix="/v1/workbench", tags=["workbench"])
    cookie_name = "liltweak_owner_session"

    def require_session(
        request: Request,
        session_cookie: Annotated[str | None, Cookie(alias=cookie_name)] = None,
    ) -> Session:
        identity = request.client.host if request.client else "local"
        limiter.admit(identity)
        try:
            return sessions.verify(session_cookie)
        except SecurityBoundaryError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def require_mutation(
        request: Request,
        csrf_token: Annotated[str | None, Header(alias="X-CSRF-Token")] = None,
        session_cookie: Annotated[str | None, Cookie(alias=cookie_name)] = None,
    ) -> Session:
        identity = request.client.host if request.client else "local"
        limiter.admit(identity)
        try:
            return sessions.verify_csrf(session_cookie, csrf_token)
        except SecurityBoundaryError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @router.post("/session", response_model=SessionResponse)
    async def login(body: LoginRequest, request: Request) -> JSONResponse:
        identity = request.client.host if request.client else "local"
        limiter.admit(f"login:{identity}")
        if not settings.dev_api_key:
            raise HTTPException(status_code=503, detail="owner authentication is not configured")
        actual = hashlib.sha256(body.owner_key.encode()).digest()
        expected = hashlib.sha256(settings.dev_api_key.encode()).digest()
        if not secrets.compare_digest(actual, expected):
            raise HTTPException(status_code=401, detail="invalid owner credentials")
        session, cookie = sessions.create(settings.owner_id)
        csrf = sessions.csrf_for_cookie(cookie)
        payload = SessionResponse(
            authenticated=True,
            actor_id=session.actor_id,
            csrf_token=csrf,
            expires_at=session.expires_at,
        )
        response = JSONResponse(payload.model_dump(mode="json"))
        response.set_cookie(
            cookie_name,
            cookie,
            httponly=True,
            secure=request.url.scheme == "https",
            samesite="strict",
            max_age=settings.workbench_session_ttl_seconds,
            path="/",
        )
        return response

    @router.delete("/session", status_code=204)
    async def logout(
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> Response:
        response = Response(status_code=204)
        response.delete_cookie(cookie_name, path="/", samesite="strict")
        return response

    @router.get("/session", response_model=SessionResponse)
    async def session_status(
        session: Annotated[Session, Depends(require_session)],
    ) -> SessionResponse:
        return SessionResponse(
            authenticated=True,
            actor_id=session.actor_id,
            csrf_token=session.csrf_token,
            expires_at=session.expires_at,
        )

    @router.get("/health", response_model=WorkbenchHealth)
    async def health(
        _session: Annotated[Session, Depends(require_session)],
        task_id: str | None = None,
    ) -> WorkbenchHealth:
        return controller.health(task_id)

    @router.post("/tasks", response_model=WorkbenchTask, status_code=202)
    async def receive_task(
        body: TaskImport,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> WorkbenchTask:
        return controller.receive(body)

    @router.get("/tasks", response_model=list[WorkbenchTask])
    async def list_tasks(
        _session: Annotated[Session, Depends(require_session)],
        limit: int = 100,
    ) -> list[WorkbenchTask]:
        return controller.store.list_tasks(limit=limit)

    @router.get("/tasks/{task_id}", response_model=WorkbenchTask)
    async def get_task(
        task_id: str,
        _session: Annotated[Session, Depends(require_session)],
    ) -> WorkbenchTask:
        return controller.store.get_task(task_id)

    @router.post("/tasks/{task_id}/inspect", response_model=WorkbenchTask)
    async def inspect_task(
        task_id: str,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> WorkbenchTask:
        return await run_in_threadpool(controller.inspect, task_id)

    @router.post("/tasks/{task_id}/analyze")
    async def analyze_task(
        task_id: str,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> dict[str, object]:
        task, approval = await controller.analyze(task_id)
        return {
            "task": task.model_dump(mode="json"),
            "approval": approval.model_dump(mode="json"),
        }

    @router.post("/tasks/{task_id}/decision", response_model=WorkbenchTask)
    async def decide_task(
        task_id: str,
        body: ApprovalAction,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> WorkbenchTask:
        return controller.decide(task_id, body.approval_id, body.decision)

    @router.post("/tasks/{task_id}/execute", response_model=WorkbenchTask)
    async def execute_task(
        task_id: str,
        body: ExecuteRequest,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> WorkbenchTask:
        return await controller.execute(task_id, body.approval_id)

    @router.post("/tasks/{task_id}/cancel", response_model=WorkbenchTask)
    async def cancel_task(
        task_id: str,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> WorkbenchTask:
        return controller.cancel(task_id)

    @router.post("/tasks/{task_id}/retry-eligible-step", response_model=WorkbenchTask)
    async def retry_step(
        task_id: str,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> WorkbenchTask:
        return controller.retry_eligible_step(task_id)

    @router.post("/tasks/{task_id}/rollback/request")
    async def request_rollback(
        task_id: str,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> dict[str, object]:
        task, approval = controller.request_rollback(task_id)
        return {
            "task": task.model_dump(mode="json"),
            "approval": approval.model_dump(mode="json"),
        }

    @router.post("/tasks/{task_id}/rollback", response_model=WorkbenchTask)
    async def rollback(
        task_id: str,
        body: ExecuteRequest,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> WorkbenchTask:
        return controller.rollback(task_id, body.approval_id)

    @router.post("/emergency-stop", response_model=EmergencyResponse)
    async def emergency_stop(
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> EmergencyResponse:
        canceled = controller.emergency_stop()
        return EmergencyResponse(emergency_stopped=True, canceled_tasks=canceled)

    @router.get("/tasks/{task_id}/approvals/{approval_id}", response_model=WorkbenchApproval)
    async def get_approval(
        task_id: str,
        approval_id: str,
        _session: Annotated[Session, Depends(require_session)],
    ) -> WorkbenchApproval:
        approval = controller.store.get_approval(approval_id)
        if approval.task_id != task_id:
            raise WorkbenchNotFound("approval does not belong to this task")
        return approval

    @router.get("/tasks/{task_id}/runs")
    async def list_runs(
        task_id: str,
        _session: Annotated[Session, Depends(require_session)],
    ) -> list[dict[str, object]]:
        controller.store.get_task(task_id)
        return [run.model_dump(mode="json") for run in controller.store.list_runs(task_id)]

    @router.get("/tasks/{task_id}/evidence", response_model=list[WorkbenchEvidence])
    async def evidence(
        task_id: str,
        _session: Annotated[Session, Depends(require_session)],
    ) -> list[WorkbenchEvidence]:
        controller.store.get_task(task_id)
        return controller.store.list_evidence(task_id)

    @router.get("/tasks/{task_id}/events")
    async def stream_events(
        task_id: str,
        _session: Annotated[Session, Depends(require_session)],
        after_sequence: int = 0,
        once: bool = False,
    ) -> StreamingResponse:
        controller.store.get_task(task_id)

        async def events():
            cursor = after_sequence
            iterations = 1 if once else 60
            for _ in range(iterations):
                records = [
                    item
                    for item in controller.store.list_evidence(task_id)
                    if item.sequence > cursor
                ]
                for record in records:
                    cursor = record.sequence
                    yield (
                        f"id: {record.sequence}\n"
                        f"event: {record.event_type}\n"
                        f"data: {record.model_dump_json()}\n\n"
                    )
                if once:
                    break
                yield ": heartbeat\n\n"
                await asyncio.sleep(0.5)

        return StreamingResponse(
            events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @router.get("/tasks/{task_id}/evidence/export")
    async def export_evidence(
        task_id: str,
        _session: Annotated[Session, Depends(require_session)],
    ) -> PlainTextResponse:
        records = controller.store.list_evidence(task_id)
        return PlainTextResponse(
            "\n".join(record.model_dump_json() for record in records),
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{task_id.replace(":", "-")}-evidence.jsonl"'
                )
            },
        )

    @router.post("/tasks/{task_id}/submission", response_model=CandidateSubmission)
    async def generate_submission(
        task_id: str,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> CandidateSubmission:
        return controller.generate_submission(task_id)

    @router.get("/tasks/{task_id}/submission")
    async def get_submission(
        task_id: str,
        _session: Annotated[Session, Depends(require_session)],
    ) -> dict[str, object]:
        submission = controller.store.get_submission_for_task(task_id)
        if submission is None:
            raise WorkbenchNotFound("candidate submission was not found")
        return {
            "submission": submission.model_dump(mode="json"),
            "rendered": submission.rendered,
        }

    @router.get("/tasks/{task_id}/submission/export")
    async def export_submission(
        task_id: str,
        _session: Annotated[Session, Depends(require_session)],
    ) -> PlainTextResponse:
        submission = controller.store.get_submission_for_task(task_id)
        if submission is None:
            raise WorkbenchNotFound("candidate submission was not found")
        return PlainTextResponse(
            submission.rendered,
            headers={
                "Content-Disposition": (
                    f'attachment; filename="{task_id.replace(":", "-")}-submission.txt"'
                )
            },
        )

    @router.post("/tasks/{task_id}/submission/lock", response_model=CandidateSubmission)
    async def lock_submission(
        task_id: str,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> CandidateSubmission:
        return controller.lock_submission(task_id)

    @router.post("/tasks/{task_id}/submission/reopen", response_model=CandidateSubmission)
    async def reopen_submission(
        task_id: str,
        _session: Annotated[Session, Depends(require_mutation)],
    ) -> CandidateSubmission:
        return controller.reopen_submission(task_id)

    app.include_router(router)

    @app.exception_handler(WorkbenchNotFound)
    async def workbench_not_found(_request: Request, exc: WorkbenchNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(WorkbenchConflict)
    async def workbench_conflict(_request: Request, exc: WorkbenchConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(WorkbenchError)
    async def workbench_error(_request: Request, exc: WorkbenchError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    for boundary_error in (
        WorkbenchModelError,
        ExecutorUnavailableError,
        ToolExecutionError,
        ToolPolicyError,
        SecurityBoundaryError,
    ):
        app.add_exception_handler(
            boundary_error,
            lambda _request, _exc: JSONResponse(
                status_code=409,
                content={"detail": "Workbench operation failed closed."},
            ),
        )

    static_root = Path(__file__).parents[1] / "web" / "workbench"

    @app.get("/workbench", include_in_schema=False)
    async def workbench_ui() -> FileResponse:
        return FileResponse(static_root / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/workbench/styles.css", include_in_schema=False)
    async def workbench_styles() -> FileResponse:
        return FileResponse(
            static_root / "styles.css",
            media_type="text/css",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/workbench/app.js", include_in_schema=False)
    async def workbench_script() -> FileResponse:
        return FileResponse(
            static_root / "app.js",
            media_type="application/javascript",
            headers={"Cache-Control": "no-store"},
        )
