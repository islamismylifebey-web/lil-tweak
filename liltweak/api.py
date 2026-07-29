from __future__ import annotations

import hashlib
import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict
from starlette.concurrency import run_in_threadpool

from .agent import OpenAIPlanner, PlanningProviderError
from .approvals import ApprovalError
from .artifacts import ArtifactIntegrityError, EncryptedArtifactStore
from .config import Settings
from .costs import BudgetExceededError, CostGuard
from .evidence import EvidenceChainError
from .models import (
    ApprovalDecisionRequest,
    ApprovalRecord,
    ChangePreparation,
    EvidenceRecord,
    JobRecord,
    RecoveryCreateRequest,
    RecoveryPackage,
    RepositoryInspection,
    TaskCreate,
)
from .recovery import RecoveryCapture, RecoveryError
from .repository import RepositoryAccessError, RepositoryInspectionError, RepositoryInspector
from .service import (
    EmergencyStopError,
    InspectionUnavailableError,
    LilTweakService,
    RunnerUnavailableError,
    SensitiveInputError,
)
from .store import IdempotencyConflictError, NotFoundError, SQLiteStore


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmergencyStopResponse(ApiModel):
    status: str
    canceled_jobs: list[str]


def _safe_match(actual: str, expected: str) -> bool:
    actual_hash = hashlib.sha256(actual.encode()).digest()
    expected_hash = hashlib.sha256(expected.encode()).digest()
    return secrets.compare_digest(actual_hash, expected_hash)


def build_default_service(settings: Settings) -> LilTweakService:
    store = SQLiteStore(settings.database_path)
    inspector = RepositoryInspector(
        workspace_root=settings.workspace_root,
        repository_mappings=settings.repository_mappings,
    )
    recovery_capture = None
    if settings.artifact_encryption_key is not None:
        recovery_capture = RecoveryCapture(
            inspector=inspector,
            artifact_store=EncryptedArtifactStore(
                root=settings.artifact_root,
                workspace_root=settings.workspace_root,
                master_key=settings.artifact_encryption_key,
                store=store,
            ),
        )
    return LilTweakService(
        store=store,
        planner=OpenAIPlanner(settings.model),
        cost_guard=CostGuard(
            monthly_limit_usd=settings.monthly_budget_usd,
            job_default_limit_usd=settings.job_hard_limit_usd,
            planning_reservation_usd=settings.planning_reservation_usd,
        ),
        repository_inspector=inspector,
        recovery_capture=recovery_capture,
        owner_id=settings.owner_id,
        evidence_signing_key=settings.evidence_signing_key,
    )


def create_app(
    service: LilTweakService | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    service = service or build_default_service(settings)
    bearer = HTTPBearer(auto_error=False)

    async def require_auth(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),  # noqa: B008
    ) -> None:
        if settings.auth_disabled:
            return
        if not settings.dev_api_key:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is not configured",
            )
        if (
            credentials is None
            or credentials.scheme.lower() != "bearer"
            or not _safe_match(credentials.credentials, settings.dev_api_key)
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="invalid credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )

    app = FastAPI(
        title="Lil Tweak Engineering API",
        version="0.3.2",
        description=(
            "Independent Phase 3 repository intelligence, encrypted recovery preparation, "
            "change specifications, approvals, and evidence runtime."
        ),
    )

    @app.middleware("http")
    async def private_api_headers(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.exception_handler(NotFoundError)
    async def not_found_handler(_request: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(RequestValidationError)
    async def validation_handler(
        _request: Request,
        _exc: RequestValidationError,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"detail": "Request validation failed."},
        )

    @app.exception_handler(IdempotencyConflictError)
    async def idempotency_handler(_request: Request, exc: IdempotencyConflictError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ApprovalError)
    async def approval_handler(_request: Request, exc: ApprovalError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(BudgetExceededError)
    async def budget_handler(_request: Request, exc: BudgetExceededError) -> JSONResponse:
        return JSONResponse(status_code=402, content={"detail": str(exc)})

    @app.exception_handler(SensitiveInputError)
    async def sensitive_input_handler(_request: Request, exc: SensitiveInputError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(EmergencyStopError)
    async def emergency_handler(_request: Request, exc: EmergencyStopError) -> JSONResponse:
        return JSONResponse(status_code=423, content={"detail": str(exc)})

    @app.exception_handler(RunnerUnavailableError)
    async def runner_handler(_request: Request, exc: RunnerUnavailableError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(RepositoryAccessError)
    async def repository_access_handler(
        _request: Request, exc: RepositoryAccessError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(InspectionUnavailableError)
    async def inspection_unavailable_handler(
        _request: Request, exc: InspectionUnavailableError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(RepositoryInspectionError)
    async def repository_inspection_handler(
        _request: Request, _exc: RepositoryInspectionError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"detail": "repository inspection is currently unavailable"},
        )

    @app.exception_handler(PlanningProviderError)
    async def planning_provider_handler(
        _request: Request, _exc: PlanningProviderError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=502,
            content={"detail": "planning provider is currently unavailable"},
        )

    @app.exception_handler(EvidenceChainError)
    async def evidence_integrity_handler(
        _request: Request, _exc: EvidenceChainError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"detail": "evidence integrity verification failed"},
        )

    @app.exception_handler(RecoveryError)
    async def recovery_handler(_request: Request, exc: RecoveryError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(ArtifactIntegrityError)
    async def artifact_integrity_handler(
        _request: Request, _exc: ArtifactIntegrityError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=409,
            content={"detail": "artifact integrity verification failed"},
        )

    @app.get("/health")
    async def health() -> dict:
        return service.health().model_dump(mode="json")

    @app.post(
        "/v1/jobs",
        response_model=JobRecord,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_auth)],
    )
    async def create_job(
        task: TaskCreate,
        idempotency_key: Annotated[
            str,
            Header(alias="Idempotency-Key", min_length=16, max_length=128),
        ],
    ) -> JobRecord:
        return service.create_job(task, idempotency_key)

    @app.get(
        "/v1/jobs/{job_id}",
        response_model=JobRecord,
        dependencies=[Depends(require_auth)],
    )
    async def get_job(job_id: str) -> JobRecord:
        return service.get_job(job_id)

    @app.post(
        "/v1/jobs/{job_id}/analyze",
        response_model=JobRecord,
        dependencies=[Depends(require_auth)],
    )
    async def analyze_job(job_id: str) -> JobRecord:
        return await service.analyze_job(job_id)

    @app.post(
        "/v1/jobs/{job_id}/inspect",
        response_model=JobRecord,
        dependencies=[Depends(require_auth)],
    )
    async def inspect_job(job_id: str) -> JobRecord:
        return await run_in_threadpool(service.inspect_job, job_id)

    @app.get(
        "/v1/jobs/{job_id}/inspection",
        response_model=RepositoryInspection,
        dependencies=[Depends(require_auth)],
    )
    async def get_inspection(job_id: str) -> RepositoryInspection:
        return service.get_inspection(job_id)

    @app.post(
        "/v1/jobs/{job_id}/recovery",
        response_model=RecoveryPackage,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_auth)],
    )
    async def create_recovery(
        job_id: str,
        body: RecoveryCreateRequest,
        idempotency_key: Annotated[
            str,
            Header(alias="Idempotency-Key", min_length=16, max_length=128),
        ],
    ) -> RecoveryPackage:
        return service.create_recovery_request(
            job_id,
            body,
            idempotency_key,
            settings.owner_id,
        )

    @app.get(
        "/v1/jobs/{job_id}/recovery",
        response_model=RecoveryPackage,
        dependencies=[Depends(require_auth)],
    )
    async def get_recovery(job_id: str) -> RecoveryPackage:
        return service.get_recovery(job_id)

    @app.post(
        "/v1/jobs/{job_id}/recovery/prepare",
        response_model=RecoveryPackage,
        dependencies=[Depends(require_auth)],
    )
    async def prepare_recovery(job_id: str) -> RecoveryPackage:
        return await run_in_threadpool(
            service.prepare_recovery,
            job_id,
            settings.owner_id,
        )

    @app.post(
        "/v1/jobs/{job_id}/changes/prepare",
        response_model=ChangePreparation,
        dependencies=[Depends(require_auth)],
    )
    async def prepare_change(job_id: str) -> ChangePreparation:
        return await run_in_threadpool(
            service.prepare_change,
            job_id,
            settings.owner_id,
        )

    @app.post(
        "/v1/jobs/{job_id}/cancel",
        response_model=JobRecord,
        dependencies=[Depends(require_auth)],
    )
    async def cancel_job(job_id: str) -> JobRecord:
        return service.cancel_job(job_id, settings.owner_id)

    @app.post(
        "/v1/jobs/{job_id}/execute",
        response_model=JobRecord,
        dependencies=[Depends(require_auth)],
    )
    async def execute_job(job_id: str) -> JobRecord:
        return service.request_execution(job_id)

    @app.get(
        "/v1/jobs/{job_id}/evidence",
        response_model=list[EvidenceRecord],
        dependencies=[Depends(require_auth)],
    )
    async def list_evidence(job_id: str) -> list[EvidenceRecord]:
        service.get_job(job_id)
        service.evidence.verify(job_id)
        return service.evidence.list(job_id)

    @app.get(
        "/v1/approvals/{approval_id}",
        response_model=ApprovalRecord,
        dependencies=[Depends(require_auth)],
    )
    async def get_approval(approval_id: str) -> ApprovalRecord:
        return service.approvals.get(approval_id)

    @app.post(
        "/v1/approvals/{approval_id}/decision",
        response_model=JobRecord,
        dependencies=[Depends(require_auth)],
    )
    async def decide_approval(approval_id: str, body: ApprovalDecisionRequest) -> JobRecord:
        return service.decide_approval(approval_id, body, settings.owner_id)

    @app.post(
        "/v1/emergency-stop",
        response_model=EmergencyStopResponse,
        dependencies=[Depends(require_auth)],
    )
    async def emergency_stop() -> EmergencyStopResponse:
        canceled = service.emergency_stop(settings.owner_id)
        return EmergencyStopResponse(status="stopped", canceled_jobs=canceled)

    return app
