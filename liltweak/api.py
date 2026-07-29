from __future__ import annotations

import hashlib
import json
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
from .creator import (
    CreatorEnvelopeError,
    CreatorInputError,
    CreatorLearningError,
    CreatorService,
)
from .creator_contract import (
    MAX_CREATOR_REQUEST_BYTES,
    CausalLearningRecord,
    CreatorBriefEnvelope,
    CreatorCompileRequest,
    CreatorHealth,
    CreatorRunPreview,
    RouteDecision,
    RoutePreviewRequest,
)
from .evidence import EvidenceChainError
from .live_contract import (
    LiveProposalDecisionRequest,
    LiveProposalDecisionResponse,
    LiveProposalPrepareRequest,
    LiveProposalRecord,
    LiveRunExecuteRequest,
    LiveRunResult,
)
from .live_model import (
    LiveCreatorController,
    LiveModelApprovalError,
    LiveModelDisabledError,
    LiveModelProviderError,
    OpenAICreatorModelProvider,
)
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
from .store import (
    IdempotencyConflictError,
    NotFoundError,
    SQLiteStore,
    StoreStateConflictError,
)


class ApiModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmergencyStopResponse(ApiModel):
    status: str
    canceled_jobs: list[str]


class _DuplicateJsonKeyError(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError
        result[key] = value
    return result


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
    creator_service: CreatorService | None = None,
    live_controller: LiveCreatorController | None = None,
) -> FastAPI:
    settings = settings or Settings.from_env()
    service = service or build_default_service(settings)
    creator_key = settings.creator_signing_key
    if creator_key is None and settings.evidence_signing_key is not None:
        creator_key = hashlib.sha256(
            settings.evidence_signing_key + b"LilTweakCreatorControlPlaneV1"
        ).digest()
    creator_service = creator_service or CreatorService(
        store=service.store,
        signing_key=creator_key,
        durable_signatures=creator_key is not None,
    )
    if live_controller is None and creator_key is not None:
        live_controller = LiveCreatorController(
            creator=creator_service,
            store=service.store,
            signing_key=creator_key,
            provider=OpenAICreatorModelProvider(),
            enabled=settings.live_model_enabled,
            owner_id=settings.owner_id,
            monthly_limit_usd=settings.live_monthly_limit_usd,
            per_call_limit_usd=settings.live_call_limit_usd,
            input_token_limit=settings.live_input_token_limit,
            output_token_limit=settings.live_output_token_limit,
        )
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
        version="0.6.0",
        description=(
            "Independent evidence-driven engineering engine with Creator Model compilation, "
            "bounded live reasoning, adaptive routing, encrypted recovery, approvals, "
            "and causal learning."
        ),
    )

    @app.middleware("http")
    async def private_api_headers(request: Request, call_next):
        if request.url.path.startswith("/v1/creator/") and request.method in {
            "POST",
            "PUT",
            "PATCH",
        }:
            body = await request.body()
            if len(body) > MAX_CREATOR_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Creator request is too large."},
                )
            try:
                json.loads(body, object_pairs_hook=_reject_duplicate_json_keys)
            except (_DuplicateJsonKeyError, json.JSONDecodeError, UnicodeDecodeError):
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Creator request JSON is invalid."},
                )
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

    @app.exception_handler(StoreStateConflictError)
    async def store_conflict_handler(
        _request: Request, exc: StoreStateConflictError
    ) -> JSONResponse:
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

    @app.exception_handler(CreatorInputError)
    async def creator_input_handler(_request: Request, exc: CreatorInputError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": str(exc)})

    @app.exception_handler(CreatorEnvelopeError)
    async def creator_envelope_handler(
        _request: Request, exc: CreatorEnvelopeError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(CreatorLearningError)
    async def creator_learning_handler(
        _request: Request, exc: CreatorLearningError
    ) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(LiveModelApprovalError)
    async def live_approval_handler(_request: Request, exc: LiveModelApprovalError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(LiveModelDisabledError)
    async def live_disabled_handler(_request: Request, exc: LiveModelDisabledError) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(LiveModelProviderError)
    async def live_provider_handler(
        _request: Request, _exc: LiveModelProviderError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=502,
            content={"detail": "live Creator provider is currently unavailable"},
        )

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

    @app.get(
        "/v1/creator/health",
        response_model=CreatorHealth,
        dependencies=[Depends(require_auth)],
    )
    async def creator_health() -> CreatorHealth:
        return creator_service.health(
            model_calls_enabled=(live_controller is not None and live_controller.enabled),
            hosted_sandbox_probe_ready=False,
        )

    @app.post(
        "/v1/creator/compile",
        response_model=CreatorBriefEnvelope,
        dependencies=[Depends(require_auth)],
    )
    async def creator_compile(body: CreatorCompileRequest) -> CreatorBriefEnvelope:
        return creator_service.compile(body, actor_id=settings.owner_id)

    @app.post(
        "/v1/creator/route",
        response_model=RouteDecision,
        dependencies=[Depends(require_auth)],
    )
    async def creator_route(body: RoutePreviewRequest) -> RouteDecision:
        return creator_service.route(body)

    @app.post(
        "/v1/creator/prepare",
        response_model=CreatorRunPreview,
        dependencies=[Depends(require_auth)],
    )
    async def creator_prepare(body: CreatorCompileRequest) -> CreatorRunPreview:
        return creator_service.prepare(body, actor_id=settings.owner_id)

    @app.get(
        "/v1/creator/learning",
        response_model=list[CausalLearningRecord],
        dependencies=[Depends(require_auth)],
    )
    async def creator_learning(
        problem_signature: str,
        limit: int = 20,
    ) -> list[CausalLearningRecord]:
        return creator_service.list_learning(problem_signature, limit=limit)

    def require_live_controller() -> LiveCreatorController:
        if live_controller is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable live Creator controls are not configured",
            )
        return live_controller

    @app.post(
        "/v1/creator/live/proposals",
        response_model=LiveProposalRecord,
        status_code=status.HTTP_202_ACCEPTED,
        dependencies=[Depends(require_auth)],
    )
    async def prepare_live_proposal(
        body: LiveProposalPrepareRequest,
    ) -> LiveProposalRecord:
        return require_live_controller().prepare(body)

    @app.get(
        "/v1/creator/live/proposals/{proposal_id}",
        response_model=LiveProposalRecord,
        dependencies=[Depends(require_auth)],
    )
    async def get_live_proposal(proposal_id: str) -> LiveProposalRecord:
        return require_live_controller().get_proposal(proposal_id)

    @app.post(
        "/v1/creator/live/proposals/{proposal_id}/decision",
        response_model=LiveProposalDecisionResponse,
        dependencies=[Depends(require_auth)],
    )
    async def decide_live_proposal(
        proposal_id: str,
        body: LiveProposalDecisionRequest,
    ) -> LiveProposalDecisionResponse:
        record, approval = require_live_controller().decide(
            proposal_id,
            body,
            actor_id=settings.owner_id,
        )
        return LiveProposalDecisionResponse(record=record, approval=approval)

    @app.post(
        "/v1/creator/live/runs",
        response_model=LiveRunResult,
        dependencies=[Depends(require_auth)],
    )
    async def execute_live_run(body: LiveRunExecuteRequest) -> LiveRunResult:
        return await require_live_controller().execute(
            proposal_id=body.proposal_id,
            approval_id=body.approval_id,
            envelope=body.envelope,
            route=body.route,
        )

    @app.get(
        "/v1/creator/live/results/{proposal_id}",
        response_model=LiveRunResult,
        dependencies=[Depends(require_auth)],
    )
    async def get_live_result(proposal_id: str) -> LiveRunResult:
        return require_live_controller().get_result(proposal_id)

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
