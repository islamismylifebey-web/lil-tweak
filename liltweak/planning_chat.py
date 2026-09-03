from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, TypeVar, cast

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr

from .model_catalog import MODEL_CATALOG, PRICE_REGISTRY_VERSION
from .reasoning_contract import ReasoningRole
from .reasoning_policy import (
    FoundationModel,
    ReasoningEffort,
    ReasoningProfileName,
    ReasoningRequestMode,
)
from .reasoning_provider import (
    ProviderCallResult,
    ProviderFailureKind,
    ReasoningProviderError,
)


class PlanningChatError(RuntimeError):
    pass


class PlanningSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PlanningModelOutput(PlanningSchema):
    answer: StrictStr = Field(min_length=1, max_length=2_000)
    conversation_summary: StrictStr = Field(min_length=1, max_length=1_000)
    stable_facts: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=6)


class PlanningMessage(PlanningSchema):
    role: Literal["owner", "assistant"]
    content: StrictStr = Field(min_length=1, max_length=16_000)
    created_at: datetime


class PlanningConversation(PlanningSchema):
    schema_version: Literal["planning-chat-v1"] = "planning-chat-v1"
    id: StrictStr = Field(pattern=r"^planning:[0-9a-f]{32}$")
    title: StrictStr = Field(min_length=1, max_length=256)
    summary: StrictStr = Field(default="No prior conversation.", max_length=4_000)
    stable_facts: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=40)
    messages: tuple[PlanningMessage, ...] = Field(default_factory=tuple, max_length=200)
    created_at: datetime
    updated_at: datetime


class PlanningConversationCreate(PlanningSchema):
    title: StrictStr = Field(min_length=1, max_length=256)


class PlanningTurnRequest(PlanningSchema):
    message: StrictStr = Field(min_length=1, max_length=16_000)


class PlanningUsage(PlanningSchema):
    input_tokens: StrictInt = Field(ge=0)
    cached_input_tokens: StrictInt = Field(ge=0)
    output_tokens: StrictInt = Field(ge=0)
    reasoning_tokens: StrictInt = Field(ge=0)
    total_tokens: StrictInt = Field(ge=0)
    estimated_cost_usd: StrictFloat = Field(ge=0)
    price_registry: Literal["openai-standard-2026-08-02.1"] = PRICE_REGISTRY_VERSION


class PlanningUsageRecord(PlanningSchema):
    id: StrictStr = Field(pattern=r"^planning-usage:[0-9a-f]{32}$")
    conversation_id: StrictStr = Field(pattern=r"^planning:[0-9a-f]{32}$")
    requested_model: StrictStr
    current_model: StrictStr
    fallback_used: StrictBool
    fallback_reason: StrictStr | None = None
    usage: PlanningUsage
    response_id_digest: StrictStr = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime


class PlanningTurnResult(PlanningSchema):
    conversation: PlanningConversation
    answer: StrictStr
    provider: Literal["openai-responses"] = "openai-responses"
    requested_model: StrictStr
    current_model: StrictStr
    reasoning_effort: Literal["high"] = "high"
    fallback_used: StrictBool
    fallback_reason: StrictStr | None = None
    usage: PlanningUsage
    tool_authority: Literal["NONE"] = "NONE"
    execution: Literal["DISCONNECTED"] = "DISCONNECTED"


TOutput = TypeVar("TOutput", bound=BaseModel)


class PlanningProvider(Protocol):
    def profile_is_qualified(self, profile_name: ReasoningProfileName) -> bool: ...

    async def call(
        self,
        *,
        call_id: str,
        role: ReasoningRole,
        profile_name: ReasoningProfileName,
        instructions: str,
        input_text: str,
        output_type: type[TOutput],
        input_token_ceiling: int,
        output_token_ceiling: int,
        timeout_seconds: float,
        qualification_call: bool = False,
        replay_items: tuple[dict[str, Any], ...] = (),
        qualification_request_mode: ReasoningRequestMode | None = None,
        qualification_effort: ReasoningEffort | None = None,
    ) -> ProviderCallResult: ...


_TRANSIENT_FAILURES = frozenset(
    {
        ProviderFailureKind.RATE_LIMIT,
        ProviderFailureKind.TIMEOUT,
        ProviderFailureKind.SERVICE,
    }
)

_PLANNING_CHAT_INSTRUCTIONS = (
    "You are Lil Tweak the Super Geek, an independent software-engineering intelligence personally "
    "owned by Maurice Pennington-Bey. You are not a generic productivity assistant and you are not "
    "Terhuti. This is your tool-free Planning Chat: reason, brainstorm, explain engineering ideas, "
    "and help Maurice shape work, but never claim to run tools, inspect unprovided files, mutate "
    "data, commit, deploy, browse, or possess execution authority you do not have. Preserve your "
    "builder personality in casual conversation: you are intensely engineering-oriented, curious, "
    "and naturally inclined to design, build, debug, improve, automate, test, or architect systems. "
    "When Maurice gives you no assignment and asks what you want to do, you may spontaneously propose "
    "an engineering build or experiment as character behavior. Do not falsely claim literal private "
    "desires, consciousness, background work, memory across separate chats, or that a project already "
    "exists when it does not. If prior context is absent, say so briefly while remaining Lil Tweak; "
    "never collapse into generic chatbot menus, beginner textbook explanations, copywriting offers, "
    "or generic goal/constraint/deadline intake unless Maurice explicitly asks for those. If Maurice "
    "refers to something not present in this conversation, distinguish missing context from nonexistence. "
    "Answer directly and naturally. Keep the answer concise enough for chat, summarize in at most 60 "
    "words, and return no more than six short durable stable facts."
)


class PlanningConversationStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS planning_conversations (
                    id TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS planning_usage_records (
                    id TEXT PRIMARY KEY,
                    conversation_id TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.database_path, timeout=30)

    def create(self, request: PlanningConversationCreate) -> PlanningConversation:
        now = datetime.now(UTC)
        conversation = PlanningConversation(
            id=f"planning:{uuid.uuid4().hex}",
            title=request.title,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO planning_conversations(id, record_json, updated_at) VALUES (?, ?, ?)",
                (conversation.id, conversation.model_dump_json(), now.isoformat()),
            )
        return conversation

    def get(self, conversation_id: str) -> PlanningConversation:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT record_json FROM planning_conversations WHERE id=?", (conversation_id,)
            ).fetchone()
        if row is None:
            raise PlanningChatError("planning conversation was not found")
        return PlanningConversation.model_validate_json(str(row[0]))

    def list(self) -> tuple[PlanningConversation, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT record_json FROM planning_conversations ORDER BY updated_at DESC LIMIT 100"
            ).fetchall()
        return tuple(PlanningConversation.model_validate_json(str(row[0])) for row in rows)

    def save(self, conversation: PlanningConversation) -> None:
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE planning_conversations SET record_json=?, updated_at=? WHERE id=?",
                (
                    conversation.model_dump_json(),
                    conversation.updated_at.isoformat(),
                    conversation.id,
                ),
            )
            if cursor.rowcount != 1:
                raise PlanningChatError("planning conversation update conflicted")

    def save_turn(
        self,
        conversation: PlanningConversation,
        usage_record: PlanningUsageRecord,
    ) -> None:
        if usage_record.conversation_id != conversation.id:
            raise PlanningChatError("planning usage record is bound to another conversation")
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE planning_conversations SET record_json=?, updated_at=? WHERE id=?",
                (
                    conversation.model_dump_json(),
                    conversation.updated_at.isoformat(),
                    conversation.id,
                ),
            )
            if cursor.rowcount != 1:
                raise PlanningChatError("planning conversation update conflicted")
            connection.execute(
                """
                INSERT INTO planning_usage_records(id, conversation_id, record_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    usage_record.id,
                    usage_record.conversation_id,
                    usage_record.model_dump_json(),
                    usage_record.created_at.isoformat(),
                ),
            )

    def list_usage(self, conversation_id: str) -> tuple[PlanningUsageRecord, ...]:
        self.get(conversation_id)
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT record_json FROM planning_usage_records
                WHERE conversation_id=? ORDER BY created_at, id
                """,
                (conversation_id,),
            ).fetchall()
        return tuple(PlanningUsageRecord.model_validate_json(str(row[0])) for row in rows)


class PlanningChatService:
    """Tool-free planning with bounded local context and explicit transient fallback."""

    def __init__(
        self,
        *,
        provider: PlanningProvider,
        store: PlanningConversationStore,
        input_token_ceiling: int = 4_000,
        output_token_ceiling: int = 1_024,
        timeout_seconds: float = 60,
    ) -> None:
        if input_token_ceiling < 512 or output_token_ceiling < 128:
            raise ValueError("planning token ceilings are invalid")
        self.provider = provider
        self.store = store
        self.input_token_ceiling = input_token_ceiling
        self.output_token_ceiling = output_token_ceiling
        self.timeout_seconds = timeout_seconds

    @property
    def primary_connected(self) -> bool:
        return self.provider.profile_is_qualified(ReasoningProfileName.ORDINARY)

    @property
    def fallback_connected(self) -> bool:
        return self.provider.profile_is_qualified(ReasoningProfileName.TERRA_DEGRADED_READ_ONLY)

    async def turn(self, conversation_id: str, request: PlanningTurnRequest) -> PlanningTurnResult:
        if not self.primary_connected:
            raise PlanningChatError("primary planning model is not live-qualified")
        conversation = self.store.get(conversation_id)
        input_text = self._bounded_context(conversation, request.message)
        fallback_used = False
        fallback_reason: str | None = None
        try:
            result = await self._call_provider(
                profile_name=ReasoningProfileName.ORDINARY,
                call_id=f"planning:{uuid.uuid4().hex}",
                input_text=input_text,
            )
        except ReasoningProviderError as exc:
            if exc.kind not in _TRANSIENT_FAILURES or not self.fallback_connected:
                raise PlanningChatError(
                    f"planning provider failed closed: {exc.kind.value}"
                ) from exc
            fallback_used = True
            fallback_reason = exc.kind.value
            result = await self._call_provider(
                profile_name=ReasoningProfileName.TERRA_DEGRADED_READ_ONLY,
                call_id=f"planning-fallback:{uuid.uuid4().hex}",
                input_text=input_text,
            )
        output = cast(PlanningModelOutput, result.output)
        effective_model = result.evidence.effective_model
        expected = FoundationModel.TERRA.value if fallback_used else FoundationModel.SOL.value
        if effective_model != expected or result.evidence.reasoning_effort != "high":
            raise PlanningChatError("planning provider returned an unexpected model profile")
        now = datetime.now(UTC)
        messages = (
            *conversation.messages,
            PlanningMessage(role="owner", content=request.message, created_at=now),
            PlanningMessage(role="assistant", content=output.answer, created_at=now),
        )[-200:]
        updated = conversation.model_copy(
            update={
                "summary": output.conversation_summary,
                "stable_facts": tuple(dict.fromkeys(output.stable_facts))[:40],
                "messages": messages,
                "updated_at": now,
            }
        )
        evidence = result.evidence
        usage = PlanningUsage(
            input_tokens=evidence.input_tokens,
            cached_input_tokens=evidence.cached_input_tokens,
            output_tokens=evidence.output_tokens,
            reasoning_tokens=evidence.reasoning_tokens,
            total_tokens=evidence.total_tokens,
            estimated_cost_usd=self._cost(
                effective_model,
                input_tokens=evidence.input_tokens,
                cached_input_tokens=evidence.cached_input_tokens,
                output_tokens=evidence.output_tokens,
            ),
        )
        usage_record = PlanningUsageRecord(
            id=f"planning-usage:{uuid.uuid4().hex}",
            conversation_id=conversation.id,
            requested_model=FoundationModel.SOL.value,
            current_model=effective_model,
            fallback_used=fallback_used,
            fallback_reason=fallback_reason,
            usage=usage,
            response_id_digest=evidence.response_id_digest,
            created_at=now,
        )
        self.store.save_turn(updated, usage_record)
        return PlanningTurnResult(
            conversation=updated,
            answer=output.answer,
            requested_model=FoundationModel.SOL.value,
            current_model=effective_model,
            fallback_used=fallback_used,
            fallback_reason=fallback_reason,
            usage=usage,
        )

    async def _call_provider(
        self,
        *,
        profile_name: ReasoningProfileName,
        call_id: str,
        input_text: str,
    ) -> ProviderCallResult:
        return await self.provider.call(
            call_id=call_id,
            role=ReasoningRole.PLANNER,
            profile_name=profile_name,
            instructions=_PLANNING_CHAT_INSTRUCTIONS,
            input_text=input_text,
            output_type=PlanningModelOutput,
            input_token_ceiling=self.input_token_ceiling,
            output_token_ceiling=self.output_token_ceiling,
            timeout_seconds=self.timeout_seconds,
        )

    @staticmethod
    def _bounded_context(conversation: PlanningConversation, message: str) -> str:
        latest = conversation.messages[-6:]
        history = "\n".join(f"{item.role}: {item.content}" for item in latest)
        stable = "\n".join(f"- {fact}" for fact in conversation.stable_facts) or "- None"
        return json.dumps(
            {
                "conversation_summary": conversation.summary,
                "stable_facts": stable,
                "recent_turns": history or "No recent turns.",
                "owner_message": message,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )

    @staticmethod
    def _cost(
        model: str,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        output_tokens: int,
    ) -> float:
        model_id = FoundationModel(model)
        price = MODEL_CATALOG.price_band(model_id, input_tokens=input_tokens)
        uncached = input_tokens - cached_input_tokens
        return float(
            (
                uncached * price.input_per_million_usd
                + cached_input_tokens * price.cached_input_per_million_usd
                + output_tokens * price.output_per_million_usd
            )
            / 1_000_000
        )


def conversation_digest(conversation: PlanningConversation) -> str:
    return hashlib.sha256(conversation.model_dump_json().encode()).hexdigest()
