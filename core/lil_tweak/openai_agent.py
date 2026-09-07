"""Host-owned OpenAI Responses tool loop for the focused code engineer."""

from __future__ import annotations

import json
import fcntl
import hashlib
import os
import re
import secrets
import shutil
import stat
import time
import tempfile
from contextlib import contextmanager
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from .contracts import JobMode
from .archive import ArchiveError, validate_portable_path
from .evidence import (
    WorkspaceEvidenceError,
    build_edit_journal_evidence,
    capture_workspace,
    workspace_changed_paths,
    workspace_delta_digest,
)
from .limits import MAX_EVIDENCE_BYTES
from .sandbox import (
    PodmanSandbox,
    atomic_exchange_directories,
    atomic_publish_noreplace,
)


class AgentError(RuntimeError):
    code = "agent_error"


class PromotionRecoveryRequired(AgentError):
    code = "patch_reconciliation_required"


class AgentLimitError(AgentError):
    code = "agent_round_limit"


class AgentToolCapacityError(AgentLimitError):
    code = "agent_tool_capacity"


class AgentDeadlineError(AgentError):
    code = "agent_deadline_exceeded"


class AgentProtocolError(AgentError):
    code = "agent_protocol_error"


MAX_INITIAL_INVENTORY_ENTRIES = 2_000
MAX_INITIAL_INVENTORY_UTF8_BYTES = 64 * 1024
_PATCH_COMMAND = [
    "patch",
    "--batch",
    "--forward",
    "--strip=1",
    "--no-backup-if-mismatch",
    "--reject-file=-",
    "--input=/tmp/lil-tweak.patch",
]
_HUNK_HEADER = re.compile(
    r"^@@ -(?P<old>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new>\d+)(?:,(?P<new_count>\d+))? @@(?: .*)?$"
)


class ResponsesClient:
    """Thin production adapter around ``OpenAI().responses.create``.

    Supplying ``sdk`` keeps tests fully local; constructing without it imports
    the SDK lazily and never makes a request until ``create`` is called.
    """

    def __init__(self, *, api_key: str | None = None, sdk: Any = None) -> None:
        if sdk is None:
            if not api_key:
                raise ValueError("OpenAI API key is required")
            from openai import OpenAI

            sdk = OpenAI(api_key=api_key)
        self._sdk = sdk

    def create(self, **request: Any) -> Any:
        return self._sdk.responses.create(**request)


class ResponsesClientProtocol(Protocol):
    def create(self, **request: Any) -> Any: ...


@dataclass(frozen=True, slots=True)
class AgentResult:
    plan: str
    summary: str
    tests: str
    patch: str
    external_action: dict[str, str] | None = None
    commands: tuple[tuple[str, ...], ...] = ()
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


RESULT_FORMAT: dict[str, Any] = {
    "type": "json_schema",
    "name": "code_engineer_result",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "plan": {"type": "string"},
            "summary": {"type": "string"},
            "tests": {"type": "string"},
            "patch": {"type": "string"},
            "external_action": {
                "type": ["object", "null"],
                "properties": {
                    "effect": {"type": "string", "enum": ["export_patch"]},
                    "target": {"type": "string", "enum": ["owner_download"]},
                },
                "required": ["effect", "target"],
                "additionalProperties": False,
            },
        },
        "required": ["plan", "summary", "tests", "patch", "external_action"],
        "additionalProperties": False,
    },
}


TOOL_SCHEMAS: tuple[dict[str, Any], ...] = (
    {
        "type": "function",
        "name": "list_files",
        "description": "List source paths inside the isolated workspace.",
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": ["string", "null"]},
                "max_entries": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                    "maximum": 2000,
                },
            },
            "required": ["path", "max_entries"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "read_file",
        "description": "Read a bounded UTF-8 source file inside the workspace.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "apply_patch",
        "description": (
            "Persist a unified diff to the clean proposal with apply_patch; "
            "run_command writes are scratch-only."
        ),
        "parameters": {
            "type": "object",
            "properties": {"patch": {"type": "string"}},
            "required": ["patch"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "run_command",
        "description": (
            "Run an allowlisted argv command in no-network scratch-only storage; "
            "writes disappear afterward and persistent edits require apply_patch."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "command": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "maxItems": 128,
                },
                "timeout": {
                    "type": ["integer", "null"],
                    "minimum": 1,
                    "maximum": 1200,
                },
            },
            "required": ["command", "timeout"],
            "additionalProperties": False,
        },
        "strict": True,
    },
)


DEFAULT_INSTRUCTIONS = """You are Lil Tweak's focused Code Engineer. Inspect before editing,
make the smallest scoped change, run relevant local tests, and return one JSON object with
plan, summary, tests, patch, and optional external_action. External actions are proposals
only and may only authorize export_patch to owner_download; you cannot commit, push, deploy,
publish, delete external data, send messages, or spend.
Command writes are scratch-only and disappear after each command or bounded batch;
persistent edits require apply_patch. Never request secrets. Use only the provided
workspace tools."""


def load_reviewed_instructions(
    path: str | os.PathLike[str], *, max_bytes: int = 64 * 1024
) -> str:
    """Load the versioned operator-reviewed prompt without following links."""

    prompt_path = Path(path)
    if max_bytes <= 0:
        raise ValueError("invalid prompt limit")
    try:
        metadata = prompt_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            raise ValueError("invalid reviewed prompt")
        with prompt_path.open("rb") as source:
            payload = source.read(max_bytes + 1)
        instructions = payload.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise ValueError("invalid reviewed prompt") from None
    if not instructions.strip() or len(payload) > max_bytes:
        raise ValueError("invalid reviewed prompt")
    return instructions


def _get(value: Any, name: str, default: Any = None) -> Any:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _normalize_response_output_item(value: Any) -> tuple[dict[str, Any], int]:
    """Return one complete replayable Responses output item and its JSON size."""

    if isinstance(value, Mapping):
        payload: Any = dict(value)
    else:
        model_dump = getattr(value, "model_dump", None)
        to_dict = getattr(value, "to_dict", None)
        try:
            if callable(model_dump):
                payload = model_dump(mode="json")
            elif callable(to_dict):
                payload = to_dict()
            else:
                raise TypeError("response output item is not replayable")
        except (TypeError, ValueError):
            raise AgentProtocolError("response output item is not replayable") from None
    if not isinstance(payload, Mapping):
        raise AgentProtocolError("response output item is not an object")
    try:
        encoded = json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        normalized = json.loads(encoded)
    except (TypeError, ValueError, UnicodeError):
        raise AgentProtocolError("response output item is not replayable") from None
    if not isinstance(normalized, dict):
        raise AgentProtocolError("response output item is not an object")
    return normalized, len(encoded)


def _validate_tool_arguments(name: str, value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("arguments must be an object")
    allowed: dict[str, set[str]] = {
        "list_files": {"path", "max_entries"},
        "read_file": {"path"},
        "apply_patch": {"patch"},
        "run_command": {"command", "timeout"},
    }
    if name not in allowed or not set(value).issubset(allowed[name]):
        raise ValueError("unknown tool or field")
    if name in ("read_file", "apply_patch"):
        field = "path" if name == "read_file" else "patch"
        if not isinstance(value.get(field), str) or not value[field]:
            raise ValueError("missing string field")
    if name == "list_files":
        if "path" in value and value["path"] is not None and not isinstance(value["path"], str):
            raise ValueError("invalid path")
        if "max_entries" in value and value["max_entries"] is not None and not (
            isinstance(value["max_entries"], int) and 1 <= value["max_entries"] <= 2000
        ):
            raise ValueError("invalid max_entries")
    if name == "run_command":
        command = value.get("command")
        if (
            not isinstance(command, list)
            or not 1 <= len(command) <= 128
            or any(not isinstance(part, str) or not part for part in command)
        ):
            raise ValueError("command must be argv")
        if "timeout" in value and value["timeout"] is not None and not (
            isinstance(value["timeout"], int) and 1 <= value["timeout"] <= 1200
        ):
            raise ValueError("invalid timeout")
    return value


def _canonical_json(value: Any, max_bytes: int) -> str:
    output = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    encoded = output.encode("utf-8")
    if len(encoded) <= max_bytes:
        return output
    base = json.dumps(
        {"error": "tool_output_truncated"},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(base.encode("utf-8")) > max_bytes:
        return "0" if max_bytes >= 1 else ""
    best = base
    lower, upper = 0, len(encoded)
    while lower <= upper:
        midpoint = (lower + upper) // 2
        candidate = json.dumps(
            {
                "error": "tool_output_truncated",
                "preview": encoded[:midpoint].decode("utf-8", "ignore"),
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        if len(candidate.encode("utf-8")) <= max_bytes:
            best = candidate
            lower = midpoint + 1
        else:
            upper = midpoint - 1
    return best


def _tool_output_record(
    call_id: Any, output: str
) -> tuple[dict[str, str], int]:
    record = {
        "type": "function_call_output",
        "call_id": str(call_id),
        "output": output,
    }
    size = len(
        json.dumps(
            record,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return record, size


class CodeEngineer:
    def __init__(
        self,
        client: ResponsesClientProtocol,
        tools: Any,
        *,
        model: str,
        max_rounds: int = 40,
        max_tool_output_bytes: int = 2 * 1024 * 1024,
        max_tool_calls: int = 128,
        max_tool_history_bytes: int = 32 * 1024 * 1024,
        instructions: str = DEFAULT_INSTRUCTIONS,
    ) -> None:
        if (
            not model
            or not 1 <= max_rounds <= 40
            or max_tool_output_bytes <= 0
            or not 1 <= max_tool_calls <= 256
            or max_tool_history_bytes <= 0
        ):
            raise ValueError("invalid agent configuration")
        self.client = client
        self.tools = tools
        self.model = model
        self.max_rounds = max_rounds
        self.max_tool_output_bytes = max_tool_output_bytes
        self.max_tool_calls = max_tool_calls
        self.max_tool_history_bytes = max_tool_history_bytes
        self.instructions = instructions

    def run(
        self,
        *,
        mode: JobMode | str,
        prompt: str,
        source_inventory: Sequence[str],
        project_context: Mapping[str, Any] | None = None,
        deadline: float | None = None,
        monotonic: Any = time.monotonic,
    ) -> AgentResult:
        mode_value = JobMode(mode)
        bounded_inventory: list[str] = []
        inventory_bytes = 0
        for path in source_inventory:
            if not isinstance(path, str):
                raise ValueError("source inventory entries must be strings")
            encoded_size = len(path.encode("utf-8")) + 1
            if (
                len(bounded_inventory) >= MAX_INITIAL_INVENTORY_ENTRIES
                or encoded_size > MAX_INITIAL_INVENTORY_UTF8_BYTES - inventory_bytes
            ):
                break
            bounded_inventory.append(path)
            inventory_bytes += encoded_size
        initial = {
            "mode": mode_value.value,
            "request": prompt,
            "source_inventory": bounded_inventory,
            "source_inventory_meta": {
                "providedEntries": len(source_inventory),
                "includedEntries": len(bounded_inventory),
                "includedUtf8Bytes": inventory_bytes,
                "truncated": len(bounded_inventory) < len(source_inventory),
            },
            "project_context": dict(project_context or {}),
            "policy": {
                "network": "disabled",
                "external_actions": "proposal_only",
                "max_tool_rounds": self.max_rounds,
                "max_tool_calls": self.max_tool_calls,
            },
        }
        history: list[Any] = [
            {
                "role": "user",
                "content": json.dumps(initial, ensure_ascii=False, separators=(",", ":")),
            }
        ]
        request: dict[str, Any] = {
            "model": self.model,
            "instructions": self.instructions,
            "input": history,
            "tools": [] if mode_value is JobMode.CHAT else list(TOOL_SCHEMAS),
            "store": False,
            "max_output_tokens": 32_000,
            "text": {"format": RESULT_FORMAT},
        }
        calls = input_tokens = output_tokens = total_tokens = 0
        tool_call_count = 0
        tool_history_bytes = 0
        for round_index in range(self.max_rounds):
            call_request = dict(request)
            if deadline is not None:
                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise AgentDeadlineError("job deadline exceeded")
                call_request["timeout"] = min(remaining, 1200)
            try:
                response = self.client.create(**call_request)
            except Exception as error:
                if (
                    isinstance(error, TimeoutError)
                    or error.__class__.__name__ == "APITimeoutError"
                ):
                    raise AgentDeadlineError("model request timed out") from None
                raise
            calls += 1
            usage = _get(response, "usage", {}) or {}
            input_tokens += _usage_value(usage, "input_tokens")
            output_tokens += _usage_value(usage, "output_tokens")
            total_tokens += _usage_value(usage, "total_tokens")
            response_id = _get(response, "id")
            if not isinstance(response_id, str) or not response_id:
                raise AgentProtocolError("response missing id")
            if _get(response, "status", "completed") != "completed":
                raise AgentProtocolError("response was incomplete")
            raw_response_output = _get(response, "output", []) or []
            try:
                normalized_with_sizes = [
                    _normalize_response_output_item(item)
                    for item in raw_response_output
                ]
            except TypeError:
                raise AgentProtocolError("response output was not iterable") from None
            response_output = [item for item, _ in normalized_with_sizes]
            assistant_history_size = sum(size for _, size in normalized_with_sizes)
            function_calls: list[dict[str, Any]] = []
            final_text: list[str] = []
            for item in response_output:
                item_type = _get(item, "type")
                if item_type == "function_call":
                    if mode_value is JobMode.CHAT:
                        raise AgentProtocolError("chat response requested a tool")
                    function_calls.append(item)
                elif item_type == "message":
                    for content in _get(item, "content", []) or []:
                        if _get(content, "type") in ("output_text", "text"):
                            final_text.append(str(_get(content, "text", "")))
                        elif _get(content, "type") == "refusal":
                            raise AgentProtocolError("response was refused")
            tool_outputs: list[dict[str, str]] = []
            tool_output_history_size = 0
            if function_calls:
                if round_index + 1 >= self.max_rounds:
                    raise AgentLimitError("maximum tool rounds exceeded")
                if tool_call_count + len(function_calls) > self.max_tool_calls:
                    raise AgentToolCapacityError("tool call capacity exceeded")
                # Preflight the complete replayable assistant output and reserve
                # every bounded tool output before executing the first tool. A
                # later item/call can therefore never turn earlier side effects
                # into an over-budget history failure.
                output_plans: list[tuple[dict[str, str], int, int]] = []
                for item in function_calls:
                    minimum_record, minimum_size = _tool_output_record(
                        _get(item, "call_id"), "0"
                    )
                    _, empty_size = _tool_output_record(
                        _get(item, "call_id"), ""
                    )
                    # _canonical_json produces valid JSON text: its control
                    # bytes are already escaped, so embedding it as a JSON
                    # string can at most double quotes and backslashes.
                    maximum_size = empty_size + 2 * self.max_tool_output_bytes
                    output_plans.append(
                        (minimum_record, minimum_size, maximum_size)
                    )
                remaining_history_capacity = (
                    self.max_tool_history_bytes
                    - tool_history_bytes
                    - assistant_history_size
                )
                minimum_output_size = sum(plan[1] for plan in output_plans)
                if minimum_output_size > remaining_history_capacity:
                    raise AgentToolCapacityError("tool history capacity exceeded")
                # Allocate the aggregate serialized budget fairly up front.
                # Each tool can use its share, while the minimum valid records
                # for every later call remain reserved.
                extra_capacity = remaining_history_capacity - minimum_output_size
                output_allocations: list[int] = []
                for index, (_, minimum_size, maximum_size) in enumerate(output_plans):
                    calls_remaining = len(output_plans) - index
                    granted = min(
                        maximum_size - minimum_size,
                        extra_capacity // calls_remaining,
                    )
                    output_allocations.append(minimum_size + granted)
                    extra_capacity -= granted
                tool_call_count += len(function_calls)
                for item, plan, output_allocation in zip(
                    function_calls, output_plans, output_allocations
                ):
                    call_id = _get(item, "call_id")
                    name = _get(item, "name")
                    raw_arguments = _get(item, "arguments", "")
                    try:
                        arguments = json.loads(raw_arguments)
                        validated = _validate_tool_arguments(name, arguments)
                        result = self.tools.execute(name, validated)
                    except PromotionRecoveryRequired:
                        raise
                    except (ValueError, TypeError, json.JSONDecodeError):
                        result = {"error": "invalid_tool_arguments"}
                    except Exception:
                        result = {"error": "tool_execution_failed"}
                    minimum_record, minimum_size, _ = plan
                    _, empty_size = _tool_output_record(call_id, "")
                    inner_output_limit = min(
                        self.max_tool_output_bytes,
                        max(1, (output_allocation - empty_size) // 2),
                    )
                    try:
                        output = _canonical_json(result, inner_output_limit)
                    except (TypeError, ValueError, UnicodeError):
                        output = _canonical_json(
                            {"error": "tool_execution_failed"}, inner_output_limit
                        )
                    output_record, output_size = _tool_output_record(call_id, output)
                    if output_size > output_allocation:
                        output_record, output_size = minimum_record, minimum_size
                    tool_output_history_size += output_size
                    tool_outputs.append(output_record)
            if tool_outputs:
                tool_history_bytes += assistant_history_size + tool_output_history_size
                history.extend(response_output)
                history.extend(tool_outputs)
                request = {
                    "model": self.model,
                    "instructions": self.instructions,
                    "input": history,
                    "tools": [] if mode_value is JobMode.CHAT else list(TOOL_SCHEMAS),
                    "store": False,
                    "max_output_tokens": 32_000,
                    "text": {"format": RESULT_FORMAT},
                }
                continue
            if final_text:
                parsed = self._parse_result("\n".join(final_text))
                return AgentResult(
                    parsed.plan,
                    parsed.summary,
                    parsed.tests,
                    parsed.patch,
                    parsed.external_action,
                    parsed.commands,
                    calls,
                    input_tokens,
                    output_tokens,
                    total_tokens,
                )
            raise AgentProtocolError("response contained no usable output")
        raise AgentLimitError("maximum tool rounds exceeded")

    @staticmethod
    def _parse_result(text: str) -> AgentResult:
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            raise AgentProtocolError("final response was not JSON") from None
        if not isinstance(value, dict):
            raise AgentProtocolError("final response was not an object")
        for field in ("plan", "summary", "tests"):
            if not isinstance(value.get(field), str):
                raise AgentProtocolError("final response missing fields")
        patch = value.get("patch", "")
        if not isinstance(patch, str):
            raise AgentProtocolError("invalid patch")
        external = value.get("external_action")
        if external is not None and (
            not isinstance(external, dict)
            or set(external) != {"effect", "target"}
            or not all(isinstance(item, str) and item for item in external.values())
        ):
            raise AgentProtocolError("invalid external action")
        return AgentResult(value["plan"], value["summary"], value["tests"], patch, external)


def _usage_value(usage: Any, name: str) -> int:
    value = _get(usage, name, 0)
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


_SENSITIVE_WORKSPACE_COMPONENTS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".ssh",
        ".aws",
        ".gnupg",
        ".npmrc",
        ".pypirc",
        "credentials",
        "id_rsa",
        "id_ed25519",
    }
)


def _sensitive_workspace_component(component: str) -> bool:
    value = component.casefold()
    if value in _SENSITIVE_WORKSPACE_COMPONENTS:
        return True
    return value == ".env" or (
        value.startswith(".env.") and value not in {".env.example", ".env.sample"}
    )


def _patch_path(header: str, prefix: str) -> str | None:
    raw = header[4:].split("\t", 1)[0]
    if raw == "/dev/null":
        return None
    if not raw.startswith(prefix):
        raise ValueError("invalid patch declaration")
    relative = raw[2:]
    try:
        portable = validate_portable_path(relative)
    except ArchiveError:
        raise ValueError("invalid patch declaration") from None
    if portable != relative:
        raise ValueError("invalid patch declaration")
    return portable


def _declared_patch_paths(patch: str) -> frozenset[str]:
    """Parse exact unified-diff headers while accounting for hunk line counts."""

    lines = patch.splitlines()
    declared: dict[str, str] = {}
    pairs = 0
    index = 0
    while index < len(lines):
        line = lines[index]
        if line.startswith("+++ "):
            raise ValueError("invalid patch declaration")
        if not line.startswith("--- "):
            index += 1
            continue
        if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
            raise ValueError("invalid patch declaration")
        before = _patch_path(line, "a/")
        after = _patch_path(lines[index + 1], "b/")
        if (before is None) == (after is None):
            if before is None or before != after:
                raise ValueError("invalid patch declaration")
        for path in (before, after):
            if path is None:
                continue
            folded = path.casefold()
            existing = declared.get(folded)
            if existing is not None and existing != path:
                raise ValueError("invalid patch declaration")
            declared[folded] = path
        pairs += 1
        index += 2
        hunks = 0
        while index < len(lines) and not lines[index].startswith("--- "):
            if lines[index].startswith("+++ "):
                raise ValueError("invalid patch declaration")
            match = _HUNK_HEADER.fullmatch(lines[index])
            if match is None:
                index += 1
                continue
            hunks += 1
            old_remaining = int(match.group("old_count") or "1")
            new_remaining = int(match.group("new_count") or "1")
            index += 1
            while old_remaining or new_remaining:
                if index >= len(lines) or not lines[index]:
                    raise ValueError("invalid patch declaration")
                marker = lines[index][0]
                if marker == " ":
                    old_remaining -= 1
                    new_remaining -= 1
                elif marker == "-":
                    old_remaining -= 1
                elif marker == "+":
                    new_remaining -= 1
                else:
                    raise ValueError("invalid patch declaration")
                if old_remaining < 0 or new_remaining < 0:
                    raise ValueError("invalid patch declaration")
                index += 1
                if index < len(lines) and lines[index].startswith("\\ No newline"):
                    index += 1
        if hunks == 0:
            raise ValueError("invalid patch declaration")
    if pairs == 0:
        raise ValueError("invalid patch declaration")
    return frozenset(declared.values())


_PATCH_REMNANT = re.compile(
    r"^\.(?P<workspace>[A-Za-z0-9][A-Za-z0-9_.-]{0,62})-"
    r"(?P<kind>candidate|patch|promotion-tmp)-"
    r"[a-z0-9_]{6,16}(?:\.diff)?$"
)
_PROMOTION_MARKER = re.compile(
    r"^\.(?P<workspace>[A-Za-z0-9][A-Za-z0-9_.-]{0,62})-promotion-v1\.json$"
)
_SAFE_WORKSPACE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROMOTION_MARKER_SCHEMA = "lil-tweak-promotion"
_PROMOTION_MARKER_VERSION = 1
_PROMOTION_MARKER_MAX_BYTES = 4096
_PROMOTION_MARKER_FIELDS = frozenset(
    {
        "schema",
        "version",
        "workspace",
        "candidate",
        "before",
        "after",
        "delta_digest",
        "journal_entry_digest",
    }
)
_PROMOTION_BINDING_FIELDS = frozenset({"dev", "ino", "source_digest"})


def _promotion_marker_name(workspace_name: str) -> str:
    if not _SAFE_WORKSPACE_NAME.fullmatch(workspace_name):
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    return f".{workspace_name}-promotion-v1.json"


def _validate_promotion_marker(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _PROMOTION_MARKER_FIELDS:
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    if (
        value.get("schema") != _PROMOTION_MARKER_SCHEMA
        or type(value.get("version")) is not int
        or value.get("version") != _PROMOTION_MARKER_VERSION
        or not isinstance(value.get("workspace"), str)
        or not _SAFE_WORKSPACE_NAME.fullmatch(value["workspace"])
        or not isinstance(value.get("candidate"), str)
        or not re.fullmatch(
            rf"\.{re.escape(value['workspace'])}-candidate-[a-z0-9_]{{6,16}}",
            value["candidate"],
        )
    ):
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    for field in ("before", "after"):
        binding = value.get(field)
        if not isinstance(binding, dict) or set(binding) != _PROMOTION_BINDING_FIELDS:
            raise PromotionRecoveryRequired("patch_reconciliation_required")
        if any(
            not isinstance(binding.get(name), int)
            or isinstance(binding.get(name), bool)
            or binding[name] < 0
            for name in ("dev", "ino")
        ) or not isinstance(binding.get("source_digest"), str) or not _HEX_DIGEST.fullmatch(
            binding["source_digest"]
        ):
            raise PromotionRecoveryRequired("patch_reconciliation_required")
    if value["before"]["dev"] != value["after"]["dev"] or (
        value["before"]["dev"],
        value["before"]["ino"],
    ) == (value["after"]["dev"], value["after"]["ino"]):
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    for field in ("delta_digest", "journal_entry_digest"):
        if not isinstance(value.get(field), str) or not _HEX_DIGEST.fullmatch(value[field]):
            raise PromotionRecoveryRequired("patch_reconciliation_required")
    return value


def _canonical_promotion_marker(value: Mapping[str, Any]) -> bytes:
    validated = _validate_promotion_marker(dict(value))
    encoded = (
        json.dumps(
            validated,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    if len(encoded) > _PROMOTION_MARKER_MAX_BYTES:
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    return encoded


def _create_secure_marker_temp(parent: Path, workspace_name: str) -> tuple[int, Path]:
    prefix = f".{workspace_name}-promotion-tmp-"
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    for _ in range(16):
        path = parent / f"{prefix}{secrets.token_hex(8)}"
        try:
            return os.open(path, flags, 0o600), path
        except FileExistsError:
            continue
    raise OSError("marker temporary name capacity exhausted")


def _journal_entry_digest(entry: Mapping[str, Any]) -> str:
    payload = json.dumps(
        dict(entry), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(b"lil-tweak-edit-entry-v1\0" + payload).hexdigest()


def _root_binding(metadata: os.stat_result, source_digest: str) -> dict[str, Any]:
    return {
        "dev": metadata.st_dev,
        "ino": metadata.st_ino,
        "source_digest": source_digest,
    }


def _read_promotion_marker(parent: Path, marker: Path) -> dict[str, Any]:
    try:
        parent_metadata = parent.lstat()
        metadata = marker.lstat()
    except OSError:
        raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != parent_metadata.st_uid
        or metadata.st_gid != parent_metadata.st_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > _PROMOTION_MARKER_MAX_BYTES
    ):
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(marker, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                opened.st_dev,
                opened.st_ino,
                opened.st_size,
                opened.st_nlink,
            ) != (metadata.st_dev, metadata.st_ino, metadata.st_size, 1):
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            payload_bytes = bytearray()
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    raise PromotionRecoveryRequired("patch_reconciliation_required")
                payload_bytes.extend(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            final = os.fstat(descriptor)
            if (
                final.st_dev,
                final.st_ino,
                final.st_size,
                final.st_nlink,
            ) != (metadata.st_dev, metadata.st_ino, metadata.st_size, 1):
                raise PromotionRecoveryRequired("patch_reconciliation_required")
        finally:
            os.close(descriptor)
        payload = bytes(payload_bytes)
        value = json.loads(payload)
    except PromotionRecoveryRequired:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    validated = _validate_promotion_marker(value)
    if _canonical_promotion_marker(validated) != payload:
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    if marker.name != _promotion_marker_name(validated["workspace"]):
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    return validated


@contextmanager
def _work_root_lock(parent: Path):
    """Hold the one bounded promotion lock for this trusted work root."""

    root = parent.absolute()
    try:
        root_metadata = root.lstat()
    except OSError:
        raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    flags = os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW
    lock_path = root / ".promotion.lock"
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError:
        raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        metadata = os.fstat(descriptor)
        try:
            current_root = root.lstat()
            current_lock = lock_path.lstat()
        except OSError:
            raise PromotionRecoveryRequired("patch_reconciliation_required") from None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != root_metadata.st_uid
            or metadata.st_gid != root_metadata.st_gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or (current_root.st_dev, current_root.st_ino)
            != (root_metadata.st_dev, root_metadata.st_ino)
            or (current_lock.st_dev, current_lock.st_ino)
            != (metadata.st_dev, metadata.st_ino)
        ):
            raise PromotionRecoveryRequired("patch_reconciliation_required")
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _PromotionLayout:
    marker: Path
    candidate: Path
    value: dict[str, Any]
    state: str


def _classify_promotion_marker(parent: Path, marker: Path) -> _PromotionLayout:
    value = _read_promotion_marker(parent, marker)
    workspace = parent / value["workspace"]
    candidate = parent / value["candidate"]
    try:
        parent_metadata = parent.lstat()
        workspace_metadata = workspace.lstat()
    except OSError:
        raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    if (
        not stat.S_ISDIR(workspace_metadata.st_mode)
        or stat.S_ISLNK(workspace_metadata.st_mode)
        or workspace_metadata.st_uid != parent_metadata.st_uid
        or workspace_metadata.st_gid != parent_metadata.st_gid
        or workspace_metadata.st_dev != parent_metadata.st_dev
    ):
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    try:
        snapshot = capture_workspace(workspace)
    except WorkspaceEvidenceError:
        raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    identity = (workspace_metadata.st_dev, workspace_metadata.st_ino)
    before = value["before"]
    after = value["after"]
    if identity == (before["dev"], before["ino"]) and snapshot.source_digest == before[
        "source_digest"
    ]:
        state = "prepared"
        expected_candidate = after
    elif identity == (after["dev"], after["ino"]) and snapshot.source_digest == after[
        "source_digest"
    ]:
        state = "committed"
        expected_candidate = before
    else:
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    try:
        candidate_metadata = candidate.lstat()
    except FileNotFoundError:
        candidate_metadata = None
    except OSError:
        raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    if candidate_metadata is not None and (
        not stat.S_ISDIR(candidate_metadata.st_mode)
        or stat.S_ISLNK(candidate_metadata.st_mode)
        or candidate_metadata.st_uid != parent_metadata.st_uid
        or candidate_metadata.st_gid != parent_metadata.st_gid
        or candidate_metadata.st_dev != parent_metadata.st_dev
        or (candidate_metadata.st_dev, candidate_metadata.st_ino)
        != (expected_candidate["dev"], expected_candidate["ino"])
    ):
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    return _PromotionLayout(marker, candidate, value, state)


def _fsync_directory(path: Path, fsync: Any = os.fsync) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        fsync(descriptor)
    finally:
        os.close(descriptor)


def _reconcile_promotion_markers_locked(
    parent: Path,
    *,
    fsync: Any = os.fsync,
    tree_remove: Any = shutil.rmtree,
) -> tuple[_PromotionLayout, ...]:
    try:
        items = list(parent.iterdir())
    except OSError:
        raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    marker_paths = sorted(item for item in items if _PROMOTION_MARKER.fullmatch(item.name))
    # Classify every published marker before mutating any path. This makes an
    # invalid marker a global fail-closed admission barrier independent of
    # directory iteration order.
    layouts = tuple(_classify_promotion_marker(parent, marker) for marker in marker_paths)
    workspaces: set[str] = set()
    candidates: set[str] = set()
    for layout in layouts:
        workspace_folded = layout.value["workspace"].casefold()
        candidate_folded = layout.value["candidate"].casefold()
        if workspace_folded in workspaces or candidate_folded in candidates:
            raise PromotionRecoveryRequired("patch_reconciliation_required")
        workspaces.add(workspace_folded)
        candidates.add(candidate_folded)
    for layout in layouts:
        try:
            layout.candidate.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            raise PromotionRecoveryRequired("patch_reconciliation_required") from None
        else:
            try:
                tree_remove(layout.candidate)
            except OSError:
                raise PromotionRecoveryRequired("patch_reconciliation_required") from None
        try:
            _fsync_directory(parent, fsync)
            layout.marker.unlink()
            _fsync_directory(parent, fsync)
        except OSError:
            raise PromotionRecoveryRequired("patch_reconciliation_required") from None
    return layouts


def reconcile_promotion_markers(
    parent: str | os.PathLike[str],
    *,
    fsync: Any = os.fsync,
    tree_remove: Any = shutil.rmtree,
) -> tuple[str, ...]:
    """Reconcile only classifiable prepared/committed promotion layouts."""

    root = Path(parent).absolute()
    with _work_root_lock(root):
        layouts = _reconcile_promotion_markers_locked(
            root, fsync=fsync, tree_remove=tree_remove
        )
    return tuple(layout.state for layout in layouts)


def _cleanup_patch_remnants_locked(
    root: Path, *, workspace_name: str | None = None, tree_remove: Any = shutil.rmtree
) -> None:
    try:
        metadata = root.lstat()
        items = list(root.iterdir())
    except OSError:
        raise PromotionRecoveryRequired("patch_cleanup_failed") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise PromotionRecoveryRequired("patch_cleanup_failed")
    markers = [item for item in items if _PROMOTION_MARKER.fullmatch(item.name)]
    if markers:
        for marker in markers:
            _read_promotion_marker(root, marker)
        raise PromotionRecoveryRequired("patch_reconciliation_required")
    selected: list[tuple[Path, str]] = []
    for item in items:
        match = _PATCH_REMNANT.fullmatch(item.name)
        if match is None or (
            workspace_name is not None and match.group("workspace") != workspace_name
        ):
            continue
        try:
            item_metadata = item.lstat()
        except OSError:
            raise PromotionRecoveryRequired("patch_cleanup_failed") from None
        kind = match.group("kind")
        valid_directory = (
            kind == "candidate"
            and stat.S_ISDIR(item_metadata.st_mode)
            and not stat.S_ISLNK(item_metadata.st_mode)
            and item_metadata.st_dev == metadata.st_dev
        )
        valid_file = (
            kind in ("patch", "promotion-tmp")
            and stat.S_ISREG(item_metadata.st_mode)
            and not stat.S_ISLNK(item_metadata.st_mode)
            and item_metadata.st_nlink == 1
        )
        if (
            item_metadata.st_uid != metadata.st_uid
            or item_metadata.st_gid != metadata.st_gid
            or item_metadata.st_mode & 0o022
            or not (valid_directory or valid_file)
        ):
            raise PromotionRecoveryRequired("patch_cleanup_failed")
        selected.append((item, kind))
    try:
        for item, kind in selected:
            if kind == "candidate":
                tree_remove(item)
            else:
                item.unlink()
    except OSError:
        raise PromotionRecoveryRequired("patch_cleanup_failed") from None


def cleanup_patch_remnants(
    parent: str | os.PathLike[str],
    *,
    workspace_name: str | None = None,
    tree_remove: Any = shutil.rmtree,
) -> None:
    """Remove only validated host-owned ordinary remnants under the root lock."""

    root = Path(parent).absolute()
    with _work_root_lock(root):
        _cleanup_patch_remnants_locked(
            root, workspace_name=workspace_name, tree_remove=tree_remove
        )


class WorkspaceTools:
    """Narrow file/command tools; all path resolution is rooted and bounded."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        sandbox: PodmanSandbox | None,
        *,
        max_read_bytes: int = 64 * 1024,
        max_patch_bytes: int = MAX_EVIDENCE_BYTES,
        max_observations: int = 128,
        max_observed_output_bytes: int = 4 * 1024 * 1024,
        directory_exchange: Any = atomic_exchange_directories,
        marker_publish: Any = atomic_publish_noreplace,
        fsync: Any = os.fsync,
        tree_remove: Any = shutil.rmtree,
        pre_exchange_hook: Any = None,
    ) -> None:
        self.root = Path(root).absolute()
        root_metadata = self.root.lstat()
        if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
            raise ValueError("invalid workspace root")
        self.sandbox = sandbox
        self.max_read_bytes = max_read_bytes
        self.max_patch_bytes = max_patch_bytes
        if max_observations < 1 or max_observed_output_bytes < 0:
            raise ValueError("invalid observation budget")
        self.max_observations = max_observations
        self.max_observed_output_bytes = max_observed_output_bytes
        self._directory_exchange = directory_exchange
        self._marker_publish = marker_publish
        self._fsync = fsync
        self._tree_remove = tree_remove
        self._pre_exchange_hook = pre_exchange_hook
        self._command_observations: list[dict[str, Any]] = []
        self._observed_output_bytes = 0
        self._observations_closed = False
        self._observation_terminal_recorded = False
        self._edit_journal: list[dict[str, Any]] = []
        self._journal_closed = False
        self._promotion_cleanup_failed = False

    @property
    def command_observations(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {
                **observation,
                "command": list(observation["command"]),
            }
            for observation in self._command_observations
        )

    @property
    def edit_journal(self) -> tuple[dict[str, Any], ...]:
        return tuple(
            {**entry, "actual_changed_paths": list(entry["actual_changed_paths"])}
            for entry in self._edit_journal
        )

    @contextmanager
    def _patch_lock(self):
        with _work_root_lock(self.root.parent):
            yield

    def _path(self, raw: str, *, must_exist: bool = True) -> Path:
        if not raw or "\x00" in raw or "\\" in raw or raw.startswith("/"):
            raise ValueError("unsafe path")
        relative = PurePosixPath(raw)
        if any(part in ("", ".", "..") for part in relative.parts):
            raise ValueError("unsafe path")
        if any(_sensitive_workspace_component(part) for part in relative.parts):
            raise ValueError("unsafe path")
        path = self.root.joinpath(*relative.parts).resolve(strict=must_exist)
        if path != self.root and self.root not in path.parents:
            raise ValueError("unsafe path")
        return path

    def _recovery_marker(self) -> Path:
        return self.root.parent / _promotion_marker_name(self.root.name)

    def _fsync_workspace_parent(self) -> None:
        descriptor = os.open(
            self.root.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            self._fsync(descriptor)
        finally:
            os.close(descriptor)

    def _create_recovery_marker(self, value: Mapping[str, Any]) -> None:
        payload = _canonical_promotion_marker(value)
        descriptor, temporary = _create_secure_marker_temp(
            self.root.parent, self.root.name
        )
        try:
            try:
                offset = 0
                while offset < len(payload):
                    written = os.write(descriptor, payload[offset:])
                    if written <= 0:
                        raise OSError("marker write failed")
                    offset += written
                self._fsync(descriptor)
            finally:
                os.close(descriptor)
            self._marker_publish(temporary, self._recovery_marker())
            self._fsync_workspace_parent()
        finally:
            temporary.unlink(missing_ok=True)

    def _remove_recovery_marker(self) -> None:
        self._recovery_marker().unlink()
        self._fsync_workspace_parent()

    def _expected_proposal_digest(self, baseline: Any) -> str:
        try:
            build_edit_journal_evidence(self._edit_journal)
        except WorkspaceEvidenceError:
            raise PromotionRecoveryRequired("patch_reconciliation_required") from None
        expected = baseline.source_digest
        if not isinstance(expected, str) or not _HEX_DIGEST.fullmatch(expected):
            raise PromotionRecoveryRequired("patch_reconciliation_required")
        for ordinal, entry in enumerate(self._edit_journal):
            if entry["ordinal"] != ordinal or entry["before_source_digest"] != expected:
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            if entry["result"] == "promoted":
                if entry["rejection_code"] is not None:
                    raise PromotionRecoveryRequired("patch_reconciliation_required")
                expected = entry["after_source_digest"]
            elif entry["result"] == "rejected":
                if entry["rejection_code"] is None:
                    raise PromotionRecoveryRequired("patch_reconciliation_required")
            else:
                raise PromotionRecoveryRequired("patch_reconciliation_required")
        return expected

    def _finish_committed_marker_locked(self, expected: str) -> None:
        marker = self._recovery_marker()
        layout = _classify_promotion_marker(self.root.parent, marker)
        if (
            layout.state != "committed"
            or not self._edit_journal
            or self._edit_journal[-1]["result"] != "promoted"
            or _journal_entry_digest(self._edit_journal[-1])
            != layout.value["journal_entry_digest"]
            or layout.value["after"]["source_digest"] != expected
        ):
            raise PromotionRecoveryRequired("patch_reconciliation_required")
        try:
            layout.candidate.lstat()
        except FileNotFoundError:
            pass
        except OSError:
            raise PromotionRecoveryRequired("patch_reconciliation_required") from None
        else:
            try:
                self._tree_remove(layout.candidate)
            except OSError:
                self._promotion_cleanup_failed = True
                raise PromotionRecoveryRequired(
                    "patch_reconciliation_required"
                ) from None
        try:
            self._fsync_workspace_parent()
            self._remove_recovery_marker()
        except OSError:
            self._promotion_cleanup_failed = True
            raise PromotionRecoveryRequired("patch_reconciliation_required") from None
        self._promotion_cleanup_failed = False

    def capture_final_snapshot(
        self, baseline: Any, staging_root: str | os.PathLike[str]
    ) -> Any:
        """Validate and freeze the final proposal while holding the patch lock."""

        with self._patch_lock():
            if bool(getattr(self.sandbox, "lifecycle_failed", False)):
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            expected = self._expected_proposal_digest(baseline)
            try:
                markers = sorted(
                    item
                    for item in self.root.parent.iterdir()
                    if _PROMOTION_MARKER.fullmatch(item.name)
                )
            except OSError:
                raise PromotionRecoveryRequired("patch_reconciliation_required") from None
            own_marker = self._recovery_marker()
            if any(marker != own_marker for marker in markers) or len(markers) > 1:
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            if markers:
                self._finish_committed_marker_locked(expected)
            elif self._promotion_cleanup_failed:
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            _cleanup_patch_remnants_locked(
                self.root.parent,
                tree_remove=self._tree_remove,
            )
            try:
                remnants = [
                    item
                    for item in self.root.parent.iterdir()
                    if _PATCH_REMNANT.fullmatch(item.name)
                    or _PROMOTION_MARKER.fullmatch(item.name)
                ]
            except OSError:
                raise PromotionRecoveryRequired("patch_reconciliation_required") from None
            if remnants:
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            try:
                current = capture_workspace(self.root)
            except WorkspaceEvidenceError:
                raise PromotionRecoveryRequired("patch_reconciliation_required") from None
            if current.source_digest != expected:
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            try:
                final = capture_workspace(self.root, staging_root=staging_root)
            except WorkspaceEvidenceError:
                raise PromotionRecoveryRequired("patch_reconciliation_required") from None
            if final.source_digest != expected:
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            return final

    def recovery_context_exists(self) -> bool:
        if self._promotion_cleanup_failed or bool(
            getattr(self.sandbox, "lifecycle_failed", False)
        ):
            return True
        try:
            return self._recovery_marker().lstat() is not None
        except FileNotFoundError:
            return False
        except OSError:
            return True

    def _observation_capacity_result(
        self, operation: str, command: list[str]
    ) -> Any:
        from .sandbox import CommandResult

        result = CommandResult(None, "", "observation_capacity")
        if not self._observation_terminal_recorded:
            self._observe(operation, command, result)
            self._observation_terminal_recorded = True
        return result

    def execute(self, name: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        if name == "list_files":
            raw_base = str(arguments.get("path") or ".")
            if raw_base != ".":
                self._path(raw_base, must_exist=False)
            limit = int(arguments.get("max_entries", 1000))
            if self.sandbox is not None and hasattr(self.sandbox, "list_files"):
                return self.sandbox.list_files(raw_base, max_entries=limit)
            base = self._path(raw_base) if raw_base != "." else self.root
            if not base.is_dir():
                raise ValueError("not a directory")
            paths: list[str] = []
            for path in sorted(base.rglob("*")):
                relative = path.relative_to(self.root)
                if any(
                    _sensitive_workspace_component(part) for part in relative.parts
                ):
                    continue
                if path.is_file() and not path.is_symlink():
                    paths.append(relative.as_posix())
                    if len(paths) >= limit:
                        break
            return {"paths": paths, "truncated": len(paths) == limit}
        if name == "read_file":
            managed = self.sandbox is not None and hasattr(self.sandbox, "read_file")
            path = self._path(str(arguments["path"]), must_exist=not managed)
            if managed:
                return self.sandbox.read_file(
                    str(arguments["path"]), max_bytes=self.max_read_bytes
                )
            if not path.is_file() or path.is_symlink():
                raise ValueError("not a regular file")
            with path.open("rb") as source:
                data = source.read(self.max_read_bytes + 1)
            return {
                "content": data[: self.max_read_bytes].decode("utf-8", "replace"),
                "truncated": len(data) > self.max_read_bytes,
            }
        if name == "run_command":
            if self.sandbox is None:
                raise ValueError("sandbox unavailable")
            if not self._admit_observation():
                result = self._observation_capacity_result(
                    "run_command", list(arguments["command"])
                )
                return asdict(result)
            result = self.sandbox.run_ephemeral(
                arguments["command"], timeout=arguments.get("timeout")
            )
            self._observe("run_command", list(arguments["command"]), result)
            return asdict(result)
        if name == "apply_patch":
            return self._apply_patch(str(arguments["patch"]))
        raise ValueError("unknown tool")

    def _apply_patch(self, patch: str) -> dict[str, Any]:
        encoded = patch.encode("utf-8")
        with self._patch_lock():
            if self._promotion_cleanup_failed:
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            if bool(getattr(self.sandbox, "lifecycle_failed", False)):
                raise PromotionRecoveryRequired("patch_reconciliation_required")
            _cleanup_patch_remnants_locked(
                self.root.parent,
                workspace_name=self.root.name,
                tree_remove=self._tree_remove,
            )
            before_root = self.root.lstat()
            before = capture_workspace(self.root)
            if self._journal_closed:
                return {
                    "exit_code": None,
                    "stdout": "",
                    "stderr": "edit_journal_capacity",
                    "timed_out": False,
                    "truncated": False,
                    "promoted": False,
                    "rejection_code": "edit_journal_capacity",
                }
            if not encoded or len(encoded) > self.max_patch_bytes:
                return self._reject_patch(before, "invalid_patch")
            try:
                declared = _declared_patch_paths(patch)
            except ValueError:
                return self._reject_patch(before, "invalid_patch_declaration")
            if self.sandbox is None:
                return self._reject_patch(before, "sandbox_unavailable")
            if not self._admit_observation():
                capacity = self._observation_capacity_result(
                    "apply_patch", list(_PATCH_COMMAND)
                )
                return self._reject_patch(
                    before, "observation_capacity", result=capacity
                )

            if not self._journal_can_fit_declared(before, declared):
                return self._close_journal(before)

            patch_descriptor: int | None = None
            try:
                candidate = Path(
                    tempfile.mkdtemp(
                        prefix=f".{self.root.name}-candidate-", dir=self.root.parent
                    )
                )
                patch_descriptor, raw_patch_path = tempfile.mkstemp(
                    prefix=f".{self.root.name}-patch-",
                    suffix=".diff",
                    dir=self.root.parent,
                )
            except OSError:
                # The first allocation may have succeeded before the second
                # failed. No marker can exist yet, so the strict ordinary
                # sweep safely closes this partial staging phase.
                _cleanup_patch_remnants_locked(
                    self.root.parent,
                    workspace_name=self.root.name,
                    tree_remove=self._tree_remove,
                )
                return self._reject_patch(before, "patch_staging_failed")
            patch_path = Path(raw_patch_path)
            candidate_safe_to_remove = True
            try:
                try:
                    output = os.fdopen(patch_descriptor, "wb")
                except OSError:
                    return self._reject_patch(before, "patch_staging_failed")
                patch_descriptor = None
                try:
                    with output:
                        output.write(encoded)
                        output.flush()
                        os.fsync(output.fileno())
                except OSError:
                    return self._reject_patch(before, "patch_staging_failed")
                try:
                    candidate_identity = candidate.lstat()
                except OSError:
                    return self._reject_patch(before, "patch_staging_failed")
                result = self.sandbox.stage_patch_candidate(patch_path, candidate)
                self._observe("apply_patch", list(_PATCH_COMMAND), result)
                if bool(getattr(self.sandbox, "lifecycle_failed", False)):
                    self._reject_patch(before, "sandbox_lifecycle_failed", result=result)
                    raise PromotionRecoveryRequired("patch_reconciliation_required")
                try:
                    patch_path.unlink()
                except OSError:
                    return self._reject_patch(
                        before, "patch_cleanup_failed", result=result
                    )
                if result.exit_code != 0 or result.timed_out or result.truncated:
                    code = (
                        "patch_timeout"
                        if result.timed_out
                        else "patch_output_limit"
                        if result.truncated
                        else "patch_exit_nonzero"
                    )
                    return self._reject_patch(before, code, result=result)
                try:
                    staged_identity = candidate.lstat()
                except OSError:
                    return self._reject_patch(before, "candidate_invalid", result=result)
                if (
                    staged_identity.st_dev,
                    staged_identity.st_ino,
                ) != (candidate_identity.st_dev, candidate_identity.st_ino):
                    return self._reject_patch(before, "candidate_root_changed", result=result)
                try:
                    after = capture_workspace(candidate)
                except WorkspaceEvidenceError:
                    return self._reject_patch(before, "candidate_invalid", result=result)
                try:
                    actual = workspace_changed_paths(before, after)
                    delta_digest = workspace_delta_digest(before, after, actual)
                except WorkspaceEvidenceError:
                    return self._reject_patch(before, "candidate_invalid", result=result)
                if not set(actual).issubset(declared):
                    return self._reject_patch(
                        before,
                        "undeclared_patch_delta",
                        result=result,
                        candidate=after,
                        actual=actual,
                        delta_digest=delta_digest,
                    )
                try:
                    current = capture_workspace(self.root)
                    current_root = self.root.lstat()
                except (OSError, WorkspaceEvidenceError):
                    return self._reject_patch(before, "proposal_changed", result=result)
                if current.source_digest != before.source_digest or (
                    current_root.st_dev,
                    current_root.st_ino,
                ) != (before_root.st_dev, before_root.st_ino):
                    return self._reject_patch(
                        before,
                        "proposal_changed",
                        result=result,
                        candidate=after,
                        actual=actual,
                        delta_digest=delta_digest,
                    )
                try:
                    second_after = capture_workspace(candidate)
                    second_candidate_root = candidate.lstat()
                except (OSError, WorkspaceEvidenceError):
                    return self._reject_patch(before, "candidate_changed", result=result)
                if second_after.source_digest != after.source_digest or (
                    second_candidate_root.st_dev,
                    second_candidate_root.st_ino,
                ) != (candidate_identity.st_dev, candidate_identity.st_ino):
                    return self._reject_patch(before, "candidate_changed", result=result)
                if self._pre_exchange_hook is not None:
                    self._pre_exchange_hook(candidate)
                # Re-bind immediately before exchange. The runner is already
                # destroyed and has no host path; a malicious same-UID host
                # process is outside this boundary because Linux renameat2 has
                # no directory-fd/AT_EMPTY_PATH whole-subtree freeze primitive.
                try:
                    bound_before = capture_workspace(self.root)
                    bound_before_root = self.root.lstat()
                except (OSError, WorkspaceEvidenceError):
                    return self._reject_patch(before, "proposal_changed", result=result)
                if bound_before.source_digest != before.source_digest or (
                    bound_before_root.st_dev,
                    bound_before_root.st_ino,
                ) != (before_root.st_dev, before_root.st_ino):
                    return self._reject_patch(
                        before,
                        "proposal_changed",
                        result=result,
                        candidate=after,
                        actual=actual,
                        delta_digest=delta_digest,
                    )
                try:
                    bound_after = capture_workspace(candidate)
                    bound_candidate_root = candidate.lstat()
                except (OSError, WorkspaceEvidenceError):
                    return self._reject_patch(before, "candidate_changed", result=result)
                if bound_after.source_digest != after.source_digest or (
                    bound_candidate_root.st_dev,
                    bound_candidate_root.st_ino,
                ) != (candidate_identity.st_dev, candidate_identity.st_ino):
                    return self._reject_patch(before, "candidate_changed", result=result)
                promoted_entry = self._journal_entry(
                    before,
                    after,
                    actual,
                    delta_digest,
                    "promoted",
                    result,
                    None,
                )
                self._check_journal_capacity(promoted_entry)
                marker_value = {
                    "schema": _PROMOTION_MARKER_SCHEMA,
                    "version": _PROMOTION_MARKER_VERSION,
                    "workspace": self.root.name,
                    "candidate": candidate.name,
                    "before": _root_binding(before_root, before.source_digest),
                    "after": _root_binding(candidate_identity, after.source_digest),
                    "delta_digest": delta_digest,
                    "journal_entry_digest": _journal_entry_digest(promoted_entry),
                }
                # Publication may have reached the fixed marker before a parent
                # fsync reports failure. Treat the candidate as marker-bound
                # until absence of the fixed marker is positively observed.
                candidate_safe_to_remove = False
                try:
                    self._create_recovery_marker(marker_value)
                except (OSError, PromotionRecoveryRequired):
                    try:
                        self._recovery_marker().lstat()
                    except FileNotFoundError:
                        _cleanup_patch_remnants_locked(
                            self.root.parent,
                            workspace_name=self.root.name,
                            tree_remove=self._tree_remove,
                        )
                        candidate_safe_to_remove = True
                        return self._reject_patch(
                            before,
                            "recovery_marker_failed",
                            result=result,
                            candidate=after,
                            actual=actual,
                            delta_digest=delta_digest,
                        )
                    except OSError:
                        raise PromotionRecoveryRequired(
                            "patch_reconciliation_required"
                        ) from None
                    raise PromotionRecoveryRequired(
                        "patch_reconciliation_required"
                    ) from None
                try:
                    self._directory_exchange(self.root, candidate)
                except Exception:
                    # A testable exchange boundary can raise either before or
                    # after the syscall. Only the exact original layout is a
                    # safe rejection; a committed or unclassifiable layout is
                    # durable recovery context and is never exchanged again.
                    layout = _classify_promotion_marker(
                        self.root.parent, self._recovery_marker()
                    )
                    if layout.state != "prepared":
                        raise PromotionRecoveryRequired(
                            "patch_reconciliation_required"
                        ) from None
                    try:
                        self._tree_remove(candidate)
                        self._fsync_workspace_parent()
                        self._remove_recovery_marker()
                    except OSError:
                        raise PromotionRecoveryRequired(
                            "patch_reconciliation_required"
                        ) from None
                    candidate_safe_to_remove = True
                    return self._reject_patch(
                        before,
                        "atomic_exchange_failed",
                        result=result,
                        candidate=after,
                        actual=actual,
                        delta_digest=delta_digest,
                    )
                try:
                    self._fsync_workspace_parent()
                    promoted_root = self.root.lstat()
                    old_root = candidate.lstat()
                    if (
                        promoted_root.st_dev,
                        promoted_root.st_ino,
                    ) != (candidate_identity.st_dev, candidate_identity.st_ino) or (
                        old_root.st_dev,
                        old_root.st_ino,
                    ) != (before_root.st_dev, before_root.st_ino):
                        raise PromotionRecoveryRequired(
                            "patch_reconciliation_required"
                        )
                    verified = capture_workspace(self.root)
                    if verified.source_digest != after.source_digest:
                        raise PromotionRecoveryRequired(
                            "patch_reconciliation_required"
                        )
                    verified_old = capture_workspace(candidate)
                    if verified_old.source_digest != before.source_digest:
                        raise PromotionRecoveryRequired(
                            "patch_reconciliation_required"
                        )
                except PromotionRecoveryRequired:
                    raise
                except (OSError, WorkspaceEvidenceError):
                    raise PromotionRecoveryRequired(
                        "patch_reconciliation_required"
                    ) from None
                self._edit_journal.append(promoted_entry)
                try:
                    self._tree_remove(candidate)
                    self._fsync_workspace_parent()
                except OSError:
                    self._promotion_cleanup_failed = True
                    raise PromotionRecoveryRequired(
                        "patch_reconciliation_required"
                    ) from None
                try:
                    self._remove_recovery_marker()
                except OSError:
                    self._promotion_cleanup_failed = True
                    raise PromotionRecoveryRequired(
                        "patch_reconciliation_required"
                    ) from None
                return {
                    **asdict(result),
                    "promoted": True,
                    "rejection_code": None,
                    "cleanup_code": None,
                }
            finally:
                cleanup_failed = False
                if patch_descriptor is not None:
                    try:
                        os.close(patch_descriptor)
                    except OSError:
                        cleanup_failed = True
                try:
                    patch_path.unlink(missing_ok=True)
                except OSError:
                    cleanup_failed = True
                if candidate_safe_to_remove and candidate.exists():
                    try:
                        self._tree_remove(candidate)
                    except OSError:
                        cleanup_failed = True
                if cleanup_failed:
                    self._promotion_cleanup_failed = True
                    raise PromotionRecoveryRequired("patch_cleanup_failed")

    def _journal_entry(
        self,
        before: Any,
        after: Any,
        actual: tuple[str, ...],
        delta_digest: str,
        outcome: str,
        result: Any,
        rejection_code: str | None,
    ) -> dict[str, Any]:
        return {
            "ordinal": len(self._edit_journal),
            "before_source_digest": before.source_digest,
            "after_source_digest": after.source_digest,
            "actual_changed_paths": list(actual),
            "delta_digest": delta_digest,
            "result": outcome,
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "truncated": result.truncated,
            "rejection_code": rejection_code,
        }

    def _check_journal_capacity(self, entry: Mapping[str, Any]) -> None:
        if self._journal_closed:
            raise WorkspaceEvidenceError("edit_journal_capacity")
        sentinel = {
            "ordinal": len(self._edit_journal) + 1,
            "before_source_digest": "0" * 64,
            "after_source_digest": "0" * 64,
            "actual_changed_paths": [],
            "delta_digest": "0" * 64,
            "result": "rejected",
            "exit_code": None,
            "timed_out": False,
            "truncated": False,
            "rejection_code": "edit_journal_capacity",
        }
        build_edit_journal_evidence([*self._edit_journal, entry, sentinel])

    def _journal_can_fit_declared(self, before: Any, declared: frozenset[str]) -> bool:
        synthetic = {
            "ordinal": len(self._edit_journal),
            "before_source_digest": before.source_digest,
            "after_source_digest": "0" * 64,
            "actual_changed_paths": sorted(declared),
            "delta_digest": "0" * 64,
            "result": "rejected",
            "exit_code": -2_147_483_648,
            "timed_out": True,
            "truncated": True,
            "rejection_code": "x" * 64,
        }
        try:
            self._check_journal_capacity(synthetic)
        except WorkspaceEvidenceError:
            return False
        return True

    def _close_journal(self, before: Any) -> dict[str, Any]:
        from .sandbox import CommandResult

        result = CommandResult(None, "", "edit_journal_capacity")
        entry = self._journal_entry(
            before,
            before,
            (),
            workspace_delta_digest(before, before, ()),
            "rejected",
            result,
            "edit_journal_capacity",
        )
        build_edit_journal_evidence([*self._edit_journal, entry])
        self._edit_journal.append(entry)
        self._journal_closed = True
        return {**asdict(result), "promoted": False, "rejection_code": "edit_journal_capacity"}

    def _reject_patch(
        self,
        before: Any,
        code: str,
        *,
        result: Any = None,
        candidate: Any = None,
        actual: tuple[str, ...] = (),
        delta_digest: str | None = None,
    ) -> dict[str, Any]:
        if result is None:
            from .sandbox import CommandResult

            result = CommandResult(None, "", "")
        after = candidate or before
        delta = delta_digest or workspace_delta_digest(before, after, actual)
        entry = self._journal_entry(
            before, after, actual, delta, "rejected", result, code
        )
        try:
            self._check_journal_capacity(entry)
        except WorkspaceEvidenceError:
            return self._close_journal(before)
        self._edit_journal.append(entry)
        return {**asdict(result), "promoted": False, "rejection_code": code}

    def _observe(self, operation: str, command: list[str], result: Any) -> None:
        if len(self._command_observations) >= self.max_observations:
            return
        remaining = max(0, self.max_observed_output_bytes - self._observed_output_bytes)
        stdout_encoded = result.stdout.encode("utf-8")
        stdout = stdout_encoded[:remaining].decode("utf-8", "ignore")
        stdout_size = len(stdout.encode("utf-8"))
        remaining -= stdout_size
        stderr_encoded = result.stderr.encode("utf-8")
        stderr = stderr_encoded[:remaining].decode("utf-8", "ignore")
        stderr_size = len(stderr.encode("utf-8"))
        retained = stdout_size + stderr_size
        clipped = stdout != result.stdout or stderr != result.stderr
        self._observed_output_bytes += retained
        self._command_observations.append(
            {
                "operation": operation,
                "command": command,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "truncated": result.truncated or clipped,
                "stdout": stdout,
                "stderr": stderr,
            }
        )

    def _admit_observation(self) -> bool:
        if self._observations_closed:
            return False
        per_execution = int(
            getattr(getattr(self.sandbox, "limits", None), "max_output_bytes", 2 * 1024 * 1024)
        )
        if (
            len(self._command_observations) + 1 >= self.max_observations
            or self._observed_output_bytes + per_execution > self.max_observed_output_bytes
        ):
            self._observations_closed = True
            return False
        return True
