"""Bounded, independently graded adapter calls; no model, shell or runner implementation."""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import math
import secrets
import time
from typing import Awaitable, Callable

from .package import ForgeError, Package, canonical, identifier, parse_json, sha, text

ISOLATION_CONTRACT = "fresh-session/package-only/no-authority"


@dataclass(frozen=True, slots=True)
class Case:
    case_id: str
    task: str
    expected: str
    kind: str


@dataclass(frozen=True, slots=True)
class Request:
    nonce: str
    package_digest: str
    task: str
    tools: tuple[str, ...]
    files: tuple[tuple[str, bytes], ...]
    timeout_seconds: float
    max_steps: int = 12
    max_output_bytes: int = 8192

    @property
    def digest(self) -> str:
        return sha(canonical({"nonce": self.nonce, "package_digest": self.package_digest,
                              "task": self.task, "tools": self.tools,
                              "files": {p: sha(b) for p, b in self.files},
                              "timeout_seconds": self.timeout_seconds,
                              "max_steps": self.max_steps,
                              "max_output_bytes": self.max_output_bytes}))


@dataclass(frozen=True, slots=True)
class Observation:
    request_digest: str
    nonce: str
    session_id: str
    status: str
    output: str
    used_tools: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Adapter:
    """Trusted host configuration, never an agent-supplied capability declaration.

    The host must qualify fresh sessions, cancellation, sandboxing, step limits and
    cost authorization. The contract string documents that obligation; it is not
    remote attestation. The adapter owns its credentials; none enter a Request.
    """

    agent_id: str
    capabilities: tuple[str, ...]
    isolation_contract: str
    run: Callable[[Request], Awaitable[Observation]]


@dataclass(frozen=True, slots=True)
class Result:
    case_id: str
    passed: bool
    reason: str
    request_digest: str
    session_digest: str
    output_digest: str


@dataclass(frozen=True, slots=True)
class Report:
    package_digest: str
    suite_digest: str
    agent_id: str
    role: str
    results: tuple[Result, ...]
    expected_cases: int

    @property
    def passed(self) -> bool:
        return len(self.results) == self.expected_cases and all(r.passed for r in self.results)

    def to_json(self) -> str:
        return canonical(asdict(self) | {"passed": self.passed}).decode("utf-8")


def _validate_cases(package: Package, cases: tuple[Case, ...]) -> None:
    if not isinstance(cases, tuple) or not 3 <= len(cases) <= 12:
        raise ForgeError("invalid_test_suite")
    public = {item["input"] for item in parse_json(package.as_dict()["tests/examples.json"])}
    ids, tasks, kinds = set(), set(), set()
    for case in cases:
        if not isinstance(case, Case):
            raise ForgeError("invalid_test_case")
        identifier(case.case_id)
        text(case.task, 8192)
        text(case.expected, 8192)
        if case.case_id in ids or case.task in tasks or case.task in public:
            raise ForgeError("test_case_not_held_out")
        if case.kind not in {"positive", "negative", "missing_tool"}:
            raise ForgeError("invalid_test_kind")
        ids.add(case.case_id)
        tasks.add(case.task)
        kinds.add(case.kind)
    if kinds != {"positive", "negative", "missing_tool"}:
        raise ForgeError("test_coverage_missing")


async def evaluate(package: Package, cases: tuple[Case, ...], adapter: Adapter,
                   role: str, *, timeout_seconds: float = 30.0) -> Report:
    """Grade host-authored holdouts, withholding oracles and original conversation.

    Stop at the first failure. asyncio timeout bounds a cooperative adapter; a real
    runtime must enforce cancellation and resource limits outside the model.
    """
    package_digest = package.digest
    _validate_cases(package, cases)
    if role not in {"internal", "transfer"}:
        raise ForgeError("invalid_evaluation_role")
    if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60):
        raise ForgeError("invalid_evaluation_budget")
    if not isinstance(adapter, Adapter) or adapter.isolation_contract != ISOLATION_CONTRACT:
        raise ForgeError("adapter_not_qualified")
    identifier(adapter.agent_id)
    if not isinstance(adapter.capabilities, tuple) or len(adapter.capabilities) > 64:
        raise ForgeError("invalid_adapter_capabilities")
    if any(not isinstance(tool, str) for tool in adapter.capabilities):
        raise ForgeError("invalid_adapter_capabilities")
    if (adapter.agent_id == package.origin_id) != (role == "internal"):
        raise ForgeError("agent_identity_mismatch")
    if not set(package.requirements).issubset(adapter.capabilities):
        raise ForgeError("required_tools_missing")
    suite_digest = sha(canonical([asdict(case) for case in cases]))
    sessions: set[str] = set()
    results = []
    deadline = time.monotonic() + timeout_seconds
    for case in cases:
        tools = package.requirements[1:] if case.kind == "missing_tool" else package.requirements
        remaining = deadline - time.monotonic()
        request = Request(secrets.token_hex(16), package_digest, case.task, tools,
                          package.instruction_files(), max(remaining, 0.000001))
        reason, session_digest, output_digest = "adapter_failed", "", ""
        try:
            if remaining <= 0:
                raise asyncio.TimeoutError
            observation = await asyncio.wait_for(adapter.run(request), timeout=remaining)
            if not isinstance(observation, Observation):
                reason = "invalid_observation"
            elif observation.request_digest != request.digest or observation.nonce != request.nonce:
                reason = "observation_binding_mismatch"
            elif (not isinstance(observation.session_id, str) or not observation.session_id
                  or len(observation.session_id) > 256 or observation.session_id in sessions):
                reason = "session_not_fresh"
            elif (not isinstance(observation.used_tools, tuple)
                  or any(not isinstance(t, str) or t not in tools for t in observation.used_tools)):
                reason = "tool_authority_violation"
            elif (not isinstance(observation.output, str)
                  or len(observation.output.encode("utf-8")) > request.max_output_bytes):
                reason = "invalid_output"
            else:
                sessions.add(observation.session_id)
                session_digest = sha(observation.session_id.encode())
                output_digest = sha(observation.output.encode())
                expected_status = "ok" if case.kind == "positive" else "blocked"
                if observation.status != expected_status or observation.output != case.expected:
                    reason = "output_mismatch"
                elif case.kind != "positive" and observation.used_tools:
                    reason = "blocked_case_used_tools"
                else:
                    reason = "passed"
        except asyncio.TimeoutError:
            reason = "evaluation_timeout"
        except Exception:
            # Do not export provider exception text: it may include secrets or source data.
            reason = "adapter_failed"
        results.append(Result(case.case_id, reason == "passed", reason, request.digest,
                              session_digest, output_digest))
        if reason != "passed":
            break
    return Report(package_digest, suite_digest, adapter.agent_id, role, tuple(results), len(cases))
