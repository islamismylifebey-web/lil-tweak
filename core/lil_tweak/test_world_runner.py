"""Durable Test World attempt execution and deterministic judging."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Mapping
from typing import Any

from .openai_agent import AgentResult
from .test_world import (
    AttemptMode,
    TestWorldAttempt,
    TestWorldConflict,
    TestWorldNotFound,
    TestWorldStore,
)


_MAX_PRIOR_FEEDBACK_BYTES = 32 * 1024


def _bounded_feedback_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    data = encoded.encode("utf-8")
    if len(data) <= _MAX_PRIOR_FEEDBACK_BYTES:
        return encoded
    preview = data[: _MAX_PRIOR_FEEDBACK_BYTES - 128].decode("utf-8", "ignore")
    return json.dumps(
        {"truncated": True, "preview": preview},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _attempt_prompt(world: Any, previous: TestWorldAttempt | None) -> str:
    parts = [
        "You are working inside a bounded Tueiq Test World.",
        f"Objective: {world.objective}",
        "The trusted core, not your self-report, decides success by running deterministic judge checks after you finish.",
        "Do not attempt external actions. Network access is disabled. Make only changes required by the objective.",
    ]
    if previous is not None:
        parts.extend(
            [
                "Previous attempt feedback:",
                _bounded_feedback_json([dict(item) for item in previous.feedback]),
                "Continue from the previous accepted cumulative patch and repair the remaining failures.",
            ]
        )
    return "\n\n".join(parts)


def _judge_feedback(check: Any, result: Mapping[str, Any]) -> dict[str, Any]:
    passed = result.get("passed")
    exit_code = result.get("exitCode")
    timed_out = result.get("timedOut")
    truncated = result.get("truncated")
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    if (
        not isinstance(passed, bool)
        or not (exit_code is None or (isinstance(exit_code, int) and not isinstance(exit_code, bool)))
        or not isinstance(timed_out, bool)
        or not isinstance(truncated, bool)
        or not isinstance(stdout, str)
        or not isinstance(stderr, str)
    ):
        raise ValueError("invalid judge result")
    return {
        "check": check.name,
        "passed": passed,
        "exitCode": exit_code,
        "timedOut": timed_out,
        "truncated": truncated,
        "stdout": stdout,
        "stderr": stderr,
    }


def _elapsed_ms(start: float, end: float) -> int:
    return max(0, min(86_400_000, int(round((end - start) * 1000))))


class TestWorldAttemptRunner:
    """Claims one durable attempt, executes Tueiq, then persists judge truth."""

    def __init__(
        self,
        *,
        store: TestWorldStore,
        worker_id: str,
        lease_seconds: int,
        prepare_workspace: Callable[[Any, TestWorldAttempt], Any],
        apply_previous_patch: Callable[[Any, str], None],
        run_agent: Callable[[Any, str], AgentResult],
        capture_cumulative_patch: Callable[[Any], str],
        run_check: Callable[[Any, Any], Mapping[str, Any]],
        cleanup_workspace: Callable[[Any], None],
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not worker_id or not 1 <= lease_seconds <= 3600:
            raise ValueError("invalid Test World runner configuration")
        self.store = store
        self.worker_id = worker_id
        self.lease_seconds = lease_seconds
        self.prepare_workspace = prepare_workspace
        self.apply_previous_patch = apply_previous_patch
        self.run_agent = run_agent
        self.capture_cumulative_patch = capture_cumulative_patch
        self.run_check = run_check
        self.cleanup_workspace = cleanup_workspace
        self.clock = clock
        self.monotonic = monotonic

    def run_attempt(self, attempt_id: str, owner_id: str) -> TestWorldAttempt:
        attempt = self.store.get_attempt(attempt_id, owner_id)
        if attempt is None:
            raise TestWorldNotFound("attempt not found")
        lease = self.store.claim_attempt(
            attempt_id,
            self.worker_id,
            lease_seconds=self.lease_seconds,
            now=self.clock(),
        )
        if lease is None:
            current = self.store.get_attempt(attempt_id, owner_id)
            if current is None:
                raise TestWorldNotFound("attempt not found")
            if current.status.value in {"passed", "failed", "error"}:
                return current
            raise TestWorldConflict("attempt is already claimed")

        world = self.store.get_world(attempt.world_id, owner_id)
        if world is None:
            self.store.release_attempt(lease)
            raise TestWorldNotFound("world not found")

        workspace: Any | None = None
        attempt_started = self.monotonic()
        try:
            workspace = self.prepare_workspace(world, attempt)
            previous = None
            if attempt.mode is AttemptMode.RETRY and attempt.previous_attempt_id is not None:
                previous = self.store.get_attempt(attempt.previous_attempt_id, owner_id)
                if previous is None:
                    raise TestWorldNotFound("previous attempt not found")
                if previous.cumulative_patch:
                    self.apply_previous_patch(workspace, previous.cumulative_patch)

            agent_result = self.run_agent(workspace, _attempt_prompt(world, previous))
            if not isinstance(agent_result, AgentResult):
                raise ValueError("invalid agent result")

            cumulative_patch = self.capture_cumulative_patch(workspace)
            if not isinstance(cumulative_patch, str):
                raise ValueError("invalid cumulative patch")

            feedback: list[dict[str, Any]] = []
            all_passed = True
            judge_started = self.monotonic()
            for check in world.checks:
                result = _judge_feedback(check, self.run_check(workspace, check))
                feedback.append(result)
                all_passed = all_passed and result["passed"]
            judge_finished = self.monotonic()
            attempt_finished = judge_finished

            return self.store.complete_attempt(
                lease,
                passed=all_passed,
                feedback=tuple(feedback),
                cumulative_patch=cumulative_patch,
                plan=agent_result.plan,
                summary=agent_result.summary,
                tests=agent_result.tests,
                model_calls=agent_result.model_calls,
                input_tokens=agent_result.input_tokens,
                output_tokens=agent_result.output_tokens,
                total_tokens=agent_result.total_tokens,
                duration_ms=_elapsed_ms(attempt_started, attempt_finished),
                judge_duration_ms=_elapsed_ms(judge_started, judge_finished),
                now=self.clock(),
            )
        except (TestWorldConflict, TestWorldNotFound):
            raise
        except Exception:
            fail_attempt = getattr(self.store, "fail_attempt", None)
            if not callable(fail_attempt):
                self.store.release_attempt(lease)
                raise
            return fail_attempt(
                lease,
                feedback=({"code": "attempt_runtime_failed"},),
                summary="Attempt runtime failed before a trustworthy judge result was produced.",
                duration_ms=_elapsed_ms(attempt_started, self.monotonic()),
                now=self.clock(),
            )
        finally:
            if workspace is not None:
                try:
                    self.cleanup_workspace(workspace)
                except Exception:
                    pass
