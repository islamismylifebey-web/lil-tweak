"""Production adapter from durable Test Worlds to Tueiq's existing execution primitives."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .contracts import JobMode
from .evidence import build_workspace_patch, capture_workspace
from .git_source import GitIntakeResult, ingest_git_source
from .openai_agent import CodeEngineer, WorkspaceTools
from .sandbox import PodmanSandbox, SandboxLimits
from .store import GitSourceSpec
from .test_world import TestCheck, TestWorld, TestWorldAttempt


@dataclass(slots=True)
class _Session:
    workspace: Path
    inventory: list[str]
    baseline: Any
    sandbox: Any
    tools: Any


class TestWorldRuntime:
    """Reuses immutable Git intake, WorkspaceTools, CodeEngineer, and PodmanSandbox.

    Credentials are intentionally not constructor inputs except for the already-built
    host-side Responses client. No host environment is copied into the workspace or
    passed to Podman.
    """

    def __init__(
        self,
        *,
        work_root: str | Path,
        runner_image: str,
        git_allowed_hosts: tuple[str, ...] | list[str],
        responses_client: Any,
        model: str,
        instructions: str,
        job_timeout_seconds: int,
        ingest_git: Callable[..., GitIntakeResult] = ingest_git_source,
        capture_workspace: Callable[..., Any] = capture_workspace,
        build_workspace_patch: Callable[..., bytes] = build_workspace_patch,
        sandbox_factory: Callable[..., Any] = PodmanSandbox,
        tools_factory: Callable[..., Any] = WorkspaceTools,
        agent_factory: Callable[..., Any] = CodeEngineer,
    ) -> None:
        root = Path(work_root).resolve()
        if not runner_image or not model or not instructions or not 1 <= job_timeout_seconds <= 86_400:
            raise ValueError("invalid Test World runtime configuration")
        hosts = tuple(git_allowed_hosts)
        if any(not isinstance(item, str) or not item for item in hosts):
            raise ValueError("invalid git allowlist")
        self.work_root = root
        self.runner_image = runner_image
        self.git_allowed_hosts = hosts
        self.responses_client = responses_client
        self.model = model
        self.instructions = instructions
        self.job_timeout_seconds = job_timeout_seconds
        self._ingest_git = ingest_git
        self._capture_workspace = capture_workspace
        self._build_workspace_patch = build_workspace_patch
        self._sandbox_factory = sandbox_factory
        self._tools_factory = tools_factory
        self._agent_factory = agent_factory
        self._sessions: dict[Path, _Session] = {}

    def _workspace(self, attempt: TestWorldAttempt) -> Path:
        suffix = attempt.id.removeprefix("attempt:")
        workspace = (self.work_root / f"tw-{suffix}").resolve()
        if workspace.parent != self.work_root:
            raise ValueError("invalid Test World workspace")
        return workspace

    def _session(self, workspace: Any) -> _Session:
        path = Path(workspace).resolve()
        session = self._sessions.get(path)
        if session is None:
            raise ValueError("Test World workspace is not prepared")
        return session

    def prepare_workspace(self, world: TestWorld, attempt: TestWorldAttempt) -> Path:
        workspace = self._workspace(attempt)
        if workspace in self._sessions:
            raise ValueError("Test World workspace is already prepared")
        try:
            shutil.rmtree(workspace)
        except FileNotFoundError:
            pass
        workspace.mkdir(parents=True, exist_ok=False, mode=0o700)
        try:
            intake = self._ingest_git(
                GitSourceSpec(world.repository_url, world.commit),
                workspace,
                allowed_hosts=self.git_allowed_hosts,
            )
            baseline = self._capture_workspace(workspace)
            sandbox = self._sandbox_factory(
                image=self.runner_image,
                workspace=workspace,
                name=f"tw-{attempt.id.removeprefix('attempt:')[:32]}",
                limits=SandboxLimits(
                    wall_timeout_seconds=self.job_timeout_seconds,
                    command_timeout_seconds=min(10 * 60, self.job_timeout_seconds),
                ),
            )
            tools = self._tools_factory(workspace, sandbox)
            self._sessions[workspace] = _Session(
                workspace=workspace,
                inventory=list(intake.inventory),
                baseline=baseline,
                sandbox=sandbox,
                tools=tools,
            )
            return workspace
        except Exception:
            self._sessions.pop(workspace, None)
            shutil.rmtree(workspace, ignore_errors=True)
            raise

    def apply_previous_patch(self, workspace: Any, patch: str) -> None:
        if not isinstance(patch, str) or not patch:
            raise ValueError("previous patch is required")
        session = self._session(workspace)
        result = session.tools.execute("apply_patch", {"patch": patch})
        if (
            not isinstance(result, dict)
            or result.get("exit_code") != 0
            or result.get("timed_out") is not False
            or result.get("truncated") is not False
            or result.get("promoted") is not True
        ):
            raise RuntimeError("previous Test World patch replay failed")

    def run_agent(self, workspace: Any, prompt: str) -> Any:
        if not isinstance(prompt, str) or not prompt:
            raise ValueError("Test World prompt is required")
        session = self._session(workspace)
        agent = self._agent_factory(
            self.responses_client,
            session.tools,
            model=self.model,
            instructions=self.instructions,
        )
        return agent.run(
            mode=JobMode.BUILD,
            prompt=prompt,
            source_inventory=session.inventory,
        )

    def capture_cumulative_patch(self, workspace: Any) -> str:
        session = self._session(workspace)
        final = self._capture_workspace(session.workspace)
        patch = self._build_workspace_patch(session.baseline, final)
        if not isinstance(patch, bytes):
            raise ValueError("trusted patch builder returned invalid data")
        try:
            return patch.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise ValueError("trusted patch was not UTF-8") from None

    def run_check(self, workspace: Any, check: TestCheck) -> dict[str, Any]:
        session = self._session(workspace)
        result = session.tools.execute(
            "run_command",
            {"command": list(check.command), "timeout": check.timeout_seconds},
        )
        if not isinstance(result, dict):
            raise ValueError("invalid sandbox check result")
        exit_code = result.get("exit_code")
        timed_out = result.get("timed_out")
        truncated = result.get("truncated")
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        if (
            not (exit_code is None or (isinstance(exit_code, int) and not isinstance(exit_code, bool)))
            or not isinstance(timed_out, bool)
            or not isinstance(truncated, bool)
            or not isinstance(stdout, str)
            or not isinstance(stderr, str)
        ):
            raise ValueError("invalid sandbox check result")
        passed = exit_code == 0 and not timed_out and not truncated
        return {
            "passed": passed,
            "exitCode": exit_code,
            "timedOut": timed_out,
            "truncated": truncated,
            "stdout": stdout,
            "stderr": stderr,
        }

    def cleanup_workspace(self, workspace: Any) -> None:
        path = Path(workspace).resolve()
        session = self._sessions.pop(path, None)
        if session is None:
            return
        teardown_error: Exception | None = None
        try:
            session.sandbox.teardown()
        except Exception as error:
            teardown_error = error
        if teardown_error is None:
            shutil.rmtree(path, ignore_errors=False)
        if teardown_error is not None:
            raise RuntimeError("Test World sandbox lifecycle failed") from teardown_error
