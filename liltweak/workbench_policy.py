from __future__ import annotations

import re
from dataclasses import dataclass

from .repository import secret_rule_ids
from .workbench_contract import (
    CommandRequest,
    GcpExamConfig,
    NetworkMode,
    ToolKind,
    ToolRequest,
    WorkbenchMode,
    WorkbenchTask,
    content_digest,
)
from .workbench_security import SecurityBoundaryError

_ALLOWED_EXECUTABLES = frozenset(
    {
        "python",
        "python3",
        "pytest",
        "ruff",
        "uv",
        "git",
        "node",
        "npm",
        "npx",
        "pnpm",
        "gcloud",
        "kubectl",
        "curl",
        "cargo",
        "go",
    }
)
_SHELLS = frozenset({"bash", "sh", "zsh", "fish", "cmd", "powershell", "pwsh"})
_DENIED_GCP_PHRASES = (
    "config set project",
    "config configurations",
    "iam service-accounts keys create",
    "iam service-accounts keys upload",
    "iam service-accounts add-iam-policy-binding",
    "iam service-accounts remove-iam-policy-binding",
    "iam service-accounts set-iam-policy",
    "iam service-accounts update",
    "iam service-accounts delete",
    "projects delete",
    "projects set-iam-policy",
    "projects add-iam-policy-binding",
    "projects remove-iam-policy-binding",
    "billing accounts",
    "billing projects unlink",
    "billing budgets",
    "organizations",
    "resource-manager folders",
    "logging sinks delete",
    "logging exclusions create",
    "auth print-access-token",
    "auth print-identity-token",
    "auth application-default print-access-token",
    "secrets versions access",
    "kms decrypt",
    "sql connect",
    "sql export",
    "sql import",
    "storage cat",
    "storage cp",
    "storage rsync",
    "compute ssh",
    "compute scp",
    "container clusters get-credentials",
    "artifacts files download",
    "functions call",
    "run services proxy",
)
_OWNER_EDITOR = re.compile(r"(?i)(roles/(?:owner|editor)|--role[=\s]+(?:owner|editor))")
_SECRET_FLAGS = re.compile(
    r"(?i)(--key-file|--access-token-file|--credential-file-override|--flags-file)"
)
_SENSITIVE_ARGUMENTS = re.compile(
    r"(?i)(authorization:\s*bearer|x-goog-api-key|access[_-]?token[=:]|"
    r"api[_-]?key[=:]|client[_-]?secret[=:]|password[=:]|ya29\.)"
)


class ToolPolicyError(SecurityBoundaryError):
    pass


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str


class GcpCommandGuard:
    def validate(self, command: CommandRequest, exam: GcpExamConfig) -> None:
        if command.executable not in {"gcloud", "kubectl"}:
            return
        args = list(command.args)
        joined = " ".join(args).casefold()
        if any(phrase in joined for phrase in _DENIED_GCP_PHRASES):
            raise ToolPolicyError("GCP command targets an examiner-protected control")
        if _OWNER_EDITOR.search(joined):
            raise ToolPolicyError("Owner and Editor grants are prohibited")
        if _SECRET_FLAGS.search(joined):
            raise ToolPolicyError("credential files and raw tokens are prohibited")
        for arg in args:
            for project in re.findall(r"projects/([a-z][a-z0-9-]{4,28}[a-z0-9])", arg):
                if project != exam.authorized_project:
                    raise ToolPolicyError("GCP resource path targets another project")
            if arg.endswith(".iam.gserviceaccount.com"):
                identity_project = arg.rsplit("@", 1)[-1].split(".iam.", 1)[0]
                if identity_project != exam.authorized_project:
                    raise ToolPolicyError("GCP service account belongs to another project")
        if command.executable == "gcloud":
            for flag in (
                "--project",
                "--impersonate-service-account",
                "--billing-project",
                "--region",
                "--zone",
            ):
                if len(self._flag_values(args, flag)) > 1:
                    raise ToolPolicyError(f"duplicate gcloud flag is prohibited: {flag}")
            project = self._flag(args, "--project")
            identity = self._flag(args, "--impersonate-service-account")
            if project != exam.authorized_project:
                raise ToolPolicyError("gcloud project does not match the authorized exam project")
            if identity != exam.candidate_service_account:
                raise ToolPolicyError("gcloud identity must use keyless candidate impersonation")
            billing_project = self._optional_flag(args, "--billing-project")
            if billing_project is not None and billing_project != exam.authorized_project:
                raise ToolPolicyError("gcloud billing project does not match the examination")
            if (
                len(args) >= 3
                and args[0] == "projects"
                and not args[2].startswith("-")
                and args[2] != exam.authorized_project
            ):
                raise ToolPolicyError("gcloud project resource targets another project")
            region = self._optional_flag(args, "--region")
            zone = self._optional_flag(args, "--zone")
            if region is not None and region != exam.region:
                raise ToolPolicyError("gcloud region does not match the examination")
            if zone is not None and zone != exam.zone:
                raise ToolPolicyError("gcloud zone does not match the examination")
        else:
            raise ToolPolicyError(
                "kubectl remains disabled until a server-owned project and identity "
                "context is bound"
            )
        if "0.0.0.0/0" in joined and any(port in joined for port in ("22", "3389", "5432", "3306")):
            raise ToolPolicyError("internet-wide administrative exposure is prohibited")

    @staticmethod
    def _flag_values(args: list[str], name: str) -> list[str]:
        values: list[str] = []
        for index, value in enumerate(args):
            if value == name and index + 1 < len(args):
                values.append(args[index + 1])
            elif value.startswith(f"{name}="):
                values.append(value.split("=", 1)[1])
        return values

    @staticmethod
    def _optional_flag(args: list[str], name: str) -> str | None:
        values = GcpCommandGuard._flag_values(args, name)
        return values[0] if values else None

    @classmethod
    def _flag(cls, args: list[str], name: str) -> str:
        value = cls._optional_flag(args, name)
        if value is None:
            raise ToolPolicyError(f"required flag is missing: {name}")
        return value


class ToolPolicyBroker:
    def __init__(self, *, allowed_executables: frozenset[str] = _ALLOWED_EXECUTABLES) -> None:
        self.allowed_executables = allowed_executables
        self.gcp = GcpCommandGuard()

    @property
    def policy_digest(self) -> str:
        return content_digest(
            {
                "schema": "liltweak-workbench-tool-policy-v2",
                "allowed_executables": sorted(self.allowed_executables),
                "gcp_execution": "deferred_fail_closed",
                "network_default": NetworkMode.DENIED.value,
            }
        )

    def authorize(self, task: WorkbenchTask, request: ToolRequest) -> PolicyDecision:
        if request.kind != ToolKind.COMMAND:
            if (
                request.file is not None
                and request.file.content is not None
                and secret_rule_ids(request.file.content.encode("utf-8"))
            ):
                raise ToolPolicyError("file proposal contains credential-shaped material")
            return PolicyDecision(True, "file_tool_allowed", "bounded workspace file operation")
        command = request.command
        if command is None:
            raise ToolPolicyError("command payload is missing")
        executable = command.executable.casefold()
        if any(_SENSITIVE_ARGUMENTS.search(argument) for argument in command.args):
            raise ToolPolicyError("command arguments contain credential-shaped material")
        if executable in _SHELLS:
            raise ToolPolicyError("interactive shells and shell command strings are prohibited")
        if executable not in self.allowed_executables:
            raise ToolPolicyError("executable is not in the server-owned allowlist")
        if executable in {"python", "python3"} and any(arg in {"-c", "-"} for arg in command.args):
            raise ToolPolicyError("interpreter command strings and stdin programs are prohibited")
        if executable == "git" and command.args:
            denied = {"credential", "config", "clean", "reset", "checkout"}
            if command.args[0].casefold() in denied:
                raise ToolPolicyError("the requested Git operation is outside the bounded bridge")
        if command.network == NetworkMode.TASK_SCOPED and executable not in {
            "gcloud",
            "kubectl",
            "curl",
        }:
            raise ToolPolicyError("network use is limited to approved task-scoped clients")
        if task.imported.mode == WorkbenchMode.GCP_QUALIFICATION:
            if task.imported.examination is None:
                raise ToolPolicyError("GCP examination binding is missing")
            if executable in {"curl", "kubectl"}:
                raise ToolPolicyError(
                    "GCP direct HTTP and kubectl clients are outside the project-bound gcloud "
                    "policy surface; qualification remains deferred"
                )
            if executable == "gcloud" and command.network != NetworkMode.TASK_SCOPED:
                raise ToolPolicyError("GCP clients require the task-scoped network namespace")
            if command.network == NetworkMode.TASK_SCOPED and executable != "gcloud":
                raise ToolPolicyError(
                    "GCP network access is limited to the project-bound gcloud policy surface"
                )
            self.gcp.validate(command, task.imported.examination)
        elif executable in {"gcloud", "kubectl"}:
            raise ToolPolicyError("cloud commands require GCP qualification mode")
        return PolicyDecision(True, "approved_exact_request", "request fits server policy")
