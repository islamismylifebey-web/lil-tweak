from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Final, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

from .repository import is_sensitive_path, secret_rule_ids

SHA256 = r"^[0-9a-f]{64}$"
REVISION = r"^[0-9a-f]{40,64}$"
SAFE_ID = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
TOKEN_BOUND_METHOD: Final[Literal["utf8-bytes-as-token-upper-bound-v1"]] = (
    "utf8-bytes-as-token-upper-bound-v1"
)

_VENDOR_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "target",
        "vendor",
    }
)
_INSTRUCTION_NAMES = frozenset(
    {"agents.md", "claude.md", "copilot-instructions.md", "instructions.md"}
)
_MANIFEST_NAMES = frozenset(
    {
        "cargo.toml",
        "composer.json",
        "gemfile",
        "go.mod",
        "package.json",
        "pom.xml",
        "pyproject.toml",
        "requirements.txt",
    }
)
_LOCK_NAMES = frozenset(
    {
        "bun.lock",
        "bun.lockb",
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
        "package-lock.json",
        "pnpm-lock.yaml",
        "poetry.lock",
        "uv.lock",
        "yarn.lock",
    }
)
_CI_NAMES = frozenset(
    {
        ".gitlab-ci.yml",
        ".gitlab-ci.yaml",
        "azure-pipelines.yml",
        "azure-pipelines.yaml",
        "jenkinsfile",
    }
)
_DIAGNOSTIC = re.compile(
    r"^(?P<path>[^:\n]+):(?P<line>[1-9][0-9]*)(?::(?P<column>[1-9][0-9]*))?:\s*"
    r"(?:(?P<severity>error|warning|info|note|fatal)\s*:?\s*)?"
    r"(?:(?P<code>[A-Za-z][A-Za-z0-9_-]{0,31})\s*:?\s*)?"
    r"(?P<message>.+)$",
    re.IGNORECASE,
)


def _canonical_json(value: object) -> str:
    return json.dumps(
        to_jsonable_python(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _digest(value: object) -> str:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = _canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_relative_path(value: str) -> str:
    if (
        not value
        or len(value) > 512
        or value.startswith(("/", "\\"))
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("path must be normalized repository-relative UTF-8 text")
    parts = PurePosixPath(value).parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path cannot contain empty, dot, or parent components")
    return value


class ContextSchema(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FileCategory(StrEnum):
    INSTRUCTION = "instruction"
    MANIFEST = "manifest"
    LOCK = "lock"
    CI = "ci"
    TEST = "test"
    PYTHON = "python"
    DOCUMENTATION = "documentation"
    OTHER = "other"
    VENDOR = "vendor"


class PolicyDecision(StrEnum):
    ALLOWED = "allowed"
    EXCLUDED = "excluded"


class ContextPolicy(ContextSchema):
    schema_version: Literal["context-policy-v1"] = "context-policy-v1"
    max_files: StrictInt = Field(default=10_000, ge=1, le=100_000)
    max_file_bytes: StrictInt = Field(default=2_000_000, ge=1, le=50_000_000)
    max_total_bytes: StrictInt = Field(default=25_000_000, ge=1, le=1_000_000_000)
    max_excerpt_characters: StrictInt = Field(default=4_000, ge=64, le=50_000)
    max_symbols_per_file: StrictInt = Field(default=256, ge=1, le=5_000)
    max_imports_per_file: StrictInt = Field(default=256, ge=1, le=5_000)
    input_token_ceiling: StrictInt = Field(default=12_000, ge=256, le=2_000_000)
    reserved_output_tokens: StrictInt = Field(default=4_096, ge=1, le=1_000_000)

    @model_validator(mode="after")
    def output_reservation_leaves_context_room(self) -> ContextPolicy:
        if self.reserved_output_tokens >= self.input_token_ceiling:
            raise ValueError("reserved output tokens must be below the input token ceiling")
        return self


class FileProvenance(ContextSchema):
    path: StrictStr = Field(max_length=512)
    category: FileCategory
    policy_decision: PolicyDecision
    sha256: StrictStr | None = Field(default=None, pattern=SHA256)
    byte_count: StrictInt = Field(ge=0)
    context_selected: StrictBool = False
    selection_blocker: StrictStr | None = Field(default=None, max_length=128)
    policy_reasons: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=16)
    secret_rule_ids: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=16)

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return _validate_relative_path(value)

    @model_validator(mode="after")
    def decision_is_consistent(self) -> FileProvenance:
        if self.policy_decision == PolicyDecision.ALLOWED:
            if self.sha256 is None or self.policy_reasons:
                raise ValueError("allowed files require a digest and no policy exclusions")
        elif not self.policy_reasons:
            raise ValueError("excluded paths require exact policy reasons")
        if self.context_selected and (
            self.policy_decision != PolicyDecision.ALLOWED or self.selection_blocker is not None
        ):
            raise ValueError("selected context must be policy-allowed and unblocked")
        return self


class ContextExcerpt(ContextSchema):
    path: StrictStr = Field(max_length=512)
    file_sha256: StrictStr = Field(pattern=SHA256)
    line_start: Literal[1] = 1
    line_end: StrictInt = Field(ge=1, le=10_000_000)
    text: StrictStr = Field(max_length=50_000)
    text_sha256: StrictStr = Field(pattern=SHA256)
    utf8_bytes: StrictInt = Field(ge=0, le=10_000_000)
    conservative_token_upper_bound: StrictInt = Field(ge=0, le=10_000_000)
    token_bound_method: Literal["utf8-bytes-as-token-upper-bound-v1"] = TOKEN_BOUND_METHOD
    truncated: StrictBool

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return _validate_relative_path(value)

    @model_validator(mode="after")
    def text_binding_is_exact(self) -> ContextExcerpt:
        encoded = self.text.encode("utf-8")
        if self.text_sha256 != _digest(encoded):
            raise ValueError("context excerpt digest does not match its text")
        if self.utf8_bytes != len(encoded):
            raise ValueError("context excerpt byte count does not match its text")
        if self.conservative_token_upper_bound != self.utf8_bytes:
            raise ValueError("conservative token bound must equal UTF-8 bytes")
        expected_lines = max(1, self.text.count("\n") + (0 if self.text.endswith("\n") else 1))
        if self.line_end != expected_lines:
            raise ValueError("context excerpt line range does not match its text")
        return self


class InstructionBinding(ContextSchema):
    path: StrictStr = Field(max_length=512)
    scope: StrictStr = Field(max_length=512)
    scope_depth: StrictInt = Field(ge=0, le=128)
    precedence: StrictInt = Field(ge=0, le=10_000)
    file_sha256: StrictStr = Field(pattern=SHA256)
    context_selected: StrictBool

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return _validate_relative_path(value)

    @field_validator("scope")
    @classmethod
    def scope_is_safe(cls, value: str) -> str:
        return value if value == "." else _validate_relative_path(value)


class PythonSymbol(ContextSchema):
    qualified_name: StrictStr = Field(min_length=1, max_length=512)
    kind: Literal["class", "function", "async_function"]
    line_start: StrictInt = Field(ge=1, le=10_000_000)
    line_end: StrictInt = Field(ge=1, le=10_000_000)

    @model_validator(mode="after")
    def range_is_forward(self) -> PythonSymbol:
        if self.line_end < self.line_start:
            raise ValueError("symbol line range is reversed")
        return self


class PythonImport(ContextSchema):
    module: StrictStr = Field(min_length=1, max_length=512)
    names: tuple[StrictStr, ...] = Field(min_length=1, max_length=256)
    level: StrictInt = Field(ge=0, le=128)
    line: StrictInt = Field(ge=1, le=10_000_000)


class PythonIndex(ContextSchema):
    path: StrictStr = Field(max_length=512)
    file_sha256: StrictStr = Field(pattern=SHA256)
    symbols: tuple[PythonSymbol, ...] = Field(default_factory=tuple, max_length=5_000)
    imports: tuple[PythonImport, ...] = Field(default_factory=tuple, max_length=5_000)
    parse_error: StrictStr | None = Field(default=None, max_length=512)

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return _validate_relative_path(value)


class ProjectSignal(ContextSchema):
    category: Literal["manifest", "lock", "ci", "test"]
    path: StrictStr = Field(max_length=512)
    file_sha256: StrictStr = Field(pattern=SHA256)

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        return _validate_relative_path(value)


class DiagnosticRecord(ContextSchema):
    source: Literal["provided-diagnostics"] = "provided-diagnostics"
    path: StrictStr | None = Field(default=None, max_length=512)
    external_path_sha256: StrictStr | None = Field(default=None, pattern=SHA256)
    line: StrictInt = Field(ge=1, le=10_000_000)
    column: StrictInt | None = Field(default=None, ge=1, le=10_000_000)
    severity: Literal["error", "warning", "info", "note", "fatal", "unknown"]
    code: StrictStr | None = Field(default=None, max_length=32)
    message: StrictStr = Field(min_length=1, max_length=512)
    raw_line_sha256: StrictStr = Field(pattern=SHA256)
    redaction_rule_ids: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=16)

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str | None) -> str | None:
        return None if value is None else _validate_relative_path(value)

    @model_validator(mode="after")
    def path_provenance_is_unambiguous(self) -> DiagnosticRecord:
        if (self.path is None) == (self.external_path_sha256 is None):
            raise ValueError("diagnostic requires one repository or external path binding")
        return self


class TokenBudgetLabel(ContextSchema):
    method: Literal["utf8-bytes-as-token-upper-bound-v1"] = TOKEN_BOUND_METHOD
    input_token_ceiling: StrictInt = Field(ge=256, le=2_000_000)
    reserved_output_tokens: StrictInt = Field(ge=1, le=1_000_000)
    available_context_tokens: StrictInt = Field(ge=1, le=2_000_000)
    selected_context_utf8_bytes: StrictInt = Field(ge=0, le=2_000_000)
    conservative_context_token_upper_bound: StrictInt = Field(ge=0, le=2_000_000)
    remaining_context_tokens: StrictInt = Field(ge=0, le=2_000_000)
    within_budget: Literal[True] = True

    @model_validator(mode="after")
    def arithmetic_is_exact(self) -> TokenBudgetLabel:
        available = self.input_token_ceiling - self.reserved_output_tokens
        if self.available_context_tokens != available:
            raise ValueError("available context budget arithmetic is invalid")
        if self.conservative_context_token_upper_bound != self.selected_context_utf8_bytes:
            raise ValueError("token upper bound must equal selected UTF-8 bytes")
        if self.remaining_context_tokens != (
            available - self.conservative_context_token_upper_bound
        ):
            raise ValueError("remaining context budget arithmetic is invalid")
        return self


class ContextManifest(ContextSchema):
    schema_version: Literal["context-manifest-v1"] = "context-manifest-v1"
    repository_id: StrictStr = Field(pattern=SAFE_ID)
    source_revision: StrictStr = Field(pattern=REVISION)
    objective_sha256: StrictStr = Field(pattern=SHA256)
    diagnostics_sha256: StrictStr = Field(pattern=SHA256)
    policy: ContextPolicy
    files: tuple[FileProvenance, ...] = Field(max_length=100_000)
    excerpts: tuple[ContextExcerpt, ...] = Field(max_length=10_000)
    instructions: tuple[InstructionBinding, ...] = Field(max_length=1_000)
    python_indexes: tuple[PythonIndex, ...] = Field(max_length=10_000)
    project_signals: tuple[ProjectSignal, ...] = Field(max_length=10_000)
    diagnostics: tuple[DiagnosticRecord, ...] = Field(max_length=10_000)
    scan_truncated: StrictBool
    scan_blockers: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=16)
    source_tree_digest: StrictStr = Field(pattern=SHA256)
    token_budget: TokenBudgetLabel
    manifest_digest: StrictStr = Field(pattern=SHA256)

    @model_validator(mode="after")
    def digests_and_order_are_exact(self) -> ContextManifest:
        if tuple(file.path for file in self.files) != tuple(
            sorted(file.path for file in self.files)
        ):
            raise ValueError("context manifest file provenance must be path-sorted")
        unsigned = self.model_dump(mode="json", exclude={"manifest_digest"})
        if self.manifest_digest != _digest(unsigned):
            raise ValueError("context manifest digest mismatch")
        selected = {excerpt.path for excerpt in self.excerpts}
        recorded = {file.path for file in self.files if file.context_selected}
        if selected != recorded:
            raise ValueError("selected files and context excerpts do not agree")
        return self


@dataclass
class _ScannedPath:
    path: str
    category: FileCategory
    policy_decision: PolicyDecision
    sha256: str | None
    byte_count: int
    text: str | None = None
    policy_reasons: tuple[str, ...] = ()
    secret_ids: tuple[str, ...] = ()
    context_selected: bool = False
    selection_blocker: str | None = None


@dataclass(frozen=True)
class _FileSnapshot:
    sha256: str | None
    byte_count: int
    data: bytes | None
    rejection_reason: str | None = None


class _PythonVisitor(ast.NodeVisitor):
    def __init__(self, *, symbol_limit: int, import_limit: int) -> None:
        self.symbol_limit = symbol_limit
        self.import_limit = import_limit
        self.scope: list[str] = []
        self.symbols: list[PythonSymbol] = []
        self.imports: list[PythonImport] = []

    def _symbol(self, node: ast.AST, name: str, kind: str) -> None:
        if len(self.symbols) >= self.symbol_limit:
            return
        qualified = ".".join((*self.scope, name))
        self.symbols.append(
            PythonSymbol(
                qualified_name=qualified,
                kind=kind,
                line_start=int(getattr(node, "lineno", 1)),
                line_end=int(getattr(node, "end_lineno", getattr(node, "lineno", 1))),
            )
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._symbol(node, node.name, "class")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._symbol(node, node.name, "function")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._symbol(node, node.name, "async_function")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_Import(self, node: ast.Import) -> None:
        if len(self.imports) < self.import_limit:
            for alias in node.names:
                self.imports.append(
                    PythonImport(
                        module=alias.name,
                        names=(alias.asname or alias.name,),
                        level=0,
                        line=node.lineno,
                    )
                )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if len(self.imports) < self.import_limit:
            self.imports.append(
                PythonImport(
                    module=node.module or ".",
                    names=tuple(alias.asname or alias.name for alias in node.names),
                    level=node.level,
                    line=node.lineno,
                )
            )


def _category(path: str) -> FileCategory:
    pure = PurePosixPath(path)
    name = pure.name.casefold()
    folded_parts = tuple(part.casefold() for part in pure.parts)
    if name in _INSTRUCTION_NAMES:
        return FileCategory.INSTRUCTION
    if name in _LOCK_NAMES:
        return FileCategory.LOCK
    if name in _MANIFEST_NAMES:
        return FileCategory.MANIFEST
    if name in _CI_NAMES or (
        len(folded_parts) >= 3
        and folded_parts[0:2] == (".github", "workflows")
        and pure.suffix.casefold() in {".yml", ".yaml"}
    ):
        return FileCategory.CI
    if (
        "tests" in folded_parts
        or "test" in folded_parts
        or name.startswith("test_")
        or name.endswith(("_test.py", ".spec.js", ".test.js", ".spec.ts", ".test.ts"))
    ):
        return FileCategory.TEST
    if pure.suffix.casefold() == ".py":
        return FileCategory.PYTHON
    if pure.suffix.casefold() in {".md", ".mdx", ".rst", ".txt"}:
        return FileCategory.DOCUMENTATION
    return FileCategory.OTHER


def _stat_identity(metadata: os.stat_result) -> tuple[int, ...]:
    """Identity and mutation fields that must remain stable while a source entry is consumed."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _secure_descriptor_support_required() -> None:
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
        or not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
    ):
        raise ValueError("secure descriptor-relative repository scanning is unavailable")


def _open_directory_at(
    parent_fd: int,
    name: str,
    *,
    expected: os.stat_result,
    root_device: int,
    relative: str,
) -> int:
    if expected.st_dev != root_device:
        raise ValueError(f"repository source crosses a filesystem boundary: {relative}")
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise ValueError(f"repository source changed during context scan: {relative}") from exc
    opened = os.fstat(descriptor)
    if not stat.S_ISDIR(opened.st_mode) or _stat_identity(opened) != _stat_identity(expected):
        os.close(descriptor)
        raise ValueError(f"repository source changed during context scan: {relative}")
    return descriptor


def _file_snapshot_at(
    parent_fd: int,
    name: str,
    *,
    expected: os.stat_result,
    root_device: int,
    relative: str,
    maximum_capture_bytes: int,
) -> _FileSnapshot:
    if stat.S_ISLNK(expected.st_mode):
        return _FileSnapshot(None, expected.st_size, None, "symlink")
    if not stat.S_ISREG(expected.st_mode):
        return _FileSnapshot(None, expected.st_size, None, "special_file")
    if expected.st_dev != root_device:
        raise ValueError(f"repository source crosses a filesystem boundary: {relative}")
    if expected.st_nlink != 1:
        return _FileSnapshot(None, expected.st_size, None, "hardlink")

    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as stat_exc:
            raise ValueError(
                f"repository source changed during context scan: {relative}"
            ) from stat_exc
        if _stat_identity(current) != _stat_identity(expected):
            raise ValueError(f"repository source changed during context scan: {relative}") from exc
        return _FileSnapshot(None, expected.st_size, None, "unreadable_content")

    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_dev != root_device
            or before.st_nlink != 1
            or _stat_identity(before) != _stat_identity(expected)
        ):
            raise ValueError(f"repository source changed during context scan: {relative}")

        if before.st_size > maximum_capture_bytes:
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if _stat_identity(after) != _stat_identity(before) or _stat_identity(
                current
            ) != _stat_identity(before):
                raise ValueError(f"repository source changed during context scan: {relative}")
            return _FileSnapshot(None, before.st_size, None)

        hasher = hashlib.sha256()
        chunks: list[bytes] = []
        byte_count = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum_capture_bytes + 1))
            if not chunk:
                break
            byte_count += len(chunk)
            if byte_count > maximum_capture_bytes:
                raise ValueError(f"repository source changed during context scan: {relative}")
            hasher.update(chunk)
            chunks.append(chunk)
        after = os.fstat(descriptor)
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise ValueError(f"repository source changed during context scan: {relative}") from exc
        if (
            byte_count != before.st_size
            or _stat_identity(after) != _stat_identity(before)
            or _stat_identity(current) != _stat_identity(before)
        ):
            raise ValueError(f"repository source changed during context scan: {relative}")
        return _FileSnapshot(hasher.hexdigest(), byte_count, b"".join(chunks))
    finally:
        os.close(descriptor)


def _excerpt(path: _ScannedPath, *, maximum_characters: int) -> ContextExcerpt:
    assert path.text is not None
    text = path.text[:maximum_characters]
    encoded = text.encode("utf-8")
    return ContextExcerpt(
        path=path.path,
        file_sha256=path.sha256,
        line_end=max(1, text.count("\n") + (0 if text.endswith("\n") else 1)),
        text=text,
        text_sha256=_digest(encoded),
        utf8_bytes=len(encoded),
        conservative_token_upper_bound=len(encoded),
        truncated=len(path.text) > len(text),
    )


def _python_index(path: _ScannedPath, policy: ContextPolicy) -> PythonIndex:
    assert path.text is not None and path.sha256 is not None
    try:
        tree = ast.parse(path.text, filename=path.path)
    except SyntaxError as exc:
        message = f"{exc.msg} at line {exc.lineno or 1}"[:512]
        return PythonIndex(path=path.path, file_sha256=path.sha256, parse_error=message)
    visitor = _PythonVisitor(
        symbol_limit=policy.max_symbols_per_file,
        import_limit=policy.max_imports_per_file,
    )
    visitor.visit(tree)
    return PythonIndex(
        path=path.path,
        file_sha256=path.sha256,
        symbols=tuple(visitor.symbols),
        imports=tuple(visitor.imports),
    )


def parse_diagnostics(text: str, *, repository_root: Path) -> tuple[DiagnosticRecord, ...]:
    root = repository_root.resolve()
    records: list[DiagnosticRecord] = []
    for raw_line in text.splitlines()[:10_000]:
        match = _DIAGNOSTIC.fullmatch(raw_line.strip())
        if match is None:
            continue
        raw_path = match.group("path")
        candidate = Path(raw_path)
        path: str | None = None
        external_digest: str | None = None
        if candidate.is_absolute():
            try:
                path = candidate.resolve().relative_to(root).as_posix()
            except (OSError, ValueError):
                external_digest = _digest(raw_path)
        else:
            normalized = PurePosixPath(raw_path).as_posix()
            try:
                path = _validate_relative_path(normalized)
            except ValueError:
                external_digest = _digest(raw_path)
        message = match.group("message")[:512]
        rules = tuple(secret_rule_ids(message.encode("utf-8")))
        if rules:
            message = "[REDACTED: diagnostic contained credential-shaped material]"
        severity = (match.group("severity") or "unknown").casefold()
        records.append(
            DiagnosticRecord(
                path=path,
                external_path_sha256=external_digest,
                line=int(match.group("line")),
                column=int(match.group("column")) if match.group("column") else None,
                severity=severity,
                code=match.group("code"),
                message=message,
                raw_line_sha256=_digest(raw_line),
                redaction_rule_ids=rules,
            )
        )
    return tuple(records)


def _scan(
    root_fd: int,
    policy: ContextPolicy,
) -> tuple[list[_ScannedPath], bool, tuple[str, ...]]:
    scanned: list[_ScannedPath] = []
    file_count = 0
    total_bytes = 0
    truncated = False
    blockers: list[str] = []
    root_metadata = os.fstat(root_fd)
    root_device = root_metadata.st_dev

    def exclude(
        relative: str,
        category: FileCategory,
        *,
        byte_count: int,
        reason: str,
        digest: str | None = None,
    ) -> None:
        scanned.append(
            _ScannedPath(
                path=relative,
                category=category,
                policy_decision=PolicyDecision.EXCLUDED,
                sha256=digest,
                byte_count=byte_count,
                policy_reasons=(reason,),
            )
        )

    def walk(directory_fd: int, prefix: str = "") -> None:
        nonlocal file_count, total_bytes, truncated
        try:
            with os.scandir(directory_fd) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            label = prefix or "."
            raise ValueError(
                f"repository directory is unreadable during context scan: {label}"
            ) from exc

        for entry in entries:
            if truncated and "max_files" in blockers:
                return
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                exclude(
                    relative,
                    _category(relative),
                    byte_count=0,
                    reason="unreadable_metadata",
                )
                continue

            if stat.S_ISDIR(metadata.st_mode):
                if entry.name.casefold() in _VENDOR_DIRECTORIES:
                    exclude(
                        relative,
                        FileCategory.VENDOR,
                        byte_count=0,
                        reason="vendor_directory",
                    )
                    continue
                child_fd = _open_directory_at(
                    directory_fd,
                    entry.name,
                    expected=metadata,
                    root_device=root_device,
                    relative=relative,
                )
                try:
                    child_before = os.fstat(child_fd)
                    walk(child_fd, relative)
                    child_after = os.fstat(child_fd)
                    current = os.stat(
                        entry.name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if _stat_identity(child_after) != _stat_identity(
                        child_before
                    ) or _stat_identity(current) != _stat_identity(child_before):
                        raise ValueError(
                            f"repository source changed during context scan: {relative}"
                        )
                finally:
                    os.close(child_fd)
                continue

            if stat.S_ISLNK(metadata.st_mode):
                exclude(
                    relative,
                    _category(relative),
                    byte_count=metadata.st_size,
                    reason="symlink",
                )
                continue

            if file_count >= policy.max_files:
                truncated = True
                if "max_files" not in blockers:
                    blockers.append("max_files")
                return
            file_count += 1
            category = _category(relative)
            snapshot = _file_snapshot_at(
                directory_fd,
                entry.name,
                expected=metadata,
                root_device=root_device,
                relative=relative,
                maximum_capture_bytes=policy.max_file_bytes,
            )
            if snapshot.rejection_reason is not None:
                exclude(
                    relative,
                    category,
                    byte_count=snapshot.byte_count,
                    reason=snapshot.rejection_reason,
                    digest=snapshot.sha256,
                )
                continue
            if is_sensitive_path(relative):
                exclude(
                    relative,
                    category,
                    byte_count=snapshot.byte_count,
                    reason="sensitive_path",
                    digest=snapshot.sha256,
                )
                continue
            if snapshot.byte_count > policy.max_file_bytes:
                exclude(
                    relative,
                    category,
                    byte_count=snapshot.byte_count,
                    reason="max_file_bytes",
                    digest=snapshot.sha256,
                )
                continue
            data = snapshot.data
            digest = snapshot.sha256
            if data is None or digest is None:
                raise ValueError(f"repository file snapshot is incomplete: {relative}")
            if total_bytes + snapshot.byte_count > policy.max_total_bytes:
                exclude(
                    relative,
                    category,
                    byte_count=snapshot.byte_count,
                    reason="max_total_bytes",
                    digest=digest,
                )
                truncated = True
                if "max_total_bytes" not in blockers:
                    blockers.append("max_total_bytes")
                continue
            if b"\x00" in data:
                exclude(
                    relative,
                    category,
                    byte_count=len(data),
                    reason="binary_content",
                    digest=digest,
                )
                continue
            try:
                decoded = data.decode("utf-8")
            except UnicodeDecodeError:
                exclude(
                    relative,
                    category,
                    byte_count=len(data),
                    reason="non_utf8_content",
                    digest=digest,
                )
                continue
            rules = tuple(secret_rule_ids(data))
            if rules:
                scanned.append(
                    _ScannedPath(
                        path=relative,
                        category=category,
                        policy_decision=PolicyDecision.EXCLUDED,
                        sha256=digest,
                        byte_count=len(data),
                        policy_reasons=("credential_shaped_content",),
                        secret_ids=rules,
                    )
                )
                continue
            total_bytes += len(data)
            scanned.append(
                _ScannedPath(
                    path=relative,
                    category=category,
                    policy_decision=PolicyDecision.ALLOWED,
                    sha256=digest,
                    byte_count=len(data),
                    text=decoded,
                )
            )

    walk(root_fd)
    return scanned, truncated, tuple(blockers)


def build_context_manifest(
    repository_root: Path,
    *,
    repository_id: str,
    source_revision: str,
    objective: str,
    diagnostics: str = "",
    policy: ContextPolicy | None = None,
) -> ContextManifest:
    _secure_descriptor_support_required()
    root = repository_root.resolve()
    if not root.is_dir() or repository_root.is_symlink():
        raise ValueError("context source must be a real repository directory")
    active_policy = policy or ContextPolicy()
    try:
        root_fd = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError as exc:
        raise ValueError("context source could not be pinned securely") from exc
    try:
        root_before = os.fstat(root_fd)
        root_path_before = os.stat(root, follow_symlinks=False)
        if not stat.S_ISDIR(root_before.st_mode) or _stat_identity(
            root_path_before
        ) != _stat_identity(root_before):
            raise ValueError("context source changed before descriptor pinning")
        scanned, scan_truncated, scan_blockers = _scan(root_fd, active_policy)
        root_after = os.fstat(root_fd)
        root_path_after = os.stat(root, follow_symlinks=False)
        if _stat_identity(root_after) != _stat_identity(root_before) or _stat_identity(
            root_path_after
        ) != _stat_identity(root_before):
            raise ValueError("context source changed during context scan: .")
    finally:
        os.close(root_fd)
    priority = {
        FileCategory.INSTRUCTION: 0,
        FileCategory.MANIFEST: 1,
        FileCategory.LOCK: 2,
        FileCategory.CI: 3,
        FileCategory.TEST: 4,
        FileCategory.PYTHON: 5,
        FileCategory.DOCUMENTATION: 6,
        FileCategory.OTHER: 7,
        FileCategory.VENDOR: 8,
    }
    available = active_policy.input_token_ceiling - active_policy.reserved_output_tokens
    selected_bytes = 0
    excerpts: list[ContextExcerpt] = []
    for item in sorted(scanned, key=lambda value: (priority[value.category], value.path)):
        if item.policy_decision != PolicyDecision.ALLOWED or item.text is None:
            continue
        candidate = _excerpt(item, maximum_characters=active_policy.max_excerpt_characters)
        if selected_bytes + candidate.conservative_token_upper_bound <= available:
            item.context_selected = True
            excerpts.append(candidate)
            selected_bytes += candidate.conservative_token_upper_bound
        else:
            item.selection_blocker = "context_token_budget"

    file_records = tuple(
        FileProvenance(
            path=item.path,
            category=item.category,
            policy_decision=item.policy_decision,
            sha256=item.sha256,
            byte_count=item.byte_count,
            context_selected=item.context_selected,
            selection_blocker=item.selection_blocker,
            policy_reasons=item.policy_reasons,
            secret_rule_ids=item.secret_ids,
        )
        for item in sorted(scanned, key=lambda value: value.path)
    )
    selected_paths = {item.path for item in file_records if item.context_selected}
    instruction_paths = [
        item
        for item in file_records
        if item.category == FileCategory.INSTRUCTION
        and item.policy_decision == PolicyDecision.ALLOWED
        and item.sha256 is not None
    ]
    instruction_paths.sort(key=lambda item: (len(PurePosixPath(item.path).parent.parts), item.path))
    instructions = tuple(
        InstructionBinding(
            path=item.path,
            scope=(
                "."
                if PurePosixPath(item.path).parent.as_posix() == "."
                else PurePosixPath(item.path).parent.as_posix()
            ),
            scope_depth=(
                0
                if PurePosixPath(item.path).parent.as_posix() == "."
                else len(PurePosixPath(item.path).parent.parts)
            ),
            precedence=index,
            file_sha256=item.sha256,
            context_selected=item.path in selected_paths,
        )
        for index, item in enumerate(instruction_paths)
    )
    python_indexes = tuple(
        _python_index(item, active_policy)
        for item in sorted(scanned, key=lambda value: value.path)
        if item.policy_decision == PolicyDecision.ALLOWED
        and item.text is not None
        and PurePosixPath(item.path).suffix.casefold() == ".py"
    )
    project_signals = tuple(
        ProjectSignal(
            category=item.category.value,
            path=item.path,
            file_sha256=item.sha256,
        )
        for item in file_records
        if item.category
        in {FileCategory.MANIFEST, FileCategory.LOCK, FileCategory.CI, FileCategory.TEST}
        and item.policy_decision == PolicyDecision.ALLOWED
        and item.sha256 is not None
    )
    diagnostic_records = parse_diagnostics(diagnostics, repository_root=root)
    tree_payload = tuple(
        {
            "path": item.path,
            "sha256": item.sha256,
            "byte_count": item.byte_count,
            "policy_decision": item.policy_decision.value,
            "policy_reasons": item.policy_reasons,
        }
        for item in file_records
    )
    budget = TokenBudgetLabel(
        input_token_ceiling=active_policy.input_token_ceiling,
        reserved_output_tokens=active_policy.reserved_output_tokens,
        available_context_tokens=available,
        selected_context_utf8_bytes=selected_bytes,
        conservative_context_token_upper_bound=selected_bytes,
        remaining_context_tokens=available - selected_bytes,
    )
    values = {
        "schema_version": "context-manifest-v1",
        "repository_id": repository_id,
        "source_revision": source_revision,
        "objective_sha256": _digest(objective),
        "diagnostics_sha256": _digest(diagnostics),
        "policy": active_policy,
        "files": file_records,
        "excerpts": tuple(sorted(excerpts, key=lambda item: item.path)),
        "instructions": instructions,
        "python_indexes": python_indexes,
        "project_signals": project_signals,
        "diagnostics": diagnostic_records,
        "scan_truncated": scan_truncated,
        "scan_blockers": scan_blockers,
        "source_tree_digest": _digest(tree_payload),
        "token_budget": budget,
    }
    return ContextManifest(**values, manifest_digest=_digest(values))
