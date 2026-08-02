from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import stat
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization:\s*bearer\s+)[^\s]+"),
    re.compile(r"(?i)((?:api[_-]?key|client[_-]?secret|password|token)\s*[=:]\s*)[^\s,;]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"ya29\.[A-Za-z0-9_-]+"),
)


class SecurityBoundaryError(ValueError):
    pass


def redact(value: str, *, limit: int = 100_000) -> str:
    bounded = value[:limit]
    for pattern in _SECRET_PATTERNS:
        bounded = pattern.sub(
            lambda match: f"{match.group(1) if match.groups() else ''}[REDACTED]",
            bounded,
        )
    return bounded


class WorkspacePathGuard:
    def __init__(
        self,
        root: Path,
        *,
        max_files: int = 10_000,
        max_bytes: int = 250_000_000,
    ) -> None:
        self.root = root.resolve()
        self.max_files = max_files
        self.max_bytes = max_bytes
        if self.root == Path("/"):
            raise SecurityBoundaryError("task workspace cannot be the filesystem root")

    @staticmethod
    def validate_relative(value: str) -> PurePosixPath:
        if not value or "\\" in value or "\x00" in value:
            raise SecurityBoundaryError("workspace path is invalid")
        path = PurePosixPath(value)
        if value != "." and path.as_posix() != value:
            raise SecurityBoundaryError("workspace path must use canonical POSIX form")
        if value != "." and (
            path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise SecurityBoundaryError("workspace path must be canonical and relative")
        return path

    def resolve(self, value: str, *, allow_missing: bool = False) -> Path:
        if value == ".":
            candidate = self.root
        else:
            candidate = self.root.joinpath(*self.validate_relative(value).parts)
        cursor = self.root
        relative_parts = candidate.relative_to(self.root).parts
        for part in relative_parts:
            cursor = cursor / part
            if cursor.exists() or cursor.is_symlink():
                metadata = cursor.lstat()
                if stat.S_ISLNK(metadata.st_mode):
                    raise SecurityBoundaryError("symlinks are prohibited in task workspaces")
                if metadata.st_nlink > 1 and stat.S_ISREG(metadata.st_mode):
                    raise SecurityBoundaryError(
                        "hardlinked files are prohibited in task workspaces"
                    )
        parent = candidate if candidate.exists() else candidate.parent
        resolved_parent = parent.resolve(strict=not allow_missing)
        if not resolved_parent.is_relative_to(self.root):
            raise SecurityBoundaryError("workspace path escapes the task root")
        resolved = candidate.resolve(strict=False)
        if not resolved.is_relative_to(self.root):
            raise SecurityBoundaryError("workspace path resolves outside the task root")
        return candidate

    def inventory(self) -> tuple[int, int]:
        count = 0
        total = 0
        for path in self.root.rglob("*"):
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise SecurityBoundaryError("task workspace contains a symlink")
            if stat.S_ISREG(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise SecurityBoundaryError("task workspace contains a hardlink")
                count += 1
                total += metadata.st_size
                if count > self.max_files or total > self.max_bytes:
                    raise SecurityBoundaryError("task workspace exceeds configured limits")
            elif not stat.S_ISDIR(metadata.st_mode):
                raise SecurityBoundaryError("task workspace contains a special file")
        return count, total


@dataclass(frozen=True)
class Session:
    session_id: str
    actor_id: str
    csrf_token: str
    expires_at: float


class SessionManager:
    def __init__(self, signing_key: bytes, *, ttl_seconds: int = 3_600) -> None:
        if len(signing_key) != 32:
            raise ValueError("session signing key must contain exactly 32 bytes")
        self._key = signing_key
        self.ttl_seconds = ttl_seconds

    def create(self, actor_id: str) -> tuple[Session, str]:
        now = int(time.time())
        session_id = secrets.token_urlsafe(24)
        session = Session(
            session_id=session_id,
            actor_id=actor_id,
            csrf_token=hmac.new(
                self._key, f"csrf:{session_id}".encode(), hashlib.sha256
            ).hexdigest(),
            expires_at=now + self.ttl_seconds,
        )
        payload = f"{session.session_id}.{session.actor_id}.{int(session.expires_at)}"
        signature = hmac.new(self._key, payload.encode("utf-8"), hashlib.sha256).digest()
        cookie = (
            base64.urlsafe_b64encode(payload.encode("utf-8") + b"." + signature)
            .decode()
            .rstrip("=")
        )
        return session, cookie

    def verify(self, cookie: str | None) -> Session:
        if not cookie:
            raise SecurityBoundaryError("owner session is required")
        try:
            raw = base64.urlsafe_b64decode(cookie + ("=" * (-len(cookie) % 4)))
            payload_raw, signature = raw.rsplit(b".", 1)
            payload = payload_raw.decode("utf-8")
            session_id, actor_id, expires_text = payload.split(".", 2)
            expires_at = float(expires_text)
        except (ValueError, UnicodeDecodeError) as exc:
            raise SecurityBoundaryError("owner session is invalid") from exc
        expected = hmac.new(self._key, payload_raw, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected) or time.time() >= expires_at:
            raise SecurityBoundaryError("owner session is invalid or expired")
        csrf = hmac.new(self._key, f"csrf:{session_id}".encode(), hashlib.sha256).hexdigest()
        return Session(session_id, actor_id, csrf, expires_at)

    def csrf_for_cookie(self, cookie: str) -> str:
        session = self.verify(cookie)
        return hmac.new(
            self._key, f"csrf:{session.session_id}".encode(), hashlib.sha256
        ).hexdigest()

    def verify_csrf(self, cookie: str | None, supplied: str | None) -> Session:
        session = self.verify(cookie)
        expected = hmac.new(
            self._key, f"csrf:{session.session_id}".encode(), hashlib.sha256
        ).hexdigest()
        if not supplied or not hmac.compare_digest(expected, supplied):
            raise SecurityBoundaryError("CSRF validation failed")
        return session


class SlidingWindowRateLimiter:
    def __init__(self, *, limit: int = 120, window_seconds: int = 60) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)

    def admit(self, identity: str) -> None:
        now = time.monotonic()
        queue = self._requests[identity]
        while queue and queue[0] <= now - self.window_seconds:
            queue.popleft()
        if len(queue) >= self.limit:
            raise SecurityBoundaryError("rate limit exceeded")
        queue.append(now)


def private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SecurityBoundaryError("private directory permissions are invalid")
    return path
