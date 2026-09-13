"""Bounded GitHub Actions builder for exact, owner-authorized Tueiq patches."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import secrets
import time
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import InvalidURL
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_REPOSITORY_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_WORKFLOW = re.compile(r"^[A-Za-z0-9_.-]+\.ya?ml$")
_PATH = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
_ACTIONS = frozenset({"inspect_source", "apply_patch", "compile_python", "npm_verify", "git_diff"})
_MAX_MANIFEST_BYTES = 45_000
_MAX_ARTIFACT_BYTES = 1_000_000
_MAX_RECEIPT_BYTES = 128_000


class GitHubRunnerError(RuntimeError):
    """A public, stable failure from the GitHub runner boundary."""


class _GitHubRedirectHandler(HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        try:
            return super().http_error_302(req, fp, code, msg, headers)
        except (HTTPError, InvalidURL, ValueError):
            raise GitHubRunnerError("GitHub runner redirect rejected") from None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            target = urlsplit(newurl)
            port = target.port
        except (TypeError, ValueError):
            raise GitHubRunnerError("GitHub runner redirect rejected") from None
        if (
            target.scheme != "https"
            or not target.hostname
            or target.username is not None
            or target.password is not None
            or port == 0
            or target.netloc.endswith(":")
            # urllib decodes escapes in the authority before HTTP transport.
            or "%" in target.netloc
            or "\\" in target.netloc
            or any(ord(character) <= 32 or ord(character) >= 127 for character in target.netloc)
        ):
            raise GitHubRunnerError("GitHub runner redirect rejected")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        redirected.remove_header("Authorization")
        return redirected


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _valid_github_repository(value: object) -> bool:
    if not isinstance(value, str):
        return False
    components = value.split("/")
    return (
        len(components) == 2
        and all(component not in {".", ".."} for component in components)
        and all(_REPOSITORY_COMPONENT.fullmatch(component) for component in components)
    )


def _patch_paths(patch: str) -> tuple[str, ...]:
    paths: list[str] = []
    lines = patch.splitlines()
    for index, line in enumerate(lines):
        if not line.startswith("diff --git a/"):
            if not line.startswith("--- "):
                continue
            if index + 1 >= len(lines) or not lines[index + 1].startswith("+++ "):
                raise GitHubRunnerError("invalid patch paths")
            before = line[4:]
            after = lines[index + 1][4:]
            selected = after if after != "/dev/null" else before
            if selected.startswith(("a/", "b/")):
                selected = selected[2:]
            if not _PATH.fullmatch(selected) or selected.startswith(".git/"):
                raise GitHubRunnerError("invalid patch paths")
            paths.append(selected)
            continue
        parts = line.split(" ")
        if len(parts) != 4 or not parts[2].startswith("a/") or not parts[3].startswith("b/"):
            raise GitHubRunnerError("invalid patch paths")
        before, after = parts[2][2:], parts[3][2:]
        if before != after or not _PATH.fullmatch(after) or after.startswith(".git/"):
            raise GitHubRunnerError("invalid patch paths")
        if after not in paths:
            paths.append(after)
    return tuple(dict.fromkeys(paths))


@dataclass(frozen=True, slots=True)
class RunnerManifest:
    execution_id: str
    repository: str
    source_commit: str
    source_tree: str
    patch: str
    authorized_paths: tuple[str, ...]
    actions: tuple[str, ...]
    issued_at: str
    expires_at: str
    authority_digest: str
    manifest_digest: str

    @classmethod
    def issue(
        cls,
        *,
        execution_id: str,
        repository: str,
        source_commit: str,
        source_tree: str,
        patch: str,
        authorized_paths: tuple[str, ...],
        actions: tuple[str, ...],
        issued_at: datetime,
        expires_at: datetime,
        authority_digest: str,
    ) -> "RunnerManifest":
        if (
            not _SAFE_ID.fullmatch(execution_id)
            or not _valid_github_repository(repository)
            or not _HEX_40.fullmatch(source_commit)
            or not _HEX_40.fullmatch(source_tree)
            or not _HEX_64.fullmatch(authority_digest)
            or issued_at.tzinfo is None
            or expires_at.tzinfo is None
            or not issued_at < expires_at
            or (expires_at - issued_at).total_seconds() > 1800
            or len(actions) < 1
            or len(actions) > 5
            or len(set(actions)) != len(actions)
            or any(action not in _ACTIONS for action in actions)
            or actions[0] != "inspect_source"
            or actions[-1] != "git_diff"
            or len(patch.encode()) > 24_000
            or len(authorized_paths) > 32
            or len(set(authorized_paths)) != len(authorized_paths)
            or any(not _PATH.fullmatch(path) or path.startswith(".git/") for path in authorized_paths)
        ):
            raise GitHubRunnerError("invalid runner manifest")
        changed_paths = _patch_paths(patch)
        if patch and (not changed_paths or set(changed_paths) != set(authorized_paths)):
            raise GitHubRunnerError("invalid patch paths")
        if bool(patch) != ("apply_patch" in actions) or bool(patch) != bool(authorized_paths):
            raise GitHubRunnerError("invalid patch authority")
        payload = {
            "schemaVersion": "lil-tweak-github-runner-manifest-v1",
            "executionId": execution_id,
            "repository": repository,
            "sourceCommit": source_commit,
            "sourceTree": source_tree,
            "patch": patch,
            "authorizedPaths": list(authorized_paths),
            "actions": list(actions),
            "issuedAt": issued_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "expiresAt": expires_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "authorityDigest": authority_digest,
        }
        digest = hashlib.sha256(_canonical(payload)).hexdigest()
        if len(_canonical({**payload, "manifestDigest": digest})) > _MAX_MANIFEST_BYTES:
            raise GitHubRunnerError("runner manifest too large")
        return cls(
            execution_id=execution_id,
            repository=repository,
            source_commit=source_commit,
            source_tree=source_tree,
            patch=patch,
            authorized_paths=authorized_paths,
            actions=actions,
            issued_at=payload["issuedAt"],
            expires_at=payload["expiresAt"],
            authority_digest=authority_digest,
            manifest_digest=digest,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schemaVersion": "lil-tweak-github-runner-manifest-v1",
            "executionId": self.execution_id,
            "repository": self.repository,
            "sourceCommit": self.source_commit,
            "sourceTree": self.source_tree,
            "patch": self.patch,
            "authorizedPaths": list(self.authorized_paths),
            "actions": list(self.actions),
            "issuedAt": self.issued_at,
            "expiresAt": self.expires_at,
            "authorityDigest": self.authority_digest,
            "manifestDigest": self.manifest_digest,
        }

    @classmethod
    def parse(cls, value: Mapping[str, Any]) -> "RunnerManifest":
        expected_keys = {
            "schemaVersion", "executionId", "repository", "sourceCommit", "sourceTree",
            "patch", "authorizedPaths", "actions", "issuedAt", "expiresAt",
            "authorityDigest", "manifestDigest",
        }
        scalar_keys = expected_keys - {"authorizedPaths", "actions"}
        if (
            not isinstance(value, Mapping)
            or set(value) != expected_keys
            or any(not isinstance(value[key], str) for key in scalar_keys)
            or not isinstance(value["authorizedPaths"], list)
            or not all(isinstance(path, str) for path in value["authorizedPaths"])
            or not isinstance(value["actions"], list)
            or not all(isinstance(action, str) for action in value["actions"])
            or value["schemaVersion"] != "lil-tweak-github-runner-manifest-v1"
        ):
            raise GitHubRunnerError("invalid runner manifest")
        try:
            issued = datetime.fromisoformat(value["issuedAt"].replace("Z", "+00:00"))
            expires = datetime.fromisoformat(value["expiresAt"].replace("Z", "+00:00"))
            parsed = cls.issue(
                execution_id=value["executionId"],
                repository=value["repository"],
                source_commit=value["sourceCommit"],
                source_tree=value["sourceTree"],
                patch=value["patch"],
                authorized_paths=tuple(value["authorizedPaths"]),
                actions=tuple(value["actions"]),
                issued_at=issued,
                expires_at=expires,
                authority_digest=value["authorityDigest"],
            )
        except (KeyError, TypeError, ValueError):
            raise GitHubRunnerError("invalid runner manifest") from None
        if not _HEX_64.fullmatch(value["manifestDigest"]) or not secrets.compare_digest(
            parsed.manifest_digest, value["manifestDigest"]
        ):
            raise GitHubRunnerError("runner manifest digest mismatch")
        return parsed


def verify_receipt(value: Mapping[str, Any], manifest: RunnerManifest) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise GitHubRunnerError("runner receipt binding failed")
    receipt = dict(value)
    digest = receipt.pop("receiptDigest", None)
    steps = receipt.get("steps")
    if (
        not isinstance(digest, str)
        or not _HEX_64.fullmatch(digest)
        or type(receipt.get("workspaceChanged")) is not bool
        or not isinstance(steps, list)
        or not all(
            isinstance(step, Mapping)
            and set(step) == {"action", "exitCode"}
            and isinstance(step["action"], str)
            and type(step["exitCode"]) is int
            for step in steps
        )
    ):
        raise GitHubRunnerError("runner receipt binding failed")
    expected = hashlib.sha256(_canonical(receipt)).hexdigest()
    bindings = (
        receipt.get("schemaVersion") == "lil-tweak-github-runner-receipt-v1"
        and receipt.get("executionId") == manifest.execution_id
        and receipt.get("repository") == manifest.repository
        and receipt.get("sourceCommit") == manifest.source_commit
        and receipt.get("sourceTree") == manifest.source_tree
        and receipt.get("manifestDigest") == manifest.manifest_digest
        and receipt.get("authorityDigest") == manifest.authority_digest
        and receipt.get("outcome") == "succeeded"
        and receipt.get("workspaceChanged") == bool(manifest.authorized_paths)
        and receipt.get("changedPaths") == sorted(manifest.authorized_paths)
        and [step.get("action") for step in steps] == list(manifest.actions)
        and all(step.get("exitCode") == 0 for step in steps)
        and secrets.compare_digest(digest, expected)
    )
    if not bindings:
        raise GitHubRunnerError("runner receipt binding failed")
    return dict(value)


class GitHubActionsRunner:
    def __init__(
        self,
        *,
        token: str,
        repository: str,
        workflow: str = "tueiq-runner.yml",
        opener: Any = None,
        sleeper: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if (
            len(token.encode()) < 32
            or not _valid_github_repository(repository)
            or not _WORKFLOW.fullmatch(workflow)
        ):
            raise ValueError("invalid GitHub runner configuration")
        self._token = token
        self.repository = repository
        self.workflow = workflow
        self._opener = opener or build_opener(_GitHubRedirectHandler())
        self._sleep = sleeper
        self._now = now

    def _request(self, method: str, path: str, body: Mapping[str, Any] | None = None) -> Response:
        data = None if body is None else _canonical(body)
        request = Request(
            f"https://api.github.com/repos/{self.repository}{path}",
            method=method,
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Content-Type": "application/json"} if data is not None else {}),
            },
        )
        request.add_unredirected_header("Authorization", f"Bearer {self._token}")
        return self._opener.open(request, timeout=5)

    @staticmethod
    def _json(response: Any, *, maximum: int = _MAX_RECEIPT_BYTES) -> Any:
        body = response.read(maximum + 1)
        if len(body) > maximum:
            raise GitHubRunnerError("GitHub runner response too large")
        try:
            return json.loads(body.decode("utf-8", "strict"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise GitHubRunnerError("invalid GitHub runner response") from None

    def execute(self, manifest: RunnerManifest) -> dict[str, Any]:
        if manifest.repository != self.repository or self._now() >= datetime.fromisoformat(manifest.expires_at.replace("Z", "+00:00")):
            raise GitHubRunnerError("runner manifest is stale or misbound")
        encoded = base64.b64encode(_canonical(manifest.as_dict())).decode("ascii")
        with self._request(
            "POST",
            f"/actions/workflows/{quote(self.workflow, safe='')}/dispatches",
            {
                "ref": "main",
                "return_run_details": True,
                "inputs": {
                    "execution_id": manifest.execution_id,
                    "expected_commit": manifest.source_commit,
                    "manifest_base64": encoded,
                    "manifest_digest": manifest.manifest_digest,
                    "acknowledge_builder_only": "true",
                },
            },
        ) as response:
            if response.status != 200:
                raise GitHubRunnerError("GitHub runner dispatch failed")
            try:
                dispatch = self._json(response)
            except GitHubRunnerError:
                raise GitHubRunnerError("GitHub runner dispatch failed") from None
        if not isinstance(dispatch, Mapping):
            raise GitHubRunnerError("GitHub runner dispatch failed")
        run_id = dispatch.get("workflow_run_id")
        if type(run_id) is not int or run_id <= 0:
            raise GitHubRunnerError("GitHub runner dispatch failed")

        self._wait_for_run(run_id, manifest)
        return self._collect(run_id, manifest)

    def _wait_for_run(self, run_id: int, manifest: RunnerManifest) -> None:
        title = f"Tueiq Runner {manifest.execution_id}"
        for _ in range(360):
            with self._request("GET", f"/actions/runs/{run_id}") as response:
                if response.status != 200:
                    raise GitHubRunnerError("GitHub runner status failed")
                run = self._json(response)
            if (
                not isinstance(run, Mapping)
                or type(run.get("id")) is not int
                or run["id"] != run_id
                or run.get("event") != "workflow_dispatch"
                or run.get("display_title") != title
            ):
                raise GitHubRunnerError("GitHub runner status failed")
            if run.get("status") == "completed":
                if run.get("conclusion") != "success":
                    raise GitHubRunnerError("GitHub runner execution failed")
                return
            self._sleep(5)
        try:
            with self._request("POST", f"/actions/runs/{run_id}/cancel"):
                pass
        except Exception:
            pass
        raise GitHubRunnerError("GitHub runner timed out")

    def _collect(self, run_id: int, manifest: RunnerManifest) -> dict[str, Any]:
        with self._request("GET", f"/actions/runs/{run_id}/artifacts") as response:
            if response.status != 200:
                raise GitHubRunnerError("GitHub runner evidence unavailable")
            payload = self._json(response)
        if not isinstance(payload, Mapping):
            raise GitHubRunnerError("GitHub runner evidence unavailable")
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list) or not all(
            isinstance(item, Mapping) for item in artifacts
        ):
            raise GitHubRunnerError("GitHub runner evidence unavailable")
        expected_name = f"tueiq-runner-evidence-{run_id}"
        matches = [item for item in artifacts if item.get("name") == expected_name]
        if len(matches) != 1:
            raise GitHubRunnerError("GitHub runner evidence unavailable")
        artifact = matches[0]
        if (
            artifact.get("expired") is not False
            or type(artifact.get("id")) is not int
            or artifact["id"] <= 0
            or type(artifact.get("size_in_bytes")) is not int
            or not 0 <= artifact["size_in_bytes"] <= _MAX_ARTIFACT_BYTES
        ):
            raise GitHubRunnerError("GitHub runner evidence unavailable")
        with self._request("GET", f"/actions/artifacts/{artifact['id']}/zip") as response:
            archive_bytes = response.read(_MAX_ARTIFACT_BYTES + 1)
        if len(archive_bytes) > _MAX_ARTIFACT_BYTES:
            raise GitHubRunnerError("GitHub runner evidence too large")
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                names = archive.namelist()
                if names != ["runner-receipt.json"]:
                    raise GitHubRunnerError("invalid GitHub runner evidence")
                info = archive.getinfo(names[0])
                if info.file_size > _MAX_RECEIPT_BYTES:
                    raise GitHubRunnerError("GitHub runner receipt too large")
                receipt = json.loads(archive.read(names[0]).decode("utf-8", "strict"))
        except (zipfile.BadZipFile, KeyError, UnicodeDecodeError, json.JSONDecodeError):
            raise GitHubRunnerError("invalid GitHub runner evidence") from None
        if not isinstance(receipt, dict):
            raise GitHubRunnerError("invalid GitHub runner receipt")
        return verify_receipt(receipt, manifest)


class GitHubPatchVerifier:
    """Translate a completed Tueiq edit into one bounded GitHub builder job."""

    def __init__(
        self,
        runner: GitHubActionsRunner,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._runner = runner
        self._now = now

    def verify(
        self,
        *,
        job: Any,
        patch: bytes,
        baseline_digest: str,
        final_digest: str,
        source_commit: str,
        source_tree: str,
    ) -> dict[str, Any]:
        source = getattr(job, "git_source", None)
        if source_commit != getattr(source, "commit", None):
            raise GitHubRunnerError("verified source commit does not match job")
        url = getattr(source, "repository_url", "")
        if (
            not isinstance(url, str)
            or "?" in url
            or "#" in url
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in url)
        ):
            raise GitHubRunnerError("unsupported GitHub source")
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except (TypeError, ValueError):
            raise GitHubRunnerError("unsupported GitHub source") from None
        path = parsed.path
        if path.endswith("/"):
            path = path[:-1]
        if path.casefold().endswith(".git"):
            path = path[:-4]
        repository = path[1:] if path.startswith("/") else ""
        if (
            parsed.scheme.casefold() != "https"
            or parsed.netloc.casefold() not in {"github.com", "github.com:443"}
            or parsed.hostname is None
            or parsed.hostname.casefold() != "github.com"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or port not in {None, 443}
            or not _valid_github_repository(repository)
        ):
            raise GitHubRunnerError("unsupported GitHub source")
        if repository.casefold() != self._runner.repository.casefold():
            raise GitHubRunnerError("GitHub source does not match runner")
        try:
            patch_text = patch.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise GitHubRunnerError("runner patch must be UTF-8") from None
        paths = _patch_paths(patch_text)
        authority = hashlib.sha256(
            _canonical(
                {
                    "schemaVersion": "lil-tweak-github-authority-v1",
                    "jobId": job.id,
                    "revision": job.revision,
                    "sourceCommit": source_commit,
                    "sourceTree": source_tree,
                    "sourceDigest": baseline_digest,
                    "resultDigest": final_digest,
                    "patchDigest": hashlib.sha256(patch).hexdigest(),
                    "authorizedPaths": list(paths),
                }
            )
        ).hexdigest()
        current = self._now().astimezone(UTC)
        actions = ["inspect_source"]
        if patch_text:
            actions.append("apply_patch")
        actions.extend(("compile_python", "npm_verify", "git_diff"))
        manifest = RunnerManifest.issue(
            execution_id=f"{job.id}-{job.revision}"[-80:],
            repository=self._runner.repository,
            source_commit=source_commit,
            source_tree=source_tree,
            patch=patch_text,
            authorized_paths=paths,
            actions=tuple(actions),
            issued_at=current,
            expires_at=datetime.fromtimestamp(current.timestamp() + 600, UTC),
            authority_digest=authority,
        )
        return self._runner.execute(manifest)
