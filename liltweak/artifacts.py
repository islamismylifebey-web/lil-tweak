from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import stat
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import ArtifactKind, ArtifactRecord, ArtifactStatus, JobRecord
from .store import SQLiteStore, canonical_json


class ArtifactConfigurationError(RuntimeError):
    pass


class ArtifactIntegrityError(RuntimeError):
    pass


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


class EncryptedArtifactStore:
    """Bounded encrypted storage whose paths are never exposed through API models."""

    def __init__(
        self,
        *,
        root: Path | str,
        workspace_root: Path | str,
        master_key: bytes,
        store: SQLiteStore,
    ) -> None:
        if len(master_key) != 32:
            raise ArtifactConfigurationError("artifact encryption key must contain 32 bytes")
        raw_root = Path(root)
        candidate_root = raw_root.resolve(strict=False)
        workspace = Path(workspace_root).resolve(strict=False)
        if _is_relative_to(candidate_root, workspace) or _is_relative_to(workspace, candidate_root):
            raise ArtifactConfigurationError(
                "artifact root and repository workspace must be disjoint"
            )
        if raw_root.exists() and raw_root.is_symlink():
            raise ArtifactConfigurationError("artifact root cannot be a symlink")
        raw_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root = raw_root.resolve(strict=True)
        if _is_relative_to(self.root, workspace) or _is_relative_to(workspace, self.root):
            raise ArtifactConfigurationError(
                "artifact root and repository workspace must be disjoint"
            )
        metadata = self.root.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_mode & 0o077
            or (hasattr(os, "geteuid") and metadata.st_uid != os.geteuid())
        ):
            raise ArtifactConfigurationError("artifact root permissions must be 0700")
        self._master_key = bytes(master_key)
        self._store = store

    def _tenant_key(self, organization_id: str, project_id: str) -> bytes:
        context = canonical_json(
            {
                "schema": "liltweak-artifact-key-v1",
                "organization_id": organization_id,
                "project_id": project_id,
            }
        ).encode()
        return hmac.new(self._master_key, context, hashlib.sha256).digest()

    @staticmethod
    def _aad(
        *,
        artifact_id: str,
        job_id: str,
        organization_id: str,
        project_id: str,
        kind: ArtifactKind,
    ) -> bytes:
        return canonical_json(
            {
                "schema_version": "3.0",
                "artifact_id": artifact_id,
                "job_id": job_id,
                "organization_id": organization_id,
                "project_id": project_id,
                "kind": kind.value,
            }
        ).encode()

    def put_bytes(
        self,
        *,
        job: JobRecord,
        kind: ArtifactKind,
        media_type: str,
        plaintext: bytes,
    ) -> ArtifactRecord:
        artifact_id = f"art_{secrets.token_urlsafe(18)}"
        storage_key = f"{artifact_id}.lta"
        nonce = secrets.token_bytes(12)
        aad = self._aad(
            artifact_id=artifact_id,
            job_id=job.id,
            organization_id=job.task.organization_id,
            project_id=job.task.project_id,
            kind=kind,
        )
        key = self._tenant_key(job.task.organization_id, job.task.project_id)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        temporary_key = f".{artifact_id}.{secrets.token_urlsafe(8)}.tmp"
        temporary_path = self.root / temporary_key
        final_path = self.root / storage_key
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary_path, flags, 0o600)
        try:
            view = memoryview(ciphertext)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        except Exception:
            os.close(descriptor)
            temporary_path.unlink(missing_ok=True)
            raise
        else:
            os.close(descriptor)
        try:
            if final_path.exists():
                raise ArtifactIntegrityError("opaque artifact storage collision")
            os.rename(temporary_path, final_path)
            directory_descriptor = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
            artifact = ArtifactRecord(
                id=artifact_id,
                job_id=job.id,
                organization_id=job.task.organization_id,
                project_id=job.task.project_id,
                kind=kind,
                status=ArtifactStatus.READY,
                media_type=media_type,
                plaintext_sha256=hashlib.sha256(plaintext).hexdigest(),
                ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
                plaintext_bytes=len(plaintext),
                storage_bytes=len(ciphertext),
                encryption_version="aes-256-gcm:v1",
            )
            self._store.save_artifact(
                artifact,
                storage_key=storage_key,
                nonce_b64=base64.urlsafe_b64encode(nonce).decode("ascii"),
            )
        except Exception:
            temporary_path.unlink(missing_ok=True)
            final_path.unlink(missing_ok=True)
            raise
        return artifact

    def verify_and_decrypt(self, artifact: ArtifactRecord) -> bytes:
        storage_key, nonce_b64 = self._store.get_artifact_storage(artifact.id)
        if storage_key != f"{artifact.id}.lta":
            raise ArtifactIntegrityError("artifact storage identity is invalid")
        path = self.root / storage_key
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ArtifactIntegrityError("artifact ciphertext is unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or metadata.st_size != artifact.storage_bytes
        ):
            raise ArtifactIntegrityError("artifact ciphertext metadata is invalid")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            observed = os.fstat(descriptor)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_dev != metadata.st_dev
                or observed.st_ino != metadata.st_ino
                or observed.st_size != metadata.st_size
            ):
                raise ArtifactIntegrityError("artifact changed before verification")
            chunks: list[bytes] = []
            remaining = observed.st_size
            while remaining:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    raise ArtifactIntegrityError("artifact ciphertext is truncated")
                chunks.append(chunk)
                remaining -= len(chunk)
            final = os.fstat(descriptor)
            if final.st_size != observed.st_size or final.st_mtime_ns != observed.st_mtime_ns:
                raise ArtifactIntegrityError("artifact changed during verification")
        finally:
            os.close(descriptor)
        ciphertext = b"".join(chunks)
        if not hmac.compare_digest(
            hashlib.sha256(ciphertext).hexdigest(),
            artifact.ciphertext_sha256,
        ):
            raise ArtifactIntegrityError("artifact ciphertext digest is invalid")
        nonce = base64.urlsafe_b64decode(nonce_b64.encode("ascii"))
        key = self._tenant_key(artifact.organization_id, artifact.project_id)
        aad = self._aad(
            artifact_id=artifact.id,
            job_id=artifact.job_id,
            organization_id=artifact.organization_id,
            project_id=artifact.project_id,
            kind=artifact.kind,
        )
        try:
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
        except Exception as exc:
            raise ArtifactIntegrityError("artifact authentication failed") from exc
        if len(plaintext) != artifact.plaintext_bytes or not hmac.compare_digest(
            hashlib.sha256(plaintext).hexdigest(),
            artifact.plaintext_sha256,
        ):
            raise ArtifactIntegrityError("artifact plaintext digest is invalid")
        return plaintext

    def quarantine(self, artifact: ArtifactRecord) -> None:
        storage_key, _nonce_b64 = self._store.get_artifact_storage(artifact.id)
        if storage_key == f"{artifact.id}.lta":
            (self.root / storage_key).unlink(missing_ok=True)
        self._store.quarantine_artifact(artifact.id)
