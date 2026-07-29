from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from typing import Any

from .models import EvidenceRecord
from .store import SQLiteStore, canonical_json


class EvidenceChainError(ValueError):
    pass


class EvidenceLedger:
    def __init__(self, store: SQLiteStore, signing_key: bytes | None = None) -> None:
        self._store = store
        self._signing_key = secrets.token_bytes(32) if signing_key is None else signing_key
        if not isinstance(self._signing_key, bytes) or len(self._signing_key) != 32:
            raise ValueError("evidence signing key must contain exactly 32 bytes")
        self.durable_integrity = signing_key is not None

    def append(self, job_id: str, event_type: str, payload: dict[str, Any]) -> EvidenceRecord:
        return self._store.append_evidence(
            evidence_id=f"ev_{secrets.token_urlsafe(18)}",
            job_id=job_id,
            event_type=event_type,
            payload=payload,
            created_at=datetime.now(UTC),
            signing_key=self._signing_key,
        )

    def list(self, job_id: str) -> list[EvidenceRecord]:
        return self._store.list_evidence(job_id)

    def verify(self, job_id: str) -> bool:
        records = self.list(job_id)
        anchor = self._store.get_evidence_anchor(job_id)
        if not records or anchor is None:
            raise EvidenceChainError("evidence chain or authenticated anchor is missing")
        previous_hash: str | None = None
        expected_sequence = 1
        for record in records:
            if record.sequence != expected_sequence or record.previous_hash != previous_hash:
                raise EvidenceChainError("evidence sequence or previous hash is invalid")
            hash_input = {
                "id": record.id,
                "job_id": record.job_id,
                "sequence": record.sequence,
                "event_type": record.event_type,
                "payload": record.payload,
                "previous_hash": record.previous_hash,
                "created_at": record.created_at.isoformat(),
            }
            expected_hash = hashlib.sha256(canonical_json(hash_input).encode()).hexdigest()
            if not secrets.compare_digest(record.record_hash, expected_hash):
                raise EvidenceChainError("evidence record hash is invalid")
            previous_hash = record.record_hash
            expected_sequence += 1
        anchor_sequence, anchor_head, anchor_signature = anchor
        anchor_payload = {
            "schema": "liltweak-evidence-anchor-v1",
            "job_id": job_id,
            "sequence": anchor_sequence,
            "head_hash": anchor_head,
        }
        expected_signature = hmac.new(
            self._signing_key,
            canonical_json(anchor_payload).encode(),
            hashlib.sha256,
        ).hexdigest()
        if (
            anchor_sequence != len(records)
            or anchor_head != previous_hash
            or not secrets.compare_digest(anchor_signature, expected_signature)
        ):
            raise EvidenceChainError("evidence chain does not match its authenticated anchor")
        return True
