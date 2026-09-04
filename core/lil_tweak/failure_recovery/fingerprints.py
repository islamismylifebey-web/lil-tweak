"""Canonical identities for failure signals and recovery decisions."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .contracts import FailureSignal, RecoveryContext


def _primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, MappingProxyType):
        return {str(key): _primitive(item) for key, item in value.items()}
    if isinstance(value, Mapping):
        return {
            str(key): _primitive(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (tuple, list)):
        return [_primitive(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_primitive(item) for item in value), key=repr)
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        _primitive(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def failure_fingerprint(signal: FailureSignal, context: RecoveryContext) -> str:
    """Fingerprint one causal failure without unstable prose or attempt metadata."""

    code = signal.code.value if hasattr(signal.code, "value") else str(signal.code)
    payload = {
        "schemaVersion": "failure-fingerprint-v1",
        "binding": {
            "ownerId": context.owner_id,
            "taskId": context.task_id,
            "dagRunId": context.dag_run_id,
            "nodeId": context.node_id,
            "sourceRevision": context.source_revision,
            "planDigest": context.plan_digest,
            "candidateDigest": context.candidate_digest,
            "contractDigest": context.contract_digest,
            "executionId": context.execution_id,
            "resourceId": context.resource_id,
        },
        "failure": {
            "code": code,
            "exceptionType": signal.exception_type,
            "failedChecks": signal.failed_checks,
            "evidence": [
                {
                    "evidenceId": item.evidence_id,
                    "kind": item.kind,
                    "sha256": item.sha256,
                }
                for item in signal.evidence
            ],
            "transient": signal.transient,
            "partialMutation": signal.partial_mutation,
            "integrityFailure": signal.integrity_failure,
            "securitySensitive": signal.security_sensitive,
        },
    }
    return canonical_digest(payload)


def decision_digest(payload: Mapping[str, Any]) -> str:
    return canonical_digest({"schemaVersion": "recovery-decision-digest-v1", **payload})
