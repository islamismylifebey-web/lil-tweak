import {
  PINNED_RUNNER_ID,
  type SignedDispatchAttestation,
} from "./attestation";
import {
  exactRecord,
  InputError,
  integerField,
  requireMatch,
  stringField,
} from "./validation";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const EXECUTION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export type ExecutionStatus =
  | "OFFERED"
  | "CLAIMED"
  | "EVIDENCE_RECORDED"
  | "CANCEL_REQUESTED"
  | "EXPIRED";

export interface OfferRequest {
  attestation: SignedDispatchAttestation;
}

export interface ClaimRequest {
  execution_id: string;
  attempt_nonce: string;
}

export interface RunnerEvidence {
  schema_version: "lil-tweak.runner-evidence/v1";
  outcome: "succeeded" | "failed" | "cancelled";
  operation_digest: string;
  stdout_digest: string;
  stderr_digest: string;
  receipt_digest: string;
  exit_code: number;
  started_at_ms: number;
  finished_at_ms: number;
}

export interface EvidenceRequest extends ClaimRequest {
  evidence: RunnerEvidence;
}

export interface CancelRequest {
  reason_digest: string;
}

export interface ExecutionSummary {
  execution_id: string;
  runner_id: typeof PINNED_RUNNER_ID;
  runner_role: "role-tweak-runner";
  status: ExecutionStatus;
  lease_digest: string;
  contract_digest: string;
  commands_digest: string;
  approval_digest: string;
  policy_digest: string;
  expires_at_ms: number;
  claim_receipt_digest?: string;
  evidence_digest?: string;
  evidence_outcome?: RunnerEvidence["outcome"];
  cancellation_reason_digest?: string;
}

export interface OfferSummary {
  execution_id: string;
  runner_id: typeof PINNED_RUNNER_ID;
  status: "OFFERED";
  lease_digest: string;
  contract_digest: string;
  commands_digest: string;
  expires_at_ms: number;
}

export interface ClaimSummary extends ExecutionSummary {
  status: "CLAIMED";
  claim_receipt_digest: string;
}

export interface EvidenceSummary {
  execution_id: string;
  status: "EVIDENCE_RECORDED";
  evidence_digest: string;
}

export interface CancelSummary {
  execution_id: string;
  status: "CANCEL_REQUESTED";
  reason_digest: string;
}

function parseClaimIdentifiers(value: unknown, label: string): ClaimRequest {
  const record = exactRecord(value, ["execution_id", "attempt_nonce"], label);
  return {
    execution_id: requireMatch(
      stringField(record, "execution_id", label),
      EXECUTION_ID_PATTERN,
      "execution_id",
    ),
    attempt_nonce: requireMatch(
      stringField(record, "attempt_nonce", label),
      NONCE_PATTERN,
      "attempt_nonce",
    ),
  };
}

export function parseOfferRequest(value: unknown): OfferRequest {
  const record = exactRecord(value, ["attestation"], "offer request");
  return { attestation: record.attestation as SignedDispatchAttestation };
}

export function parseClaimRequest(value: unknown): ClaimRequest {
  return parseClaimIdentifiers(value, "claim request");
}

export function parseEvidenceRequest(value: unknown): EvidenceRequest {
  const record = exactRecord(
    value,
    ["execution_id", "attempt_nonce", "evidence"],
    "evidence request",
  );
  const identifiers = parseClaimIdentifiers(
    {
      execution_id: record.execution_id,
      attempt_nonce: record.attempt_nonce,
    },
    "evidence request",
  );
  const evidence = exactRecord(
    record.evidence,
    [
      "schema_version",
      "outcome",
      "operation_digest",
      "stdout_digest",
      "stderr_digest",
      "receipt_digest",
      "exit_code",
      "started_at_ms",
      "finished_at_ms",
    ],
    "evidence",
  );
  const outcome = stringField(evidence, "outcome", "evidence");
  if (outcome !== "succeeded" && outcome !== "failed" && outcome !== "cancelled") {
    throw new InputError("evidence.outcome is invalid");
  }
  if (
    stringField(evidence, "schema_version", "evidence") !==
    "lil-tweak.runner-evidence/v1"
  ) {
    throw new InputError("evidence schema is invalid");
  }
  const evidenceDigests = [
    "operation_digest",
    "stdout_digest",
    "stderr_digest",
    "receipt_digest",
  ] as const;
  const digests = Object.fromEntries(
    evidenceDigests.map((field) => [
      field,
      requireMatch(
        stringField(evidence, field, "evidence"),
        DIGEST_PATTERN,
        field,
      ),
    ]),
  ) as Record<(typeof evidenceDigests)[number], string>;
  const startedAt = integerField(evidence, "started_at_ms", "evidence");
  const finishedAt = integerField(evidence, "finished_at_ms", "evidence");
  if (startedAt > finishedAt) {
    throw new InputError("evidence timestamps are not ordered");
  }
  const exitCode = integerField(evidence, "exit_code", "evidence");
  if (exitCode < 0 || exitCode > 255) {
    throw new InputError("evidence exit code is invalid");
  }
  return {
    ...identifiers,
    evidence: {
      schema_version: "lil-tweak.runner-evidence/v1",
      outcome,
      ...digests,
      exit_code: exitCode,
      started_at_ms: startedAt,
      finished_at_ms: finishedAt,
    },
  };
}

export function parseCancelRequest(value: unknown): CancelRequest {
  const record = exactRecord(value, ["reason_digest"], "cancel request");
  return {
    reason_digest: requireMatch(
      stringField(record, "reason_digest", "cancel request"),
      DIGEST_PATTERN,
      "reason_digest",
    ),
  };
}

export function parseExecutionId(value: string): string {
  return requireMatch(value, EXECUTION_ID_PATTERN, "execution_id");
}
