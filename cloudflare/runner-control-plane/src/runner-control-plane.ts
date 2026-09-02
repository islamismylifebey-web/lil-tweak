import { DurableObject } from "cloudflare:workers";
import {
  canonicalJson,
  PINNED_RUNNER_ID,
  PINNED_RUNNER_ROLE,
  sha256Hex,
  type SignedDispatchAttestation,
  type VerifiedDispatchAttestation,
} from "./attestation";
import type {
  CancelSummary,
  ClaimRequest,
  ClaimSummary,
  EvidenceRequest,
  EvidenceSummary,
  ExecutionStatus,
  ExecutionSummary,
  OfferSummary,
  RunnerOfferSummary,
  RunnerEvidence,
  RunnerJobManifest,
} from "./protocol";
import type { Env } from "./index";
import { MAX_RUNNER_REQUEST_SKEW_MS, type RunnerOperation } from "./runner-auth";

type FailureCode = "not_found" | "conflict" | "expired";
export type ControlPlaneResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: FailureCode };

interface ExecutionRow extends Record<string, string | number | null> {
  execution_id: string;
  runner_id: string;
  runner_role: string;
  lease_digest: string;
  contract_digest: string;
  commands_digest: string;
  approval_digest: string;
  policy_digest: string;
  attempt_nonce: string;
  attestation_digest: string;
  attestation_json: string | null;
  manifest_json: string | null;
  issued_at_ms: number;
  expires_at_ms: number;
  status: ExecutionStatus;
  nonce_consumed_at_ms: number | null;
  claimed_at_ms: number | null;
  claim_receipt_digest: string | null;
  evidence_digest: string | null;
  evidence_outcome: RunnerEvidence["outcome"] | null;
  cancellation_reason_digest: string | null;
  updated_at_ms: number;
}

function asRow(value: ExecutionRow | undefined): ExecutionRow | undefined {
  return value;
}

/** A deterministic, SQLite-backed coordination atom for the single pinned runner. */
export class RunnerControlPlane extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS executions (
          execution_id TEXT PRIMARY KEY,
          runner_id TEXT NOT NULL,
          runner_role TEXT NOT NULL,
          lease_digest TEXT NOT NULL,
          contract_digest TEXT NOT NULL,
          commands_digest TEXT NOT NULL,
          approval_digest TEXT NOT NULL,
          policy_digest TEXT NOT NULL,
          attempt_nonce TEXT NOT NULL UNIQUE,
          attestation_digest TEXT NOT NULL UNIQUE,
          attestation_json TEXT,
          manifest_json TEXT,
          issued_at_ms INTEGER NOT NULL,
          expires_at_ms INTEGER NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('OFFERED', 'CLAIMED', 'EVIDENCE_RECORDED', 'CANCEL_REQUESTED', 'EXPIRED')),
          nonce_consumed_at_ms INTEGER,
          claimed_at_ms INTEGER,
          claim_receipt_digest TEXT,
          evidence_digest TEXT,
          evidence_outcome TEXT,
          cancellation_reason_digest TEXT,
          updated_at_ms INTEGER NOT NULL
        )
      `);
      const columns = new Set(
        this.ctx.storage.sql
          .exec<{ name: string }>("PRAGMA table_info(executions)")
          .toArray()
          .map((column) => column.name),
      );
      if (!columns.has("attestation_json")) {
        this.ctx.storage.sql.exec("ALTER TABLE executions ADD COLUMN attestation_json TEXT");
      }
      if (!columns.has("manifest_json")) {
        this.ctx.storage.sql.exec("ALTER TABLE executions ADD COLUMN manifest_json TEXT");
      }
      this.ctx.storage.sql.exec(
        "CREATE INDEX IF NOT EXISTS idx_executions_expiry ON executions(expires_at_ms)",
      );
      this.ctx.storage.sql.exec(`
        CREATE TABLE IF NOT EXISTS runner_request_nonces (
          request_nonce TEXT PRIMARY KEY,
          operation TEXT NOT NULL CHECK(operation IN ('poll', 'claim', 'status', 'evidence')),
          issued_at_ms INTEGER NOT NULL,
          consumed_at_ms INTEGER NOT NULL
        )
      `);
      this.ctx.storage.sql.exec(
        "CREATE INDEX IF NOT EXISTS idx_runner_request_nonces_consumed ON runner_request_nonces(consumed_at_ms)",
      );
    });
  }

  private selectExecution(executionId: string): ExecutionRow | undefined {
    return asRow(
      this.ctx.storage.sql
        .exec<ExecutionRow>(
          `SELECT execution_id, runner_id, runner_role, lease_digest, contract_digest,
                  commands_digest, approval_digest, policy_digest, attempt_nonce,
                  attestation_digest, attestation_json, manifest_json,
                  issued_at_ms, expires_at_ms, status, claimed_at_ms,
                  nonce_consumed_at_ms,
                  claim_receipt_digest, evidence_digest, evidence_outcome,
                  cancellation_reason_digest, updated_at_ms
           FROM executions WHERE execution_id = ?`,
          executionId,
        )
        .toArray()[0],
    );
  }

  private updateExpiry(row: ExecutionRow, nowMs: number): ExecutionRow {
    if (
      row.expires_at_ms <= nowMs &&
      (row.status === "OFFERED" || row.status === "CLAIMED")
    ) {
      this.ctx.storage.sql.exec(
        "UPDATE executions SET status = 'EXPIRED', updated_at_ms = ? WHERE execution_id = ?",
        nowMs,
        row.execution_id,
      );
      return { ...row, status: "EXPIRED", updated_at_ms: nowMs };
    }
    return row;
  }

  private consumeRunnerRequestNonce(
    requestNonce: string,
    operation: RunnerOperation,
    issuedAtMs: number,
    nowMs: number,
  ): boolean {
    this.ctx.storage.sql.exec(
      "DELETE FROM runner_request_nonces WHERE consumed_at_ms < ?",
      nowMs - 2 * MAX_RUNNER_REQUEST_SKEW_MS,
    );
    const existing = this.ctx.storage.sql
      .exec<{ request_nonce: string }>(
        "SELECT request_nonce FROM runner_request_nonces WHERE request_nonce = ?",
        requestNonce,
      )
      .toArray()[0];
    if (existing !== undefined) {
      return false;
    }
    this.ctx.storage.sql.exec(
      `INSERT INTO runner_request_nonces
       (request_nonce, operation, issued_at_ms, consumed_at_ms)
       VALUES (?, ?, ?, ?)`,
      requestNonce,
      operation,
      issuedAtMs,
      nowMs,
    );
    return true;
  }

  private summary(row: ExecutionRow): ExecutionSummary {
    const summary: ExecutionSummary = {
      execution_id: row.execution_id,
      runner_id: PINNED_RUNNER_ID,
      runner_role: PINNED_RUNNER_ROLE,
      status: row.status,
      lease_digest: row.lease_digest,
      contract_digest: row.contract_digest,
      commands_digest: row.commands_digest,
      approval_digest: row.approval_digest,
      policy_digest: row.policy_digest,
      expires_at_ms: row.expires_at_ms,
    };
    if (row.claim_receipt_digest !== null) {
      summary.claim_receipt_digest = row.claim_receipt_digest;
    }
    if (row.evidence_digest !== null) {
      summary.evidence_digest = row.evidence_digest;
    }
    if (row.evidence_outcome !== null) {
      summary.evidence_outcome = row.evidence_outcome;
    }
    if (row.cancellation_reason_digest !== null) {
      summary.cancellation_reason_digest = row.cancellation_reason_digest;
    }
    return summary;
  }

  async offer(
    verified: VerifiedDispatchAttestation,
    manifest: RunnerJobManifest,
    nowMs: number,
  ): Promise<ControlPlaneResult<OfferSummary>> {
    const { attestation: payload } = verified.attestation;
    let result: ControlPlaneResult<OfferSummary> = {
      ok: false,
      error: "conflict",
    };
    this.ctx.storage.transactionSync(() => {
      const existing = this.selectExecution(payload.execution_id);
      const nonceTaken = this.ctx.storage.sql
        .exec<{ attempt_nonce: string }>(
          "SELECT attempt_nonce FROM executions WHERE attempt_nonce = ?",
          payload.attempt_nonce,
        )
        .toArray()[0];
      if (existing !== undefined || nonceTaken !== undefined) {
        result = { ok: false, error: "conflict" };
        return;
      }
      this.ctx.storage.sql.exec(
        `INSERT INTO executions (
          execution_id, runner_id, runner_role, lease_digest, contract_digest,
          commands_digest, approval_digest, policy_digest, attempt_nonce,
          attestation_digest, attestation_json, manifest_json,
          issued_at_ms, expires_at_ms, status, updated_at_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OFFERED', ?)`,
        payload.execution_id,
        PINNED_RUNNER_ID,
        PINNED_RUNNER_ROLE,
        payload.lease_digest,
        payload.contract_digest,
        payload.commands_digest,
        payload.approval_digest,
        payload.policy_digest,
        payload.attempt_nonce,
        verified.attestation_digest,
        canonicalJson(verified.attestation),
        canonicalJson(manifest),
        payload.issued_at_ms,
        payload.expires_at_ms,
        nowMs,
      );
      result = {
        ok: true,
        value: {
          execution_id: payload.execution_id,
          runner_id: PINNED_RUNNER_ID,
          status: "OFFERED",
          lease_digest: payload.lease_digest,
          contract_digest: payload.contract_digest,
          commands_digest: payload.commands_digest,
          expires_at_ms: payload.expires_at_ms,
        },
      };
    });
    return result;
  }

  async getNextOffer(
    requestNonce: string,
    issuedAtMs: number,
    nowMs: number,
  ): Promise<ControlPlaneResult<RunnerOfferSummary>> {
    let result: ControlPlaneResult<RunnerOfferSummary> = {
      ok: false,
      error: "not_found",
    };
    this.ctx.storage.transactionSync(() => {
      if (!this.consumeRunnerRequestNonce(requestNonce, "poll", issuedAtMs, nowMs)) {
        result = { ok: false, error: "conflict" };
        return;
      }
      this.ctx.storage.sql.exec(
        `UPDATE executions
         SET status = 'EXPIRED', updated_at_ms = ?
         WHERE status = 'OFFERED' AND expires_at_ms <= ?`,
        nowMs,
        nowMs,
      );
      const row = this.ctx.storage.sql
        .exec<ExecutionRow>(
          `SELECT execution_id, runner_id, runner_role, lease_digest, contract_digest,
                  commands_digest, approval_digest, policy_digest, attempt_nonce,
                  attestation_digest, attestation_json, manifest_json,
                  issued_at_ms, expires_at_ms, status, claimed_at_ms,
                  nonce_consumed_at_ms, claim_receipt_digest, evidence_digest,
                  evidence_outcome, cancellation_reason_digest, updated_at_ms
           FROM executions
           WHERE status = 'OFFERED' AND expires_at_ms > ?
             AND attestation_json IS NOT NULL AND manifest_json IS NOT NULL
           ORDER BY issued_at_ms, execution_id
           LIMIT 1`,
          nowMs,
        )
        .toArray()[0];
      if (row === undefined || row.attestation_json === null || row.manifest_json === null) {
        return;
      }
      result = {
        ok: true,
        value: {
          execution_id: row.execution_id,
          status: "OFFERED",
          expires_at_ms: row.expires_at_ms,
          attestation: JSON.parse(row.attestation_json) as SignedDispatchAttestation,
          manifest: JSON.parse(row.manifest_json) as RunnerJobManifest,
        },
      };
    });
    return result;
  }

  async claim(
    request: ClaimRequest,
    requestNonce: string,
    issuedAtMs: number,
    nowMs: number,
  ): Promise<ControlPlaneResult<ClaimSummary>> {
    const receiptDigest = await sha256Hex(
      canonicalJson({
        execution_id: request.execution_id,
        attempt_nonce: request.attempt_nonce,
        runner_id: PINNED_RUNNER_ID,
        runner_role: PINNED_RUNNER_ROLE,
        claimed_at_ms: nowMs,
      }),
    );
    let result: ControlPlaneResult<ClaimSummary> = {
      ok: false,
      error: "conflict",
    };
    this.ctx.storage.transactionSync(() => {
      if (!this.consumeRunnerRequestNonce(requestNonce, "claim", issuedAtMs, nowMs)) {
        result = { ok: false, error: "conflict" };
        return;
      }
      const selected = this.selectExecution(request.execution_id);
      if (selected === undefined) {
        result = { ok: false, error: "not_found" };
        return;
      }
      const row = this.updateExpiry(selected, nowMs);
      if (row.status === "EXPIRED") {
        result = { ok: false, error: "expired" };
        return;
      }
      if (
        row.status !== "OFFERED" ||
        row.nonce_consumed_at_ms !== null ||
        row.attempt_nonce !== request.attempt_nonce
      ) {
        result = { ok: false, error: "conflict" };
        return;
      }
      this.ctx.storage.sql.exec(
        `UPDATE executions
         SET status = 'CLAIMED', nonce_consumed_at_ms = ?, claimed_at_ms = ?, claim_receipt_digest = ?, updated_at_ms = ?
         WHERE execution_id = ? AND status = 'OFFERED' AND attempt_nonce = ? AND nonce_consumed_at_ms IS NULL`,
        nowMs,
        nowMs,
        receiptDigest,
        nowMs,
        row.execution_id,
        request.attempt_nonce,
      );
      result = {
        ok: true,
        value: {
          ...this.summary({
            ...row,
            status: "CLAIMED",
            nonce_consumed_at_ms: nowMs,
            claimed_at_ms: nowMs,
            claim_receipt_digest: receiptDigest,
            updated_at_ms: nowMs,
          }),
          status: "CLAIMED",
          claim_receipt_digest: receiptDigest,
        },
      };
    });
    return result;
  }

  async recordEvidence(
    request: EvidenceRequest,
    evidenceDigest: string,
    requestNonce: string,
    issuedAtMs: number,
    nowMs: number,
  ): Promise<ControlPlaneResult<EvidenceSummary>> {
    let result: ControlPlaneResult<EvidenceSummary> = {
      ok: false,
      error: "conflict",
    };
    this.ctx.storage.transactionSync(() => {
      if (!this.consumeRunnerRequestNonce(requestNonce, "evidence", issuedAtMs, nowMs)) {
        result = { ok: false, error: "conflict" };
        return;
      }
      const selected = this.selectExecution(request.execution_id);
      if (selected === undefined) {
        result = { ok: false, error: "not_found" };
        return;
      }
      const row = this.updateExpiry(selected, nowMs);
      if (row.status === "EXPIRED") {
        result = { ok: false, error: "expired" };
        return;
      }
      if (
        row.status !== "CLAIMED" ||
        row.attempt_nonce !== request.attempt_nonce ||
        row.commands_digest !== request.evidence.operation_digest
      ) {
        result = { ok: false, error: "conflict" };
        return;
      }
      this.ctx.storage.sql.exec(
        `UPDATE executions
         SET status = 'EVIDENCE_RECORDED', evidence_digest = ?, evidence_outcome = ?, updated_at_ms = ?
         WHERE execution_id = ? AND status = 'CLAIMED'`,
        evidenceDigest,
        request.evidence.outcome,
        nowMs,
        row.execution_id,
      );
      result = {
        ok: true,
        value: {
          execution_id: row.execution_id,
          status: "EVIDENCE_RECORDED",
          evidence_digest: evidenceDigest,
        },
      };
    });
    return result;
  }

  async getStatus(
    executionId: string,
    nowMs: number,
  ): Promise<ControlPlaneResult<ExecutionSummary>> {
    let result: ControlPlaneResult<ExecutionSummary> = {
      ok: false,
      error: "not_found",
    };
    this.ctx.storage.transactionSync(() => {
      const selected = this.selectExecution(executionId);
      if (selected === undefined) {
        result = { ok: false, error: "not_found" };
        return;
      }
      result = { ok: true, value: this.summary(this.updateExpiry(selected, nowMs)) };
    });
    return result;
  }

  async getRunnerStatus(
    executionId: string,
    requestNonce: string,
    issuedAtMs: number,
    nowMs: number,
  ): Promise<ControlPlaneResult<ExecutionSummary>> {
    let result: ControlPlaneResult<ExecutionSummary> = {
      ok: false,
      error: "not_found",
    };
    this.ctx.storage.transactionSync(() => {
      if (!this.consumeRunnerRequestNonce(requestNonce, "status", issuedAtMs, nowMs)) {
        result = { ok: false, error: "conflict" };
        return;
      }
      const selected = this.selectExecution(executionId);
      if (selected === undefined) {
        result = { ok: false, error: "not_found" };
        return;
      }
      result = { ok: true, value: this.summary(this.updateExpiry(selected, nowMs)) };
    });
    return result;
  }

  async cancel(
    executionId: string,
    reasonDigest: string,
    nowMs: number,
  ): Promise<ControlPlaneResult<CancelSummary>> {
    let result: ControlPlaneResult<CancelSummary> = {
      ok: false,
      error: "not_found",
    };
    this.ctx.storage.transactionSync(() => {
      const selected = this.selectExecution(executionId);
      if (selected === undefined) {
        result = { ok: false, error: "not_found" };
        return;
      }
      const row = this.updateExpiry(selected, nowMs);
      if (row.status === "EXPIRED") {
        result = { ok: false, error: "expired" };
        return;
      }
      if (row.status === "CANCEL_REQUESTED") {
        if (row.cancellation_reason_digest === reasonDigest) {
          result = {
            ok: true,
            value: {
              execution_id: executionId,
              status: "CANCEL_REQUESTED",
              reason_digest: reasonDigest,
            },
          };
          return;
        }
        result = { ok: false, error: "conflict" };
        return;
      }
      if (row.status !== "OFFERED" && row.status !== "CLAIMED") {
        result = { ok: false, error: "conflict" };
        return;
      }
      this.ctx.storage.sql.exec(
        `UPDATE executions
         SET status = 'CANCEL_REQUESTED', cancellation_reason_digest = ?, updated_at_ms = ?
         WHERE execution_id = ?`,
        reasonDigest,
        nowMs,
        executionId,
      );
      result = {
        ok: true,
        value: {
          execution_id: executionId,
          status: "CANCEL_REQUESTED",
          reason_digest: reasonDigest,
        },
      };
    });
    return result;
  }
}
