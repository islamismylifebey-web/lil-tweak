import {
  type EngineerMode,
  type ApprovalProposal,
  type EngineeringEvidence,
  type EngineeringJob,
  type EngineeringJobDetail,
  type EngineeringSource,
  type DecisionIntent,
  type JobState,
  JOB_STATES,
  MAX_ENGINEERING_EVIDENCE_BYTES,
  approvalProposalsEqual,
  coreSnapshotTransitionAllowed,
  coreSnapshotAlreadyMirrored,
  decisionAuthorizesCoreState,
  engineeringObjectKey,
  newEngineeringId,
  parseApprovalProposal,
  safeSourceFilename,
  transitionAllowed,
} from "./engineering.ts";
import { engineeringCreateRequestDigest, engineeringJobIdForCreate, type EngineeringJobCreate, type EngineeringStore, type SourceCreateInput } from "./engineering-store.ts";
import { sha256Hex } from "./core-signing.ts";
import { parseGitSource } from "./engineering-input.ts";

const MAX_SOURCES = 10;
const MAX_SOURCE_BYTES = 25_000_000;
const MAX_JOB_SOURCE_BYTES = 100_000_000;
const MAX_AUDIT_DETAIL_BYTES = 16_000;
const EVIDENCE_CATEGORIES = new Set<EngineeringEvidence["category"]>([
  "plan",
  "patch",
  "tests",
  "manifest",
  "summary",
  "log",
]);
const CREATE_KEY = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[a-f0-9]{64}$/;

export class EngineeringNotFoundError extends Error {
  constructor() {
    super("Engineering job was not found.");
  }
}

export class EngineeringConflictError extends Error {
  constructor(message = "Engineering job changed. Refresh and try again.") {
    super(message);
  }
}

export interface CoreEvidenceInput {
  id: string;
  category: EngineeringEvidence["category"];
  filename: string;
  mediaType: string;
  sizeBytes: number;
  sha256: string;
  createdAt: string;
  corePath: string;
}

export interface CoreSnapshotInput {
  state: JobState;
  summary: string;
  coreRevision: number;
  proposalDigest?: string | null;
  sourceDigest?: string | null;
  approvalProposal?: ApprovalProposal | null;
  approvalConsumed?: boolean;
  evidence?: CoreEvidenceInput[];
}

type JobRow = {
  id: string;
  project_id: string | null;
  git_repository_url: string | null;
  git_commit: string | null;
  mode: EngineerMode;
  prompt_preview: string;
  state: JobState;
  revision: number;
  summary: string;
  proposal_digest: string | null;
  source_digest: string | null;
  approval_proposal_json: string | null;
  approval_consumed: number;
  remote_job_id: string | null;
  core_revision: number | null;
  request_r2_key: string;
  source_r2_prefix: string;
  evidence_r2_prefix: string;
  created_at: string;
  updated_at: string;
};

type SourceRow = {
  id: string;
  job_id: string;
  filename: string;
  media_type: string;
  size_bytes: number;
  sha256: string | null;
  uploaded_at: string | null;
  r2_etag: string | null;
  revision_applied: number;
};

type EvidenceRow = {
  id: string;
  job_id: string;
  category: EngineeringEvidence["category"];
  filename: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  created_at: string;
};

type EventRow = { id: string; event_type: string; summary: string; created_at: string };

function now() {
  return new Date().toISOString();
}

function auditId() {
  return `audit:${crypto.randomUUID().replaceAll("-", "")}`;
}

function correlationId() {
  return crypto.randomUUID();
}

function sourceInput(value: SourceCreateInput) {
  const filename = safeSourceFilename(value.filename);
  const mediaType = value.mediaType.trim().toLowerCase() || "application/octet-stream";
  if (mediaType.length > 120 || !/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/.test(mediaType)) {
    throw new Error("Engineering source media type is invalid.");
  }
  if (!Number.isSafeInteger(value.sizeBytes) || value.sizeBytes <= 0 || value.sizeBytes > MAX_SOURCE_BYTES) {
    throw new Error("Each engineering source must be between 1 byte and 25 MB.");
  }
  return { filename, mediaType, sizeBytes: value.sizeBytes };
}

function sourcesInput(values: SourceCreateInput[]) {
  if (!Array.isArray(values) || values.length > MAX_SOURCES) {
    throw new Error("A job may contain up to 10 sources.");
  }
  let total = 0;
  const sources = values.map((value) => {
    const source = sourceInput(value);
    total += source.sizeBytes;
    if (total > MAX_JOB_SOURCE_BYTES) throw new Error("Engineering sources exceed the 100 MB job limit.");
    return source;
  });
  const filenames = sources.map((source) => source.filename.toLocaleLowerCase());
  if (new Set(filenames).size !== filenames.length) {
    throw new Error("Engineering source filenames must be unique.");
  }
  return sources;
}

function mapJob(row: JobRow): EngineeringJob {
  let approvalProposal: ApprovalProposal | null = null;
  if (row.approval_proposal_json) {
    try {
      approvalProposal = parseApprovalProposal(JSON.parse(row.approval_proposal_json));
    } catch {
      throw new Error("Engineering approval storage is invalid.");
    }
  }
  return {
    id: row.id,
    projectId: row.project_id,
    gitSource: row.git_repository_url && row.git_commit
      ? parseGitSource({ repositoryUrl: row.git_repository_url, commit: row.git_commit })
      : null,
    mode: row.mode,
    promptPreview: row.prompt_preview,
    state: row.state,
    revision: row.revision,
    summary: row.summary,
    proposalDigest: row.proposal_digest,
    sourceDigest: row.source_digest,
    approvalProposal,
    approvalConsumed: row.approval_consumed === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapSource(row: SourceRow): EngineeringSource {
  return {
    id: row.id,
    jobId: row.job_id,
    filename: row.filename,
    mediaType: row.media_type,
    sizeBytes: row.size_bytes,
    sha256: row.sha256,
    uploadedAt: row.uploaded_at,
  };
}

function mapEvidence(row: EvidenceRow): EngineeringEvidence {
  return {
    id: row.id,
    jobId: row.job_id,
    category: row.category,
    filename: row.filename,
    mediaType: row.media_type,
    sizeBytes: row.size_bytes,
    sha256: row.sha256,
    createdAt: row.created_at,
  };
}

function safeAuditDetail(value: unknown) {
  const encoded = JSON.stringify(value ?? {});
  if (encoded.length > MAX_AUDIT_DETAIL_BYTES) return "{}";
  return encoded;
}

function evidenceDescriptorMatches(
  stored: EngineeringEvidence,
  incoming: CoreEvidenceInput,
) {
  return stored.id === incoming.id &&
    stored.category === incoming.category &&
    stored.filename === incoming.filename &&
    stored.mediaType === incoming.mediaType &&
    stored.sizeBytes === incoming.sizeBytes &&
    stored.sha256 === incoming.sha256 &&
    stored.createdAt === incoming.createdAt;
}

function appendOnlyEvidenceManifest(
  stored: EngineeringEvidence[],
  incoming: CoreEvidenceInput[],
  frozen: boolean,
) {
  if (incoming.length > 10) throw new Error("Core evidence is invalid.");
  const ids = new Set(incoming.map((item) => item.id));
  const filenames = new Set(incoming.map((item) => item.filename));
  const paths = new Set(incoming.map((item) => item.corePath));
  if (ids.size !== incoming.length || filenames.size !== incoming.length || paths.size !== incoming.length) {
    throw new Error("Core evidence is invalid.");
  }
  const incomingById = new Map(incoming.map((item) => [item.id, item]));
  for (const item of stored) {
    const descriptor = incomingById.get(item.id);
    if (!descriptor || !evidenceDescriptorMatches(item, descriptor)) {
      throw new EngineeringConflictError("Core changed the immutable evidence manifest.");
    }
  }
  if (frozen && stored.length !== incoming.length) {
    throw new EngineeringConflictError("Core changed evidence after owner review.");
  }
}

export class D1EngineeringStore implements EngineeringStore {
  private readonly database: D1Database;

  constructor(database: D1Database) {
    this.database = database;
  }

  async createJob(owner: string, input: EngineeringJobCreate): Promise<EngineeringJobDetail> {
    const fallbackDigest = await engineeringCreateRequestDigest(input);
    return (await this.createJobWithIdempotency(
      owner,
      input,
      crypto.randomUUID(),
      fallbackDigest,
    )).job;
  }

  async createJobWithIdempotency(
    owner: string,
    input: EngineeringJobCreate,
    createKey: string,
    requestDigest: string,
  ): Promise<{ job: EngineeringJobDetail; created: boolean }> {
    if (!CREATE_KEY.test(createKey) || !SHA256.test(requestDigest)) {
      throw new Error("Engineering creation idempotency is invalid.");
    }
    if (await engineeringCreateRequestDigest(input) !== requestDigest) {
      throw new Error("Engineering creation request digest is invalid.");
    }
    const existing = await this.database.prepare(
      "SELECT id, create_request_digest FROM engineering_jobs WHERE owner_key=? AND create_idempotency_key=? LIMIT 1",
    ).bind(owner, createKey).first<{ id: string; create_request_digest: string }>();
    if (existing) {
      if (existing.create_request_digest !== requestDigest) {
        throw new EngineeringConflictError("Engineering creation key was already used for a different request.");
      }
      return { job: await this.requireJob(owner, existing.id), created: false };
    }
    const sources = sourcesInput(input.sources);
    const gitSource = parseGitSource(input.gitSource);
    const createdAt = now();
    const jobId = await engineeringJobIdForCreate(owner, createKey);
    const state: JobState = sources.length ? "uploading" : "queued";
    const requestR2Key = `engineering/${owner}/jobs/${jobId}/request.json`;
    const sourceR2Prefix = `engineering/${owner}/jobs/${jobId}/sources/`;
    const evidenceR2Prefix = `engineering/${owner}/jobs/${jobId}/evidence/`;
    const promptDigest = await sha256Hex(input.prompt);
    const sourceRows = sources.map((source) => ({
      id: newEngineeringId("src"),
      ...source,
    }));
    const statements: D1PreparedStatement[] = [
      this.database.prepare(
        "INSERT INTO engineering_jobs (id, owner_key, create_idempotency_key, create_request_digest, project_id, git_repository_url, git_commit, mode, prompt_digest, prompt_preview, state, revision, summary, proposal_digest, remote_job_id, core_revision, request_r2_key, source_r2_prefix, evidence_r2_prefix, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, NULL, NULL, NULL, ?, ?, ?, ?, ?)",
      ).bind(
        jobId, owner, createKey, requestDigest, input.projectId,
        gitSource?.repositoryUrl ?? null, gitSource?.commit ?? null,
        input.mode, promptDigest, input.prompt.slice(0, 240), state,
        sources.length ? "Waiting for source upload." : "Ready for secure dispatch.",
        requestR2Key, sourceR2Prefix, evidenceR2Prefix, createdAt, createdAt,
      ),
      this.auditStatement(owner, jobId, "owner", "job_created", "Engineering job created.", createdAt),
    ];
    for (const source of sourceRows) {
      statements.push(this.database.prepare(
        "INSERT INTO engineering_sources (id, job_id, owner_key, filename, media_type, size_bytes, r2_key, r2_etag, sha256, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
      ).bind(
        source.id, jobId, owner, source.filename, source.mediaType, source.sizeBytes,
        engineeringObjectKey(owner, jobId, "source", source.id),
      ));
    }
    try {
      await this.database.batch(statements);
    } catch (error) {
      const raced = await this.database.prepare(
        "SELECT id, create_request_digest FROM engineering_jobs WHERE owner_key=? AND create_idempotency_key=? LIMIT 1",
      ).bind(owner, createKey).first<{ id: string; create_request_digest: string }>();
      if (!raced) throw error;
      if (raced.create_request_digest !== requestDigest) {
        throw new EngineeringConflictError("Engineering creation key was already used for a different request.");
      }
      return { job: await this.requireJob(owner, raced.id), created: false };
    }
    return { job: await this.requireJob(owner, jobId), created: true };
  }

  async getJob(owner: string, jobId: string): Promise<EngineeringJobDetail | null> {
    const row = await this.database.prepare(
      "SELECT id, project_id, git_repository_url, git_commit, mode, prompt_preview, state, revision, summary, proposal_digest, source_digest, approval_proposal_json, approval_consumed, remote_job_id, core_revision, request_r2_key, source_r2_prefix, evidence_r2_prefix, created_at, updated_at FROM engineering_jobs WHERE id=? AND owner_key=? LIMIT 1",
    ).bind(jobId, owner).first<JobRow>();
    if (!row) return null;
    const [sources, evidence, events] = await Promise.all([
      this.database.prepare("SELECT id, job_id, filename, media_type, size_bytes, sha256, uploaded_at, r2_etag, revision_applied FROM engineering_sources WHERE job_id=? AND owner_key=? ORDER BY filename ASC").bind(jobId, owner).all<SourceRow>(),
      this.database.prepare("SELECT id, job_id, category, filename, media_type, size_bytes, sha256, created_at FROM engineering_evidence WHERE job_id=? AND owner_key=? ORDER BY created_at ASC").bind(jobId, owner).all<EvidenceRow>(),
      this.database.prepare("SELECT id, event_type, summary, created_at FROM engineering_audit_events WHERE job_id=? AND owner_key=? ORDER BY created_at DESC, id DESC LIMIT 250").bind(jobId, owner).all<EventRow>(),
    ]);
    return {
      ...mapJob(row),
      sources: sources.results.map(mapSource),
      evidence: evidence.results.map(mapEvidence),
      events: events.results.slice().reverse().map((event) => ({ id: event.id, type: event.event_type, summary: event.summary, createdAt: event.created_at })),
    };
  }

  async listJobs(owner: string, limit: number): Promise<EngineeringJob[]> {
    const boundedLimit = Math.max(1, Math.min(50, Math.trunc(limit)));
    const rows = await this.database.prepare(
      "SELECT id, project_id, git_repository_url, git_commit, mode, prompt_preview, state, revision, summary, proposal_digest, source_digest, approval_proposal_json, approval_consumed, remote_job_id, core_revision, request_r2_key, source_r2_prefix, evidence_r2_prefix, created_at, updated_at FROM engineering_jobs WHERE owner_key=? ORDER BY updated_at DESC, id DESC LIMIT ?",
    ).bind(owner, boundedLimit).all<JobRow>();
    return rows.results.map(mapJob);
  }

  async markSourceUploaded(owner: string, jobId: string, sourceId: string, etag: string, sha256: string): Promise<EngineeringJobDetail> {
    const source = await this.database.prepare(
      "SELECT id, job_id, filename, media_type, size_bytes, sha256, uploaded_at, r2_etag, revision_applied FROM engineering_sources WHERE id=? AND job_id=? AND owner_key=? LIMIT 1",
    ).bind(sourceId, jobId, owner).first<SourceRow>();
    if (!source) throw new EngineeringNotFoundError();
    if (!etag) throw new Error("Source upload did not return an object ETag.");
    if (!SHA256.test(sha256)) throw new Error("Source upload did not return a valid SHA-256 digest.");
    if (source.uploaded_at && (source.r2_etag !== etag || source.sha256 !== sha256)) {
      throw new EngineeringConflictError("Engineering source integrity does not match the uploaded object.");
    }

    const updatedAt = now();
    await this.database.batch([
      this.database.prepare(
        "UPDATE engineering_sources SET r2_etag=?, sha256=?, uploaded_at=? WHERE id=? AND job_id=? AND owner_key=? AND uploaded_at IS NULL",
      ).bind(etag, sha256, updatedAt, sourceId, jobId, owner),
      this.database.prepare(
        "UPDATE engineering_jobs SET state=CASE WHEN NOT EXISTS (SELECT 1 FROM engineering_sources WHERE job_id=? AND owner_key=? AND uploaded_at IS NULL) THEN 'queued' ELSE state END, summary=CASE WHEN NOT EXISTS (SELECT 1 FROM engineering_sources WHERE job_id=? AND owner_key=? AND uploaded_at IS NULL) THEN 'Ready for secure dispatch.' ELSE summary END, revision=revision+1, updated_at=? WHERE id=? AND owner_key=? AND state='uploading' AND EXISTS (SELECT 1 FROM engineering_sources WHERE id=? AND job_id=? AND owner_key=? AND uploaded_at IS NOT NULL AND revision_applied=0)",
      ).bind(jobId, owner, jobId, owner, updatedAt, jobId, owner, sourceId, jobId, owner),
      this.database.prepare(
        "INSERT INTO engineering_audit_events (id, job_id, owner_key, actor, event_type, correlation_id, summary, detail_json, created_at) SELECT ?, ?, ?, 'owner', 'source_uploaded', ?, ?, '{}', ? WHERE EXISTS (SELECT 1 FROM engineering_sources WHERE id=? AND job_id=? AND owner_key=? AND uploaded_at IS NOT NULL AND revision_applied=0)",
      ).bind(auditId(), jobId, owner, correlationId(), `${source.filename} uploaded.`, updatedAt, sourceId, jobId, owner),
      this.database.prepare(
        "INSERT INTO engineering_audit_events (id, job_id, owner_key, actor, event_type, correlation_id, summary, detail_json, created_at) SELECT ?, ?, ?, 'worker', 'sources_ready', ?, 'All sources are ready.', '{}', ? WHERE EXISTS (SELECT 1 FROM engineering_sources WHERE id=? AND job_id=? AND owner_key=? AND uploaded_at IS NOT NULL AND revision_applied=0) AND NOT EXISTS (SELECT 1 FROM engineering_sources WHERE job_id=? AND owner_key=? AND uploaded_at IS NULL)",
      ).bind(auditId(), jobId, owner, correlationId(), updatedAt, sourceId, jobId, owner, jobId, owner),
      this.database.prepare(
        "UPDATE engineering_sources SET revision_applied=1 WHERE id=? AND job_id=? AND owner_key=? AND uploaded_at IS NOT NULL AND revision_applied=0",
      ).bind(sourceId, jobId, owner),
    ]);
    const persisted = await this.database.prepare(
      "SELECT id, job_id, filename, media_type, size_bytes, sha256, uploaded_at, r2_etag, revision_applied FROM engineering_sources WHERE id=? AND job_id=? AND owner_key=? LIMIT 1",
    ).bind(sourceId, jobId, owner).first<SourceRow>();
    if (!persisted) throw new EngineeringNotFoundError();
    if (!persisted.uploaded_at || persisted.r2_etag !== etag || persisted.sha256 !== sha256 || persisted.revision_applied !== 1) {
      throw new EngineeringConflictError("Engineering source upload could not be reconciled.");
    }
    return this.requireJob(owner, jobId);
  }

  async transition(owner: string, jobId: string, next: JobState, expectedRevision: number, eventType: string, summary = ""): Promise<EngineeringJobDetail> {
    const current = await this.requireJob(owner, jobId);
    if (current.revision !== expectedRevision) throw new EngineeringConflictError("Stale job revision.");
    if (next === "cancelled" && await this.dispatchIsReserved(owner, jobId)) {
      throw new EngineeringConflictError("Engineering dispatch must be reconciled before cancellation.");
    }
    if (!transitionAllowed(current.state, next)) {
      throw new EngineeringConflictError(`Illegal job transition from ${current.state} to ${next}.`);
    }
    const updatedAt = now();
    const nextSummary = summary || next.replaceAll("_", " ");
    const results = await this.database.batch([
      this.database.prepare(
        "UPDATE engineering_jobs SET state=?, summary=?, revision=revision+1, updated_at=? WHERE id=? AND owner_key=? AND revision=?",
      ).bind(next, nextSummary, updatedAt, jobId, owner, expectedRevision),
      this.database.prepare(
        "INSERT OR IGNORE INTO engineering_audit_events (id, job_id, owner_key, actor, event_type, correlation_id, summary, detail_json, created_at) SELECT ?, ?, ?, 'owner', ?, ?, ?, '{}', ? WHERE EXISTS (SELECT 1 FROM engineering_jobs WHERE id=? AND owner_key=? AND revision=?)",
      ).bind(auditId(), jobId, owner, eventType, `transition:${jobId}:${expectedRevision}`, nextSummary, updatedAt, jobId, owner, expectedRevision + 1),
    ]);
    if (!results[0].meta.changes) throw new EngineeringConflictError("Stale job revision.");
    return this.requireJob(owner, jobId);
  }

  async reserveDispatch(owner: string, jobId: string, expectedRevision: number): Promise<EngineeringJobDetail> {
    const current = await this.requireJob(owner, jobId);
    if (current.state !== "queued") {
      throw new EngineeringConflictError("Engineering job is not ready for dispatch.");
    }
    if (await this.getRemoteJobId(owner, jobId)) return current;
    if (await this.dispatchIsReserved(owner, jobId)) return current;
    if (current.revision !== expectedRevision) throw new EngineeringConflictError("Stale job revision.");
    const reservedAt = now();
    const summary = "Dispatch reserved for private core reconciliation.";
    const results = await this.database.batch([
      this.database.prepare(
        "UPDATE engineering_jobs SET dispatch_reserved_at=?, summary=?, revision=revision+1, updated_at=? WHERE id=? AND owner_key=? AND revision=? AND state='queued' AND remote_job_id IS NULL AND dispatch_reserved_at IS NULL",
      ).bind(reservedAt, summary, reservedAt, jobId, owner, expectedRevision),
      this.database.prepare(
        "INSERT OR IGNORE INTO engineering_audit_events (id, job_id, owner_key, actor, event_type, correlation_id, summary, detail_json, created_at) SELECT ?, ?, ?, 'worker', 'dispatch_reserved', ?, ?, '{}', ? WHERE EXISTS (SELECT 1 FROM engineering_jobs WHERE id=? AND owner_key=? AND revision=? AND dispatch_reserved_at=?)",
      ).bind(
        auditId(), jobId, owner, `dispatch-reserved:${jobId}`, summary, reservedAt,
        jobId, owner, expectedRevision + 1, reservedAt,
      ),
    ]);
    if (!results[0].meta.changes) {
      if (await this.dispatchIsReserved(owner, jobId)) return this.requireJob(owner, jobId);
      throw new EngineeringConflictError("Engineering job changed before dispatch reservation.");
    }
    return this.requireJob(owner, jobId);
  }

  async setRemoteJob(owner: string, jobId: string, expectedRevision: number, remoteJobId: string, summary: string): Promise<EngineeringJobDetail> {
    if (!remoteJobId || remoteJobId.length > 256) {
      throw new Error("Core job response is invalid.");
    }
    const updatedAt = now();
    const results = await this.database.batch([
      this.database.prepare(
        "UPDATE engineering_jobs SET remote_job_id=?, dispatch_reserved_at=NULL, summary=?, revision=revision+1, updated_at=? WHERE id=? AND owner_key=? AND revision=? AND remote_job_id IS NULL AND dispatch_reserved_at IS NOT NULL",
      ).bind(remoteJobId, summary.slice(0, 2_000), updatedAt, jobId, owner, expectedRevision),
      this.database.prepare(
        "INSERT OR IGNORE INTO engineering_audit_events (id, job_id, owner_key, actor, event_type, correlation_id, summary, detail_json, created_at) SELECT ?, ?, ?, 'worker', 'core_dispatched', ?, 'Engineering job dispatched to the private core.', '{}', ? WHERE EXISTS (SELECT 1 FROM engineering_jobs WHERE id=? AND owner_key=? AND revision=? AND remote_job_id=?)",
      ).bind(auditId(), jobId, owner, `dispatch:${jobId}`, updatedAt, jobId, owner, expectedRevision + 1, remoteJobId),
    ]);
    if (!results[0].meta.changes) {
      if (await this.getRemoteJobId(owner, jobId) === remoteJobId) {
        return this.requireJob(owner, jobId);
      }
      throw new EngineeringConflictError("Engineering job was already dispatched or changed.");
    }
    return this.requireJob(owner, jobId);
  }

  async applyCoreSnapshot(
    owner: string,
    jobId: string,
    snapshot: CoreSnapshotInput,
  ): Promise<EngineeringJobDetail> {
    if (
      !JOB_STATES.includes(snapshot.state) ||
      !Number.isSafeInteger(snapshot.coreRevision) ||
      snapshot.coreRevision < 0
    ) {
      throw new Error("Core job state is invalid.");
    }
    const [current, currentCoreRevision, decisionIntent] = await Promise.all([
      this.requireJob(owner, jobId),
      this.getCoreRevision(owner, jobId),
      this.getDecisionIntent(owner, jobId),
    ]);
    if (currentCoreRevision !== null && snapshot.coreRevision < currentCoreRevision) {
      throw new EngineeringConflictError("Core reported a stale job revision.");
    }
    const evidence = snapshot.evidence ?? [];
    appendOnlyEvidenceManifest(
      current.evidence,
      evidence,
      current.approvalProposal !== null || current.state === "awaiting_approval" || current.approvalConsumed,
    );
    const summary = snapshot.summary.trim().slice(0, 2_000) || snapshot.state.replaceAll("_", " ");
    const proposalDigest = snapshot.proposalDigest ?? current.proposalDigest;
    const sourceDigest = snapshot.sourceDigest ?? current.sourceDigest;
    if (sourceDigest !== null && !/^[a-f0-9]{64}$/.test(sourceDigest)) {
      throw new Error("Core source digest is invalid.");
    }
    if (current.sourceDigest && sourceDigest !== current.sourceDigest) {
      throw new EngineeringConflictError("Core reported a different frozen source digest.");
    }
    const approvalProposal = snapshot.approvalProposal
      ? parseApprovalProposal(snapshot.approvalProposal)
      : current.approvalProposal;
    if (approvalProposal && (
      approvalProposal.proposalDigest !== proposalDigest ||
      approvalProposal.sourceDigest !== sourceDigest
    )) {
      throw new Error("Core approval proposal is invalid.");
    }
    if (current.approvalProposal && !approvalProposalsEqual(current.approvalProposal, approvalProposal)) {
      throw new EngineeringConflictError("Core reported a different immutable approval proposal.");
    }
    const approvedIntent = Boolean(
      decisionIntent?.decision === "approve" &&
      proposalDigest &&
      decisionIntent.proposalDigest === proposalDigest,
    );
    if (!current.approvalConsumed && snapshot.approvalConsumed === true && (
      !approvedIntent || current.state !== "applying" || snapshot.state !== "completed"
    )) {
      throw new EngineeringConflictError("Core claimed approval without the exact durable owner decision.");
    }
    if (
      approvalProposal && snapshot.state === "applying" &&
      (!approvedIntent || snapshot.approvalConsumed === true)
    ) {
      throw new EngineeringConflictError("Core reported an invalid pending export.");
    }
    if (
      approvalProposal && snapshot.state === "completed" &&
      (!approvedIntent || snapshot.approvalConsumed !== true)
    ) {
      throw new EngineeringConflictError("Core did not consume the exact approved proposal.");
    }
    const approvalConsumed = current.approvalConsumed || snapshot.approvalConsumed === true;
    const normalizedSnapshot = { ...snapshot, summary, proposalDigest, sourceDigest, approvalProposal, approvalConsumed, evidence };
    if (coreSnapshotAlreadyMirrored(current, currentCoreRevision, normalizedSnapshot)) {
      return current;
    }
    if (currentCoreRevision !== null && snapshot.coreRevision === currentCoreRevision) {
      throw new EngineeringConflictError("Core changed a snapshot without advancing its revision.");
    }
    const authorizedDecision = decisionAuthorizesCoreState(
      decisionIntent,
      current.proposalDigest,
      snapshot.state,
    );
    if (!coreSnapshotTransitionAllowed(current.state, snapshot.state, authorizedDecision)) {
      throw new EngineeringConflictError("Core reported an invalid job transition.");
    }
    const updatedAt = now();
    const mirroredRevision = current.revision + 1;
    const statements: D1PreparedStatement[] = [
      this.database.prepare(
        "UPDATE engineering_jobs SET state=?, summary=?, proposal_digest=?, source_digest=?, approval_proposal_json=?, approval_consumed=?, core_revision=?, revision=revision+1, updated_at=?, last_polled_at=? WHERE id=? AND owner_key=? AND revision=? AND (core_revision IS NULL OR core_revision<=?)",
      ).bind(
        snapshot.state,
        summary,
        proposalDigest,
        sourceDigest,
        approvalProposal ? JSON.stringify(approvalProposal) : null,
        approvalConsumed ? 1 : 0,
        snapshot.coreRevision,
        updatedAt,
        updatedAt,
        jobId,
        owner,
        current.revision,
        snapshot.coreRevision,
      ),
      this.database.prepare(
        "INSERT OR IGNORE INTO engineering_audit_events (id, job_id, owner_key, actor, event_type, correlation_id, summary, detail_json, created_at) SELECT ?, ?, ?, 'core', 'core_status_mirrored', ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM engineering_jobs WHERE id=? AND owner_key=? AND revision=? AND core_revision=?)",
      ).bind(
        auditId(),
        jobId,
        owner,
        `core-snapshot:${jobId}:${snapshot.coreRevision}`,
        `Core state mirrored: ${snapshot.state.replaceAll("_", " ")}.`,
        safeAuditDetail({ state: snapshot.state }),
        updatedAt,
        jobId,
        owner,
        mirroredRevision,
        snapshot.coreRevision,
      ),
    ];
    for (const descriptor of evidence) {
      if (!EVIDENCE_CATEGORIES.has(descriptor.category) || !/^evidence:[0-9a-f]{32}$/.test(descriptor.id)) {
        throw new Error("Core evidence is invalid.");
      }
      const filename = safeSourceFilename(descriptor.filename);
      const mediaType = sourceInput({ filename, mediaType: descriptor.mediaType, sizeBytes: Math.max(1, descriptor.sizeBytes || 1) }).mediaType;
      if (!Number.isSafeInteger(descriptor.sizeBytes) || descriptor.sizeBytes < 0 || descriptor.sizeBytes > MAX_ENGINEERING_EVIDENCE_BYTES || !/^[a-f0-9]{64}$/.test(descriptor.sha256)) {
        throw new Error("Core evidence is invalid.");
      }
      statements.push(this.database.prepare(
        "INSERT OR IGNORE INTO engineering_evidence (id, job_id, owner_key, category, filename, media_type, size_bytes, sha256, r2_key, created_at) SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM engineering_jobs WHERE id=? AND owner_key=? AND revision=? AND core_revision=?)",
      ).bind(
        descriptor.id, jobId, owner, descriptor.category, filename, mediaType, descriptor.sizeBytes, descriptor.sha256,
        engineeringObjectKey(owner, jobId, "evidence", descriptor.id), descriptor.createdAt,
        jobId, owner, mirroredRevision, snapshot.coreRevision,
      ));
    }
    const results = await this.database.batch(statements);
    if (!results[0].meta.changes) {
      throw new EngineeringConflictError("Engineering job changed while its core status was being mirrored.");
    }
    return this.requireJob(owner, jobId);
  }

  async recordDecisionIntent(
    owner: string,
    jobId: string,
    expectedRevision: number,
    decision: "approve" | "reject",
    proposalDigest: string,
  ) {
    if (!/^[a-f0-9]{64}$/.test(proposalDigest)) {
      throw new EngineeringConflictError("Engineering proposal is unavailable.");
    }
    const authorizedAt = now();
    const intentCorrelation = `decision:${jobId}:${expectedRevision}`;
    const eventSummary = decision === "approve"
      ? "Exact proposal approved."
      : "Exact proposal rejected.";
    const results = await this.database.batch([
      this.database.prepare(
        "UPDATE engineering_jobs SET authorized_decision=?, authorized_proposal_digest=?, authorized_at=COALESCE(authorized_at, ?) WHERE id=? AND owner_key=? AND revision=? AND state='awaiting_approval' AND proposal_digest=? AND (authorized_decision IS NULL OR (authorized_decision=? AND authorized_proposal_digest=?))",
      ).bind(
        decision,
        proposalDigest,
        authorizedAt,
        jobId,
        owner,
        expectedRevision,
        proposalDigest,
        decision,
        proposalDigest,
      ),
      this.database.prepare(
        "INSERT OR IGNORE INTO engineering_audit_events (id, job_id, owner_key, actor, event_type, correlation_id, summary, detail_json, created_at) SELECT ?, ?, ?, 'owner', 'decision_authorized', ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM engineering_jobs WHERE id=? AND owner_key=? AND revision=? AND state='awaiting_approval' AND authorized_decision=? AND authorized_proposal_digest=?)",
      ).bind(
        auditId(),
        jobId,
        owner,
        intentCorrelation,
        eventSummary,
        safeAuditDetail({ decision, proposalDigest }),
        authorizedAt,
        jobId,
        owner,
        expectedRevision,
        decision,
        proposalDigest,
      ),
    ]);
    if (!results[0].meta.changes) {
      throw new EngineeringConflictError("Engineering job is not awaiting this decision.");
    }
  }

  async getSource(owner: string, jobId: string, sourceId: string) {
    const row = await this.database.prepare(
      "SELECT id, job_id, filename, media_type, size_bytes, sha256, uploaded_at, r2_etag, revision_applied FROM engineering_sources WHERE id=? AND job_id=? AND owner_key=? LIMIT 1",
    ).bind(sourceId, jobId, owner).first<SourceRow>();
    if (!row) throw new EngineeringNotFoundError();
    return mapSource(row);
  }

  async getEvidence(owner: string, evidenceId: string) {
    const row = await this.database.prepare(
      "SELECT id, job_id, category, filename, media_type, size_bytes, sha256, created_at FROM engineering_evidence WHERE id=? AND owner_key=? LIMIT 1",
    ).bind(evidenceId, owner).first<EvidenceRow>();
    if (!row) throw new EngineeringNotFoundError();
    return mapEvidence(row);
  }

  async getRemoteJobId(owner: string, jobId: string) {
    const row = await this.database.prepare(
      "SELECT remote_job_id FROM engineering_jobs WHERE id=? AND owner_key=? LIMIT 1",
    ).bind(jobId, owner).first<{ remote_job_id: string | null }>();
    if (!row) throw new EngineeringNotFoundError();
    return row.remote_job_id;
  }

  async dispatchIsReserved(owner: string, jobId: string) {
    const row = await this.database.prepare(
      "SELECT dispatch_reserved_at FROM engineering_jobs WHERE id=? AND owner_key=? LIMIT 1",
    ).bind(jobId, owner).first<{ dispatch_reserved_at: string | null }>();
    if (!row) throw new EngineeringNotFoundError();
    return Boolean(row.dispatch_reserved_at);
  }

  async getDispatchMetadata(owner: string, jobId: string) {
    const row = await this.database.prepare(
      "SELECT request_r2_key, create_request_digest, prompt_digest FROM engineering_jobs WHERE id=? AND owner_key=? LIMIT 1",
    ).bind(jobId, owner).first<{
      request_r2_key: string;
      create_request_digest: string;
      prompt_digest: string;
    }>();
    if (!row) throw new EngineeringNotFoundError();
    if (!SHA256.test(row.create_request_digest) || !SHA256.test(row.prompt_digest)) {
      throw new Error("Engineering request storage is invalid.");
    }
    return {
      requestR2Key: row.request_r2_key,
      createRequestDigest: row.create_request_digest,
      promptDigest: row.prompt_digest,
    };
  }

  async deleteUndispatchedJob(owner: string, jobId: string) {
    const result = await this.database.prepare(
      "DELETE FROM engineering_jobs WHERE id=? AND owner_key=? AND remote_job_id IS NULL",
    ).bind(jobId, owner).run();
    if (!result.meta.changes) {
      throw new EngineeringConflictError("Engineering job could not be rolled back safely.");
    }
  }

  async getCoreRevision(owner: string, jobId: string) {
    const row = await this.database.prepare(
      "SELECT core_revision FROM engineering_jobs WHERE id=? AND owner_key=? LIMIT 1",
    ).bind(jobId, owner).first<{ core_revision: number | null }>();
    if (!row) throw new EngineeringNotFoundError();
    return row.core_revision;
  }

  async getDecisionIntent(owner: string, jobId: string): Promise<DecisionIntent | null> {
    const row = await this.database.prepare(
      "SELECT authorized_decision, authorized_proposal_digest FROM engineering_jobs WHERE id=? AND owner_key=? LIMIT 1",
    ).bind(jobId, owner).first<{
      authorized_decision: "approve" | "reject" | null;
      authorized_proposal_digest: string | null;
    }>();
    if (!row) throw new EngineeringNotFoundError();
    if (!row.authorized_decision && !row.authorized_proposal_digest) return null;
    if (
      (row.authorized_decision !== "approve" && row.authorized_decision !== "reject") ||
      !row.authorized_proposal_digest ||
      !/^[a-f0-9]{64}$/.test(row.authorized_proposal_digest)
    ) {
      throw new Error("Engineering decision record is invalid.");
    }
    return {
      decision: row.authorized_decision,
      proposalDigest: row.authorized_proposal_digest,
    };
  }

  private async requireJob(owner: string, jobId: string) {
    const job = await this.getJob(owner, jobId);
    if (!job) throw new EngineeringNotFoundError();
    return job;
  }

  private auditStatement(
    owner: string,
    jobId: string,
    actor: "owner" | "worker" | "core",
    eventType: string,
    summary: string,
    createdAt: string,
    detail: unknown = {},
  ) {
    return this.database.prepare(
      "INSERT INTO engineering_audit_events (id, job_id, owner_key, actor, event_type, correlation_id, summary, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(auditId(), jobId, owner, actor, eventType, correlationId(), summary.slice(0, 2_000), safeAuditDetail(detail), createdAt);
  }
}
