import { sql } from "drizzle-orm";
import { check, index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const workspaceProjects = sqliteTable(
  "workspace_projects",
  {
    id: text("id").primaryKey(),
    ownerEmail: text("owner_email").notNull(),
    name: text("name").notNull(),
    description: text("description").notNull().default(""),
    status: text("status", {
      enum: ["planned", "active", "complete", "archived"],
    })
      .notNull()
      .default("planned"),
    recordJson: text("record_json").notNull(),
    createIdempotencyKey: text("create_idempotency_key"),
    createRequestDigest: text("create_request_digest"),
    createComplete: integer("create_complete", { mode: "boolean" }).notNull().default(true),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
  },
  (table) => [
    index("idx_workspace_projects_owner_updated").on(
      table.ownerEmail,
      table.updatedAt,
    ),
    index("idx_workspace_projects_owner_status").on(
      table.ownerEmail,
      table.status,
    ),
    uniqueIndex("idx_workspace_projects_owner_create_key")
      .on(table.ownerEmail, table.createIdempotencyKey)
      .where(sql`${table.createIdempotencyKey} is not null`),
    check(
      "workspace_projects_create_complete_check",
      sql`${table.createComplete} in (0,1)`,
    ),
  ],
);

export const engineeringJobs = sqliteTable(
  "engineering_jobs",
  {
    id: text("id").primaryKey(),
    ownerKey: text("owner_key").notNull(),
    createIdempotencyKey: text("create_idempotency_key").notNull(),
    createRequestDigest: text("create_request_digest").notNull(),
    projectId: text("project_id"),
    gitRepositoryUrl: text("git_repository_url"),
    gitCommit: text("git_commit"),
    mode: text("mode", {
      enum: ["build", "debug", "refactor", "test", "architect", "chat"],
    }).notNull(),
    promptDigest: text("prompt_digest").notNull(),
    promptPreview: text("prompt_preview").notNull(),
    state: text("state", {
      enum: [
        "draft", "uploading", "queued", "ingesting", "planning", "executing",
        "testing", "collecting", "awaiting_approval", "applying", "completed",
        "rejected", "cancelled", "failed", "timed_out",
      ],
    }).notNull(),
    revision: integer("revision").notNull().default(0),
    summary: text("summary").notNull().default(""),
    proposalDigest: text("proposal_digest"),
    sourceDigest: text("source_digest"),
    approvalProposalJson: text("approval_proposal_json"),
    approvalConsumed: integer("approval_consumed", { mode: "boolean" }).notNull().default(false),
    remoteJobId: text("remote_job_id"),
    coreRevision: integer("core_revision"),
    dispatchReservedAt: text("dispatch_reserved_at"),
    authorizedDecision: text("authorized_decision", { enum: ["approve", "reject"] }),
    authorizedProposalDigest: text("authorized_proposal_digest"),
    authorizedAt: text("authorized_at"),
    requestR2Key: text("request_r2_key").notNull(),
    sourceR2Prefix: text("source_r2_prefix").notNull(),
    evidenceR2Prefix: text("evidence_r2_prefix").notNull(),
    createdAt: text("created_at").notNull(),
    updatedAt: text("updated_at").notNull(),
    lastPolledAt: text("last_polled_at"),
  },
  (table) => [
    index("idx_engineering_jobs_owner_updated").on(table.ownerKey, table.updatedAt),
    index("idx_engineering_jobs_owner_state").on(table.ownerKey, table.state),
    uniqueIndex("idx_engineering_jobs_owner_create_key").on(table.ownerKey, table.createIdempotencyKey),
    uniqueIndex("idx_engineering_jobs_remote_id")
      .on(table.remoteJobId)
      .where(sql`${table.remoteJobId} is not null`),
    check(
      "engineering_jobs_mode_check",
      sql`${table.mode} in ('build','debug','refactor','test','architect','chat')`,
    ),
    check(
      "engineering_jobs_state_check",
      sql`${table.state} in ('draft','uploading','queued','ingesting','planning','executing','testing','collecting','awaiting_approval','applying','completed','rejected','cancelled','failed','timed_out')`,
    ),
    check(
      "engineering_jobs_approval_consumed_check",
      sql`${table.approvalConsumed} in (0,1)`,
    ),
    check(
      "engineering_jobs_authorized_decision_check",
      sql`${table.authorizedDecision} in ('approve','reject') or ${table.authorizedDecision} is null`,
    ),
  ],
);

export const engineeringSources = sqliteTable(
  "engineering_sources",
  {
    id: text("id").primaryKey(),
    jobId: text("job_id").notNull().references(() => engineeringJobs.id, { onDelete: "cascade" }),
    ownerKey: text("owner_key").notNull(),
    filename: text("filename").notNull(),
    mediaType: text("media_type").notNull(),
    sizeBytes: integer("size_bytes").notNull(),
    r2Key: text("r2_key").notNull(),
    r2Etag: text("r2_etag"),
    sha256: text("sha256"),
    uploadedAt: text("uploaded_at"),
    revisionApplied: integer("revision_applied").notNull().default(0),
  },
  (table) => [
    uniqueIndex("idx_engineering_sources_job_filename").on(table.jobId, table.filename),
    index("idx_engineering_sources_owner_job").on(table.ownerKey, table.jobId),
    check(
      "engineering_sources_size_check",
      sql`${table.sizeBytes} > 0 and ${table.sizeBytes} <= 25000000`,
    ),
    check(
      "engineering_sources_sha256_check",
      sql`${table.sha256} is null or (length(${table.sha256}) = 64 and ${table.sha256} not glob '*[^a-f0-9]*')`,
    ),
    check(
      "engineering_sources_revision_applied_check",
      sql`${table.revisionApplied} in (0,1)`,
    ),
  ],
);

export const engineeringEvidence = sqliteTable(
  "engineering_evidence",
  {
    id: text("id").primaryKey(),
    jobId: text("job_id").notNull().references(() => engineeringJobs.id, { onDelete: "cascade" }),
    ownerKey: text("owner_key").notNull(),
    category: text("category").notNull(),
    filename: text("filename").notNull(),
    mediaType: text("media_type").notNull(),
    sizeBytes: integer("size_bytes").notNull(),
    sha256: text("sha256").notNull(),
    r2Key: text("r2_key").notNull(),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    index("idx_engineering_evidence_owner_job").on(table.ownerKey, table.jobId, table.createdAt),
    check(
      "engineering_evidence_size_check",
      sql`${table.sizeBytes} >= 0 and ${table.sizeBytes} <= 2097152`,
    ),
  ],
);

export const engineeringAuditEvents = sqliteTable(
  "engineering_audit_events",
  {
    id: text("id").primaryKey(),
    jobId: text("job_id").notNull().references(() => engineeringJobs.id, { onDelete: "cascade" }),
    ownerKey: text("owner_key").notNull(),
    actor: text("actor", { enum: ["owner", "worker", "core"] }).notNull(),
    eventType: text("event_type").notNull(),
    correlationId: text("correlation_id").notNull(),
    summary: text("summary").notNull(),
    detailJson: text("detail_json").notNull().default("{}"),
    createdAt: text("created_at").notNull(),
  },
  (table) => [
    index("idx_engineering_audit_job_created").on(table.jobId, table.createdAt),
    uniqueIndex("idx_engineering_audit_correlation").on(table.ownerKey, table.correlationId),
    check(
      "engineering_audit_actor_check",
      sql`${table.actor} in ('owner','worker','core')`,
    ),
  ],
);
