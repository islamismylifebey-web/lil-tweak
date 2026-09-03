CREATE TABLE `engineering_jobs` (
	`id` text PRIMARY KEY NOT NULL,
	`owner_key` text NOT NULL,
	`create_idempotency_key` text NOT NULL,
	`create_request_digest` text NOT NULL,
	`project_id` text,
	`git_repository_url` text,
	`git_commit` text,
	`mode` text NOT NULL CONSTRAINT `engineering_jobs_mode_check` CHECK (`mode` IN ('build','debug','refactor','test','architect','chat')),
	`prompt_digest` text NOT NULL,
	`prompt_preview` text NOT NULL,
	`state` text NOT NULL CONSTRAINT `engineering_jobs_state_check` CHECK (`state` IN ('draft','uploading','queued','ingesting','planning','executing','testing','collecting','awaiting_approval','applying','completed','rejected','cancelled','failed','timed_out')),
	`revision` integer DEFAULT 0 NOT NULL,
	`summary` text DEFAULT '' NOT NULL,
	`proposal_digest` text,
	`source_digest` text,
	`approval_proposal_json` text,
	`approval_consumed` integer DEFAULT 0 NOT NULL CONSTRAINT `engineering_jobs_approval_consumed_check` CHECK (`approval_consumed` IN (0,1)),
	`remote_job_id` text,
	`core_revision` integer,
	`dispatch_reserved_at` text,
	`authorized_decision` text CONSTRAINT `engineering_jobs_authorized_decision_check` CHECK (`authorized_decision` IN ('approve','reject') OR `authorized_decision` IS NULL),
	`authorized_proposal_digest` text,
	`authorized_at` text,
	`request_r2_key` text NOT NULL,
	`source_r2_prefix` text NOT NULL,
	`evidence_r2_prefix` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	`last_polled_at` text
);
--> statement-breakpoint
CREATE INDEX `idx_engineering_jobs_owner_updated` ON `engineering_jobs` (`owner_key`,`updated_at`);
--> statement-breakpoint
CREATE INDEX `idx_engineering_jobs_owner_state` ON `engineering_jobs` (`owner_key`,`state`);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_engineering_jobs_owner_create_key` ON `engineering_jobs` (`owner_key`,`create_idempotency_key`);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_engineering_jobs_remote_id` ON `engineering_jobs` (`remote_job_id`) WHERE `remote_job_id` IS NOT NULL;
--> statement-breakpoint
CREATE TABLE `engineering_sources` (
	`id` text PRIMARY KEY NOT NULL,
	`job_id` text NOT NULL REFERENCES `engineering_jobs` (`id`) ON DELETE CASCADE,
	`owner_key` text NOT NULL,
	`filename` text NOT NULL,
	`media_type` text NOT NULL,
	`size_bytes` integer NOT NULL CONSTRAINT `engineering_sources_size_check` CHECK (`size_bytes` > 0 AND `size_bytes` <= 25000000),
	`r2_key` text NOT NULL,
	`r2_etag` text,
	`sha256` text CONSTRAINT `engineering_sources_sha256_check` CHECK (`sha256` IS NULL OR (length(`sha256`) = 64 AND `sha256` NOT GLOB '*[^a-f0-9]*')),
	`uploaded_at` text,
	`revision_applied` integer DEFAULT 0 NOT NULL CONSTRAINT `engineering_sources_revision_applied_check` CHECK (`revision_applied` IN (0,1))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_engineering_sources_job_filename` ON `engineering_sources` (`job_id`,`filename`);
--> statement-breakpoint
CREATE INDEX `idx_engineering_sources_owner_job` ON `engineering_sources` (`owner_key`,`job_id`);
--> statement-breakpoint
CREATE TABLE `engineering_evidence` (
	`id` text PRIMARY KEY NOT NULL,
	`job_id` text NOT NULL REFERENCES `engineering_jobs` (`id`) ON DELETE CASCADE,
	`owner_key` text NOT NULL,
	`category` text NOT NULL,
	`filename` text NOT NULL,
	`media_type` text NOT NULL,
	`size_bytes` integer NOT NULL CONSTRAINT `engineering_evidence_size_check` CHECK (`size_bytes` >= 0 AND `size_bytes` <= 2097152),
	`sha256` text NOT NULL,
	`r2_key` text NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_engineering_evidence_owner_job` ON `engineering_evidence` (`owner_key`,`job_id`,`created_at`);
--> statement-breakpoint
CREATE TABLE `engineering_audit_events` (
	`id` text PRIMARY KEY NOT NULL,
	`job_id` text NOT NULL REFERENCES `engineering_jobs` (`id`) ON DELETE CASCADE,
	`owner_key` text NOT NULL,
	`actor` text NOT NULL CONSTRAINT `engineering_audit_actor_check` CHECK (`actor` IN ('owner','worker','core')),
	`event_type` text NOT NULL,
	`correlation_id` text NOT NULL,
	`summary` text NOT NULL,
	`detail_json` text DEFAULT '{}' NOT NULL,
	`created_at` text NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_engineering_audit_job_created` ON `engineering_audit_events` (`job_id`,`created_at`);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_engineering_audit_correlation` ON `engineering_audit_events` (`owner_key`,`correlation_id`);
