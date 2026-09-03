-- Read-only release gate. Every "missing_*" query must return zero rows.
WITH required(name) AS (
  VALUES
    ('workspace_projects'),
    ('engineering_jobs'),
    ('engineering_sources'),
    ('engineering_evidence'),
    ('engineering_audit_events')
)
SELECT required.name AS missing_table
FROM required
LEFT JOIN sqlite_master ON sqlite_master.type = 'table' AND sqlite_master.name = required.name
WHERE sqlite_master.name IS NULL;

WITH required(table_name, column_name, declared_type, not_null, primary_key) AS (
  VALUES
    ('workspace_projects', 'id', 'TEXT', 1, 1),
    ('workspace_projects', 'owner_email', 'TEXT', 1, 0),
    ('workspace_projects', 'name', 'TEXT', 1, 0),
    ('workspace_projects', 'description', 'TEXT', 1, 0),
    ('workspace_projects', 'status', 'TEXT', 1, 0),
    ('workspace_projects', 'record_json', 'TEXT', 1, 0),
    ('workspace_projects', 'create_idempotency_key', 'TEXT', 0, 0),
    ('workspace_projects', 'create_request_digest', 'TEXT', 0, 0),
    ('workspace_projects', 'create_complete', 'INTEGER', 1, 0),
    ('workspace_projects', 'created_at', 'TEXT', 1, 0),
    ('workspace_projects', 'updated_at', 'TEXT', 1, 0),
    ('engineering_jobs', 'id', 'TEXT', 1, 1),
    ('engineering_jobs', 'owner_key', 'TEXT', 1, 0),
    ('engineering_jobs', 'create_idempotency_key', 'TEXT', 1, 0),
    ('engineering_jobs', 'create_request_digest', 'TEXT', 1, 0),
    ('engineering_jobs', 'project_id', 'TEXT', 0, 0),
    ('engineering_jobs', 'git_repository_url', 'TEXT', 0, 0),
    ('engineering_jobs', 'git_commit', 'TEXT', 0, 0),
    ('engineering_jobs', 'mode', 'TEXT', 1, 0),
    ('engineering_jobs', 'prompt_digest', 'TEXT', 1, 0),
    ('engineering_jobs', 'prompt_preview', 'TEXT', 1, 0),
    ('engineering_jobs', 'state', 'TEXT', 1, 0),
    ('engineering_jobs', 'revision', 'INTEGER', 1, 0),
    ('engineering_jobs', 'summary', 'TEXT', 1, 0),
    ('engineering_jobs', 'proposal_digest', 'TEXT', 0, 0),
    ('engineering_jobs', 'source_digest', 'TEXT', 0, 0),
    ('engineering_jobs', 'approval_proposal_json', 'TEXT', 0, 0),
    ('engineering_jobs', 'approval_consumed', 'INTEGER', 1, 0),
    ('engineering_jobs', 'remote_job_id', 'TEXT', 0, 0),
    ('engineering_jobs', 'core_revision', 'INTEGER', 0, 0),
    ('engineering_jobs', 'dispatch_reserved_at', 'TEXT', 0, 0),
    ('engineering_jobs', 'authorized_decision', 'TEXT', 0, 0),
    ('engineering_jobs', 'authorized_proposal_digest', 'TEXT', 0, 0),
    ('engineering_jobs', 'authorized_at', 'TEXT', 0, 0),
    ('engineering_jobs', 'request_r2_key', 'TEXT', 1, 0),
    ('engineering_jobs', 'source_r2_prefix', 'TEXT', 1, 0),
    ('engineering_jobs', 'evidence_r2_prefix', 'TEXT', 1, 0),
    ('engineering_jobs', 'created_at', 'TEXT', 1, 0),
    ('engineering_jobs', 'updated_at', 'TEXT', 1, 0),
    ('engineering_jobs', 'last_polled_at', 'TEXT', 0, 0),
    ('engineering_sources', 'id', 'TEXT', 1, 1),
    ('engineering_sources', 'job_id', 'TEXT', 1, 0),
    ('engineering_sources', 'owner_key', 'TEXT', 1, 0),
    ('engineering_sources', 'filename', 'TEXT', 1, 0),
    ('engineering_sources', 'media_type', 'TEXT', 1, 0),
    ('engineering_sources', 'size_bytes', 'INTEGER', 1, 0),
    ('engineering_sources', 'r2_key', 'TEXT', 1, 0),
    ('engineering_sources', 'r2_etag', 'TEXT', 0, 0),
    ('engineering_sources', 'sha256', 'TEXT', 0, 0),
    ('engineering_sources', 'uploaded_at', 'TEXT', 0, 0),
    ('engineering_sources', 'revision_applied', 'INTEGER', 1, 0),
    ('engineering_evidence', 'id', 'TEXT', 1, 1),
    ('engineering_evidence', 'job_id', 'TEXT', 1, 0),
    ('engineering_evidence', 'owner_key', 'TEXT', 1, 0),
    ('engineering_evidence', 'category', 'TEXT', 1, 0),
    ('engineering_evidence', 'filename', 'TEXT', 1, 0),
    ('engineering_evidence', 'media_type', 'TEXT', 1, 0),
    ('engineering_evidence', 'size_bytes', 'INTEGER', 1, 0),
    ('engineering_evidence', 'sha256', 'TEXT', 1, 0),
    ('engineering_evidence', 'r2_key', 'TEXT', 1, 0),
    ('engineering_evidence', 'created_at', 'TEXT', 1, 0),
    ('engineering_audit_events', 'id', 'TEXT', 1, 1),
    ('engineering_audit_events', 'job_id', 'TEXT', 1, 0),
    ('engineering_audit_events', 'owner_key', 'TEXT', 1, 0),
    ('engineering_audit_events', 'actor', 'TEXT', 1, 0),
    ('engineering_audit_events', 'event_type', 'TEXT', 1, 0),
    ('engineering_audit_events', 'correlation_id', 'TEXT', 1, 0),
    ('engineering_audit_events', 'summary', 'TEXT', 1, 0),
    ('engineering_audit_events', 'detail_json', 'TEXT', 1, 0),
    ('engineering_audit_events', 'created_at', 'TEXT', 1, 0)
), present(table_name, column_name, declared_type, not_null, primary_key) AS (
  SELECT 'workspace_projects', name, upper(type), "notnull", pk FROM pragma_table_info('workspace_projects')
  UNION ALL
  SELECT 'engineering_jobs', name, upper(type), "notnull", pk FROM pragma_table_info('engineering_jobs')
  UNION ALL
  SELECT 'engineering_sources', name, upper(type), "notnull", pk FROM pragma_table_info('engineering_sources')
  UNION ALL
  SELECT 'engineering_evidence', name, upper(type), "notnull", pk FROM pragma_table_info('engineering_evidence')
  UNION ALL
  SELECT 'engineering_audit_events', name, upper(type), "notnull", pk FROM pragma_table_info('engineering_audit_events')
)
SELECT required.table_name, required.column_name AS missing_or_incompatible_column
FROM required
LEFT JOIN present
  ON present.table_name = required.table_name AND present.column_name = required.column_name
WHERE present.column_name IS NULL
   OR present.declared_type <> required.declared_type
   OR present.not_null <> required.not_null
   OR present.primary_key <> required.primary_key;

WITH required(table_name, name, is_unique, is_partial) AS (
  VALUES
    ('workspace_projects', 'idx_workspace_projects_owner_updated', 0, 0),
    ('workspace_projects', 'idx_workspace_projects_owner_status', 0, 0),
    ('workspace_projects', 'idx_workspace_projects_owner_create_key', 1, 1),
    ('engineering_jobs', 'idx_engineering_jobs_owner_updated', 0, 0),
    ('engineering_jobs', 'idx_engineering_jobs_owner_state', 0, 0),
    ('engineering_jobs', 'idx_engineering_jobs_owner_create_key', 1, 0),
    ('engineering_jobs', 'idx_engineering_jobs_remote_id', 1, 1),
    ('engineering_sources', 'idx_engineering_sources_job_filename', 1, 0),
    ('engineering_sources', 'idx_engineering_sources_owner_job', 0, 0),
    ('engineering_evidence', 'idx_engineering_evidence_owner_job', 0, 0),
    ('engineering_audit_events', 'idx_engineering_audit_job_created', 0, 0),
    ('engineering_audit_events', 'idx_engineering_audit_correlation', 1, 0)
), present(table_name, name, is_unique, is_partial) AS (
  SELECT 'workspace_projects', name, "unique", partial FROM pragma_index_list('workspace_projects')
  UNION ALL
  SELECT 'engineering_jobs', name, "unique", partial FROM pragma_index_list('engineering_jobs')
  UNION ALL
  SELECT 'engineering_sources', name, "unique", partial FROM pragma_index_list('engineering_sources')
  UNION ALL
  SELECT 'engineering_evidence', name, "unique", partial FROM pragma_index_list('engineering_evidence')
  UNION ALL
  SELECT 'engineering_audit_events', name, "unique", partial FROM pragma_index_list('engineering_audit_events')
)
SELECT required.table_name, required.name AS missing_or_incompatible_index
FROM required
LEFT JOIN present ON present.table_name = required.table_name AND present.name = required.name
WHERE present.name IS NULL
   OR present.is_unique <> required.is_unique
   OR present.is_partial <> required.is_partial;

WITH required(index_name, sequence_number, column_name) AS (
  VALUES
    ('idx_workspace_projects_owner_updated', 0, 'owner_email'),
    ('idx_workspace_projects_owner_updated', 1, 'updated_at'),
    ('idx_workspace_projects_owner_status', 0, 'owner_email'),
    ('idx_workspace_projects_owner_status', 1, 'status'),
    ('idx_workspace_projects_owner_create_key', 0, 'owner_email'),
    ('idx_workspace_projects_owner_create_key', 1, 'create_idempotency_key'),
    ('idx_engineering_jobs_owner_updated', 0, 'owner_key'),
    ('idx_engineering_jobs_owner_updated', 1, 'updated_at'),
    ('idx_engineering_jobs_owner_state', 0, 'owner_key'),
    ('idx_engineering_jobs_owner_state', 1, 'state'),
    ('idx_engineering_jobs_owner_create_key', 0, 'owner_key'),
    ('idx_engineering_jobs_owner_create_key', 1, 'create_idempotency_key'),
    ('idx_engineering_jobs_remote_id', 0, 'remote_job_id'),
    ('idx_engineering_sources_job_filename', 0, 'job_id'),
    ('idx_engineering_sources_job_filename', 1, 'filename'),
    ('idx_engineering_sources_owner_job', 0, 'owner_key'),
    ('idx_engineering_sources_owner_job', 1, 'job_id'),
    ('idx_engineering_evidence_owner_job', 0, 'owner_key'),
    ('idx_engineering_evidence_owner_job', 1, 'job_id'),
    ('idx_engineering_evidence_owner_job', 2, 'created_at'),
    ('idx_engineering_audit_job_created', 0, 'job_id'),
    ('idx_engineering_audit_job_created', 1, 'created_at'),
    ('idx_engineering_audit_correlation', 0, 'owner_key'),
    ('idx_engineering_audit_correlation', 1, 'correlation_id')
), present(index_name, sequence_number, column_name) AS (
  SELECT 'idx_workspace_projects_owner_updated', seqno, name FROM pragma_index_info('idx_workspace_projects_owner_updated')
  UNION ALL SELECT 'idx_workspace_projects_owner_status', seqno, name FROM pragma_index_info('idx_workspace_projects_owner_status')
  UNION ALL SELECT 'idx_workspace_projects_owner_create_key', seqno, name FROM pragma_index_info('idx_workspace_projects_owner_create_key')
  UNION ALL SELECT 'idx_engineering_jobs_owner_updated', seqno, name FROM pragma_index_info('idx_engineering_jobs_owner_updated')
  UNION ALL SELECT 'idx_engineering_jobs_owner_state', seqno, name FROM pragma_index_info('idx_engineering_jobs_owner_state')
  UNION ALL SELECT 'idx_engineering_jobs_owner_create_key', seqno, name FROM pragma_index_info('idx_engineering_jobs_owner_create_key')
  UNION ALL SELECT 'idx_engineering_jobs_remote_id', seqno, name FROM pragma_index_info('idx_engineering_jobs_remote_id')
  UNION ALL SELECT 'idx_engineering_sources_job_filename', seqno, name FROM pragma_index_info('idx_engineering_sources_job_filename')
  UNION ALL SELECT 'idx_engineering_sources_owner_job', seqno, name FROM pragma_index_info('idx_engineering_sources_owner_job')
  UNION ALL SELECT 'idx_engineering_evidence_owner_job', seqno, name FROM pragma_index_info('idx_engineering_evidence_owner_job')
  UNION ALL SELECT 'idx_engineering_audit_job_created', seqno, name FROM pragma_index_info('idx_engineering_audit_job_created')
  UNION ALL SELECT 'idx_engineering_audit_correlation', seqno, name FROM pragma_index_info('idx_engineering_audit_correlation')
)
SELECT required.index_name AS incompatible_index_columns, required.sequence_number, required.column_name
FROM required
LEFT JOIN present
  ON present.index_name = required.index_name
 AND present.sequence_number = required.sequence_number
 AND present.column_name = required.column_name
WHERE present.column_name IS NULL
UNION ALL
SELECT present.index_name, present.sequence_number, present.column_name
FROM present
LEFT JOIN required
  ON required.index_name = present.index_name
 AND required.sequence_number = present.sequence_number
 AND required.column_name = present.column_name
WHERE required.column_name IS NULL;

SELECT 'workspace_projects_create_complete_check' AS missing_or_incompatible_check
WHERE NOT EXISTS (
  SELECT 1
  FROM sqlite_master
  WHERE type = 'table'
    AND name = 'workspace_projects'
    AND instr(
      replace(replace(replace(replace(replace(replace(lower(sql), '`', ''), '"', ''), ' ', ''), char(9), ''), char(10), ''), char(13), ''),
      'constraintworkspace_projects_create_complete_checkcheck(workspace_projects.create_completein(0,1))'
    ) > 0
);

SELECT 'idx_workspace_projects_owner_create_key' AS incompatible_partial_index
WHERE NOT EXISTS (
  SELECT 1
  FROM sqlite_master
  WHERE type = 'index'
    AND name = 'idx_workspace_projects_owner_create_key'
    AND instr(
      replace(replace(replace(replace(replace(replace(lower(sql), '`', ''), '"', ''), ' ', ''), char(9), ''), char(10), ''), char(13), ''),
      'whereworkspace_projects.create_idempotency_keyisnotnull'
    ) > 0
);

SELECT 'idx_engineering_jobs_remote_id' AS incompatible_partial_index
WHERE NOT EXISTS (
  SELECT 1
  FROM sqlite_master
  WHERE type = 'index'
    AND name = 'idx_engineering_jobs_remote_id'
    AND instr(replace(lower(sql), '`', ''), 'where remote_job_id is not null') > 0
);

WITH required(table_name, from_column, to_table, to_column, on_delete) AS (
  VALUES
    ('engineering_sources', 'job_id', 'engineering_jobs', 'id', 'CASCADE'),
    ('engineering_evidence', 'job_id', 'engineering_jobs', 'id', 'CASCADE'),
    ('engineering_audit_events', 'job_id', 'engineering_jobs', 'id', 'CASCADE')
), present(table_name, from_column, to_table, to_column, on_delete) AS (
  SELECT 'engineering_sources', "from", "table", "to", upper(on_delete) FROM pragma_foreign_key_list('engineering_sources')
  UNION ALL
  SELECT 'engineering_evidence', "from", "table", "to", upper(on_delete) FROM pragma_foreign_key_list('engineering_evidence')
  UNION ALL
  SELECT 'engineering_audit_events', "from", "table", "to", upper(on_delete) FROM pragma_foreign_key_list('engineering_audit_events')
)
SELECT required.table_name, required.from_column AS missing_foreign_key
FROM required
LEFT JOIN present
  ON present.table_name = required.table_name
 AND present.from_column = required.from_column
 AND present.to_table = required.to_table
 AND present.to_column = required.to_column
 AND present.on_delete = required.on_delete
WHERE present.from_column IS NULL;

SELECT * FROM pragma_foreign_key_check;

WITH required(sequence_number, name) AS (
  VALUES
    (1, '0000_gifted_sharon_ventura.sql'),
    (2, '0001_lil_tweak_engineering.sql'),
    (3, '0002_workspace_creation_idempotency.sql')
), present(sequence_number, name) AS (
  SELECT row_number() OVER (ORDER BY id), name FROM d1_migrations
)
SELECT required.name AS missing_or_incompatible_migration
FROM required
LEFT JOIN present
  ON present.sequence_number = required.sequence_number
 AND present.name = required.name
WHERE present.name IS NULL
UNION ALL
SELECT present.name
FROM present
LEFT JOIN required
  ON required.sequence_number = present.sequence_number
 AND required.name = present.name
WHERE required.name IS NULL;

SELECT id, name, applied_at FROM d1_migrations ORDER BY id;
