\set ON_ERROR_STOP on

BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '30s';
SET LOCAL timezone = 'UTC';

SELECT jsonb_build_array('schema_version', version, applied_at)::text
FROM lil_tweak_schema_version
ORDER BY version;

SELECT jsonb_build_array(
    'job', id, owner_id, mode, prompt, state, revision, proposal_digest,
    evidence_manifest, summary, source_manifest, source_digest,
    approval_proposal, approval_consumed, project_context, git_source,
    cancel_requested, lease_owner, lease_expires_at, attempt, created_at, updated_at
)::text
FROM lil_tweak_jobs
ORDER BY id;

SELECT jsonb_build_array(
    'source', id, job_id, owner_id, source_id, kind, filename, media_type,
    object_key, source_digest, frozen_reference, size_bytes, created_at
)::text
FROM lil_tweak_sources
ORDER BY id;

SELECT jsonb_build_array(
    'evidence', id, job_id, owner_id, name, object_key, sha256,
    size_bytes, created_at
)::text
FROM lil_tweak_evidence
ORDER BY id;

COMMIT;
