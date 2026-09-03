\set ON_ERROR_STOP on

BEGIN TRANSACTION READ ONLY;
SET LOCAL statement_timeout = '30s';

WITH schema_contract AS (
    SELECT
        (SELECT array_agg(version ORDER BY version)
         FROM lil_tweak_schema_version) = ARRAY[1, 2] AS versions_ok,
        EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'lil_tweak_jobs'
              AND column_name = 'lease_generation'
              AND data_type = 'bigint'
              AND is_nullable = 'NO'
        ) AS lease_generation_ok,
        EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conrelid = 'public.lil_tweak_approvals'::regclass
              AND conname = 'lil_tweak_approvals_one_proposal'
              AND contype = 'u'
              AND pg_get_constraintdef(oid) =
                  'UNIQUE (job_id, revision, proposal_digest)'
        ) AS approval_invariant_ok
)
SELECT NOT (versions_ok AND lease_generation_ok AND approval_invariant_ok)
    AS schema_integrity_failed
FROM schema_contract
\gset

\if :schema_integrity_failed
    \echo 'schema version 2 integrity check failed'
    ROLLBACK;
    \quit 1
\endif

WITH integrity_failures AS (
    SELECT count(*) AS failures
    FROM lil_tweak_jobs
    WHERE owner_id = ''
       OR jsonb_typeof(source_manifest) <> 'array'
       OR (evidence_manifest IS NOT NULL AND jsonb_typeof(evidence_manifest) <> 'object')
       OR (source_digest IS NOT NULL AND source_digest !~ '^[0-9a-f]{64}$')
       OR (proposal_digest IS NOT NULL AND proposal_digest !~ '^[0-9a-f]{64}$')
    UNION ALL
    SELECT count(*)
    FROM lil_tweak_sources AS source
    LEFT JOIN lil_tweak_jobs AS job ON job.id = source.job_id
    WHERE job.id IS NULL
       OR source.owner_id = ''
       OR source.owner_id <> job.owner_id
       OR source.source_id = ''
       OR source.kind NOT IN ('upload', 'git')
       OR source.filename = ''
       OR source.media_type = ''
       OR (source.source_digest IS NOT NULL AND source.source_digest !~ '^[0-9a-f]{64}$')
       OR (source.kind = 'upload' AND (source.object_key IS NULL OR source.object_key = ''))
       OR (source.kind = 'git' AND (
           source.frozen_reference IS NULL
           OR source.frozen_reference !~ '^[0-9a-f]{40}$|^[0-9a-f]{64}$'
       ))
    UNION ALL
    SELECT count(*)
    FROM lil_tweak_evidence AS evidence
    LEFT JOIN lil_tweak_jobs AS job ON job.id = evidence.job_id
    WHERE job.id IS NULL
       OR evidence.owner_id = ''
       OR evidence.owner_id <> job.owner_id
       OR evidence.name = ''
       OR evidence.object_key = ''
       OR evidence.sha256 !~ '^[0-9a-f]{64}$'
)
SELECT COALESCE(sum(failures), 0) > 0 AS normalized_integrity_failed
FROM integrity_failures
\gset

\if :normalized_integrity_failed
    \echo 'normalized source/evidence integrity check failed'
    ROLLBACK;
    \quit 1
\endif

SELECT json_build_object(
    'jobs', (SELECT count(*) FROM lil_tweak_jobs),
    'sources', (SELECT count(*) FROM lil_tweak_sources),
    'evidence', (SELECT count(*) FROM lil_tweak_evidence)
) AS normalized_row_counts;

COMMIT;
