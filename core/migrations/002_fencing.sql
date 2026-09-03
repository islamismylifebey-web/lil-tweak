BEGIN;

ALTER TABLE lil_tweak_jobs
    ADD COLUMN lease_generation bigint NOT NULL DEFAULT 0
    CHECK (lease_generation >= 0);

-- Older code could mint more than one internal token for an unchanged
-- proposal. Keep the consumed (otherwise earliest) audit row deterministically
-- before installing the invariant.
WITH ranked AS (
    SELECT token_hash,
           row_number() OVER (
               PARTITION BY job_id, revision, proposal_digest
               ORDER BY (consumed_at IS NOT NULL) DESC, created_at, token_hash
           ) AS position
    FROM lil_tweak_approvals
)
DELETE FROM lil_tweak_approvals approval
USING ranked
WHERE approval.token_hash = ranked.token_hash
  AND ranked.position > 1;

ALTER TABLE lil_tweak_approvals
    ADD CONSTRAINT lil_tweak_approvals_one_proposal
    UNIQUE (job_id, revision, proposal_digest);

INSERT INTO lil_tweak_schema_version(version) VALUES (2);
COMMIT;
