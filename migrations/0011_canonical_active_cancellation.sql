BEGIN IMMEDIATE;

DROP TRIGGER IF EXISTS canonical_task_update_guard;

CREATE TRIGGER canonical_task_update_guard
BEFORE UPDATE ON canonical_tasks
BEGIN
    SELECT CASE
        WHEN NEW.version != OLD.version + 1
        THEN RAISE(ABORT, 'canonical task version must increment by one')
    END;
    SELECT CASE
        WHEN NOT (
            NEW.state = OLD.state
            OR (OLD.state = 'RECEIVED' AND NEW.state IN (
                'INSPECTED','CANCELED','FAILED','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'INSPECTED' AND NEW.state IN (
                'PLANNING','CANCELED','FAILED','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'PLANNING' AND NEW.state IN (
                'PLAN_PROPOSED','CANCELED','FAILED','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'PLAN_PROPOSED' AND NEW.state IN (
                'APPROVAL_PENDING','CANCELED','FAILED','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'APPROVAL_PENDING' AND NEW.state IN (
                'APPROVED','CANCELED','FAILED','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'APPROVED' AND NEW.state IN (
                'RUNNER_PREFLIGHT','CANCELED','FAILED','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'RUNNER_PREFLIGHT' AND NEW.state IN (
                'EXECUTING','CANCELED','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'EXECUTING' AND NEW.state IN (
                'TESTING','CANCELED','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'TESTING' AND NEW.state IN (
                'VERIFYING','CANCELED','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'VERIFYING' AND NEW.state IN (
                'EVIDENCE_SEALED','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'EVIDENCE_SEALED' AND NEW.state IN (
                'PATCH_READY','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'PATCH_READY' AND NEW.state IN (
                'APPLY_APPROVAL_PENDING','CANCELED','FAILED','ROLLBACK_PENDING',
                'EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'APPLY_APPROVAL_PENDING' AND NEW.state IN (
                'APPLIED','CANCELED','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'APPLIED' AND NEW.state IN (
                'COMMIT_APPROVAL_PENDING','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'COMMIT_APPROVAL_PENDING' AND NEW.state IN (
                'LOCALLY_COMMITTED','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'LOCALLY_COMMITTED' AND NEW.state IN (
                'COMPLETED','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'FAILED' AND NEW.state IN (
                'ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'ROLLBACK_PENDING' AND NEW.state IN (
                'ROLLED_BACK','EMERGENCY_STOPPED'
            ))
        )
        THEN RAISE(ABORT, 'illegal canonical task state transition')
    END;
END;

INSERT OR IGNORE INTO canonical_schema_migrations(migration_id, applied_at)
VALUES ('0011_canonical_active_cancellation', CURRENT_TIMESTAMP);

COMMIT;
