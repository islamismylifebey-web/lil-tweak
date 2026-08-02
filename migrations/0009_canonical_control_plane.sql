BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS canonical_schema_migrations (
    migration_id TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS canonical_tasks (
    id TEXT PRIMARY KEY,
    task_digest TEXT NOT NULL UNIQUE CHECK(length(task_digest) = 64),
    source_snapshot_digest TEXT NOT NULL CHECK(length(source_snapshot_digest) = 64),
    state TEXT NOT NULL CHECK(state IN (
        'RECEIVED','INSPECTED','PLANNING','PLAN_PROPOSED','APPROVAL_PENDING',
        'APPROVED','RUNNER_PREFLIGHT','EXECUTING','TESTING','VERIFYING',
        'EVIDENCE_SEALED','PATCH_READY','APPLY_APPROVAL_PENDING','APPLIED',
        'COMMIT_APPROVAL_PENDING','LOCALLY_COMMITTED','COMPLETED','CANCELED',
        'FAILED','ROLLBACK_PENDING','ROLLED_BACK','EMERGENCY_STOPPED'
    )),
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS canonical_evidence (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES canonical_tasks(id),
    sequence INTEGER NOT NULL CHECK(sequence >= 1),
    event_type TEXT NOT NULL,
    record_json TEXT NOT NULL,
    previous_hash TEXT,
    record_hash TEXT NOT NULL UNIQUE CHECK(length(record_hash) = 64),
    created_at TEXT NOT NULL,
    UNIQUE(task_id, sequence)
);

CREATE TABLE IF NOT EXISTS canonical_capabilities (
    name TEXT PRIMARY KEY CHECK(name IN (
        'model','runner','owner_tree_apply','local_commit','external_checkpoint',
        'browser_execution'
    )),
    version INTEGER NOT NULL DEFAULT 0 CHECK(version >= 0),
    status TEXT NOT NULL CHECK(status IN (
        'NOT_IMPLEMENTED','IMPLEMENTED_UNVERIFIED','OFFLINE_TESTED','QUALIFIED',
        'CONNECTED','OPERATIONAL','DEGRADED','DISABLED_BY_POLICY','BLOCKED','FAILED'
    )),
    operational INTEGER NOT NULL CHECK(operational IN (0, 1)),
    record_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS canonical_approvals (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES canonical_tasks(id),
    purpose TEXT NOT NULL CHECK(purpose IN (
        'execution','apply_patch','local_commit','rollback'
    )),
    status TEXT NOT NULL CHECK(status IN (
        'pending','approved','consumed','rejected','expired','revoked'
    )),
    approval_digest TEXT NOT NULL UNIQUE CHECK(length(approval_digest) = 64),
    nonce TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_canonical_approval_task_status
ON canonical_approvals(task_id, status);

CREATE TABLE IF NOT EXISTS canonical_dispatch_leases (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES canonical_tasks(id),
    approval_id TEXT NOT NULL REFERENCES canonical_approvals(id),
    request_digest TEXT NOT NULL CHECK(length(request_digest) = 64),
    token_digest TEXT NOT NULL UNIQUE CHECK(length(token_digest) = 64),
    runtime_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 0),
    status TEXT NOT NULL CHECK(status IN ('active','completed','canceled','expired')),
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_canonical_active_dispatch_per_task
ON canonical_dispatch_leases(task_id) WHERE status = 'active';

CREATE TABLE IF NOT EXISTS canonical_control (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    emergency_stopped INTEGER NOT NULL CHECK(emergency_stopped IN (0, 1)),
    generation INTEGER NOT NULL CHECK(generation >= 0),
    active_runtime_id TEXT,
    reason_code TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
INSERT OR IGNORE INTO canonical_control(
    singleton, emergency_stopped, generation, active_runtime_id, reason_code, updated_at
) VALUES (1, 0, 0, NULL, 'initializing', CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS canonical_control_events (
    sequence INTEGER PRIMARY KEY CHECK(sequence >= 1),
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    record_json TEXT NOT NULL,
    previous_hash TEXT,
    record_hash TEXT NOT NULL UNIQUE CHECK(length(record_hash) = 64),
    created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS canonical_task_update_guard
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
                'TESTING','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
            ))
            OR (OLD.state = 'TESTING' AND NEW.state IN (
                'VERIFYING','FAILED','ROLLBACK_PENDING','EMERGENCY_STOPPED'
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
        THEN RAISE(ABORT, 'illegal canonical task transition')
    END;
END;

INSERT OR IGNORE INTO canonical_schema_migrations(migration_id, applied_at)
VALUES ('0009_canonical_control_plane', CURRENT_TIMESTAMP);

COMMIT;
