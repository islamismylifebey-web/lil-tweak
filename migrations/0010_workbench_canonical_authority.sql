BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS canonical_workbench_task_bindings (
    workbench_task_id TEXT PRIMARY KEY REFERENCES workbench_tasks(id),
    canonical_task_id TEXT NOT NULL UNIQUE REFERENCES canonical_tasks(id),
    created_at TEXT NOT NULL,
    CHECK(workbench_task_id = canonical_task_id)
);

CREATE TABLE IF NOT EXISTS canonical_workbench_approval_bindings (
    workbench_approval_id TEXT PRIMARY KEY REFERENCES workbench_approvals(id),
    canonical_approval_id TEXT NOT NULL UNIQUE REFERENCES canonical_approvals(id),
    created_at TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS canonical_evidence_immutable_update
BEFORE UPDATE ON canonical_evidence
BEGIN
    SELECT RAISE(ABORT, 'canonical evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_evidence_immutable_delete
BEFORE DELETE ON canonical_evidence
BEGIN
    SELECT RAISE(ABORT, 'canonical evidence is immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_control_events_immutable_update
BEFORE UPDATE ON canonical_control_events
BEGIN
    SELECT RAISE(ABORT, 'canonical control events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_control_events_immutable_delete
BEFORE DELETE ON canonical_control_events
BEGIN
    SELECT RAISE(ABORT, 'canonical control events are immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_approval_update_guard
BEFORE UPDATE ON canonical_approvals
BEGIN
    SELECT CASE
        WHEN NEW.id != OLD.id
          OR NEW.task_id != OLD.task_id
          OR NEW.purpose != OLD.purpose
          OR NEW.approval_digest != OLD.approval_digest
          OR NEW.nonce != OLD.nonce
          OR NEW.created_at != OLD.created_at
          OR NEW.expires_at != OLD.expires_at
        THEN RAISE(ABORT, 'canonical approval binding is immutable')
    END;
    SELECT CASE
        WHEN NOT (
            (OLD.status = 'pending' AND NEW.status IN (
                'approved','rejected','expired','revoked'
            ))
            OR (OLD.status = 'approved' AND NEW.status IN (
                'consumed','expired','revoked'
            ))
        )
        THEN RAISE(ABORT, 'illegal canonical approval status transition')
    END;
END;

CREATE TRIGGER IF NOT EXISTS canonical_approval_immutable_delete
BEFORE DELETE ON canonical_approvals
BEGIN
    SELECT RAISE(ABORT, 'canonical approvals are immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_dispatch_update_guard
BEFORE UPDATE ON canonical_dispatch_leases
BEGIN
    SELECT CASE
        WHEN NEW.id != OLD.id
          OR NEW.task_id != OLD.task_id
          OR NEW.approval_id != OLD.approval_id
          OR NEW.request_digest != OLD.request_digest
          OR NEW.token_digest != OLD.token_digest
          OR NEW.runtime_id != OLD.runtime_id
          OR NEW.generation != OLD.generation
          OR NEW.created_at != OLD.created_at
          OR NEW.expires_at != OLD.expires_at
        THEN RAISE(ABORT, 'canonical dispatch binding is immutable')
    END;
    SELECT CASE
        WHEN NOT (
            OLD.status = 'active'
            AND NEW.status IN ('completed','canceled','expired')
        )
        THEN RAISE(ABORT, 'illegal canonical dispatch status transition')
    END;
END;

CREATE TRIGGER IF NOT EXISTS canonical_dispatch_immutable_delete
BEFORE DELETE ON canonical_dispatch_leases
BEGIN
    SELECT RAISE(ABORT, 'canonical dispatch leases are immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_capability_update_guard
BEFORE UPDATE ON canonical_capabilities
BEGIN
    SELECT CASE
        WHEN NEW.name != OLD.name OR NEW.version != OLD.version + 1
        THEN RAISE(ABORT, 'canonical capability version must increment by one')
    END;
END;

CREATE TRIGGER IF NOT EXISTS canonical_workbench_task_binding_immutable_update
BEFORE UPDATE ON canonical_workbench_task_bindings
BEGIN
    SELECT RAISE(ABORT, 'canonical Workbench task binding is immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_workbench_task_binding_immutable_delete
BEFORE DELETE ON canonical_workbench_task_bindings
BEGIN
    SELECT RAISE(ABORT, 'canonical Workbench task binding is immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_workbench_approval_binding_immutable_update
BEFORE UPDATE ON canonical_workbench_approval_bindings
BEGIN
    SELECT RAISE(ABORT, 'canonical Workbench approval binding is immutable');
END;

CREATE TRIGGER IF NOT EXISTS canonical_workbench_approval_binding_immutable_delete
BEFORE DELETE ON canonical_workbench_approval_bindings
BEGIN
    SELECT RAISE(ABORT, 'canonical Workbench approval binding is immutable');
END;

INSERT OR IGNORE INTO canonical_schema_migrations(migration_id, applied_at)
VALUES ('0010_workbench_canonical_authority', CURRENT_TIMESTAMP);

COMMIT;
