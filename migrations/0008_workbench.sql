BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS workbench_tasks (
    id TEXT PRIMARY KEY,
    task_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_workbench_one_active_task
ON workbench_tasks((1))
WHERE state NOT IN ('COMPLETED','BLOCKED','FAILED','ROLLED_BACK','CANCELED');

CREATE TABLE IF NOT EXISTS workbench_approvals (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES workbench_tasks(id),
    status TEXT NOT NULL,
    approval_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_workbench_approval_task
ON workbench_approvals(task_id, status);

CREATE TABLE IF NOT EXISTS workbench_runs (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES workbench_tasks(id),
    attempt INTEGER NOT NULL,
    tool_id TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, attempt, tool_id)
);

CREATE TABLE IF NOT EXISTS workbench_model_admissions (
    id TEXT PRIMARY KEY,
    task_digest TEXT NOT NULL,
    planning_attempt INTEGER NOT NULL CHECK(planning_attempt BETWEEN 1 AND 3),
    model TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('claimed','succeeded','failed')),
    reservation_usd REAL NOT NULL CHECK(reservation_usd > 0),
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    response_id_hash TEXT,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE(task_digest, planning_attempt)
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_workbench_one_claimed_model
ON workbench_model_admissions(task_digest) WHERE status='claimed';

CREATE TABLE IF NOT EXISTS workbench_evidence (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES workbench_tasks(id),
    sequence INTEGER NOT NULL,
    kind TEXT NOT NULL,
    event_type TEXT NOT NULL,
    record_json TEXT NOT NULL,
    record_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    UNIQUE(task_id, sequence)
);

CREATE TABLE IF NOT EXISTS workbench_submissions (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES workbench_tasks(id),
    locked INTEGER NOT NULL DEFAULT 0,
    submission_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS workbench_control (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
INSERT OR IGNORE INTO workbench_control(name, value, updated_at)
VALUES ('emergency_stop', 'false', CURRENT_TIMESTAMP);

COMMIT;
