BEGIN;

CREATE TABLE lil_tweak_test_worlds (
    id text PRIMARY KEY CHECK (id ~ '^world:[0-9a-f]{32}$'),
    owner_id text NOT NULL,
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 240),
    objective text NOT NULL CHECK (length(objective) BETWEEN 1 AND 16000),
    repository_url text NOT NULL CHECK (repository_url LIKE 'https://%'),
    source_commit text NOT NULL CHECK (source_commit ~ '^(?:[0-9a-f]{40}|[0-9a-f]{64})$'),
    checks jsonb NOT NULL CHECK (jsonb_typeof(checks) = 'array' AND jsonb_array_length(checks) BETWEEN 1 AND 8),
    max_attempts integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
    status text NOT NULL CHECK (status IN ('ready','running','failed','passed','exhausted','blocked')),
    world_fingerprint text NOT NULL CHECK (world_fingerprint ~ '^[0-9a-f]{64}$'),
    judge_version text NOT NULL CHECK (judge_version ~ '^[0-9a-f]{64}$'),
    create_idempotency_key text NOT NULL CHECK (length(create_idempotency_key) BETWEEN 1 AND 200),
    request_hash text NOT NULL CHECK (request_hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (owner_id, create_idempotency_key)
);

CREATE TABLE lil_tweak_test_world_attempts (
    id text PRIMARY KEY CHECK (id ~ '^attempt:[0-9a-f]{32}$'),
    world_id text NOT NULL REFERENCES lil_tweak_test_worlds(id) ON DELETE CASCADE,
    owner_id text NOT NULL,
    attempt_number integer NOT NULL CHECK (attempt_number BETWEEN 1 AND 10),
    status text NOT NULL CHECK (status IN ('queued','running','passed','failed','error')),
    attempt_mode text NOT NULL CHECK (attempt_mode IN ('retry','fresh')),
    world_fingerprint text NOT NULL CHECK (world_fingerprint ~ '^[0-9a-f]{64}$'),
    judge_version text NOT NULL CHECK (judge_version ~ '^[0-9a-f]{64}$'),
    expected_check_count integer NOT NULL CHECK (expected_check_count BETWEEN 1 AND 8),
    outcome text CHECK (outcome IS NULL OR outcome IN ('pass','fail','error')),
    previous_attempt_id text REFERENCES lil_tweak_test_world_attempts(id) ON DELETE SET NULL,
    feedback jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(feedback) = 'array'),
    cumulative_patch text NOT NULL DEFAULT '' CHECK (octet_length(cumulative_patch) <= 2097152),
    plan text NOT NULL DEFAULT '' CHECK (octet_length(plan) <= 65536),
    summary text NOT NULL DEFAULT '' CHECK (octet_length(summary) <= 65536),
    tests text NOT NULL DEFAULT '' CHECK (octet_length(tests) <= 65536),
    model_calls bigint NOT NULL DEFAULT 0 CHECK (model_calls >= 0),
    input_tokens bigint NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
    output_tokens bigint NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
    total_tokens bigint NOT NULL DEFAULT 0 CHECK (total_tokens >= 0),
    duration_ms bigint NOT NULL DEFAULT 0 CHECK (duration_ms BETWEEN 0 AND 86400000),
    judge_duration_ms bigint NOT NULL DEFAULT 0 CHECK (judge_duration_ms BETWEEN 0 AND 86400000),
    attempt_idempotency_key text NOT NULL CHECK (length(attempt_idempotency_key) BETWEEN 1 AND 200),
    lease_owner text,
    lease_generation bigint NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    UNIQUE (owner_id, attempt_idempotency_key),
    UNIQUE (world_id, attempt_number),
    CHECK (judge_duration_ms <= duration_ms OR duration_ms = 0),
    CHECK (status <> 'passed' OR jsonb_array_length(feedback) = expected_check_count),
    CHECK ((status IN ('queued','running') AND outcome IS NULL AND finished_at IS NULL)
        OR (status IN ('passed','failed','error') AND outcome IS NOT NULL AND finished_at IS NOT NULL)),
    CHECK ((status = 'running' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR status <> 'running')
);

CREATE INDEX lil_tweak_test_worlds_owner_updated_idx
    ON lil_tweak_test_worlds (owner_id, updated_at DESC);
CREATE INDEX lil_tweak_test_world_attempts_world_idx
    ON lil_tweak_test_world_attempts (world_id, attempt_number);
CREATE INDEX lil_tweak_test_world_attempts_schedulable_idx
    ON lil_tweak_test_world_attempts (status, lease_expires_at, created_at);

INSERT INTO lil_tweak_schema_version (version) VALUES (3);

COMMIT;
