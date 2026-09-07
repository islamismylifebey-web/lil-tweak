BEGIN;

CREATE TABLE lil_tweak_schema_version (
    version integer PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE lil_tweak_jobs (
    id uuid PRIMARY KEY,
    owner_id text NOT NULL,
    mode text NOT NULL CHECK (mode IN ('build','debug','refactor','test','architect','chat')),
    prompt text NOT NULL,
    state text NOT NULL CHECK (state IN ('draft','queued','ingesting','planning','executing','testing','collecting','awaiting_approval','applying','completed','rejected','cancelled','failed','timed_out')),
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0),
    proposal_digest char(64),
    evidence_manifest jsonb,
    summary text NOT NULL DEFAULT '',
    source_manifest jsonb NOT NULL DEFAULT '[]'::jsonb,
    source_digest char(64),
    approval_proposal jsonb,
    approval_consumed boolean NOT NULL DEFAULT false,
    project_context jsonb,
    git_source jsonb,
    cancel_requested boolean NOT NULL DEFAULT false,
    lease_owner text,
    lease_expires_at timestamptz,
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX lil_tweak_jobs_owner_created_idx ON lil_tweak_jobs(owner_id, created_at DESC);
CREATE INDEX lil_tweak_jobs_recovery_idx ON lil_tweak_jobs(state, lease_expires_at);

CREATE TABLE lil_tweak_events (
    job_id uuid NOT NULL REFERENCES lil_tweak_jobs(id) ON DELETE RESTRICT,
    sequence bigint NOT NULL,
    owner_id text NOT NULL,
    kind text NOT NULL,
    redacted_data jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (job_id, sequence)
);

CREATE TABLE lil_tweak_nonces (
    key_id text NOT NULL,
    nonce text NOT NULL,
    request_timestamp timestamptz NOT NULL,
    consumed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (key_id, nonce)
);
CREATE INDEX lil_tweak_nonces_consumed_idx ON lil_tweak_nonces(consumed_at);

CREATE TABLE lil_tweak_idempotency (
    owner_id text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash char(64) NOT NULL,
    job_id uuid NOT NULL REFERENCES lil_tweak_jobs(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, idempotency_key)
);

CREATE TABLE lil_tweak_decisions (
    owner_id text NOT NULL,
    idempotency_key text NOT NULL,
    request_hash char(64) NOT NULL,
    job_id uuid NOT NULL REFERENCES lil_tweak_jobs(id) ON DELETE RESTRICT,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (owner_id, idempotency_key)
);

CREATE TABLE lil_tweak_approvals (
    token_hash char(64) PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES lil_tweak_jobs(id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    revision bigint NOT NULL,
    proposal_digest char(64) NOT NULL,
    action text NOT NULL,
    target text NOT NULL,
    policy_version text NOT NULL,
    source_digest char(64) NOT NULL,
    resource_profile jsonb NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE lil_tweak_sources (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES lil_tweak_jobs(id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    source_id text NOT NULL,
    kind text NOT NULL,
    filename text NOT NULL,
    media_type text NOT NULL,
    object_key text,
    source_digest char(64),
    frozen_reference text,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (job_id, source_id)
);

CREATE TABLE lil_tweak_evidence (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES lil_tweak_jobs(id) ON DELETE RESTRICT,
    owner_id text NOT NULL,
    name text NOT NULL,
    object_key text NOT NULL UNIQUE,
    sha256 char(64) NOT NULL,
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (job_id, name)
);

INSERT INTO lil_tweak_schema_version(version) VALUES (1);
COMMIT;
