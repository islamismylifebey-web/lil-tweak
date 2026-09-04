# Lil' Tweak Engineering Contract Registry V1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, PostgreSQL-backed, shadow-mode authority registry that decides what Lil' Tweak may do for an authenticated requester, asset, action, intent, and environment.

**Architecture:** Add focused Python trusted-Core modules for immutable records, canonical serialization, resolution, approval/evidence validation, audit integrity, and a store protocol. Add an in-memory test adapter and PostgreSQL production adapter, then expose a signed decision-only API without connecting enforcement to the orchestrator or either runner branch.

**Tech Stack:** Python 3.12 dataclasses/enums/hashlib/json, existing HMAC request authentication, PostgreSQL via the existing Core connection pattern, Drizzle SQL migrations, `unittest`, Node 22+/24 repository verification.

**Spec:** `docs/superpowers/specs/2026-09-04-engineering-contract-registry-v1-design.md`

## Global Constraints

- Work only on `feature/engineering-contract-registry-v1`, based on current `main`.
- Do not modify PR #21, PR #24, `infra/digitalocean-runner-v3-activation`, `infra/runner-v3-core-activation`, runner configuration, deployment configuration, or live runner state.
- V1 is shadow-only: it records `observedMode`, `recommendedMode`, and `enforced: false`; it never blocks the current orchestrator.
- A valid unmatched request returns `EXPLAIN_ONLY`; invalid, ambiguous, conflicting, unavailable, or integrity-failed decisions return `BLOCKED`.
- V1 never grants production mutation, push, merge, publish, or deploy.
- No raw secrets, credentials, or unredacted regulated data may be persisted.
- Contract activation and high-risk exceptions require the authenticated identity bound to Mauce Pennington Bey; a display name is not authentication.
- Every code task follows red-green-refactor, exact-head verification, and a focused commit.

## File Map

- Create `core/lil_tweak/registry_types.py`: closed enums and immutable validated records.
- Create `core/lil_tweak/registry_canonical.py`: canonical JSON and digest functions.
- Create `core/lil_tweak/registry_decision.py`: deterministic selection, precedence, and reason codes.
- Create `core/lil_tweak/registry_validation.py`: approval and evidence validity.
- Create `core/lil_tweak/registry_store.py`: store protocol, in-memory adapter, PostgreSQL adapter, audit chain.
- Create `core/lil_tweak/registry_seed.py`: idempotent V1 authority seed records.
- Modify `core/lil_tweak/api.py`: authenticated decision-only shadow endpoint.
- Modify `core/lil_tweak/main.py`: construct and inject the registry service, without orchestrator wiring.
- Modify `db/schema.ts`: registry table declarations.
- Create `drizzle/0003_engineering_contract_registry.sql`: immutable PostgreSQL schema and constraints.
- Create `core/tests/test_registry_types.py`.
- Create `core/tests/test_registry_decision.py`.
- Create `core/tests/test_registry_validation.py`.
- Create `core/tests/test_registry_store.py`.
- Create `core/tests/test_registry_api.py`.
- Create `tests/registry-migration.test.mjs`.
- Create `tests/registry-shadow-contract.test.mjs`.

---

### Task 1: Closed Vocabulary and Immutable Records

**Files:**
- Create: `core/lil_tweak/registry_types.py`
- Create: `core/tests/test_registry_types.py`

**Interfaces:**
- Produces: `ExecutionMode`, `Environment`, `ActionClass`, `OperationIntent`, `ReasonCode`, `PrincipalStatus`, `DecisionRequest`, `ContractVersion`, `ApprovalRecord`, `EvidenceReference`, `Decision`.
- All later tasks consume these exact types.

- [ ] **Step 1: Write failing enum and validation tests**

```python
def test_governed_vocabulary_rejects_unknown_values():
    with self.assertRaises(ValueError):
        Environment("staging-ish")
    with self.assertRaises(ValueError):
        ReasonCode("maybe_allowed")

def test_decision_request_requires_exact_revision_for_repository_work():
    with self.assertRaises(RegistryValidationError):
        DecisionRequest(
            owner_id="owner-12345678",
            requester_id="principal:requester",
            agent_id="principal:lil-tweak",
            asset_id="asset:lil-tweak",
            action_class=ActionClass.CODE_GENERATION,
            operation_intent=OperationIntent.PROPOSE,
            environment=Environment.REPOSITORY,
            source_revision=None,
        ).validate()
```

- [ ] **Step 2: Run the tests and confirm they fail because the module is absent**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_types -v`

Expected: FAIL with `ModuleNotFoundError: core.lil_tweak.registry_types`.

- [ ] **Step 3: Implement the closed enums and frozen records**

```python
class ExecutionMode(StrEnum):
    BLOCKED = "BLOCKED"
    EXPLAIN_ONLY = "EXPLAIN_ONLY"
    DRAFT_CODE = "DRAFT_CODE"
    PREPARE_PATCH = "PREPARE_PATCH"
    APPLY_SANDBOX = "APPLY_SANDBOX"
    APPLY_NON_PRODUCTION = "APPLY_NON_PRODUCTION"

class Environment(StrEnum):
    DOCUMENT_ONLY = "DOCUMENT_ONLY"
    REPOSITORY = "REPOSITORY"
    SANDBOX = "SANDBOX"
    NON_PRODUCTION = "NON_PRODUCTION"
    PRODUCTION = "PRODUCTION"

class ActionClass(StrEnum):
    ANALYSIS = "ANALYSIS"
    CODE_GENERATION = "CODE_GENERATION"
    PATCH_PREPARATION = "PATCH_PREPARATION"
    PATCH_APPLICATION = "PATCH_APPLICATION"
    APPROVAL_BINDING = "APPROVAL_BINDING"
    EVIDENCE_BINDING = "EVIDENCE_BINDING"

class OperationIntent(StrEnum):
    READ = "READ"
    PROPOSE = "PROPOSE"
    MODIFY = "MODIFY"
    APPLY = "APPLY"
    PUBLISH = "PUBLISH"
    DEPLOY = "DEPLOY"
```

Define `ReasonCode` with every exact code from the spec. Use `@dataclass(frozen=True, slots=True)` for every record. Validate bounded IDs, lowercase 64-character SHA-256 values, UTC-aware times, non-empty owner scope, and the repository revision rule. Do not accept free-form enum strings after object construction.

- [ ] **Step 4: Run focused tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_types -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/lil_tweak/registry_types.py core/tests/test_registry_types.py
git commit -m "feat: define registry governed vocabulary"
```

### Task 2: Canonical Serialization and Digests

**Files:**
- Create: `core/lil_tweak/registry_canonical.py`
- Create: `core/tests/test_registry_canonical.py`

**Interfaces:**
- Consumes: frozen records from `registry_types.py`.
- Produces: `canonical_json(value: object) -> bytes`, `sha256_digest(value: object) -> str`, and `decision_binding(request, contract_digests) -> str`.

- [ ] **Step 1: Write deterministic golden tests**

```python
def test_canonical_json_is_key_and_input_order_independent():
    left = {"b": [2, 1], "a": {"z": True}}
    right = {"a": {"z": True}, "b": [2, 1]}
    self.assertEqual(canonical_json(left), canonical_json(right))
    self.assertEqual(
        sha256_digest(left),
        "8b55f0ef6843b36b27f4d351d7f7228194782492604f00e2b17e5428d99d77e4",
    )

def test_canonical_json_rejects_float_and_naive_datetime():
    with self.assertRaises(CanonicalizationError):
        canonical_json({"unsafe": 1.2})
```

Recalculate the displayed golden digest once using the completed serializer and commit that fixed value; the test must never calculate its own expected digest.

- [ ] **Step 2: Run the tests and verify red**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_canonical -v`

Expected: FAIL because canonical functions do not exist.

- [ ] **Step 3: Implement one canonical form**

```python
def canonical_json(value: object) -> bytes:
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")

def sha256_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
```

Normalize `StrEnum` to values, tuples to lists, dataclasses by declared field order before JSON key sorting, and aware datetimes to UTC `Z`. Reject bytes, floats, naive datetimes, unknown objects, and secret-bearing field names such as `password`, `token`, `secret`, or `credential` anywhere in the value.

- [ ] **Step 4: Run focused tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_canonical -v`

Expected: PASS with the fixed golden digest.

- [ ] **Step 5: Commit**

```bash
git add core/lil_tweak/registry_canonical.py core/tests/test_registry_canonical.py
git commit -m "feat: add canonical registry digests"
```

### Task 3: Deterministic Contract Resolution and Decision Table

**Files:**
- Create: `core/lil_tweak/registry_decision.py`
- Create: `core/tests/test_registry_decision.py`

**Interfaces:**
- Consumes: `DecisionRequest`, `ContractVersion`, validation results, canonical digests.
- Produces: `resolve_contracts(request, contracts, approvals=(), evidence=(), now=None) -> Decision`.

- [ ] **Step 1: Write table-driven golden tests**

```python
CASES = (
    ("no match", (), ExecutionMode.EXPLAIN_ONLY, ReasonCode.NO_MATCHING_CONTRACT),
    ("prohibition wins", (permit_draft, prohibit_code), ExecutionMode.BLOCKED, ReasonCode.PROHIBITED_ACTION),
    ("lowest authority wins", (permit_draft, explain_only), ExecutionMode.EXPLAIN_ONLY, None),
)

def test_decision_table():
    for label, contracts, mode, reason in CASES:
        with self.subTest(label=label):
            decision = resolve_contracts(REQUEST, contracts, now=NOW)
            self.assertEqual(decision.recommended_mode, mode)
            if reason is not None:
                self.assertIn(reason, decision.reason_codes)

def test_requirements_are_union_of_compatible_contracts():
    decision = resolve_contracts(REQUEST, (requires_a, requires_b), now=NOW)
    self.assertEqual(decision.required_approval_ids, ("approval:a", "approval:b"))
    self.assertEqual(decision.required_evidence_types, ("lint", "tests"))
```

- [ ] **Step 2: Run the tests and verify red**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_decision -v`

Expected: FAIL because `resolve_contracts` is absent.

- [ ] **Step 3: Implement explicit precedence**

```python
_AUTHORITY_ORDER = {
    ExecutionMode.BLOCKED: 0,
    ExecutionMode.EXPLAIN_ONLY: 1,
    ExecutionMode.DRAFT_CODE: 2,
    ExecutionMode.PREPARE_PATCH: 3,
    ExecutionMode.APPLY_SANDBOX: 4,
    ExecutionMode.APPLY_NON_PRODUCTION: 5,
}

def _most_restrictive(modes: Iterable[ExecutionMode]) -> ExecutionMode:
    return min(modes, key=_AUTHORITY_ORDER.__getitem__)
```

Filter by exact owner, active principals, asset, action class, operation intent, environment, and effective interval. Make explicit prohibitions win, union compatible requirements, block incompatible matches, sort all returned IDs and codes, and bind the decision digest to the complete request and ordered contract digests. Hard-block `PRODUCTION`, `PUBLISH`, and `DEPLOY` regardless of stored contract content.

- [ ] **Step 4: Run the decision matrix**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_decision -v`

Expected: PASS for every precedence and failure row.

- [ ] **Step 5: Commit**

```bash
git add core/lil_tweak/registry_decision.py core/tests/test_registry_decision.py
git commit -m "feat: add deterministic contract resolution"
```

### Task 4: Approval and Evidence Validation

**Files:**
- Create: `core/lil_tweak/registry_validation.py`
- Create: `core/tests/test_registry_validation.py`

**Interfaces:**
- Produces: `validate_approval(record, request, target_digest, now, superseded_at=None) -> ReasonCode | None` and `validate_evidence(reference, request, target_digest) -> ReasonCode | None`.
- `registry_decision.resolve_contracts` consumes these validators.

- [ ] **Step 1: Write failing freshness and evidence tests**

```python
def test_approval_must_be_current_exact_and_unrevoked():
    for changed, reason in (
        ({"revoked_at": NOW}, ReasonCode.REVOKED_APPROVAL),
        ({"expires_at": NOW}, ReasonCode.STALE_APPROVAL),
        ({"target_digest": "0" * 64}, ReasonCode.WRONG_DIGEST_BINDING),
    ):
        record = replace(VALID_APPROVAL, **changed)
        self.assertEqual(validate_approval(record, REQUEST, DIGEST, NOW), reason)

def test_evidence_requires_safe_flag_and_exact_revision():
    unsafe = replace(VALID_EVIDENCE, asserted_safe=False)
    stale = replace(VALID_EVIDENCE, source_revision="1" * 40)
    self.assertEqual(validate_evidence(unsafe, REQUEST, DIGEST), ReasonCode.INTEGRITY_CHECK_FAILED)
    self.assertEqual(validate_evidence(stale, REQUEST, DIGEST), ReasonCode.WRONG_DIGEST_BINDING)
```

- [ ] **Step 2: Run tests and verify red**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_validation -v`

Expected: FAIL because validators are absent.

- [ ] **Step 3: Implement exact mechanical checks**

Check authentication binding, revocation, issue time, expiry, digest, exact scope tuple, and post-approval supersession in that order. For evidence, permit only closed locator classes `CORE_DB`, `R2_IMMUTABLE`, and `GITHUB_EXACT_COMMIT`; require supported digest `sha256`, source system, evidence type, creation time, asserted-safe flag, target digest, and source revision when the request has one. Return stable codes; never free-form explanations from validators.

- [ ] **Step 4: Integrate validators into resolution and rerun both suites**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_validation core.tests.test_registry_decision -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/lil_tweak/registry_validation.py core/lil_tweak/registry_decision.py core/tests/test_registry_validation.py core/tests/test_registry_decision.py
git commit -m "feat: bind registry approvals and evidence"
```

### Task 5: Append-Only Store and Audit Integrity

**Files:**
- Create: `core/lil_tweak/registry_store.py`
- Create: `core/lil_tweak/registry_seed.py`
- Create: `core/tests/test_registry_store.py`

**Interfaces:**
- Produces: `ContractRegistryStore` protocol, `MemoryContractRegistryStore`, `PostgresContractRegistryStore`, `verify_owner_chain(owner_id) -> bool`, and `seed_v1_authority(store, owner_id, approver_principal_id) -> None`.

- [ ] **Step 1: Write store contract tests against the memory adapter**

```python
def test_owner_sequence_and_hash_chain_are_append_only():
    store = MemoryContractRegistryStore()
    first = store.append_audit(OWNER, "contract.created", SUBJECT, {"version": "1"})
    second = store.append_audit(OWNER, "contract.activated", SUBJECT, {"version": "1"})
    self.assertEqual((first.sequence, second.sequence), (1, 2))
    self.assertEqual(second.previous_hash, first.event_hash)
    self.assertTrue(store.verify_owner_chain(OWNER))

def test_seed_is_idempotent_and_never_authenticates_display_name():
    seed_v1_authority(store, OWNER, "principal:mauce-bound-owner")
    seed_v1_authority(store, OWNER, "principal:mauce-bound-owner")
    self.assertEqual(len(store.list_contract_versions(OWNER, "contract:v1-default")), 1)
```

- [ ] **Step 2: Run tests and verify red**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_store -v`

Expected: FAIL because store classes are absent.

- [ ] **Step 3: Implement the protocol, atomic memory adapter, and seeds**

```python
class ContractRegistryStore(Protocol):
    def list_active_contracts(self, owner_id: str, at: datetime) -> tuple[ContractVersion, ...]: ...
    def append_decision(self, decision: Decision) -> Decision: ...
    def append_audit(self, owner_id: str, kind: str, subject_id: str, payload: object) -> AuditEvent: ...
    def verify_owner_chain(self, owner_id: str) -> bool: ...
```

Use one lock per adapter operation. Reject duplicate immutable versions unless every canonical byte is identical, in which case seed replay is a no-op. Build seed records for Lil' Tweak, the repository asset, the bound approver principal, the explain-only default, and prohibited runner/deployment surfaces.

- [ ] **Step 4: Run store and decision tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_store core.tests.test_registry_decision -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/lil_tweak/registry_store.py core/lil_tweak/registry_seed.py core/tests/test_registry_store.py
git commit -m "feat: add append-only registry store"
```

### Task 6: PostgreSQL Schema and Production Adapter

**Files:**
- Modify: `db/schema.ts`
- Create: `drizzle/0003_engineering_contract_registry.sql`
- Create: `tests/registry-migration.test.mjs`
- Modify: `core/lil_tweak/registry_store.py`
- Modify: `core/tests/test_registry_store.py`

**Interfaces:**
- Produces immutable registry tables and a `PostgresContractRegistryStore(connect)` implementing the Task 5 protocol.

- [ ] **Step 1: Write failing migration contract tests**

```javascript
test('registry migration enforces immutable owner-scoped records', () => {
  const sql = readFileSync('drizzle/0003_engineering_contract_registry.sql', 'utf8')
  for (const table of ['registry_principals', 'registry_assets', 'registry_contract_versions', 'registry_approvals', 'registry_evidence_references', 'registry_exceptions', 'registry_decisions', 'registry_audit_events']) {
    assert.match(sql, new RegExp(`CREATE TABLE ${table}`))
  }
  assert.match(sql, /UNIQUE \(owner_id, sequence\)/)
  assert.match(sql, /CHECK \(expires_at IS NULL OR expires_at > effective_at\)/)
})
```

- [ ] **Step 2: Run migration test and verify red**

Run: `node --test tests/registry-migration.test.mjs`

Expected: FAIL because migration 0003 is absent.

- [ ] **Step 3: Add tables, constraints, and no-update protections**

Create the eight tables named in the test. Use UUID primary keys or bounded text identities consistently with the current schema. Include owner IDs on every row, immutable `(owner_id, logical_id, version)` uniqueness, digest checks, effective/expiry checks, per-owner sequence uniqueness, previous/current hash fields, and foreign keys that include owner scope. Add PostgreSQL triggers that reject `UPDATE` and `DELETE` for contract versions, decisions, and audit events. Drizzle declarations must match the SQL exactly.

- [ ] **Step 4: Implement the PostgreSQL adapter atomically**

For `append_audit`, lock the owner's latest audit row with `FOR UPDATE`, calculate the next sequence and hash, insert once, and return the committed event. For `append_decision`, insert the decision and audit event in one transaction. Map integrity or connection failures to `RegistryPersistenceError`; never downgrade them to no-match.

- [ ] **Step 5: Run migration, store, and existing database tests**

Run: `node --test tests/registry-migration.test.mjs tests/engineering-migration.test.mjs tests/engineering-d1.integration.test.mjs`

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_store -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add db/schema.ts drizzle/0003_engineering_contract_registry.sql tests/registry-migration.test.mjs core/lil_tweak/registry_store.py core/tests/test_registry_store.py
git commit -m "feat: persist registry in PostgreSQL"
```

### Task 7: Authenticated Shadow Decision Endpoint

**Files:**
- Modify: `core/lil_tweak/api.py`
- Modify: `core/lil_tweak/main.py`
- Create: `core/tests/test_registry_api.py`
- Create: `tests/registry-shadow-contract.test.mjs`

**Interfaces:**
- Adds signed `POST /v1/registry/decisions`.
- Accepts exact JSON fields: `requesterId`, `agentId`, `assetId`, `actionClass`, `operationIntent`, `environment`, `sourceRevision`, `observedMode`.
- Returns: `decisionId`, `decisionDigest`, `observedMode`, `recommendedMode`, `enforced`, `reasonCodes`, `requiredApprovalIds`, `requiredEvidenceTypes`, `contractVersions`, `createdAt`.

- [ ] **Step 1: Write failing signed endpoint tests**

```python
def test_valid_unmatched_request_is_shadow_explain_only(self):
    status, payload = self.signed_post("/v1/registry/decisions", VALID_UNMATCHED)
    self.assertEqual(status, 200)
    self.assertEqual(payload["recommendedMode"], "EXPLAIN_ONLY")
    self.assertEqual(payload["reasonCodes"], ["no_matching_contract"])
    self.assertIs(payload["enforced"], False)

def test_store_failure_blocks_and_never_becomes_no_match(self):
    status, payload = self.signed_post_with_broken_store(VALID_UNMATCHED)
    self.assertEqual(status, 503)
    self.assertEqual(payload["code"], "audit_persist_failed")
```

- [ ] **Step 2: Run API tests and verify red**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_api -v`

Expected: FAIL with a 404 response.

- [ ] **Step 3: Add strict routing and response shaping**

Set a small fixed body limit, reuse `verify_request`, require exact keys and types, map every public reason through `ReasonCode`, and use generic authentication failures. Persist the decision before returning success. Ensure `enforced` is the literal boolean `false`. Do not call or import `EngineeringOrchestrator` from registry modules.

- [ ] **Step 4: Wire construction but not enforcement**

Construct the registry store and seed service in `main.py`, then inject only into `LilTweakApi`. Do not pass it into the orchestrator, runner client, sandbox, export, deployment, or publishing paths.

- [ ] **Step 5: Add Node contract test for non-interference**

```javascript
test('registry remains shadow-only and outside runner surfaces', () => {
  const api = readFileSync('core/lil_tweak/api.py', 'utf8')
  const orchestrator = readFileSync('core/lil_tweak/orchestrator.py', 'utf8')
  assert.match(api, /"enforced": false|"enforced": False/)
  assert.doesNotMatch(orchestrator, /registry_decision|ContractRegistry/)
})
```

- [ ] **Step 6: Run focused API and contract tests**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_api core.tests.test_api -v`

Run: `node --test tests/registry-shadow-contract.test.mjs tests/core-protocol.test.mjs tests/core-transport.test.mjs`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add core/lil_tweak/api.py core/lil_tweak/main.py core/tests/test_registry_api.py tests/registry-shadow-contract.test.mjs
git commit -m "feat: expose shadow registry decisions"
```

### Task 8: Exact-Head Proof and Pull Request

**Files:**
- Modify: `README.md`
- Create: `docs/engineering-contract-registry-v1.md`

**Interfaces:**
- Documents request/response semantics, non-claims, shadow-mode limits, reason codes, and operator verification.

- [ ] **Step 1: Write operator documentation**

Document that V1 recommends but does not enforce, that display names do not authenticate people, that no external execution control or artifact-existence proof is claimed, and that production/runner authority is absent. Include one signed request fixture and one explain-only response fixture with fake IDs and digests only.

- [ ] **Step 2: Run every focused registry suite**

Run: `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest core.tests.test_registry_types core.tests.test_registry_canonical core.tests.test_registry_decision core.tests.test_registry_validation core.tests.test_registry_store core.tests.test_registry_api -v`

Run: `node --test tests/registry-migration.test.mjs tests/registry-shadow-contract.test.mjs`

Expected: PASS.

- [ ] **Step 3: Prove runner and deployment surfaces were not changed**

Run: `git diff --name-only main...HEAD`

Expected: no `.github/workflows/*runner*`, `core/lil_tweak/galor.py`, runner configuration, deployment configuration, or infrastructure branch files.

Run: `git diff --exit-code main...HEAD -- core/lil_tweak/orchestrator.py core/lil_tweak/galor.py .github/workflows .openai/hosting.json`

Expected: exit 0 with no diff.

- [ ] **Step 4: Run the full exact-head repository verification**

Run: `npm ci`

Run: `npm run verify`

Expected: typecheck, lint, build, Node tests, and Python Core tests all PASS.

- [ ] **Step 5: Record the exact verified commit**

Run: `git rev-parse HEAD`

Write the returned 40-character commit into the pull-request verification section. Do not claim another revision passed.

- [ ] **Step 6: Commit documentation**

```bash
git add README.md docs/engineering-contract-registry-v1.md
git commit -m "docs: explain registry shadow mode"
```

- [ ] **Step 7: Rerun exact-head verification after the documentation commit**

Run: `npm run verify`

Expected: PASS on the new exact HEAD.

- [ ] **Step 8: Open a draft pull request**

Title: `Build Lil' Tweak Engineering Contract Registry V1`

The body must identify the exact tested commit, summarize decision behavior, state `enforced: false`, state that PR #21 and PR #24 were untouched, list focused and full verification results, and explicitly supersede PR #13 without copying its authority or qualification claims.

