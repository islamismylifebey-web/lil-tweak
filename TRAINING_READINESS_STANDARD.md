# Lil Tweak Training Readiness Standard

Lil Tweak does not perform training in this repository. The implemented subsystem prepares an auditable, redacted, contamination-screened, deterministically split export for human review. Every readiness report is `export_only=true` and `training_execution_enabled=false`.

## Binding

| Field | Value |
|---|---|
| Audited remote baseline | `373400cb2b459dbf8a37dacceb0d3d1186eef949` |
| Branch / PR | `codex/lil-tweak-live-workbench-build` / `#6` |
| Working candidate commit | Pending |
| Training execution available | `false` |
| Readiness report schema | `training-readiness-v1` |
| Implementation status | Export preparation implemented and offline-tested; no dataset is approved or trained by this artifact |

## 1. Non-negotiable admission gates

A source may become a prepared case only when all of these are true:

1. Training use is explicitly authorized by an owner-created, permissively licensed, or contractually permitted `TrainingAuthority`.
2. Authority evidence and privacy review have stable SHA-256 bindings.
3. The candidate has complete provenance to repository, revision, task, memory record, context manifest, prompt, model policy, evidence digests, and observation time.
4. Its source memory has not been deleted.
5. Redaction has run over instruction and response.
6. The redacted content and shingles do not intersect the contamination index.
7. It is not an exact duplicate of an earlier canonical prepared case.
8. It receives a deterministic train or holdout split.
9. A human reviews the export before any external training workflow.

Model quality, an apparent successful answer, or live-provider origin never substitutes for authority, privacy, provenance, or contamination gates.

## 2. Versioned schemas

| Schema | Purpose |
|---|---|
| `training-authority-v1` | Legal/owner basis, license, authorization flag, evidence, privacy review, and digest |
| `training-candidate-v1` | Raw instruction/response plus full lineage and authority |
| `contamination-index-v1` | Forbidden content/shingle digests, holdout IDs, deleted-memory digests, and index digest |
| `prepared-training-case-v1` | Redacted content, split, content/shingle digests, rule IDs, lineage, authority, and case digest |
| `training-readiness-v1` | Reconciled cases, exclusions, split counts, cutoff, export-only controls, and report digest |

All models are frozen and reject extra fields. Identifiers and SHA-256 values are format-constrained. Evidence and index sets must be sorted and unique. Times are timezone-aware and normalized to UTC.

## 3. Required lineage

Every `TrainingLineage` binds:

- `repository_id` and exact `source_revision`;
- `task_id` and `task_digest`;
- `memory_record_digest`;
- `context_manifest_digest`;
- `prompt_digest`;
- `model_policy_digest`;
- one or more unique, sorted `evidence_digests`;
- timezone-aware `observed_at`.

Missing, malformed, or changed lineage fails validation. The prepared case retains the source candidate digest and authority digest, allowing audit without treating the prepared text as self-authenticating.

## 4. Redaction standard

Both instruction and response are redacted before digesting, shingling, deduplicating, or exporting. Implemented rule families cover:

- private keys;
- OpenAI API keys;
- GitHub tokens;
- AWS access keys;
- credential assignments such as API keys, tokens, client secrets, passwords, and secrets;
- email addresses;
- North American phone numbers.

`RedactedText` binds the original digest, redacted digest, applied rule IDs, and change flag. The report never needs to expose the original secret to prove that a rule was applied. A future redaction-rule change requires re-preparation and new digests.

## 5. Contamination controls

The contamination index contains five independent exclusion sets:

1. forbidden normalized instruction/response content digests;
2. forbidden normalized eight-token shingle digests;
3. repository IDs reserved for holdout;
4. task IDs reserved for holdout;
5. deleted memory-record digests.

An exact content match or any shingle intersection is excluded as `evaluation_contamination`. A deleted source is excluded as `source_memory_deleted`. A repeated canonical content digest is excluded as `exact_duplicate`. An unauthorized source is excluded as `training_use_not_authorized`.

The frozen reasoning holdout and all of its outputs are evaluation material. The immutable suite digest `6214b2ecaf182bd3947d1871d243525dcb7b55dc606df67e8423c073958700fd` and historical v1 result digest `cc0da9762f2a2bd5ec9d68df2ec38ee31d8bd4b029f2db2b9f205a82286bb0fe` must remain contamination provenance and must not be admitted as training cases. That v1 result is label-exposed and invalid for qualification, but invalidation does not make it training-eligible. The passed label-blind v2 request/result/evidence identified by request digest `1dcfb4d464286cb8152abd06e57a54400553872c6cfa3212623ad5accdec0f71`, result digest `1d87e511d222d15322bdbe0bd9b96d02464268aec9897da84b7b044108067e70`, and evidence-file SHA-256 `f74c90f1cfbc24526ce10df4b17be9353a582f3bae7dd8d7ff3a3e9c73cfba65` is equally excluded, as is every future v2 request, response, or evaluation artifact.

## 6. Deterministic split policy

Split assignment is applied after authority, deletion, redaction, and contamination preparation:

1. An explicitly reserved repository becomes `repository_holdout`.
2. An explicitly reserved task becomes `task_holdout`.
3. An observation at or after the timezone-aware cutoff becomes `temporal_holdout`.
4. Otherwise, a deterministic repository hash bucket of zero becomes `repository_holdout`.
5. Otherwise, a deterministic task hash bucket of zero becomes `task_holdout`.
6. Remaining cases become `train`.

The report must list all four splits in canonical order and reconcile each count exactly. Random, operator-selected, or post-result split reassignment is prohibited.

## 7. Deduplication and canonicalization

Instruction and response are Unicode NFC-normalized, case-folded, and whitespace-collapsed before the pair digest and shingle set are calculated. Exact duplicate detection always retains a holdout copy over a train copy, independent of candidate-ID ordering; ties within the same protection class retain the first candidate by sorted candidate ID. Excluded duplicates bind to the retained case digest. After exact deduplication, any train case that shares a normalized shingle with a retained repository, task, or temporal holdout is excluded as `evaluation_contamination` and binds to the overlapping shingle digest.

This is a deterministic exact/near-overlap defense, not a claim of semantic deduplication. Human review should still identify paraphrased evaluation leakage, low-quality examples, mislabeled outcomes, and distribution imbalance.

## 8. Readiness report rules

A valid `TrainingReadinessReport` must prove:

- source count equals prepared cases plus exclusions;
- ready count equals the number of cases;
- cases and exclusions are candidate-ID sorted;
- split counts cover all four splits and reconcile exactly;
- contamination-index digest and temporal cutoff are present;
- `ready_for_human_review` is true exactly when at least one prepared case exists;
- `export_only=true`;
- `training_execution_enabled=false`;
- the canonical report digest matches every unsigned field.

`ready_for_human_review` does not mean legally approved for training, technically suitable for a model, or executed. It means only that the deterministic preparation gates produced at least one reviewable case.

## 9. Required human review

Before any external training use, a reviewer must verify:

- authority evidence and license scope;
- privacy review and redaction sufficiency;
- correct success/failure labels and absence of false completion claims;
- complete repository/task/model/prompt/evidence lineage;
- no holdout or benchmark leakage, including paraphrases;
- deletion propagation;
- split integrity and temporal cutoff;
- representative quality and absence of harmful or insecure patterns;
- external training platform controls, retention, and deletion behavior.

Review approval must be stored outside the model output and bound to the exact report digest.

## 10. Current decision

The training-readiness implementation is offline-tested for redaction, deduplication, deterministic splitting, contamination exclusion, lineage validation, and deletion propagation. No live dataset export, human approval, or training run is evidenced here.

The correct status is **training preparation implemented; training execution disabled; no dataset authorized by this report**.
