import {
  PINNED_RUNNER_ID,
  type SignedDispatchAttestation,
} from "./attestation";
import {
  booleanField,
  exactRecord,
  InputError,
  integerField,
  isRecord,
  requireMatch,
  stringField,
} from "./validation";

const DIGEST_PATTERN = /^[a-f0-9]{64}$/;
const EXECUTION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const GIT_SHA_PATTERN = /^[a-f0-9]{40}$/;
const QUALIFICATION_BRANCH_PATTERN =
  /^qualification\/galor-tweak-runner-01\/[a-z0-9][a-z0-9-]{0,31}$/;

export const RUNNER_JOB_MANIFEST_SCHEMA = "lil-tweak.runner-job-manifest/v1";
export const QUALIFICATION_REPOSITORY = "islamismylifebey-web/lil-tweak";
export const QUALIFICATION_ARTIFACT_PATH =
  "docs/runner-qualification/galor-tweak-runner-01.md";
export const EMPTY_SHA256 =
  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
export const QUALIFICATION_CONTENT_SHA256 =
  "62253a2945ea498f3b206a0449e5a97a0cf5783dd7858d7a11fbb365f4c04a91";
export const RUNNER_EVIDENCE_SCHEMA = "lil-tweak.runner-evidence/v2";
export const RUNNER_RUNTIME_IMAGE =
  "python@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36";
export const RUNNER_SECCOMP_SHA256 =
  "50eeb8b4cb2c33284f09453c8dd64c5895f5e1a2fa6b7a7440dfbac175fe1c23";
export const MAX_CANDIDATE_BUNDLE_BYTES = 1_000_000;

interface ManifestSource {
  repository: typeof QUALIFICATION_REPOSITORY;
  commit_sha: string;
  tree_sha: string;
}

interface CommonRunnerJobManifest {
  schema_version: typeof RUNNER_JOB_MANIFEST_SCHEMA;
  source: ManifestSource;
  verification_profile: "runner_qualification_subset_v1";
  timeout_seconds: number;
  network_scope: "github_repository_only";
  allow_package_install: false;
  allow_production_access: false;
  allow_deploy: false;
}

export interface ReadOnlyRunnerJobManifest extends CommonRunnerJobManifest {
  job_type: "read_only";
  action: "qualification_read_only_v1";
}

export interface BoundedWriteRunnerJobManifest extends CommonRunnerJobManifest {
  job_type: "bounded_write";
  action: "qualification_bounded_docs_v1";
  qualification_branch: string;
  artifact: {
    path: typeof QUALIFICATION_ARTIFACT_PATH;
    expected_before_sha256: typeof EMPTY_SHA256;
    content_sha256: typeof QUALIFICATION_CONTENT_SHA256;
  };
}

export type RunnerJobManifest =
  | ReadOnlyRunnerJobManifest
  | BoundedWriteRunnerJobManifest;

export type ExecutionStatus =
  | "OFFERED"
  | "CLAIMED"
  | "EVIDENCE_RECORDED"
  | "CANCEL_REQUESTED"
  | "EXPIRED";

export interface OfferRequest {
  attestation: SignedDispatchAttestation;
  manifest: RunnerJobManifest;
}

export interface ClaimRequest {
  execution_id: string;
  attempt_nonce: string;
}

export interface BaseRunnerReceipt {
  runner_id: typeof PINNED_RUNNER_ID;
  runtime_image: typeof RUNNER_RUNTIME_IMAGE;
  seccomp_sha256: typeof RUNNER_SECCOMP_SHA256;
  apparmor_profile: "liltweak-runner-job";
  network_denied: true;
  package_install_allowed: false;
  production_access_allowed: false;
  deploy_allowed: false;
  workspace_cleaned: boolean;
  cgroup_cleaned: boolean;
}

export interface ReadOnlyRunnerReceipt extends BaseRunnerReceipt {
  candidate_sha: null;
  source_commit: string;
  source_tree: string;
  source_mutated: false;
}

export interface BoundedWriteRunnerReceipt extends BaseRunnerReceipt {
  artifact_path: typeof QUALIFICATION_ARTIFACT_PATH;
  artifact_sha256: typeof QUALIFICATION_CONTENT_SHA256;
  candidate_sha: string;
  candidate_tree: string;
  source_commit: string;
  source_tree: string;
  source_mutated: true;
  bundle_sha256: string;
  bundle_size: number;
  candidate_store_id: string;
  created_at_ms: number;
  qualification_branch: string;
}

export interface CancelledBeforeExecutionReceipt {
  cancelled_before_execution: true;
}

export type RunnerReceipt =
  | BaseRunnerReceipt
  | ReadOnlyRunnerReceipt
  | BoundedWriteRunnerReceipt
  | CancelledBeforeExecutionReceipt;

export interface RunnerEvidence {
  schema_version: typeof RUNNER_EVIDENCE_SCHEMA;
  outcome: "succeeded" | "failed" | "cancelled";
  operation_digest: string;
  stdout_digest: string;
  stderr_digest: string;
  receipt_digest: string;
  receipt: RunnerReceipt;
  exit_code: number;
  started_at_ms: number;
  finished_at_ms: number;
}

export interface EvidenceRequest extends ClaimRequest {
  evidence: RunnerEvidence;
}

export interface RunnerEvidenceEnvelope {
  request: {
    schema_version: "lil-tweak.runner-request/v1";
    runner_id: typeof PINNED_RUNNER_ID;
    operation: "evidence";
    request_nonce: string;
    issued_at_ms: number;
    payload: EvidenceRequest;
  };
  signature: string;
}

export interface CancelRequest {
  reason_digest: string;
}

export interface ExecutionSummary {
  execution_id: string;
  runner_id: typeof PINNED_RUNNER_ID;
  runner_role: "role-tweak-runner";
  status: ExecutionStatus;
  lease_digest: string;
  contract_digest: string;
  commands_digest: string;
  approval_digest: string;
  policy_digest: string;
  expires_at_ms: number;
  claim_receipt_digest?: string;
  evidence_digest?: string;
  evidence_outcome?: RunnerEvidence["outcome"];
  evidence_envelope?: RunnerEvidenceEnvelope;
  cancellation_reason_digest?: string;
}

export interface OfferSummary {
  execution_id: string;
  runner_id: typeof PINNED_RUNNER_ID;
  status: "OFFERED";
  lease_digest: string;
  contract_digest: string;
  commands_digest: string;
  expires_at_ms: number;
}

export interface RunnerOfferSummary {
  execution_id: string;
  status: "OFFERED";
  expires_at_ms: number;
  attestation: SignedDispatchAttestation;
  manifest: RunnerJobManifest;
}

export interface ClaimSummary extends ExecutionSummary {
  status: "CLAIMED";
  claim_receipt_digest: string;
}

export interface EvidenceSummary {
  execution_id: string;
  status: "EVIDENCE_RECORDED";
  evidence_digest: string;
}

export interface CancelSummary {
  execution_id: string;
  status: "CANCEL_REQUESTED";
  reason_digest: string;
}

function parseClaimIdentifiers(value: unknown, label: string): ClaimRequest {
  const record = exactRecord(value, ["execution_id", "attempt_nonce"], label);
  return {
    execution_id: requireMatch(
      stringField(record, "execution_id", label),
      EXECUTION_ID_PATTERN,
      "execution_id",
    ),
    attempt_nonce: requireMatch(
      stringField(record, "attempt_nonce", label),
      NONCE_PATTERN,
      "attempt_nonce",
    ),
  };
}

function parseManifestSource(value: unknown): ManifestSource {
  const source = exactRecord(
    value,
    ["repository", "commit_sha", "tree_sha"],
    "manifest.source",
  );
  if (stringField(source, "repository", "manifest.source") !== QUALIFICATION_REPOSITORY) {
    throw new InputError("manifest repository is not authorized");
  }
  return {
    repository: QUALIFICATION_REPOSITORY,
    commit_sha: requireMatch(
      stringField(source, "commit_sha", "manifest.source"),
      GIT_SHA_PATTERN,
      "manifest.source.commit_sha",
    ),
    tree_sha: requireMatch(
      stringField(source, "tree_sha", "manifest.source"),
      GIT_SHA_PATTERN,
      "manifest.source.tree_sha",
    ),
  };
}

function commonManifest(record: Record<string, unknown>): CommonRunnerJobManifest {
  if (
    stringField(record, "schema_version", "manifest") !== RUNNER_JOB_MANIFEST_SCHEMA
  ) {
    throw new InputError("manifest schema is invalid");
  }
  if (
    stringField(record, "verification_profile", "manifest") !==
    "runner_qualification_subset_v1"
  ) {
    throw new InputError("manifest verification profile is invalid");
  }
  const timeoutSeconds = integerField(record, "timeout_seconds", "manifest");
  if (timeoutSeconds < 60 || timeoutSeconds > 1_800) {
    throw new InputError("manifest timeout is outside the approved bound");
  }
  if (
    stringField(record, "network_scope", "manifest") !==
    "github_repository_only"
  ) {
    throw new InputError("manifest network scope is invalid");
  }
  for (const field of [
    "allow_package_install",
    "allow_production_access",
    "allow_deploy",
  ] as const) {
    if (booleanField(record, field, "manifest")) {
      throw new InputError(`manifest.${field} must remain false`);
    }
  }
  return {
    schema_version: RUNNER_JOB_MANIFEST_SCHEMA,
    source: parseManifestSource(record.source),
    verification_profile: "runner_qualification_subset_v1" as const,
    timeout_seconds: timeoutSeconds,
    network_scope: "github_repository_only" as const,
    allow_package_install: false as const,
    allow_production_access: false as const,
    allow_deploy: false as const,
  };
}

export function parseRunnerJobManifest(value: unknown): RunnerJobManifest {
  if (!isRecord(value)) {
    throw new InputError("manifest must be an object");
  }
  const jobType = stringField(value, "job_type", "manifest");
  const commonKeys = [
    "schema_version",
    "job_type",
    "action",
    "source",
    "verification_profile",
    "timeout_seconds",
    "network_scope",
    "allow_package_install",
    "allow_production_access",
    "allow_deploy",
  ] as const;
  if (jobType === "read_only") {
    const record = exactRecord(value, commonKeys, "manifest");
    if (stringField(record, "action", "manifest") !== "qualification_read_only_v1") {
      throw new InputError("manifest action does not match its job type");
    }
    return {
      ...commonManifest(record),
      job_type: "read_only",
      action: "qualification_read_only_v1",
    };
  }
  if (jobType === "bounded_write") {
    const record = exactRecord(
      value,
      [...commonKeys, "qualification_branch", "artifact"],
      "manifest",
    );
    if (
      stringField(record, "action", "manifest") !==
      "qualification_bounded_docs_v1"
    ) {
      throw new InputError("manifest action does not match its job type");
    }
    const artifact = exactRecord(
      record.artifact,
      ["path", "expected_before_sha256", "content_sha256"],
      "manifest.artifact",
    );
    if (
      stringField(artifact, "path", "manifest.artifact") !==
        QUALIFICATION_ARTIFACT_PATH ||
      stringField(artifact, "expected_before_sha256", "manifest.artifact") !==
        EMPTY_SHA256 ||
      stringField(artifact, "content_sha256", "manifest.artifact") !==
        QUALIFICATION_CONTENT_SHA256
    ) {
      throw new InputError("manifest artifact is not the fixed qualification artifact");
    }
    return {
      ...commonManifest(record),
      job_type: "bounded_write",
      action: "qualification_bounded_docs_v1",
      qualification_branch: requireMatch(
        stringField(record, "qualification_branch", "manifest"),
        QUALIFICATION_BRANCH_PATTERN,
        "manifest.qualification_branch",
      ),
      artifact: {
        path: QUALIFICATION_ARTIFACT_PATH,
        expected_before_sha256: EMPTY_SHA256,
        content_sha256: QUALIFICATION_CONTENT_SHA256,
      },
    };
  }
  throw new InputError("manifest job type is invalid");
}

export function parseOfferRequest(value: unknown): OfferRequest {
  const record = exactRecord(value, ["attestation", "manifest"], "offer request");
  return {
    attestation: record.attestation as SignedDispatchAttestation,
    manifest: parseRunnerJobManifest(record.manifest),
  };
}

export function parseClaimRequest(value: unknown): ClaimRequest {
  return parseClaimIdentifiers(value, "claim request");
}

const BASE_RECEIPT_KEYS = [
  "runner_id",
  "runtime_image",
  "seccomp_sha256",
  "apparmor_profile",
  "network_denied",
  "package_install_allowed",
  "production_access_allowed",
  "deploy_allowed",
  "workspace_cleaned",
  "cgroup_cleaned",
] as const;

function parseBaseReceiptFields(
  receipt: Record<string, unknown>,
): BaseRunnerReceipt {
  if (
    stringField(receipt, "runner_id", "evidence.receipt") !== PINNED_RUNNER_ID ||
    stringField(receipt, "runtime_image", "evidence.receipt") !==
      RUNNER_RUNTIME_IMAGE ||
    stringField(receipt, "seccomp_sha256", "evidence.receipt") !==
      RUNNER_SECCOMP_SHA256 ||
    stringField(receipt, "apparmor_profile", "evidence.receipt") !==
      "liltweak-runner-job" ||
    !booleanField(receipt, "network_denied", "evidence.receipt") ||
    booleanField(receipt, "package_install_allowed", "evidence.receipt") ||
    booleanField(receipt, "production_access_allowed", "evidence.receipt") ||
    booleanField(receipt, "deploy_allowed", "evidence.receipt")
  ) {
    throw new InputError("evidence receipt violates the fixed sandbox contract");
  }
  return {
    runner_id: PINNED_RUNNER_ID,
    runtime_image: RUNNER_RUNTIME_IMAGE,
    seccomp_sha256: RUNNER_SECCOMP_SHA256,
    apparmor_profile: "liltweak-runner-job",
    network_denied: true,
    package_install_allowed: false,
    production_access_allowed: false,
    deploy_allowed: false,
    workspace_cleaned: booleanField(
      receipt,
      "workspace_cleaned",
      "evidence.receipt",
    ),
    cgroup_cleaned: booleanField(
      receipt,
      "cgroup_cleaned",
      "evidence.receipt",
    ),
  };
}

function parseRunnerReceipt(
  value: unknown,
  outcome: RunnerEvidence["outcome"],
  exitCode: number,
): RunnerReceipt {
  if (!isRecord(value)) {
    throw new InputError("evidence.receipt must be an object");
  }
  if ("cancelled_before_execution" in value) {
    const receipt = exactRecord(
      value,
      ["cancelled_before_execution"],
      "evidence.receipt",
    );
    if (
      outcome !== "cancelled" ||
      exitCode !== 0 ||
      !booleanField(receipt, "cancelled_before_execution", "evidence.receipt")
    ) {
      throw new InputError("pre-execution cancellation receipt is invalid");
    }
    return { cancelled_before_execution: true };
  }
  if (!("source_mutated" in value)) {
    const receipt = exactRecord(value, BASE_RECEIPT_KEYS, "evidence.receipt");
    if (outcome === "succeeded") {
      throw new InputError("successful evidence requires a completed job receipt");
    }
    return parseBaseReceiptFields(receipt);
  }

  const sourceMutated = booleanField(value, "source_mutated", "evidence.receipt");
  if (!sourceMutated) {
    const receipt = exactRecord(
      value,
      [...BASE_RECEIPT_KEYS, "candidate_sha", "source_commit", "source_tree", "source_mutated"],
      "evidence.receipt",
    );
    if (receipt.candidate_sha !== null) {
      throw new InputError("read-only evidence receipt candidate_sha must be null");
    }
    return {
      ...parseBaseReceiptFields(receipt),
      candidate_sha: null,
      source_commit: requireMatch(
        stringField(receipt, "source_commit", "evidence.receipt"),
        GIT_SHA_PATTERN,
        "evidence.receipt.source_commit",
      ),
      source_tree: requireMatch(
        stringField(receipt, "source_tree", "evidence.receipt"),
        GIT_SHA_PATTERN,
        "evidence.receipt.source_tree",
      ),
      source_mutated: false,
    };
  }

  const receipt = exactRecord(
    value,
    [
      ...BASE_RECEIPT_KEYS,
      "artifact_path",
      "artifact_sha256",
      "candidate_sha",
      "candidate_tree",
      "source_commit",
      "source_tree",
      "source_mutated",
      "bundle_sha256",
      "bundle_size",
      "candidate_store_id",
      "created_at_ms",
      "qualification_branch",
    ],
    "evidence.receipt",
  );
  if (
    stringField(receipt, "artifact_path", "evidence.receipt") !==
      QUALIFICATION_ARTIFACT_PATH ||
    stringField(receipt, "artifact_sha256", "evidence.receipt") !==
      QUALIFICATION_CONTENT_SHA256
  ) {
    throw new InputError("bounded-write receipt artifact is not authorized");
  }
  const bundleSize = integerField(receipt, "bundle_size", "evidence.receipt");
  if (bundleSize < 1 || bundleSize > MAX_CANDIDATE_BUNDLE_BYTES) {
    throw new InputError("evidence.receipt.bundle_size is outside the approved bound");
  }
  const createdAt = integerField(receipt, "created_at_ms", "evidence.receipt");
  if (createdAt < 0) {
    throw new InputError("evidence.receipt.created_at_ms is invalid");
  }
  return {
    ...parseBaseReceiptFields(receipt),
    artifact_path: QUALIFICATION_ARTIFACT_PATH,
    artifact_sha256: QUALIFICATION_CONTENT_SHA256,
    candidate_sha: requireMatch(
      stringField(receipt, "candidate_sha", "evidence.receipt"),
      GIT_SHA_PATTERN,
      "evidence.receipt.candidate_sha",
    ),
    candidate_tree: requireMatch(
      stringField(receipt, "candidate_tree", "evidence.receipt"),
      GIT_SHA_PATTERN,
      "evidence.receipt.candidate_tree",
    ),
    source_commit: requireMatch(
      stringField(receipt, "source_commit", "evidence.receipt"),
      GIT_SHA_PATTERN,
      "evidence.receipt.source_commit",
    ),
    source_tree: requireMatch(
      stringField(receipt, "source_tree", "evidence.receipt"),
      GIT_SHA_PATTERN,
      "evidence.receipt.source_tree",
    ),
    source_mutated: true,
    bundle_sha256: requireMatch(
      stringField(receipt, "bundle_sha256", "evidence.receipt"),
      DIGEST_PATTERN,
      "evidence.receipt.bundle_sha256",
    ),
    bundle_size: bundleSize,
    candidate_store_id: requireMatch(
      stringField(receipt, "candidate_store_id", "evidence.receipt"),
      EXECUTION_ID_PATTERN,
      "evidence.receipt.candidate_store_id",
    ),
    created_at_ms: createdAt,
    qualification_branch: requireMatch(
      stringField(receipt, "qualification_branch", "evidence.receipt"),
      QUALIFICATION_BRANCH_PATTERN,
      "evidence.receipt.qualification_branch",
    ),
  };
}

export function parseEvidenceRequest(value: unknown): EvidenceRequest {
  const record = exactRecord(
    value,
    ["execution_id", "attempt_nonce", "evidence"],
    "evidence request",
  );
  const identifiers = parseClaimIdentifiers(
    {
      execution_id: record.execution_id,
      attempt_nonce: record.attempt_nonce,
    },
    "evidence request",
  );
  const evidence = exactRecord(
    record.evidence,
    [
      "schema_version",
      "outcome",
      "operation_digest",
      "stdout_digest",
      "stderr_digest",
      "receipt_digest",
      "receipt",
      "exit_code",
      "started_at_ms",
      "finished_at_ms",
    ],
    "evidence",
  );
  const outcome = stringField(evidence, "outcome", "evidence");
  if (outcome !== "succeeded" && outcome !== "failed" && outcome !== "cancelled") {
    throw new InputError("evidence.outcome is invalid");
  }
  if (
    stringField(evidence, "schema_version", "evidence") !==
    RUNNER_EVIDENCE_SCHEMA
  ) {
    throw new InputError("evidence schema is invalid");
  }
  const evidenceDigests = [
    "operation_digest",
    "stdout_digest",
    "stderr_digest",
    "receipt_digest",
  ] as const;
  const digests = Object.fromEntries(
    evidenceDigests.map((field) => [
      field,
      requireMatch(
        stringField(evidence, field, "evidence"),
        DIGEST_PATTERN,
        field,
      ),
    ]),
  ) as Record<(typeof evidenceDigests)[number], string>;
  const startedAt = integerField(evidence, "started_at_ms", "evidence");
  const finishedAt = integerField(evidence, "finished_at_ms", "evidence");
  if (startedAt > finishedAt) {
    throw new InputError("evidence timestamps are not ordered");
  }
  const exitCode = integerField(evidence, "exit_code", "evidence");
  if (exitCode < 0 || exitCode > 255) {
    throw new InputError("evidence exit code is invalid");
  }
  return {
    ...identifiers,
    evidence: {
      schema_version: RUNNER_EVIDENCE_SCHEMA,
      outcome,
      ...digests,
      receipt: parseRunnerReceipt(evidence.receipt, outcome, exitCode),
      exit_code: exitCode,
      started_at_ms: startedAt,
      finished_at_ms: finishedAt,
    },
  };
}

export function parseCancelRequest(value: unknown): CancelRequest {
  const record = exactRecord(value, ["reason_digest"], "cancel request");
  return {
    reason_digest: requireMatch(
      stringField(record, "reason_digest", "cancel request"),
      DIGEST_PATTERN,
      "reason_digest",
    ),
  };
}

export function parseExecutionId(value: string): string {
  return requireMatch(value, EXECUTION_ID_PATTERN, "execution_id");
}
