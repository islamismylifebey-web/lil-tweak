import type {
  ApprovalProposal,
  EngineerMode,
  EngineeringJob,
  EngineeringJobDetail,
  JobState,
} from "../lib/engineering.ts";
import type { GitSourceInput } from "../lib/engineering-input.ts";
import { sha256Hex } from "../lib/core-signing.ts";

const STATE_LABELS: Readonly<Record<JobState, string>> = {
  draft: "Draft",
  uploading: "Uploading source",
  queued: "Queued securely",
  ingesting: "Inspecting source",
  planning: "Planning changes",
  executing: "Editing in sandbox",
  testing: "Running tests",
  collecting: "Building evidence",
  awaiting_approval: "Your approval is required",
  applying: "Applying approved action",
  completed: "Completed",
  rejected: "Rejected",
  cancelled: "Cancelled",
  failed: "Failed",
  timed_out: "Timed out",
};

const POLLING_STATES = new Set<JobState>([
  "queued",
  "ingesting",
  "planning",
  "executing",
  "testing",
  "collecting",
  "applying",
]);

export function jobStateLabel(state: JobState): string {
  return STATE_LABELS[state];
}

export function jobNeedsApproval(state: JobState): boolean {
  return state === "awaiting_approval";
}

export function jobIsPolling(state: JobState): boolean {
  return POLLING_STATES.has(state);
}

export function jobCanCancel(state: JobState): boolean {
  return !["completed", "rejected", "cancelled", "failed", "timed_out"].includes(state);
}

export type EngineeringBridgeState =
  | "pending_configuration"
  | "configured_pending_probe"
  | "health_reachable"
  | "health_unreachable";

export interface EngineeringConnectionStatus {
  generatedAt: string;
  controlPlane: {
    storage: "configured" | "missing";
    d1: "configured" | "missing";
    r2: "configured" | "missing";
  };
  bridge: {
    state: EngineeringBridgeState;
    origin: "none" | "core_origin" | "sites_private_tunnel";
    transport: "configured" | "missing";
    signing: "configured" | "missing";
    access: "configured" | "missing" | "not_required";
    health: "not_checked" | "ok" | "failed";
    missing: string[];
  };
  github: {
    lilTweak: {
      repository: "islamismylifebey-web/lil-tweak";
      branch: "main";
      head: string;
      pr6Merge: string;
    };
    galorHub: {
      repository: "islamismylifebey-web/galor-hub";
      branch: "main";
      head: string;
      pr28Merge: string;
    };
  };
  galor: {
    contract: "galor-runner";
    version: string;
    executionHost: string;
    integration: "awaiting_runtime_probe";
  };
  runner: {
    state: EngineeringBridgeState;
    label: string;
  };
}

interface FetchResult {
  ok: boolean;
  status?: number;
  json?: () => Promise<unknown>;
}

type FetchLike = (url: string, init: RequestInit) => Promise<FetchResult>;

interface SessionStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

interface ApprovalAttemptOptions {
  storage?: SessionStore;
  randomBytes?: () => Uint8Array;
  randomUUID?: () => string;
}

interface ApprovalAttempt {
  version: 1;
  jobId: string;
  proposalDigest: string;
  expiresAt: string;
  approvalToken: string;
  approvalTokenHash: string;
  attemptId: string;
}

function sessionStore(provided?: SessionStore): SessionStore {
  if (provided) return provided;
  if (typeof sessionStorage === "undefined") {
    throw new Error("One-time patch export requires browser session storage.");
  }
  return sessionStorage;
}

function approvalAttemptKey(jobId: string, proposalDigest: string): string {
  return `lil-tweak:patch-export:v1:${jobId}:${proposalDigest}`;
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function validAttempt(
  value: unknown,
  jobId: string,
  proposal: ApprovalProposal,
): Promise<boolean> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const attempt = value as Partial<ApprovalAttempt>;
  if (!(
    attempt.version === 1 &&
    attempt.jobId === jobId &&
    attempt.proposalDigest === proposal.proposalDigest &&
    attempt.expiresAt === proposal.expiresAt &&
    typeof attempt.approvalToken === "string" &&
    /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(attempt.approvalToken) &&
    typeof attempt.approvalTokenHash === "string" &&
    /^[a-f0-9]{64}$/.test(attempt.approvalTokenHash) &&
    typeof attempt.attemptId === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(attempt.attemptId)
  )) return false;
  return await sha256Hex(attempt.approvalToken) === attempt.approvalTokenHash;
}

async function approvalAttempt(
  jobId: string,
  proposal: ApprovalProposal,
  options: ApprovalAttemptOptions,
): Promise<ApprovalAttempt> {
  const storage = sessionStore(options.storage);
  const key = approvalAttemptKey(jobId, proposal.proposalDigest);
  const stored = storage.getItem(key);
  if (stored) {
    try {
      const parsed: unknown = JSON.parse(stored);
      if (await validAttempt(parsed, jobId, proposal)) return parsed as ApprovalAttempt;
    } catch {
      // Replace malformed session-only state with a fresh bound attempt.
    }
    throw new Error("The saved one-time patch export attempt is invalid.");
  }
  const bytes = options.randomBytes?.() ?? crypto.getRandomValues(new Uint8Array(32));
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) {
    throw new Error("One-time patch export token generation failed.");
  }
  const token = base64Url(bytes);
  const attempt: ApprovalAttempt = {
    version: 1,
    jobId,
    proposalDigest: proposal.proposalDigest,
    expiresAt: proposal.expiresAt,
    approvalToken: token,
    approvalTokenHash: await sha256Hex(token),
    attemptId: options.randomUUID?.() ?? crypto.randomUUID(),
  };
  if (!await validAttempt(attempt, jobId, proposal)) {
    throw new Error("One-time patch export attempt generation failed.");
  }
  storage.setItem(key, JSON.stringify(attempt));
  return attempt;
}

async function errorFrom(response: FetchResult): Promise<Error> {
  if (response.json) {
    try {
      const payload = (await response.json()) as { error?: string; message?: string };
      return new Error(payload.error ?? payload.message ?? "Lil Tweak request failed.");
    } catch {
      // The public fallback below intentionally contains no transport detail.
    }
  }
  return new Error("Lil Tweak request failed.");
}

export async function engineeringRequest<T>(
  url: string,
  init: RequestInit = {},
  fetcher: typeof fetch = fetch,
): Promise<T> {
  const response = await fetcher(url, {
    credentials: "same-origin",
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.body && typeof init.body === "string" ? { "Content-Type": "application/json" } : {}),
      ...init.headers,
    },
  });
  if (!response.ok) throw await errorFrom(response);
  return (await response.json()) as T;
}

export async function getEngineeringConnectionStatus(
  fetcher: typeof fetch = fetch,
): Promise<EngineeringConnectionStatus> {
  const result = await engineeringRequest<{ status: EngineeringConnectionStatus }>(
    "/api/engineering/status",
    {},
    fetcher,
  );
  return result.status;
}

export async function createEngineeringJob(input: {
  requestId: string;
  mode: EngineerMode;
  prompt: string;
  projectId: string | null;
  files: File[];
  gitSource?: GitSourceInput | null;
}, fetcher: typeof fetch = fetch): Promise<EngineeringJobDetail> {
  const result = await engineeringRequest<{ job: EngineeringJobDetail }>(
    "/api/engineering/jobs",
    {
      method: "POST",
      headers: { "Idempotency-Key": input.requestId },
      body: JSON.stringify({
        requestId: input.requestId,
        mode: input.mode,
        prompt: input.prompt,
        projectId: input.projectId,
        gitSource: input.gitSource ?? null,
        sources: input.files.map((file) => ({
          filename: file.name.trim(),
          mediaType: file.type || "application/octet-stream",
          sizeBytes: file.size,
        })),
      }),
    },
    fetcher,
  );
  return result.job;
}

export async function uploadSourcesForJob(
  jobId: string,
  files: File[],
  sources: Array<{ id: string; filename: string; sizeBytes: number }>,
  fetcher: FetchLike = fetch,
  onProgress?: (completed: number, total: number) => void,
): Promise<void> {
  if (files.length !== sources.length) throw new Error("Source manifest does not match selected files.");
  const sourceByFilename = new Map(sources.map((source) => [source.filename, source]));
  if (sourceByFilename.size !== sources.length) {
    throw new Error("Source manifest contains duplicate filenames.");
  }
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const source = sourceByFilename.get(file.name.trim());
    if (!source || file.size !== source.sizeBytes) {
      throw new Error("Source manifest changed before upload.");
    }
    const response = await fetcher(
      `/api/engineering/jobs/${encodeURIComponent(jobId)}/sources?sourceId=${encodeURIComponent(source.id)}`,
      {
        method: "PUT",
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": file.type || "application/octet-stream",
          "X-Source-Filename": source.filename,
        },
        body: file,
      },
    );
    if (!response.ok) throw await errorFrom(response);
    onProgress?.(index + 1, files.length);
  }
}

export async function dispatchEngineeringJob(job: EngineeringJobDetail): Promise<EngineeringJobDetail> {
  const result = await engineeringRequest<{ job: EngineeringJobDetail }>(
    `/api/engineering/jobs/${encodeURIComponent(job.id)}`,
    { method: "POST", body: JSON.stringify({ action: "dispatch", revision: job.revision }) },
  );
  return result.job;
}

export async function getEngineeringJob(jobId: string): Promise<EngineeringJobDetail> {
  const result = await engineeringRequest<{ job: EngineeringJobDetail }>(
    `/api/engineering/jobs/${encodeURIComponent(jobId)}?fresh=1`,
  );
  return result.job;
}

export async function listEngineeringJobs(): Promise<EngineeringJob[]> {
  const result = await engineeringRequest<{ jobs: EngineeringJob[] }>("/api/engineering/jobs?limit=30");
  return result.jobs;
}

export async function decideEngineeringJob(
  job: Pick<EngineeringJobDetail, "id" | "revision" | "approvalProposal">,
  decision: "approve" | "reject",
  reason = "",
  fetcher: typeof fetch = fetch,
  options: ApprovalAttemptOptions = {},
): Promise<EngineeringJobDetail> {
  const approvalProposal: ApprovalProposal | null = job.approvalProposal;
  if (!approvalProposal) throw new Error("Engineering approval proposal is unavailable.");
  const attempt = decision === "approve"
    ? await approvalAttempt(job.id, approvalProposal, options)
    : null;
  const result = await engineeringRequest<{ job: EngineeringJobDetail }>(
    `/api/engineering/jobs/${encodeURIComponent(job.id)}/decision`,
    {
      method: "POST",
      body: JSON.stringify({
        decision,
        reason,
        revision: job.revision,
        approvalProposal,
        ...(attempt ? { approvalTokenHash: attempt.approvalTokenHash } : {}),
      }),
    },
    fetcher,
  );
  return result.job;
}

export async function exportEngineeringPatch(
  job: Pick<EngineeringJobDetail, "id" | "proposalDigest" | "approvalProposal">,
  evidence: Pick<EngineeringJobDetail["evidence"][number], "id" | "category" | "filename">,
  fetcher: typeof fetch = fetch,
  options: Pick<ApprovalAttemptOptions, "storage"> = {},
): Promise<Blob> {
  const proposal = job.approvalProposal;
  if (
    !proposal ||
    job.proposalDigest !== proposal.proposalDigest ||
    evidence.category !== "patch" ||
    evidence.filename !== "changes.patch"
  ) {
    throw new Error("One-time patch export is unavailable.");
  }
  const storage = sessionStore(options.storage);
  const stored = storage.getItem(approvalAttemptKey(job.id, proposal.proposalDigest));
  let parsed: unknown;
  try {
    parsed = stored ? JSON.parse(stored) : null;
  } catch {
    parsed = null;
  }
  if (!await validAttempt(parsed, job.id, proposal)) {
    throw new Error("Approve this exact proposal in the current browser session before exporting it.");
  }
  const attempt = parsed as ApprovalAttempt;
  const response = await fetcher(
    `/api/engineering/evidence/${encodeURIComponent(evidence.id)}`,
    {
      method: "POST",
      credentials: "same-origin",
      headers: { Accept: "application/octet-stream", "Content-Type": "application/json" },
      body: JSON.stringify({
        approvalToken: attempt.approvalToken,
        attemptId: attempt.attemptId,
      }),
    },
  );
  if (!response.ok) throw await errorFrom(response);
  return response.blob();
}

export async function cancelEngineeringJob(
  job: Pick<EngineeringJobDetail, "id" | "revision">,
  fetcher: typeof fetch = fetch,
): Promise<EngineeringJobDetail> {
  const result = await engineeringRequest<{ job: EngineeringJobDetail }>(
    `/api/engineering/jobs/${encodeURIComponent(job.id)}/cancel`,
    {
      method: "POST",
      body: JSON.stringify({ revision: job.revision }),
    },
    fetcher,
  );
  return result.job;
}
