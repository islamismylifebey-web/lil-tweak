"use client";

// Immutable activation request. The caller supplies only a fresh correlation ID.
export const ACTIVATION_REPOSITORY = "https://github.com/octocat/Hello-World.git";
export const ACTIVATION_COMMIT = "7fd1a60b01f91b314f59955a4e4d4e80d8edf11d";
export const ACTIVATION_INSTRUCTION = "Inspect README, run literal sha256sum README, report only findings, and make no edit or external action.";
export const ACTIVATION_README_SHA256 = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340";
const MAX_BODY = 2 * 1024 * 1024;
const MAX_JSON = 256 * 1024;
const seen = new Set<string>();
const UUID4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const EVIDENCE_ID = /^evidence:[0-9a-f]{32}$/;
const JOB_KEYS = ["id", "projectId", "mode", "promptPreview", "state", "revision", "summary", "proposalDigest", "sourceDigest", "approvalProposal", "approvalConsumed", "gitSource", "createdAt", "updatedAt", "sources", "evidence", "events"];

type ObjectValue = Record<string, unknown>;
interface CaptureResponse {
  id: string;
  status: number;
  mediaType: string;
  declaredLength: number | null;
  contentSha256: string | null;
  bodyBase64: string;
}

function requireValue(condition: unknown): asserts condition {
  if (!condition) throw new Error("Activation collection rejected.");
}

function exactKeys(value: unknown, keys: readonly string[]): asserts value is ObjectValue {
  requireValue(value && typeof value === "object" && !Array.isArray(value));
  requireValue(Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)));
}

function publicJob(value: unknown): ObjectValue {
  exactKeys(value, ["job"]);
  const job = value.job;
  exactKeys(job, JOB_KEYS);
  requireValue(typeof job.id === "string" && /^job:[0-9a-f]{32}$/.test(job.id));
  requireValue(job.mode === "architect" && job.projectId === null && job.promptPreview === ACTIVATION_INSTRUCTION);
  exactKeys(job.gitSource, ["repositoryUrl", "commit"]);
  requireValue(job.gitSource.repositoryUrl === ACTIVATION_REPOSITORY && job.gitSource.commit === ACTIVATION_COMMIT);
  requireValue(job.approvalProposal === null && job.approvalConsumed === false);
  requireValue(Array.isArray(job.sources) && job.sources.length === 0);
  requireValue(Array.isArray(job.evidence) && job.evidence.length <= 5);
  for (const descriptor of job.evidence) {
    exactKeys(descriptor, ["id", "jobId", "category", "filename", "mediaType", "sizeBytes", "sha256", "createdAt"]);
    requireValue(typeof descriptor.id === "string" && EVIDENCE_ID.test(descriptor.id) && descriptor.jobId === job.id);
    requireValue(typeof descriptor.sha256 === "string" && /^[0-9a-f]{64}$/.test(descriptor.sha256));
    requireValue(Number.isSafeInteger(descriptor.sizeBytes) && Number(descriptor.sizeBytes) >= 0 && Number(descriptor.sizeBytes) <= MAX_BODY);
  }
  requireValue(Array.isArray(job.events) && job.events.length <= 250);
  for (const event of job.events) exactKeys(event, ["id", "type", "summary", "createdAt"]);
  return job;
}

function statusBody(value: unknown) {
  exactKeys(value, ["status"]);
  const status = value.status;
  exactKeys(status, ["generatedAt", "controlPlane", "bridge", "runner"]);
  exactKeys(status.controlPlane, ["storage", "d1", "r2"]);
  requireValue(Object.values(status.controlPlane).every((item) => item === "configured"));
  exactKeys(status.bridge, ["origin", "transport", "signing", "access", "missing"]);
  requireValue(status.bridge.origin === "core_origin" && status.bridge.transport === "configured" && status.bridge.signing === "configured" && status.bridge.access === "configured");
  requireValue(Array.isArray(status.bridge.missing) && status.bridge.missing.length === 0);
  exactKeys(status.runner, ["owner", "provider", "dropletId", "host", "role", "route", "intermediary", "imagePolicy", "connection", "qualification"]);
  const expected = { owner: "tueiq", provider: "digitalocean", dropletId: "597343619", host: "galor-tweak-runner-01", role: "role-tweak-runner", route: "direct_core_to_local_podman", intermediary: "none", imagePolicy: "digest_pinned", connection: "ready", qualification: "not_reported" };
  requireValue(Object.entries(expected).every(([key, value]) => (status.runner as ObjectValue)[key] === value));
}

async function sha256(bytes: Uint8Array) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>))].map((value) => value.toString(16).padStart(2, "0")).join("");
}

async function retain(response: Response, id: string, evidence: boolean): Promise<{ retained: CaptureResponse; value: unknown }> {
  // Read only these three response metadata fields. No header iterator/copy.
  const mediaType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  const length = response.headers.get("content-length");
  const contentSha256 = response.headers.get("x-content-sha256");
  requireValue(mediaType === (evidence ? "text/plain" : "application/json"));
  requireValue(response.status === (id === "create" ? 201 : 200));
  const maximum = evidence ? MAX_BODY : MAX_JSON;
  requireValue(length === null || /^(0|[1-9][0-9]{0,8})$/.test(length));
  const declaredLength = length === null ? null : Number(length);
  requireValue(declaredLength === null || declaredLength <= maximum);
  const reader = response.body?.getReader();
  requireValue(reader);
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      total += chunk.value.length;
      requireValue(total <= maximum);
      chunks.push(chunk.value);
    }
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
  requireValue(declaredLength === null || total === declaredLength);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  requireValue(evidence ? contentSha256 === await sha256(bytes) && declaredLength === total : contentSha256 === null);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  requireValue(!/(?:authorization|set-cookie|bearer\s|-----BEGIN|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:secret|token|password|api_key)\s*[:=])/i.test(text));
  let binary = "";
  for (let index = 0; index < bytes.length; index += 8192) binary += String.fromCharCode(...bytes.subarray(index, index + 8192));
  return { retained: { id, status: response.status, mediaType, declaredLength, contentSha256, bodyBase64: btoa(binary) }, value: evidence ? null : JSON.parse(text) };
}

export async function collectTueiqActivationEvidence(input: { requestId: string }) {
  exactKeys(input, ["requestId"]);
  requireValue(typeof input.requestId === "string" && UUID4.test(input.requestId) && !seen.has(input.requestId) && seen.size < 64);
  seen.add(input.requestId);
  const startedAt = new Date().toISOString();
  const deadline = Date.now() + 1_200_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1_200_000);
  const responses: CaptureResponse[] = [];
  const request = async (path: string, id: string, init: RequestInit = {}, evidence = false) => {
    requireValue(Date.now() < deadline && path.startsWith("/api/engineering/") && !path.includes("//"));
    const result = await retain(await fetch(path, { ...init, credentials: "same-origin", redirect: "error", cache: "no-store", signal: controller.signal }), id, evidence);
    return result;
  };
  try {
    const status = await request("/api/engineering/status", "status");
    statusBody(status.value); responses.push(status.retained);
    const create = await request("/api/engineering/jobs", "create", {
      method: "POST", headers: { "Content-Type": "application/json", "Idempotency-Key": input.requestId },
      body: JSON.stringify({ requestId: input.requestId, mode: "architect", prompt: ACTIVATION_INSTRUCTION, projectId: null, sources: [], gitSource: { repositoryUrl: ACTIVATION_REPOSITORY, commit: ACTIVATION_COMMIT } }),
    });
    let job = publicJob(create.value);
    requireValue(job.state === "queued" && job.revision === 0);
    responses.push(create.retained);
    const jobId = job.id as string;
    const dispatched = await request(`/api/engineering/jobs/${jobId}`, "dispatch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ action: "dispatch", revision: job.revision }) });
    job = publicJob(dispatched.value); requireValue(job.id === jobId); responses.push(dispatched.retained);
    for (;;) {
      const poll = await request(`/api/engineering/jobs/${jobId}?fresh=1`, "poll-final");
      job = publicJob(poll.value); requireValue(job.id === jobId);
      if (job.state === "completed") { responses.push(poll.retained); break; }
      requireValue(!["awaiting_approval", "applying", "rejected", "cancelled", "failed", "timed_out"].includes(String(job.state)));
      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
    const evidence = job.evidence as ObjectValue[];
    requireValue(evidence.length === 5 && new Set(evidence.map((d) => d.id)).size === 5);
    requireValue(["plan.md", "changes.patch", "tests.log", "manifest.json", "summary.md"].every((name) => evidence.some((d) => d.filename === name)));
    for (const d of evidence) {
      const preview = await request(`/api/engineering/evidence/${d.id}?preview=1`, d.id as string, {}, true);
      requireValue(preview.retained.contentSha256 === d.sha256 && preview.retained.declaredLength === d.sizeBytes);
      responses.push(preview.retained);
    }
    return { schema: "tueiq-site-primary-capture-v1", requestId: input.requestId, startedAt, completedAt: new Date().toISOString(), responses };
  } finally { clearTimeout(timer); controller.abort(); }
}
