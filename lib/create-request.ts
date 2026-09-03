import { sha256Hex } from "./core-signing.ts";
import { parseJobCreate, type EngineeringJobDetail } from "./engineering.ts";
import { boundedProjectContext, parseGitSource } from "./engineering-input.ts";
import { engineeringCreateRequestDigest, type EngineeringJobCreate } from "./engineering-store.ts";
import { ImmutableObjectConflictError, putImmutableObject } from "./immutable-r2.ts";

const CREATE_REQUEST_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[a-f0-9]{64}$/;

interface RequestObject {
  size: number;
  customMetadata?: Record<string, string>;
  checksums?: { sha256?: ArrayBuffer | string };
  text(): Promise<string>;
}

interface RequestBucket {
  get(key: string): Promise<RequestObject | null>;
  put(key: string, value: string, options: R2PutOptions): Promise<unknown | null>;
}

export function requireCreateRequestId(headerValue: string | null, bodyValue: unknown): string {
  if (
    typeof bodyValue !== "string" ||
    headerValue !== bodyValue ||
    !CREATE_REQUEST_ID.test(bodyValue)
  ) {
    throw new Error("Engineering creation idempotency is invalid.");
  }
  return bodyValue;
}

async function exactRequestObject(
  object: RequestObject | null,
  body: string,
  requestDigest: string,
): Promise<boolean> {
  if (!object || object.customMetadata?.requestDigest !== requestDigest) return false;
  const bytes = new TextEncoder().encode(body).byteLength;
  if (object.size !== bytes) return false;
  const [storedDigest, expectedDigest] = await Promise.all([
    sha256Hex(await object.text()),
    sha256Hex(body),
  ]);
  return storedDigest === expectedDigest && checksumHex(object.checksums?.sha256) === expectedDigest;
}

function checksumHex(value: ArrayBuffer | string | undefined) {
  if (typeof value === "string") return /^[a-f0-9]{64}$/.test(value) ? value : null;
  if (!(value instanceof ArrayBuffer) || value.byteLength !== 32) return null;
  return [...new Uint8Array(value)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function integrityFailure(): never {
  throw new Error("Engineering request integrity check failed.");
}

const REQUEST_FIELDS = new Set(["id", "mode", "prompt", "projectId", "projectContext", "gitSource"]);

async function frozenRequestPayload(
  object: RequestObject | null,
  expectedRequestDigest?: string,
) {
  if (
    !object || object.size <= 0 || object.size > 32 * 1024 ||
    !SHA256.test(object.customMetadata?.requestDigest ?? "") ||
    (expectedRequestDigest && object.customMetadata?.requestDigest !== expectedRequestDigest)
  ) integrityFailure();
  const body = await object.text();
  if (new TextEncoder().encode(body).byteLength !== object.size) integrityFailure();
  const bodyDigest = await sha256Hex(body);
  if (checksumHex(object.checksums?.sha256) !== bodyDigest) integrityFailure();
  let payload: Record<string, unknown>;
  try {
    const value = JSON.parse(body) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) integrityFailure();
    payload = value as Record<string, unknown>;
  } catch {
    integrityFailure();
  }
  if (Object.keys(payload).some((key) => !REQUEST_FIELDS.has(key))) integrityFailure();
  return {
    payload,
    requestDigest: object.customMetadata?.requestDigest as string,
  };
}

function canonicalProjectContext(payload: Record<string, unknown>, projectId: string | null) {
  if (!projectId) {
    if (payload.projectContext !== null) integrityFailure();
    return null;
  }
  let projectContext;
  try {
    projectContext = boundedProjectContext(payload.projectContext);
  } catch {
    integrityFailure();
  }
  if (
    projectContext.projectId !== projectId ||
    JSON.stringify(projectContext) !== JSON.stringify(payload.projectContext)
  ) integrityFailure();
  return projectContext;
}

export async function recoverEngineeringCreateRequest(input: {
  object: RequestObject | null;
  jobId: string;
  ownerInput: Omit<EngineeringJobCreate, "projectContext">;
}) {
  const { payload, requestDigest } = await frozenRequestPayload(input.object);
  if (payload.id !== input.jobId) integrityFailure();
  let request;
  let gitSource;
  try {
    request = parseJobCreate(payload);
    gitSource = parseGitSource(payload.gitSource);
  } catch {
    integrityFailure();
  }
  if (
    request.mode !== input.ownerInput.mode ||
    request.prompt !== input.ownerInput.prompt ||
    request.projectId !== input.ownerInput.projectId ||
    JSON.stringify(gitSource) !== JSON.stringify(parseGitSource(input.ownerInput.gitSource))
  ) integrityFailure();
  const projectContext = canonicalProjectContext(payload, request.projectId);
  const computedDigest = await engineeringCreateRequestDigest({
    ...input.ownerInput,
    gitSource,
    projectContext,
  });
  if (computedDigest !== requestDigest) integrityFailure();
  return { requestDigest, projectContext };
}

export async function validateEngineeringDispatchRequest(input: {
  object: RequestObject | null;
  expectedRequestDigest: string;
  expectedPromptDigest: string;
  job: Pick<EngineeringJobDetail, "id" | "mode" | "projectId" | "gitSource" | "sources">;
}) {
  const { payload } = await frozenRequestPayload(input.object, input.expectedRequestDigest);
  if (payload.id !== input.job.id) integrityFailure();
  let request;
  let gitSource;
  try {
    request = parseJobCreate(payload);
    gitSource = parseGitSource(payload.gitSource);
  } catch {
    integrityFailure();
  }
  if (
    request.mode !== input.job.mode || request.projectId !== input.job.projectId ||
    JSON.stringify(gitSource) !== JSON.stringify(input.job.gitSource)
  ) integrityFailure();
  const projectContext = canonicalProjectContext(payload, request.projectId);
  const [requestDigest, promptDigest] = await Promise.all([
    engineeringCreateRequestDigest({
      ...request,
      sources: input.job.sources.map(({ filename, mediaType, sizeBytes }) => ({ filename, mediaType, sizeBytes })),
      gitSource,
      projectContext,
    }),
    sha256Hex(request.prompt),
  ]);
  if (requestDigest !== input.expectedRequestDigest || promptDigest !== input.expectedPromptDigest) {
    integrityFailure();
  }
  return { prompt: request.prompt, projectContext, gitSource };
}

export async function ensureEngineeringRequestObject(input: {
  bucket: RequestBucket;
  key: string;
  body: string;
  requestDigest: string;
}): Promise<boolean> {
  if (!SHA256.test(input.requestDigest)) throw new Error("Engineering creation idempotency is invalid.");
  const existing = await input.bucket.get(input.key);
  if (existing) {
    if (!await exactRequestObject(existing, input.body, input.requestDigest)) {
      throw new Error("Engineering request object belongs to a different request.");
    }
    return false;
  }
  const bodySha256 = await sha256Hex(input.body);
  try {
    await putImmutableObject(input.bucket, input.key, input.body, {
      httpMetadata: { contentType: "application/json" },
      customMetadata: { requestDigest: input.requestDigest },
      sha256: bodySha256,
    });
    return true;
  } catch (error) {
    if (!(error instanceof ImmutableObjectConflictError)) throw error;
    if (!await exactRequestObject(await input.bucket.get(input.key), input.body, input.requestDigest)) {
      throw new Error("Engineering request object belongs to a different request.");
    }
    return false;
  }
}
