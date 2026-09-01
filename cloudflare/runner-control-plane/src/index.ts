import {
  canonicalJson,
  PINNED_RUNNER_ID,
  sha256Hex,
  verifyDispatchAttestation,
} from "./attestation";
import {
  parseCancelRequest,
  parseClaimRequest,
  parseEvidenceRequest,
  parseExecutionId,
  parseOfferRequest,
  type ExecutionSummary,
} from "./protocol";
import {
  RunnerControlPlane,
  type ControlPlaneResult,
} from "./runner-control-plane";
import { InputError } from "./validation";

export interface Env {
  RUNNER_CONTROL_PLANE: DurableObjectNamespace<RunnerControlPlane>;
  /** Cloudflare secret binding: control-plane server bearer. Never place a value in wrangler.jsonc. */
  CONTROL_PLANE_BEARER_TOKEN: string;
  /** Cloudflare secret binding: runner bearer. Never place a value in wrangler.jsonc. */
  RUNNER_BEARER_TOKEN: string;
  /** Public, pinned Ed25519 signer identity. */
  LIL_TWEAK_ATTESTATION_KEY_ID: string;
  /** Public, base64url-encoded 32-byte Ed25519 public key. */
  LIL_TWEAK_ATTESTATION_PUBLIC_KEY: string;
}

const MAX_JSON_BYTES = 16 * 1024;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function error(status: number, code: string): Response {
  return json({ error: code }, status);
}

async function constantTimeStringEqual(left: string, right: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [leftDigest, rightDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const leftBytes = new Uint8Array(leftDigest);
  const rightBytes = new Uint8Array(rightDigest);
  let difference = leftBytes.length ^ rightBytes.length;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index]! ^ rightBytes[index]!;
  }
  return difference === 0;
}

async function hasBearer(
  request: Request,
  expected: string | undefined,
): Promise<boolean> {
  const authorization = request.headers.get("authorization");
  if (
    typeof expected !== "string" ||
    !authorization?.startsWith("Bearer ") ||
    expected.length < 16
  ) {
    return false;
  }
  const token = authorization.slice("Bearer ".length);
  if (!/^[A-Za-z0-9._~+/-]{16,1024}$/.test(token)) {
    return false;
  }
  return constantTimeStringEqual(token, expected);
}

async function readJson(request: Request): Promise<unknown> {
  if (request.headers.get("content-type")?.split(";", 1)[0] !== "application/json") {
    throw new InputError("content type must be application/json");
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_JSON_BYTES) {
    throw new InputError("request body is too large");
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new InputError("request body is not valid JSON");
  }
}

function controlObject(env: Env): DurableObjectStub<RunnerControlPlane> {
  return env.RUNNER_CONTROL_PLANE.getByName(PINNED_RUNNER_ID);
}

function resultResponse<T>(result: ControlPlaneResult<T>, successStatus: number): Response {
  if (result.ok) {
    return json(result.value, successStatus);
  }
  switch (result.error) {
    case "not_found":
      return error(404, "not_found");
    case "expired":
      return error(409, "expired");
    case "conflict":
      return error(409, "conflict");
  }
}

async function handle(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const runnerPrefix = `/v1/runners/${PINNED_RUNNER_ID}`;
  const controlExecution = /^\/v1\/control\/executions\/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})$/;
  const controlCancel = /^\/v1\/control\/executions\/([A-Za-z0-9][A-Za-z0-9._:-]{0,127})\/cancel$/;

  if (request.method === "POST" && url.pathname === "/v1/control/offer") {
    if (!(await hasBearer(request, env.CONTROL_PLANE_BEARER_TOKEN))) {
      return error(401, "unauthorized");
    }
    const body = parseOfferRequest(await readJson(request));
    const verified = await verifyDispatchAttestation(body.attestation, env, Date.now());
    return resultResponse(await controlObject(env).offer(verified, Date.now()), 201);
  }

  if (request.method === "POST" && url.pathname === `${runnerPrefix}/claim`) {
    if (!(await hasBearer(request, env.RUNNER_BEARER_TOKEN))) {
      return error(401, "unauthorized");
    }
    const claim = parseClaimRequest(await readJson(request));
    return resultResponse(await controlObject(env).claim(claim, Date.now()), 200);
  }

  if (request.method === "POST" && url.pathname === `${runnerPrefix}/evidence`) {
    if (!(await hasBearer(request, env.RUNNER_BEARER_TOKEN))) {
      return error(401, "unauthorized");
    }
    const evidence = parseEvidenceRequest(await readJson(request));
    const evidenceDigest = await sha256Hex(canonicalJson(evidence.evidence));
    return resultResponse(
      await controlObject(env).recordEvidence(evidence, evidenceDigest, Date.now()),
      202,
    );
  }

  const statusMatch = controlExecution.exec(url.pathname);
  if (request.method === "GET" && statusMatch !== null) {
    if (!(await hasBearer(request, env.CONTROL_PLANE_BEARER_TOKEN))) {
      return error(401, "unauthorized");
    }
    const executionId = parseExecutionId(statusMatch[1]!);
    return resultResponse(await controlObject(env).getStatus(executionId, Date.now()), 200);
  }

  const cancelMatch = controlCancel.exec(url.pathname);
  if (request.method === "POST" && cancelMatch !== null) {
    if (!(await hasBearer(request, env.CONTROL_PLANE_BEARER_TOKEN))) {
      return error(401, "unauthorized");
    }
    const cancellation = parseCancelRequest(await readJson(request));
    return resultResponse(
      await controlObject(env).cancel(
        parseExecutionId(cancelMatch[1]!),
        cancellation.reason_digest,
        Date.now(),
      ),
      202,
    );
  }

  return error(404, "not_found");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await handle(request, env);
    } catch (exception) {
      if (exception instanceof InputError) {
        return error(400, "invalid_request");
      }
      return error(500, "internal_error");
    }
  },
} satisfies ExportedHandler<Env>;

export { RunnerControlPlane };
