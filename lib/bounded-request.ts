export class RequestBoundaryError extends Error {
  readonly status: 400 | 413 | 415;
  readonly code: string;

  constructor(
    message: string,
    status: 400 | 413 | 415,
    code: string,
  ) {
    super(message);
    this.name = "RequestBoundaryError";
    this.status = status;
    this.code = code;
  }
}

export function requireExactLength(value: string | null, maximum: number): number {
  if (!value || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new RequestBoundaryError("A valid Content-Length is required.", 400, "invalid_length");
  }
  const length = Number(value);
  if (!Number.isSafeInteger(length)) {
    throw new RequestBoundaryError("A valid Content-Length is required.", 400, "invalid_length");
  }
  if (length > maximum) {
    throw new RequestBoundaryError("Content-Length exceeds the request limit.", 413, "body_too_large");
  }
  return length;
}

export async function readBoundedBytes(request: Request, maximum: number): Promise<Uint8Array> {
  const declared = requireExactLength(request.headers.get("content-length"), maximum);
  if (!request.body) {
    if (declared === 0) return new Uint8Array();
    throw new RequestBoundaryError("Body length does not match Content-Length.", 400, "length_mismatch");
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) {
        throw new RequestBoundaryError("Request body exceeds the request limit.", 413, "body_too_large");
      }
      if (total > declared) {
        throw new RequestBoundaryError("Body length does not match Content-Length.", 400, "length_mismatch");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total !== declared) {
    throw new RequestBoundaryError("Body length does not match Content-Length.", 400, "length_mismatch");
  }

  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

export async function readBoundedJson(request: Request, maximum: number): Promise<unknown> {
  const mediaType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") {
    throw new RequestBoundaryError("Content-Type must be application/json.", 415, "json_required");
  }
  const bytes = await readBoundedBytes(request, maximum);
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new RequestBoundaryError("Request body is not valid JSON.", 400, "invalid_json");
  }
}
