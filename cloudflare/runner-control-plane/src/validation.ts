export class InputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InputError";
  }
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function exactRecord(
  value: unknown,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new InputError(`${label} must be an object`);
  }
  const actualKeys = Object.keys(value).sort();
  const expectedKeys = [...keys].sort();
  if (
    actualKeys.length !== expectedKeys.length ||
    actualKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new InputError(`${label} contains unexpected or missing fields`);
  }
  return value;
}

export function stringField(
  record: Record<string, unknown>,
  field: string,
  label: string,
): string {
  const value = record[field];
  if (typeof value !== "string") {
    throw new InputError(`${label}.${field} must be a string`);
  }
  return value;
}

export function integerField(
  record: Record<string, unknown>,
  field: string,
  label: string,
): number {
  const value = record[field];
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new InputError(`${label}.${field} must be a safe integer`);
  }
  return value;
}

export function booleanField(
  record: Record<string, unknown>,
  field: string,
  label: string,
): boolean {
  const value = record[field];
  if (typeof value !== "boolean") {
    throw new InputError(`${label}.${field} must be a boolean`);
  }
  return value;
}

export function requireMatch(
  value: string,
  pattern: RegExp,
  label: string,
): string {
  if (!pattern.test(value)) {
    throw new InputError(`${label} has an invalid format`);
  }
  return value;
}
