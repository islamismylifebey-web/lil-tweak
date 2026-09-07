import { cookies, headers } from "next/headers";
import {
  CANONICAL_OWNER_KEY,
  trustedOwnerFromHeaders,
} from "./owner-auth";
import {
  SESSION_COOKIE,
  verifyOwnerSessionToken,
} from "./owner-session";

function cookieValue(cookieHeader: string | null, name: string) {
  if (!cookieHeader) return undefined;
  for (const entry of cookieHeader.split(";")) {
    const separator = entry.indexOf("=");
    if (separator === -1) continue;
    if (entry.slice(0, separator).trim() === name) {
      return entry.slice(separator + 1).trim();
    }
  }
  return undefined;
}

export async function authenticatedOwner(request: Request) {
  const trustedOwner = trustedOwnerFromHeaders(request.headers);
  if (trustedOwner) return trustedOwner;
  const token = cookieValue(request.headers.get("cookie"), SESSION_COOKIE);
  return await verifyOwnerSessionToken(token) ? CANONICAL_OWNER_KEY : null;
}

export async function currentOwner() {
  const requestHeaders = await headers();
  const trustedOwner = trustedOwnerFromHeaders(requestHeaders);
  if (trustedOwner) return trustedOwner;
  const cookieStore = await cookies();
  return await verifyOwnerSessionToken(cookieStore.get(SESSION_COOKIE)?.value)
    ? CANONICAL_OWNER_KEY
    : null;
}
