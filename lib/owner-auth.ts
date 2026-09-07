// Keep the established D1 partition key so existing workspace records remain reachable.
// Login authorization is controlled separately by OWNER_IDENTITIES.
export const CANONICAL_OWNER_KEY = "beythetruth4ever@paradigmshiftingthepodcast.net";
export const OWNER_EMAIL = "islamismylifebey@gmail.com";
const OWNER_IDENTITIES = new Set([
  OWNER_EMAIL,
]);

export function ownerIdentityIsAllowed(value: string | null | undefined) {
  return OWNER_IDENTITIES.has(value?.trim().toLowerCase() ?? "");
}

export function trustedOwnerFromHeaders(headers: Headers) {
  const forwardedId = headers.get("oai-authenticated-user-id")?.trim();
  const forwarded = headers
    .get("oai-authenticated-user-email")
    ?.trim()
    .toLowerCase();
  return forwardedId && ownerIdentityIsAllowed(forwarded)
    ? CANONICAL_OWNER_KEY
    : null;
}

export function authenticatedOwner(request: Request) {
  return trustedOwnerFromHeaders(request.headers);
}

export function mutationRequestIsSafe(request: Request) {
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  return origin === new URL(request.url).origin && (!fetchSite || fetchSite === "same-origin");
}
