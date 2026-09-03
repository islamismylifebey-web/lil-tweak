// Keep the established D1 partition key so existing workspace records remain reachable.
// Login authorization is controlled separately by OWNER_IDENTITIES.
const CANONICAL_OWNER_KEY = "beythetruth4ever@paradigmshiftingthepodcast.net";
const OWNER_IDENTITIES = new Set([
  "islamismylifebey@gmail.com",
]);

export function ownerIdentityIsAllowed(value: string | null | undefined) {
  return OWNER_IDENTITIES.has(value?.trim().toLowerCase() ?? "");
}

export function authenticatedOwner(request: Request) {
  const forwardedId = request.headers.get("oai-authenticated-user-id")?.trim();
  const forwarded = request.headers
    .get("oai-authenticated-user-email")
    ?.trim()
    .toLowerCase();
  return forwardedId && ownerIdentityIsAllowed(forwarded)
    ? CANONICAL_OWNER_KEY
    : null;
}

export function mutationRequestIsSafe(request: Request) {
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  return origin === new URL(request.url).origin && (!fetchSite || fetchSite === "same-origin");
}
